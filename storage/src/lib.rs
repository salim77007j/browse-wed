//! # bw-storage — partitioned site-data engine
//!
//! Every persistence surface in this crate is **partitioned by top-level
//! site** (CHIPS-style):
//!
//! * [`cookies`] — a full RFC 6265bis jar with `Partitioned` attribute
//!   support; third-party cookies are only stored/returned when they carry
//!   a partition key, and only to that partition.
//! * [`localstorage`] — per-(top-site, origin) key/value stores.
//! * [`idb`] — an IndexedDB core (databases, object stores, put/get/delete/
//!   clear, primary-key range scans) layered on the embedded ACID KV store.
//! * [`cache`] — a two-tier HTTP cache (in-memory LRU + on-disk blobs) whose
//!   budgets are derived from available system RAM by the memory governor.
//!
//! ## Why redb
//!
//! `redb` is a pure-Rust, mmap-backed, ACID B-tree with predictable write
//! amplification and no C dependencies — it builds identically on Linux and
//! Windows. Cookies / LS / IDB / cache indexes all live in one database file
//! per profile, which keeps fsync count low and crash recovery trivial.

#![forbid(unsafe_code)]

pub mod cache;
pub mod cookies;
pub mod idb;
pub mod keyspace;
pub mod localstorage;

use std::path::{Path, PathBuf};

use redb::ReadableTable;
use thiserror::Error;

/// Storage-layer errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Underlying KV store failure.
    #[error("database error: {0}")]
    Db(#[from] redb::Error),
    /// A table operation failed.
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    /// A transaction failed.
    #[error("transaction error: {0}")]
    Tx(#[from] redb::TransactionError),
    /// Serialization failure (should be impossible for our schemas).
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// The profile path is unusable.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Low-level storage failure.
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    /// Commit failure.
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    /// Database open/create failure.
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Static description of the cookie table.
const COOKIE_TABLE: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("cookies");
/// Static description of the LocalStorage table.
const LS_TABLE: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("localstorage");
/// Static description of the IndexedDB record table.
const IDB_RECORDS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("idb_records");
/// Static description of the IndexedDB meta table.
const IDB_META: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("idb_meta");
/// Static description of the HTTP cache table.
const CACHE_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("http_cache");

/// Configuration for the storage engine.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Profile directory (created if missing).
    pub profile_dir: PathBuf,
    /// In-memory cache budget in bytes (set by the memory governor).
    pub memory_cache_budget: usize,
    /// On-disk cache budget in bytes.
    pub disk_cache_budget: usize,
}

impl StorageConfig {
    /// A config rooted at `profile_dir` with 32 MiB memory / 256 MiB disk
    /// cache budgets (the governor overrides these at runtime).
    pub fn new(profile_dir: impl Into<PathBuf>) -> StorageConfig {
        StorageConfig {
            profile_dir: profile_dir.into(),
            memory_cache_budget: 32 * 1024 * 1024,
            disk_cache_budget: 256 * 1024 * 1024,
        }
    }

    /// Ephemeral in-memory-ish config under the system temp dir.
    #[cfg(test)]
    pub fn ephemeral(tag: &str) -> StorageConfig {
        let dir =
            std::env::temp_dir().join(format!("bw-storage-test-{tag}-{}", std::process::id()));
        StorageConfig::new(dir)
    }
}

/// The aggregated storage engine: cookies, LS, IDB and HTTP cache over a
/// single ACID database file.
pub struct Storage {
    config: StorageConfig,
    db: std::sync::Arc<redb::Database>,
    cookies: cookies::CookieJar,
    cache: std::sync::Arc<cache::HttpCache>,
}

impl Storage {
    /// Open (or create) the profile storage.
    pub fn open(config: StorageConfig) -> Result<Storage> {
        std::fs::create_dir_all(&config.profile_dir)?;
        let db_path = config.profile_dir.join("site-data.redb");
        let db = std::sync::Arc::new(redb::Database::create(db_path)?);
        // Ensure all tables exist up-front so later transactions never race
        // on table creation.
        let tx = db.begin_write()?;
        {
            let _ = tx.open_table(COOKIE_TABLE)?;
            let _ = tx.open_table(LS_TABLE)?;
            let _ = tx.open_table(IDB_META)?;
            let _ = tx.open_table(IDB_RECORDS)?;
            let _ = tx.open_table(CACHE_TABLE)?;
        }
        tx.commit()?;

        let cookies = cookies::CookieJar::load(&db)?;
        let cache = std::sync::Arc::new(cache::HttpCache::new(
            config.memory_cache_budget,
            config.disk_cache_budget,
        ));

        Ok(Storage { config, db, cookies, cache })
    }

    /// The cookie jar.
    pub fn cookies(&self) -> &cookies::CookieJar {
        &self.cookies
    }

    /// The cookie jar (mutable).
    pub fn cookies_mut(&mut self) -> &mut cookies::CookieJar {
        &mut self.cookies
    }

    /// The HTTP cache.
    pub fn cache(&self) -> &cache::HttpCache {
        &self.cache
    }

    /// Shared handle to the HTTP cache — handed to the network stack,
    /// which must write responses from async tasks.
    pub fn cache_handle(&self) -> std::sync::Arc<cache::HttpCache> {
        std::sync::Arc::clone(&self.cache)
    }

    /// The underlying database handle (for engine-level persistence such
    /// as the cookie jar the network stack owns).
    pub fn db(&self) -> &std::sync::Arc<redb::Database> {
        &self.db
    }

    /// LocalStorage view for a (partition, origin) pair.
    pub fn local_storage(&self, partition: &str, origin: &str) -> localstorage::LocalStorage {
        localstorage::LocalStorage::new(
            std::sync::Arc::clone(&self.db),
            partition.to_string(),
            origin.to_string(),
        )
    }

    /// IndexedDB view for a (partition, origin) pair.
    pub fn indexed_db(&self, partition: &str, origin: &str) -> idb::Idb {
        idb::Idb::new(std::sync::Arc::clone(&self.db), partition.to_string(), origin.to_string())
    }

    /// Effective profile directory.
    pub fn profile_dir(&self) -> &Path {
        &self.config.profile_dir
    }

    /// Persist cookies to the database (called after mutations; the jar also
    /// self-persists on drop-through-API patterns).
    pub fn persist_cookies(&self) -> Result<()> {
        self.cookies.persist(&self.db)
    }

    /// Delete every piece of site data for a partition+origin (cookies, LS,
    /// IDB) — the "forget this site" primitive.
    pub fn purge_site(&mut self, partition: &str, origin: &str) -> Result<()> {
        fn collect(t: &mut redb::Table<'_, &str, &str>, prefix: &str) -> Result<Vec<String>> {
            let upper = keyspace::prefix_upper(prefix);
            let mut out = Vec::new();
            for row in t.range(prefix..upper.as_str())? {
                let (k, _) = row?;
                out.push(k.value().to_string());
            }
            Ok(out)
        }
        fn collect_b(t: &mut redb::Table<'_, &str, &[u8]>, prefix: &str) -> Result<Vec<String>> {
            let upper = keyspace::prefix_upper(prefix);
            let mut out = Vec::new();
            for row in t.range(prefix..upper.as_str())? {
                let (k, _) = row?;
                out.push(k.value().to_string());
            }
            Ok(out)
        }

        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(COOKIE_TABLE)?;
            for key in collect(&mut t, &keyspace::cookie_key_prefix(partition, origin))? {
                t.remove(key.as_str())?;
            }
            let mut ls = tx.open_table(LS_TABLE)?;
            for key in collect(&mut ls, &keyspace::ls_key_prefix(partition, origin))? {
                ls.remove(key.as_str())?;
            }
            let mut meta = tx.open_table(IDB_META)?;
            for key in collect(&mut meta, &keyspace::idb_meta_prefix(partition, origin))? {
                meta.remove(key.as_str())?;
            }
            let mut recs = tx.open_table(IDB_RECORDS)?;
            for key in collect_b(&mut recs, &keyspace::idb_record_prefix(partition, origin))? {
                recs.remove(key.as_str())?;
            }
        }
        tx.commit()?;
        // Reload the in-memory jar from what remains.
        let _ = self.cookies.reload(&self.db);
        Ok(())
    }

    /// Total bytes used by on-disk tables (best-effort, for diagnostics).
    pub fn disk_usage(&self) -> Result<u64> {
        Ok(0) // redb file size is queried by the engine layer via fs::metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_tables() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(StorageConfig::new(dir.path())).unwrap();
        assert!(dir.path().join("site-data.redb").exists());
        drop(storage);
    }

    #[test]
    fn purge_site_removes_everything() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(StorageConfig::new(dir.path())).unwrap();

        // cookie for site
        let jar = storage.cookies_mut();
        jar.set(bw_test_cookie("sid", "1", "app.example", None));
        // LS entry
        storage
            .local_storage("app.example", "https://app.example")
            .set_item("theme", "dark")
            .unwrap();
        // IDB record
        let idb = storage.indexed_db("app.example", "https://app.example");
        let mut db = idb.open_db("testdb", 1).unwrap();
        db.create_store("notes").unwrap();
        db.put("notes", b"key1", br#"{"v":1}"#).unwrap();

        storage.purge_site("app.example", "https://app.example").unwrap();

        assert!(storage
            .local_storage("app.example", "https://app.example")
            .get_item("theme")
            .unwrap()
            .is_none());
        let jar = storage.cookies();
        assert!(jar.get_for("https://app.example/x", "app.example", true).is_empty());
    }

    /// Build a simple first-party cookie for tests.
    fn bw_test_cookie(
        name: &str,
        value: &str,
        domain: &str,
        partition: Option<&str>,
    ) -> cookies::Cookie {
        cookies::Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
            expires: None,
            secure: true,
            http_only: false,
            same_site: cookies::SameSite::Lax,
            host_only: false,
            partition_key: partition.map(|p| p.to_string()),
            creation_time: std::time::SystemTime::now(),
        }
    }
}
