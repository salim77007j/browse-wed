//! Partitioned LocalStorage.
//!
//! API mirrors the web platform: per (top-level-site partition, origin)
//! string-to-string map with a quota (default 5 MiB, the browser norm).
//! All writes are transactional through the shared redb database.

use redb::{ReadableDatabase, ReadableTable};

use crate::keyspace;
use crate::{LS_TABLE, Result};

/// Default quota per (partition, origin): 5 MiB.
pub const DEFAULT_QUOTA_BYTES: usize = 5 * 1024 * 1024;

/// LocalStorage view bound to one (partition, origin) pair.
#[derive(Clone)]
pub struct LocalStorage {
    db: std::sync::Arc<redb::Database>,
    partition: String,
    origin: String,
    quota: usize,
}

impl LocalStorage {
    /// Bind a view. Created by [`crate::Storage::local_storage`].
    pub fn new(
        db: std::sync::Arc<redb::Database>,
        partition: impl Into<String>,
        origin: impl Into<String>,
    ) -> LocalStorage {
        LocalStorage {
            db,
            partition: partition.into(),
            origin: origin.into(),
            quota: DEFAULT_QUOTA_BYTES,
        }
    }

    /// Override the quota (engine policy).
    pub fn set_quota(&mut self, quota: usize) {
        self.quota = quota;
    }

    fn key(&self, k: &str) -> String {
        keyspace::ls_key(&self.partition, &self.origin, k)
    }

    /// Read one item.
    pub fn get_item(&self, k: &str) -> Result<Option<String>> {
        let tx = self.db.begin_read()?;
        match tx.open_table(LS_TABLE) {
            Ok(t) => Ok(t.get(self.key(k).as_str())?.map(|v| v.value().to_string())),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write one item. Fails with a quota error when the store would exceed
    /// its budget.
    pub fn set_item(&self, k: &str, v: &str) -> Result<()> {
        if self.usage()? + v.len() > self.quota {
            return Err(crate::StorageError::Io(std::io::Error::other(format!(
                "LocalStorage quota exceeded ({}) for {}/{}",
                self.quota, self.partition, self.origin
            ))));
        }
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(LS_TABLE)?;
            t.insert(self.key(k).as_str(), v)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Remove one item.
    pub fn remove_item(&self, k: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(LS_TABLE)?;
            t.remove(self.key(k).as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Remove all items of this store.
    pub fn clear(&self) -> Result<()> {
        let prefix = keyspace::ls_key_prefix(&self.partition, &self.origin);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(LS_TABLE)?;
            let mut doomed: Vec<String> = Vec::new();
            for row in t.range(prefix.as_str()..upper.as_str())? {
                let (k, _) = row?;
                doomed.push(k.value().to_string());
            }
            for k in doomed {
                t.remove(k.as_str())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Number of items.
    pub fn length(&self) -> Result<usize> {
        let prefix = keyspace::ls_key_prefix(&self.partition, &self.origin);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db.begin_read()?;
        match tx.open_table(LS_TABLE) {
            Ok(t) => {
                let mut n = 0;
                for row in t.range(prefix.as_str()..upper.as_str())? {
                    let _ = row?;
                    n += 1;
                }
                Ok(n)
            }
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Total value bytes used by this store.
    pub fn usage(&self) -> Result<usize> {
        let prefix = keyspace::ls_key_prefix(&self.partition, &self.origin);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db.begin_read()?;
        match tx.open_table(LS_TABLE) {
            Ok(t) => {
                let mut bytes = 0;
                for row in t.range(prefix.as_str()..upper.as_str())? {
                    let (_, v) = row?;
                    bytes += v.value().len();
                }
                Ok(bytes)
            }
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// All (key, value) pairs (bounded by quota, safe to materialize).
    pub fn entries(&self) -> Result<Vec<(String, String)>> {
        let prefix = keyspace::ls_key_prefix(&self.partition, &self.origin);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db.begin_read()?;
        let Ok(t) = tx.open_table(LS_TABLE) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for row in t.range(prefix.as_str()..upper.as_str())? {
            let (k, v) = row?;
            // strip the prefix (partition \x1f origin \x1f) from the key
            let key = k.value().to_string();
            let user_key = key
                .split_once('\u{1f}')
                .and_then(|(_, rest)| rest.split_once('\u{1f}'))
                .map(|(_, k)| k.to_string())
                .unwrap_or_default();
            out.push((user_key, v.value().to_string()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(tag: &str) -> (LocalStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(redb::Database::create(dir.path().join(format!("{tag}.redb"))).unwrap());
        (LocalStorage::new(db, "top.example", "https://origin.example"), dir)
    }

    #[test]
    fn set_get_remove() {
        let (ls, _d) = ls("basic");
        ls.set_item("theme", "dark").unwrap();
        assert_eq!(ls.get_item("theme").unwrap().as_deref(), Some("dark"));
        ls.remove_item("theme").unwrap();
        assert_eq!(ls.get_item("theme").unwrap(), None);
    }

    #[test]
    fn partitions_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(redb::Database::create(dir.path().join("p.redb")).unwrap());
        let a = LocalStorage::new(std::sync::Arc::clone(&db), "site-a.com", "https://app.io");
        let b = LocalStorage::new(db, "site-b.com", "https://app.io");
        a.set_item("k", "from-a").unwrap();
        b.set_item("k", "from-b").unwrap();
        assert_eq!(a.get_item("k").unwrap().as_deref(), Some("from-a"));
        assert_eq!(b.get_item("k").unwrap().as_deref(), Some("from-b"));
    }

    #[test]
    fn clear_and_length() {
        let (ls, _d) = ls("clear");
        ls.set_item("a", "1").unwrap();
        ls.set_item("b", "2").unwrap();
        assert_eq!(ls.length().unwrap(), 2);
        ls.clear().unwrap();
        assert_eq!(ls.length().unwrap(), 0);
        assert_eq!(ls.entries().unwrap().len(), 0);
    }

    #[test]
    fn quota_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(redb::Database::create(dir.path().join("q.redb")).unwrap());
        let mut ls = LocalStorage::new(db, "top.com", "https://app.io");
        ls.set_quota(16);
        assert!(ls.set_item("k", "0123456789").is_ok());
        assert!(ls.set_item("k2", "0123456789").is_err(), "must exceed quota");
    }
}
