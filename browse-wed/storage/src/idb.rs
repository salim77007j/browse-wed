//! IndexedDB core on top of the embedded KV store.
//!
//! Scope: the storage-level half of IndexedDB — database/version registry,
//! object-store CRUD, ordered range scans by primary key, and clear/delete.
//! The async event/transaction glue required by the JS bindings lives in
//! `bw-js`; this crate provides the ACID substrate.
//!
//! Record values are opaque bytes (`&[u8]`): the JS layer serializes values
//! with the structured-clone algorithm's wire format before they reach here.
//! Primary keys are normalized through a JSON encoding that preserves IDB
//! ordering for the common key types (numbers sort before strings).

use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::keyspace;
use crate::{IDB_META, IDB_RECORDS, Result};

/// Metadata for one IDB database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMeta {
    /// Database name.
    pub name: String,
    /// Schema version.
    pub version: u64,
    /// Object store names.
    pub stores: Vec<String>,
}

/// A bound (possibly open) range for scans, in JSON-encoded key space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRange {
    /// Lower bound (JSON-encoded IDB key), `None` = unbounded.
    pub lower: Option<String>,
    /// Upper bound (JSON-encoded IDB key), `None` = unbounded.
    pub upper: Option<String>,
    /// Lower bound inclusive.
    pub lower_inclusive: bool,
    /// Upper bound inclusive.
    pub upper_inclusive: bool,
}

impl KeyRange {
    /// Full-range scan.
    pub fn all() -> KeyRange {
        KeyRange {
            lower: None,
            upper: None,
            lower_inclusive: true,
            upper_inclusive: true,
        }
    }

    /// `IDBKeyRange.bound(lower, upper, lower_open, upper_open)`.
    pub fn bound(lower: &str, upper: &str, lower_open: bool, upper_open: bool) -> KeyRange {
        KeyRange {
            lower: Some(lower.to_string()),
            upper: Some(upper.to_string()),
            lower_inclusive: !lower_open,
            upper_inclusive: !upper_open,
        }
    }

    /// `IDBKeyRange.only(key)`.
    pub fn only(key: &str) -> KeyRange {
        Self::bound(key, key, false, false)
    }
}

/// An IDB database handle bound to (partition, origin, name).
pub struct IdbDb {
    db: std::sync::Arc<redb::Database>,
    partition: String,
    origin: String,
    meta: DbMeta,
}

impl IdbDb {
    /// Database name.
    pub fn name(&self) -> &str {
        &self.meta.name
    }

    /// Schema version.
    pub fn version(&self) -> u64 {
        self.meta.version
    }

    /// Object store names.
    pub fn stores(&self) -> &[String] {
        &self.meta.stores
    }

    /// Create an object store (fails when it already exists).
    pub fn create_store(&mut self, store: &str) -> Result<()> {
        if self.meta.stores.iter().any(|s| s == store) {
            return Err(crate::StorageError::Io(std::io::Error::other(format!(
                "object store {store} already exists"
            ))));
        }
        self.meta.stores.push(store.to_string());
        self.save_meta()
    }

    /// Delete an object store with all its records.
    pub fn delete_store(&mut self, store: &str) -> Result<()> {
        let prefix = keyspace::idb_store_prefix(&self.partition, &self.origin, &self.meta.name, store);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db_begin_write()?;
        {
            let mut recs = tx.open_table(IDB_RECORDS)?;
            let mut doomed: Vec<String> = Vec::new();
            for row in recs.range(prefix.as_str()..upper.as_str())? {
                let (k, _) = row?;
                doomed.push(k.value().to_string());
            }
            for k in doomed {
                recs.remove(k.as_str())?;
            }
        }
        tx.commit()?;
        self.meta.stores.retain(|s| s != store);
        self.save_meta()
    }

    /// Put a record (upsert) into `store` under primary key `pk`.
    pub fn put(&self, store: &str, pk: &[u8], value: &[u8]) -> Result<()> {
        self.ensure_store(store)?;
        let key = keyspace::idb_record_key(
            &self.partition,
            &self.origin,
            &self.meta.name,
            store,
            &String::from_utf8_lossy(pk),
        );
        let tx = self.db_begin_write()?;
        {
            let mut recs = tx.open_table(IDB_RECORDS)?;
            recs.insert(key.as_str(), value)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Fetch one record.
    pub fn get(&self, store: &str, pk: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_store(store)?;
        let key = keyspace::idb_record_key(
            &self.partition,
            &self.origin,
            &self.meta.name,
            store,
            &String::from_utf8_lossy(pk),
        );
        let tx = self.db_begin_read()?;
        let t = tx.open_table(IDB_RECORDS)?;
        Ok(t.get(key.as_str())?.map(|v| v.value().to_vec()))
    }

    /// Delete one record.
    pub fn delete(&self, store: &str, pk: &[u8]) -> Result<()> {
        self.ensure_store(store)?;
        let key = keyspace::idb_record_key(
            &self.partition,
            &self.origin,
            &self.meta.name,
            store,
            &String::from_utf8_lossy(pk),
        );
        let tx = self.db_begin_write()?;
        {
            let mut recs = tx.open_table(IDB_RECORDS)?;
            recs.remove(key.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Clear all records of one store.
    pub fn clear(&self, store: &str) -> Result<()> {
        self.ensure_store(store)?;
        let prefix = keyspace::idb_store_prefix(&self.partition, &self.origin, &self.meta.name, store);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db_begin_write()?;
        {
            let mut recs = tx.open_table(IDB_RECORDS)?;
            let mut doomed: Vec<String> = Vec::new();
            for row in recs.range(prefix.as_str()..upper.as_str())? {
                let (k, _) = row?;
                doomed.push(k.value().to_string());
            }
            for k in doomed {
                recs.remove(k.as_str())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Count records in a store.
    pub fn count(&self, store: &str) -> Result<usize> {
        let recs = self.scan(store, &KeyRange::all())?;
        Ok(recs.len())
    }

    /// Ordered scan over a store. Returns `(pk, value)` pairs ordered by
    /// primary key (matching IDB key order for homogeneous stores).
    pub fn scan(&self, store: &str, range: &KeyRange) -> Result<Vec<(String, Vec<u8>)>> {
        self.ensure_store(store)?;
        let prefix = keyspace::idb_store_prefix(&self.partition, &self.origin, &self.meta.name, store);
        let upper_bound = match (&range.upper, range.upper_inclusive) {
            (None, _) => keyspace::prefix_upper(&prefix),
            (Some(u), true) => keyspace::prefix_upper(&keyspace::join(&[
                &prefix,
                u,
            ])),
            (Some(u), false) => {
                let k = keyspace::join(&[&prefix, u]);
                keyspace::prefix_upper(&k)
            }
        };
        let lower_bound = match (&range.lower, range.lower_inclusive) {
            (None, _) => prefix.clone(),
            (Some(l), true) => keyspace::join(&[&prefix, l]),
            (Some(l), false) => {
                let k = keyspace::join(&[&prefix, l]);
                keyspace::prefix_upper(&k)
            }
        };

        let tx = self.db_begin_read()?;
        let Ok(t) = tx.open_table(IDB_RECORDS) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for row in t.range(lower_bound.as_str()..upper_bound.as_str())? {
            let (k, v) = row?;
            let full = k.value().to_string();
            // strip prefix + separator to recover the user key
            let pk = full
                .splitn(5, '\u{1f}')
                .nth(4)
                .map(|s| s.to_string())
                .unwrap_or_default();
            out.push((pk, v.value().to_vec()));
        }
        Ok(out)
    }

    /// Bulk insert used by the JS layer's import/restore paths.
    pub fn bulk_put(&self, store: &str, records: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        self.ensure_store(store)?;
        let tx = self.db_begin_write()?;
        {
            let mut recs = tx.open_table(IDB_RECORDS)?;
            for (pk, value) in records {
                let key = keyspace::idb_record_key(
                    &self.partition,
                    &self.origin,
                    &self.meta.name,
                    store,
                    &String::from_utf8_lossy(pk),
                );
                recs.insert(key.as_str(), value.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn ensure_store(&self, store: &str) -> Result<()> {
        if self.meta.stores.iter().any(|s| s == store) {
            Ok(())
        } else {
            Err(crate::StorageError::Io(std::io::Error::other(format!(
                "no such object store: {store}"
            ))))
        }
    }

    fn save_meta(&self) -> Result<()> {
        let key = keyspace::idb_meta_key(&self.partition, &self.origin, &self.meta.name);
        let val = serde_json::to_string(&self.meta)?;
        let tx = self.db_begin_write()?;
        {
            let mut t = tx.open_table(IDB_META)?;
            t.insert(key.as_str(), val.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Per-origin IDB namespace.
pub struct Idb {
    db: std::sync::Arc<redb::Database>,
    partition: String,
    origin: String,
}

impl Idb {
    /// Bind a namespace. Created by [`crate::Storage::indexed_db`].
    pub fn new(db: std::sync::Arc<redb::Database>, partition: impl Into<String>, origin: impl Into<String>) -> Idb {
        Idb {
            db,
            partition: partition.into(),
            origin: origin.into(),
        }
    }

    /// List database names for this origin.
    pub fn database_names(&self) -> Result<Vec<String>> {
        let prefix = keyspace::idb_meta_prefix(&self.partition, &self.origin);
        let upper = keyspace::prefix_upper(&prefix);
        let tx = self.db.begin_read()?;
        match tx.open_table(IDB_META) {
            Ok(t) => {
                let mut out = Vec::new();
                for row in t.range(prefix.as_str()..upper.as_str())? {
                    let (k, _) = row?;
                    let key = k.value().to_string();
                    if let Some(name) = key.splitn(3, '\u{1f}').nth(2) {
                        out.push(name.to_string());
                    }
                }
                Ok(out)
            }
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Open (or create at `version`) a database.
    pub fn open_db(&self, name: &str, version: u64) -> Result<IdbDb> {
        let key = keyspace::idb_meta_key(&self.partition, &self.origin, name);
        let existing: Option<DbMeta> = {
            let tx = self.db.begin_read()?;
            match tx.open_table(IDB_META) {
                Ok(t) => t
                    .get(key.as_str())?
                    .and_then(|v| serde_json::from_str(v.value()).ok()),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(e.into()),
            }
        };
        let meta = match existing {
            Some(m) => m,
            None => DbMeta {
                name: name.to_string(),
                version,
                stores: Vec::new(),
            },
        };
        Ok(IdbDb {
            db: std::sync::Arc::clone(&self.db),
            partition: self.partition.clone(),
            origin: self.origin.clone(),
            meta,
        })
    }

    /// Delete an entire database.
    pub fn delete_db(&self, name: &str) -> Result<()> {
        let records_prefix = keyspace::join(&[&self.partition, &self.origin, name]);
        let upper = keyspace::prefix_upper(&records_prefix);
        let meta_key = keyspace::idb_meta_key(&self.partition, &self.origin, name);
        let tx = self.db.begin_write()?;
        {
            let mut recs = tx.open_table(IDB_RECORDS)?;
            let mut doomed: Vec<String> = Vec::new();
            for row in recs.range(records_prefix.as_str()..upper.as_str())? {
                let (k, _) = row?;
                doomed.push(k.value().to_string());
            }
            for k in doomed {
                recs.remove(k.as_str())?;
            }
            let mut meta = tx.open_table(IDB_META)?;
            meta.remove(meta_key.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }
}

impl IdbDb {
    fn db_begin_write(&self) -> Result<redb::WriteTransaction> {
        Ok(self.db.begin_write()?)
    }

    fn db_begin_read(&self) -> Result<redb::ReadTransaction> {
        Ok(self.db.begin_read()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idb(tag: &str) -> (Idb, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(redb::Database::create(dir.path().join(format!("{tag}.redb"))).unwrap());
        (
            Idb::new(db, "top.example", "https://app.example"),
            dir,
        )
    }

    #[test]
    fn db_store_crud() {
        let (idb, _d) = idb("crud");
        let mut db = idb.open_db("library", 1).unwrap();
        db.create_store("books").unwrap();
        db.put("books", b"1", br#"{"title":"Dune"}"#).unwrap();
        db.put("books", b"2", br#"{"title":"Hyperion"}"#).unwrap();
        assert_eq!(db.count("books").unwrap(), 2);
        let got = db.get("books", b"1").unwrap().unwrap();
        assert_eq!(got, br#"{"title":"Dune"}"#.to_vec());
        db.delete("books", b"1").unwrap();
        assert_eq!(db.count("books").unwrap(), 1);
        assert!(db.get("books", b"1").unwrap().is_none());
    }

    #[test]
    fn ordered_scan() {
        let (idb, _d) = idb("scan");
        let mut db = idb.open_db("ledger", 1).unwrap();
        db.create_store("entries").unwrap();
        for i in 0..10 {
            let pk = format!("k{i:03}");
            db.put("entries", pk.as_bytes(), format!("v{i}").as_bytes()).unwrap();
        }
        // IDBKeyRange.bound(k002, k005, lowerOpen=true, upperOpen=false) = (k002, k005]
        let range = KeyRange::bound("k002", "k005", true, false);
        let rows = db.scan("entries", &range).unwrap();
        let keys: Vec<String> = rows.into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["k003", "k004", "k005"]);
    }

    #[test]
    fn partitions_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(redb::Database::create(dir.path().join("p.redb")).unwrap());
        let a = Idb::new(std::sync::Arc::clone(&db), "a.com", "https://app.io");
        let b = Idb::new(db, "b.com", "https://app.io");
        let mut dba = a.open_db("notes", 1).unwrap();
        dba.create_store("s").unwrap();
        dba.put("s", b"x", b"from-a").unwrap();
        let dbb = b.open_db("notes", 1).unwrap();
        assert!(dbb.stores().is_empty());
    }

    #[test]
    fn delete_db() {
        let (idb, _d) = idb("deldb");
        let mut db = idb.open_db("temp", 1).unwrap();
        db.create_store("s").unwrap();
        db.put("s", b"a", b"1").unwrap();
        idb.delete_db("temp").unwrap();
        assert!(idb.database_names().unwrap().is_empty());
    }
}
