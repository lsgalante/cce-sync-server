//! [`Store`] over the Durable Object's SQLite and R2.
//!
//! Metadata, the change feed, history and blobs up to [`INLINE_MAX`] live
//! in SQLite; bigger blobs in R2 under `blobs/<sha256>`. [`Store::commit`]
//! issues every statement without an await in between, which a Durable
//! Object commits atomically (its writes coalesce until the next await).

use cce_sync::core::{Commit, FileRow, Store, StoreError};
use cce_sync::proto::{fold, Change, Op, Rev, Seq, Version};
use worker::{Env, SqlStorage, SqlStorageValue as V};

/// Blobs up to this size stay in SQLite (a row holds at most 2 MB).
pub const INLINE_MAX: usize = 1_000_000;
const BUCKET: &str = "BLOBS";

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS files (
        path TEXT PRIMARY KEY, fold TEXT NOT NULL, rev INTEGER NOT NULL,
        hash TEXT, size INTEGER NOT NULL, device TEXT NOT NULL, at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS files_fold ON files(fold)",
    "CREATE TABLE IF NOT EXISTS changes (
        seq INTEGER PRIMARY KEY, op TEXT NOT NULL, path TEXT NOT NULL, rev INTEGER NOT NULL,
        hash TEXT, size INTEGER, from_path TEXT, device TEXT NOT NULL, at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS versions (
        path TEXT NOT NULL, rev INTEGER NOT NULL, hash TEXT, size INTEGER NOT NULL,
        device TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (path, rev))",
    "CREATE TABLE IF NOT EXISTS blobs (hash TEXT PRIMARY KEY, bytes BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
];

pub struct SqlStore {
    sql: SqlStorage,
    env: Env,
}

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError(e.to_string())
}

pub(crate) fn int(v: &V) -> Result<i64, StoreError> {
    match v {
        V::Integer(i) => Ok(*i),
        V::Float(f) if f.fract() == 0.0 => Ok(*f as i64),
        other => Err(StoreError(format!("expected an integer, got {other:?}"))),
    }
}

pub(crate) fn text(v: &V) -> Result<String, StoreError> {
    match v {
        V::String(s) => Ok(s.clone()),
        other => Err(StoreError(format!("expected text, got {other:?}"))),
    }
}

pub(crate) fn opt_text(v: &V) -> Result<Option<String>, StoreError> {
    match v {
        V::Null => Ok(None),
        other => text(other).map(Some),
    }
}

pub(crate) fn opt_int(v: &V) -> Result<Option<i64>, StoreError> {
    match v {
        V::Null => Ok(None),
        other => int(other).map(Some),
    }
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Put => "put",
        Op::Delete => "delete",
        Op::Move => "move",
    }
}

fn op_parse(s: &str) -> Result<Op, StoreError> {
    match s {
        "put" => Ok(Op::Put),
        "delete" => Ok(Op::Delete),
        "move" => Ok(Op::Move),
        other => Err(StoreError(format!("unknown op {other}"))),
    }
}

const FILE_COLS: &str = "path, rev, hash, size, device, at";

fn file_row(r: &[V]) -> Result<FileRow, StoreError> {
    Ok(FileRow {
        path: text(&r[0])?,
        rev: int(&r[1])? as Rev,
        hash: opt_text(&r[2])?,
        size: int(&r[3])? as u64,
        device: text(&r[4])?,
        at: int(&r[5])?,
    })
}

const VERSION_COLS: &str = "path, rev, hash, size, device, at";

fn version_row(r: &[V]) -> Result<Version, StoreError> {
    Ok(Version {
        path: text(&r[0])?,
        rev: int(&r[1])? as Rev,
        hash: opt_text(&r[2])?,
        size: int(&r[3])? as u64,
        device: text(&r[4])?,
        at: int(&r[5])?,
    })
}

impl SqlStore {
    pub fn open(sql: SqlStorage, env: Env) -> Result<SqlStore, StoreError> {
        for stmt in SCHEMA {
            sql.exec(stmt, None).map_err(err)?;
        }
        Ok(SqlStore { sql, env })
    }

    fn rows(&self, query: &str, bind: Vec<V>) -> Result<Vec<Vec<V>>, StoreError> {
        let cursor = self.sql.exec(query, bind).map_err(err)?;
        cursor.raw().map(|r| r.map_err(err)).collect()
    }

    fn exec(&self, query: &str, bind: Vec<V>) -> Result<(), StoreError> {
        self.sql.exec(query, bind).map_err(err).map(|_| ())
    }

    /// The database's size in bytes, for status.
    pub fn database_size(&self) -> usize {
        self.sql.database_size()
    }
}

fn i(n: u64) -> V {
    V::Integer(n as i64)
}

impl Store for SqlStore {
    fn file(&self, path: &str) -> Result<Option<FileRow>, StoreError> {
        let rows = self.rows(&format!("SELECT {FILE_COLS} FROM files WHERE path = ?"), vec![path.into()])?;
        rows.first().map(|r| file_row(r)).transpose()
    }

    fn live_by_fold(&self, folded: &str) -> Result<Vec<FileRow>, StoreError> {
        let rows = self.rows(
            &format!("SELECT {FILE_COLS} FROM files WHERE fold = ? AND hash IS NOT NULL"),
            vec![folded.into()],
        )?;
        rows.iter().map(|r| file_row(r)).collect()
    }

    fn live_files(&self) -> Result<Vec<FileRow>, StoreError> {
        let rows = self.rows(&format!("SELECT {FILE_COLS} FROM files WHERE hash IS NOT NULL ORDER BY path"), vec![])?;
        rows.iter().map(|r| file_row(r)).collect()
    }

    fn seq(&self) -> Result<Seq, StoreError> {
        let rows = self.rows("SELECT value FROM meta WHERE key = 'seq'", vec![])?;
        Ok(rows.first().map(|r| int(&r[0])).transpose()?.unwrap_or(0) as Seq)
    }

    fn oldest_seq(&self) -> Result<Option<Seq>, StoreError> {
        let rows = self.rows("SELECT MIN(seq) FROM changes", vec![])?;
        Ok(rows.first().map(|r| opt_int(&r[0])).transpose()?.flatten().map(|s| s as Seq))
    }

    fn changes_after(&self, since: Seq, limit: usize) -> Result<Vec<Change>, StoreError> {
        let rows = self.rows(
            "SELECT seq, op, path, rev, hash, size, from_path, device, at FROM changes
             WHERE seq > ? ORDER BY seq LIMIT ?",
            vec![i(since), i(limit as u64)],
        )?;
        rows.iter()
            .map(|r| {
                Ok(Change {
                    seq: int(&r[0])? as Seq,
                    op: op_parse(&text(&r[1])?)?,
                    path: text(&r[2])?,
                    rev: int(&r[3])? as Rev,
                    hash: opt_text(&r[4])?,
                    size: opt_int(&r[5])?.map(|s| s as u64),
                    from: opt_text(&r[6])?,
                    device: text(&r[7])?,
                    at: int(&r[8])?,
                })
            })
            .collect()
    }

    fn versions(&self, path: &str) -> Result<Vec<Version>, StoreError> {
        let rows = self.rows(
            &format!("SELECT {VERSION_COLS} FROM versions WHERE path = ? ORDER BY rev DESC"),
            vec![path.into()],
        )?;
        rows.iter().map(|r| version_row(r)).collect()
    }

    fn version(&self, path: &str, rev: Rev) -> Result<Option<Version>, StoreError> {
        let rows = self.rows(
            &format!("SELECT {VERSION_COLS} FROM versions WHERE path = ? AND rev = ?"),
            vec![path.into(), i(rev)],
        )?;
        rows.first().map(|r| version_row(r)).transpose()
    }

    async fn blob_get(&self, hash: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let rows = self.rows("SELECT bytes FROM blobs WHERE hash = ?", vec![hash.into()])?;
        if let Some(r) = rows.first() {
            return match &r[0] {
                V::Blob(b) => Ok(Some(b.clone())),
                // An empty BLOB can come back as something else; it is empty.
                V::Null => Ok(Some(Vec::new())),
                other => Err(StoreError(format!("blob {hash}: unexpected {other:?}"))),
            };
        }
        let bucket = self.env.bucket(BUCKET).map_err(err)?;
        match bucket.get(format!("blobs/{hash}")).execute().await.map_err(err)? {
            Some(obj) => match obj.body() {
                Some(body) => Ok(Some(body.bytes().await.map_err(err)?)),
                None => Ok(Some(Vec::new())),
            },
            None => Ok(None),
        }
    }

    async fn blob_put(&self, hash: &str, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.len() <= INLINE_MAX {
            return self.exec(
                "INSERT INTO blobs (hash, bytes) VALUES (?, ?) ON CONFLICT(hash) DO NOTHING",
                vec![hash.into(), V::Blob(bytes.to_vec())],
            );
        }
        let bucket = self.env.bucket(BUCKET).map_err(err)?;
        bucket.put(format!("blobs/{hash}"), bytes.to_vec()).execute().await.map_err(err)?;
        Ok(())
    }

    fn commit(&mut self, commit: Commit) -> Result<Seq, StoreError> {
        // No await from here to the end: the Durable Object commits all of
        // it, or none.
        for row in &commit.rows {
            self.exec(
                "INSERT INTO files (path, fold, rev, hash, size, device, at) VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(path) DO UPDATE SET rev = excluded.rev, hash = excluded.hash,
                 size = excluded.size, device = excluded.device, at = excluded.at",
                vec![
                    row.path.as_str().into(),
                    fold(&row.path).into(),
                    i(row.rev),
                    row.hash.clone().into(),
                    i(row.size),
                    row.device.as_str().into(),
                    V::Integer(row.at),
                ],
            )?;
            self.exec(
                "INSERT OR REPLACE INTO versions (path, rev, hash, size, device, at) VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    row.path.as_str().into(),
                    i(row.rev),
                    row.hash.clone().into(),
                    i(row.size),
                    row.device.as_str().into(),
                    V::Integer(row.at),
                ],
            )?;
        }
        let mut seq = self.seq()?;
        for c in &commit.changes {
            seq += 1;
            self.exec(
                "INSERT INTO changes (seq, op, path, rev, hash, size, from_path, device, at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    i(seq),
                    op_name(c.op).into(),
                    c.path.as_str().into(),
                    i(c.rev),
                    c.hash.clone().into(),
                    c.size.map(|s| s as i64).into(),
                    c.from.clone().into(),
                    c.device.as_str().into(),
                    V::Integer(c.at),
                ],
            )?;
        }
        self.exec(
            "INSERT INTO meta (key, value) VALUES ('seq', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            vec![i(seq)],
        )?;
        Ok(seq)
    }
}
