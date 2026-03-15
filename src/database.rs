use crate::utils::FileKind;
use crate::{AnyHowError, AnyHowResult};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use tokio_rusqlite::{params, Connection, Error as SQLError, OpenFlags};
use uuid::Uuid;

pub async fn open_db_by_dir(dirpath: &Path) -> AnyHowResult<Connection> {
    let filepath = dirpath.join("hb2-rs.dev.sqlite");
    open_db_by_path(filepath.as_path()).await
}

async fn schema_upgrade_v1(conn: &Connection) -> AnyHowResult<()> {
    conn.call(|conn| {
        conn.execute_batch(include_str!("schema_v1.sql"))?;
        conn.pragma_update(None, "user_version", 1)?;
        Ok::<(), SQLError>(())
    })
    .await?;
    info!("Upgraded schema to version 1");
    Ok(())
}

async fn open_db_by_path(filepath: &Path) -> AnyHowResult<Connection> {
    let filepath_str = filepath.to_str().expect("filepath should be valid UTF-8");
    debug!("Opening database at {}", filepath_str);
    let conn = Connection::open_with_flags(
        filepath,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .await?;
    info!("Opened database at {}", filepath_str);

    // Check schema version
    let schema_ver: i32 = conn
        .call(|conn| conn.pragma_query_value(None, "user_version", |row| row.get(0)))
        .await
        .expect("failed to load pragma user_version");

    if schema_ver == 0 {
        schema_upgrade_v1(&conn).await?;
    }

    Ok(conn)
}

pub async fn new_backup_record(
    conn: &Connection,
    name: Option<String>,
    description: Option<String>,
    source_dir: String,
) -> Result<String, AnyHowError> {
    let backup_uuid = Uuid::new_v4();
    let backup_uuid_str = backup_uuid.hyphenated().to_string();
    let utc_now: DateTime<Utc> = Utc::now();
    Ok(conn.call(move |conn| {
        conn.execute(
            "INSERT INTO backups (uuid, name, description, source_dir, started_at) VALUES (?, ?, ?, ?, ?)",
            (&backup_uuid_str, name, description, source_dir, utc_now),
        )?;
        Ok::<_, SQLError>(backup_uuid_str)
    }).await?)
}

#[derive(Debug, Clone)]
pub struct BlobRecord {
    pub hash: String,
    pub size: i64,
    pub added_at: DateTime<Utc>,
}

pub async fn save_blob_record(
    conn: &Connection,
    hash_val: &str,
    size: i64,
) -> Result<(), AnyHowError> {
    let hash_val = hash_val.to_string();
    Ok(conn
        .call(move |conn| {
            let utc_now: DateTime<Utc> = Utc::now();
            conn.execute(
                "INSERT OR IGNORE INTO blobs (hash, size, added_at) VALUES (?, ?, ?)",
                params![hash_val, size, utc_now],
            )?;
            debug!("saved {:?}", hash_val);
            Ok::<_, SQLError>(())
        })
        .await?)
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub uuid: Option<String>,
    pub backup_uuid: Option<String>,
    pub parent_uuid: Option<String>,
    pub inode: Option<i64>,
    pub name: String,
    pub size: i64,
    pub kind: FileKind,
    pub mode_num: Option<u16>,
    pub mode_text: Option<String>,
    pub uid_num: Option<i64>,
    pub uid_text: Option<String>,
    pub gid_num: Option<i64>,
    pub gid_text: Option<String>,
    pub mod_time: Option<DateTime<Utc>>,
    pub sec_ctx: Option<String>,
    pub lsattr: Option<String>,
    pub full_path: PathBuf,
    pub link_path: Option<PathBuf>,
    pub scanned_hash: Option<String>,
    pub acquired_hash: Option<String>,
}

pub async fn insert_file_record(
    conn: &Connection,
    backup_uuid: &str,
    parent_uuid: Option<&String>,
    mut file_rec: FileRecord,
) -> Result<FileRecord, AnyHowError> {
    if file_rec.uuid.is_none() {
        file_rec.uuid = Some(Uuid::new_v4().hyphenated().to_string());
    }
    if file_rec.backup_uuid.is_none() {
        file_rec.backup_uuid = Some(backup_uuid.to_string());
    }
    file_rec.parent_uuid = parent_uuid.map(|s| s.to_string());

    Ok(conn.call(move |conn| {
        conn.execute(
            "INSERT INTO files (uuid, backup_uuid, parent_uuid, inode, name, mode, size, kind, uid_num, gid_num, uid_str, gid_str, mod_time, sec_ctx, lsattr, full_path, link_path, scanned_hash, acquired_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                file_rec.uuid.as_ref().unwrap(),
                file_rec.backup_uuid.as_ref().unwrap(),
                file_rec.parent_uuid,
                file_rec.inode,
                file_rec.name,
                file_rec.mode_num,
                file_rec.size,
                file_rec.kind.to_char().to_string(),
                file_rec.uid_num,
                file_rec.gid_num,
                file_rec.uid_text,
                file_rec.gid_text,
                file_rec.mod_time,
                file_rec.sec_ctx,
                file_rec.lsattr,
                file_rec.full_path.to_str(),
                file_rec.link_path.as_ref().map(|p| p.to_str()),
                file_rec.scanned_hash,
                file_rec.acquired_hash],
        )?;
        debug!("saved {:?}", file_rec);
        Ok::<_, SQLError>(file_rec)
    }).await?)
}

pub async fn replace_file_record(
    conn: &Connection,
    mut file_rec: FileRecord,
) -> Result<FileRecord, AnyHowError> {
    Ok(conn.call(move |conn| {
        conn.execute(
            "REPLACE INTO files (uuid, backup_uuid, parent_uuid, inode, name, mode, size, kind, uid_num, gid_num, uid_str, gid_str, mod_time, sec_ctx, lsattr, full_path, link_path, scanned_hash, acquired_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                file_rec.uuid.as_ref().unwrap(),
                file_rec.backup_uuid.as_ref().unwrap(),
                file_rec.parent_uuid,
                file_rec.inode,
                file_rec.name,
                file_rec.mode_num,
                file_rec.size,
                file_rec.kind.to_char().to_string(),
                file_rec.uid_num,
                file_rec.gid_num,
                file_rec.uid_text,
                file_rec.gid_text,
                file_rec.mod_time,
                file_rec.sec_ctx,
                file_rec.lsattr,
                file_rec.full_path.to_str(),
                file_rec.link_path.as_ref().map(|p| p.to_str()),
                file_rec.scanned_hash,
                file_rec.acquired_hash],
        )?;
        debug!("saved {:?}", file_rec);
        Ok::<_, SQLError>(file_rec)
    }).await?)
}
