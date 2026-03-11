use crate::find_utils::FindLineGeneric;
use crate::AnyHowError;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, Result as SQLResult};
use std::path::Path;
use uuid::Uuid;
use rusqlite::params;

pub fn open_db_by_dir(dirpath: &Path) -> SQLResult<Connection> {
    let filepath = dirpath.join("hb2-rs.dev.sqlite");
    open_db_by_path(filepath.as_path())
}

fn schema_upgrade_v1(conn: &Connection) -> SQLResult<()> {
    conn.execute_batch(include_str!("schema_v1.sql"))?;
    conn.pragma_update(None, "user_version", 1)?;
    info!("Upgraded schema to version 1");
    Ok(())
}

fn open_db_by_path(filepath: &Path) -> SQLResult<Connection> {
    let filepath_str = filepath.to_str().expect("filepath should be valid UTF-8");
    debug!("Opening database at {}", filepath_str);
    let conn = Connection::open_with_flags(
        filepath,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    info!("Opened database at {}", filepath_str);

    // Check schema version
    let schema_ver: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("failed to load pragma user_version");

    if schema_ver == 0 {
        schema_upgrade_v1(&conn)?;
    }

    Ok(conn)
}

pub fn new_backup_record(
    conn: &Connection,
    name: Option<&str>,
    description: Option<&str>,
    source_dir: &str,
) -> Result<String, AnyHowError> {
    let backup_uuid = Uuid::new_v4();
    let backup_uuid_str = backup_uuid.hyphenated().to_string();
    let utc_now: DateTime<Utc> = Utc::now();
    conn.execute(
        "INSERT INTO backups (uuid, name, description, source_dir, started_at) VALUES (?, ?, ?, ?, ?)",
        (&backup_uuid_str, name, description, source_dir, utc_now),
    )?;
    return Ok(backup_uuid_str);
}

pub fn save_new_file_info(
    conn: &Connection,
    backup_uuid: &str,
    parent_uuid: Option<&str>,
    find_line: &FindLineGeneric,
) -> Result<String, AnyHowError> {
    let file_uuid = Uuid::new_v4();
    let file_uuid_str = file_uuid.hyphenated().to_string();
    let utc_now: DateTime<Utc> = Utc::now();
    println!("{:?}", find_line.full_path.file_name());
    let base_name = find_line.full_path.file_name().map_or(find_line.full_path.to_str(), |p| p.to_str()).unwrap();
    conn.execute(
        "INSERT INTO files (uuid, backup_uuid, parent_uuid, inode, name, mode, size, kind, uid_num, gid_num, uid_str, gid_str, mod_time, sec_ctx, lsattr, full_path, link_path, scanned_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![&file_uuid_str, backup_uuid, parent_uuid, find_line.inode, base_name, find_line.mode_num, find_line.size, find_line.kind.to_char().to_string(), find_line.uid_num, find_line.gid_num, find_line.uid_text, find_line.gid_text, find_line.mod_time, find_line.sec_ctx, None::<String>, find_line.full_path.to_str(), find_line.link_path.as_ref().map(|p| p.to_str()), find_line.hash_val],
    )?;
    conn.cache_flush()?;
    return Ok(file_uuid_str);
}
