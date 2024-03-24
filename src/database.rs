use rusqlite::{Connection, OpenFlags, Result as SQLResult};
use std::path::Path;

pub fn open_by_dir(dirpath: &Path) -> SQLResult<Connection> {
    let filepath = dirpath.join("hb2-rs.sqlite");
    open_by_path(filepath.as_path())
}

fn schema_upgrade_v1(conn: &Connection) -> SQLResult<()> {
    conn.execute_batch(include_str!("schema_v1.sql"))?;
    conn.pragma_update(None, "user_version", 1)?;
    info!("Upgraded schema to version 1");
    Ok(())
}

fn open_by_path(filepath: &Path) -> SQLResult<Connection> {
    let filepath_str = filepath.to_str().expect("filepath should be valid UTF-8");
    debug!("Opening database at {}", filepath_str);
    let conn = Connection::open_with_flags(filepath, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    info!("Opened database at {}", filepath_str);

    // Check schema version
    let schema_ver: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).expect("failed to load pragma user_version");


    if schema_ver == 0 {
        schema_upgrade_v1(&conn)?;
    }

    Ok(conn)
}
