use anyhow::Error as AnyHowError;
use anyhow::Result as AnyHowResult;
use clap::{Arg, ArgAction, ArgMatches, Command};
use core::hash;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rusqlite::Connection;

#[macro_use]
extern crate log;

mod adb_utils;
mod database;
mod find_utils;
mod log_hack;
mod utils;
use crate::database::FileRecord;
use crate::find_utils::FindLineCoreTrait;
use crate::utils::FileKind;
use adb_utils::{adb_copy_file, adb_full_scanner, adb_quick_scanner};
use database::{
    insert_file_record, new_backup_record, open_db_by_dir, replace_file_record, save_blob_record,
};
use utils::{blob_full_path, blob_parent_path, HashAlg, UrlLike};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

const BUILD_TIMESTAMP: &str = env!("VERGEN_BUILD_TIMESTAMP");
const BUILD_SEMVER: &str = env!("VERGEN_BUILD_SEMVER");
const GIT_BRANCH: &str = env!("VERGEN_GIT_BRANCH");
const GIT_COMMIT_TIMESTAMP: &str = env!("VERGEN_GIT_COMMIT_TIMESTAMP");
const GIT_SEMVER: &str = env!("VERGEN_GIT_SEMVER");
const GIT_SHA: &str = env!("VERGEN_GIT_SHA");
const RUSTC_CHANNEL: &str = env!("VERGEN_RUSTC_CHANNEL");
const RUSTC_HOST_TRIPLE: &str = env!("VERGEN_RUSTC_HOST_TRIPLE");
const RUSTC_COMMIT_HASH: &str = env!("VERGEN_RUSTC_COMMIT_HASH");
const RUSTC_SEMVER: &str = env!("VERGEN_RUSTC_SEMVER");
const RUSTC_LLVM_VERSION: &str = env!("VERGEN_RUSTC_LLVM_VERSION");
static LONG_VERSION: OnceLock<String> = OnceLock::new();

fn get_long_version() -> &'static String {
    LONG_VERSION.get_or_init(|| {
        format!("\nVersion: {VERSION}\nBuild info: {BUILD_SEMVER} built at {BUILD_TIMESTAMP}\nGit info: {GIT_SEMVER} from commit {GIT_SHA} date {GIT_COMMIT_TIMESTAMP} at branch {GIT_BRANCH}\nRustc info: {RUSTC_CHANNEL} {RUSTC_SEMVER} {RUSTC_HOST_TRIPLE} with LLVM {RUSTC_LLVM_VERSION} (rustc commit {RUSTC_COMMIT_HASH})")
    })
}

#[tokio::main]
async fn main() -> Result<(), AnyHowError> {
    let backup_cmd = Command::new("backup")
        .about("Backups files")
        .arg(
            Arg::new("SOURCE")
                .help("Path to backup. Use a scheme use adb:// or file:// to avoid ambiguities.")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("name")
                .help("Name of the backup. Defaults to the basename of SOURCE.")
                .action(ArgAction::Set)
                .long("name"),
        )
        .arg(
            Arg::new("description")
                .help("Description of the backup.")
                .action(ArgAction::Set)
                .long("desc"),
        )
        .arg(
            Arg::new("STORAGE")
                .help("Where to save the backups")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("alg")
                .default_value("SHA256")
                .action(ArgAction::Set)
                .long("alg")
                .value_parser(["MD5", "SHA1", "SHA224", "SHA384", "SHA256", "SHA512"])
                .help("Selects the hash algorithm"),
        )
        .arg(
            Arg::new("exclude")
                .action(ArgAction::Append)
                .long("exclude")
                .help("Specifies a directory to skip while backing up"),
        )
        .arg(
            Arg::new("no-file-flags")
                .long("no-file-flags")
                .action(ArgAction::SetFalse)
                .help("If present, hb2-rs won't even attempt to get the file flags"),
        );

    let verify_blobs_cmd = Command::new("verify-blobs")
        .about("Verifies the stores blobs to see if the file sizes and hashes make sense");

    let import_log_cmd =
        Command::new("import-log").about("Imports a backup log file into the SQLITE db");

    let main_cmd = Command::new("Hash Based Backup tool")
        .version(VERSION)
        .long_version(get_long_version().as_str())
        .author(AUTHORS)
        .about(DESCRIPTION)
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .after_help("Use HB2_LOG environment variable to control verbosity (options: ERROR, WARN, INFO, DEBUG, TRACE)")
        .arg(
            Arg::new("force-color")
                .long("force-color")
                .action(ArgAction::SetTrue)
                .help("Forces the use of colours even when STDOUT is redirected"),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("Prints additional debugging info"),
        )
        .subcommand(backup_cmd)
        .subcommand(verify_blobs_cmd)
        .subcommand(import_log_cmd);

    let matches = main_cmd.get_matches();

    let force_color = matches.get_flag("force-color");
    let debug = matches.get_flag("debug");
    log_hack::start_logger(force_color, debug);
    debug!("started log");

    match matches.subcommand() {
        Some(("backup", sub_matches)) => main_backup(sub_matches).await?,
        _ => unreachable!("Exhausted list of subcommands and subcommand_required prevents `None`"),
    };

    Ok(())
}

async fn main_backup(sub_matches: &ArgMatches) -> Result<(), AnyHowError> {
    debug!("{:?}", sub_matches);
    let source_raw: &String = sub_matches.get_one("SOURCE").unwrap();
    let source = UrlLike::parse(source_raw)?;
    debug!("source={:?}", source);
    let storage_path = PathBuf::from(sub_matches.get_one::<String>("STORAGE").unwrap());
    debug!("storage_path={:?}", storage_path);
    let file_flags = sub_matches.get_flag("no-file-flags");
    debug!("file_flags={:?}", file_flags);
    let excludes = sub_matches
        .get_many::<String>("exclude")
        .unwrap_or_default()
        .map(|v| PathBuf::from(v.as_str()))
        .collect::<HashSet<_>>();
    debug!("excludes={:?}", excludes);

    let hash_alg_raw: &String = sub_matches.get_one("alg").unwrap();
    let hash_alg = HashAlg::from(hash_alg_raw).expect("invalid hash algorithm");

    let conn = open_db_by_dir(&storage_path)
        .await
        .expect("failed to open db");

    match source {
        UrlLike::ADB(source_path) => {
            main_backup_adb(
                conn,
                &source_path,
                &storage_path,
                hash_alg,
                None,
                None,
                excludes,
            )
            .await
        }
        _ => unreachable!(),
    }
}

async fn main_backup_adb(
    conn: Connection,
    source: &Path,
    storage: &Path,
    hash_alg: HashAlg,
    name: Option<String>,
    description: Option<String>,
    mut excludes: HashSet<PathBuf>,
) -> Result<(), AnyHowError> {
    excludes.insert(PathBuf::from("/dev"));
    excludes.insert(PathBuf::from("/proc"));
    excludes.insert(PathBuf::from("/sys"));
    let mut task_set = JoinSet::new();

    let source_fancy = format!("adb://{}", source.to_str().unwrap());
    let backup_uuid =
        new_backup_record(&conn, name.clone(), description.clone(), source_fancy).await?;

    let (tx1, mut rx1) = mpsc::channel(32);
    let source1 = source.to_path_buf();
    task_set.spawn(
        async move { adb_full_scanner(&source1, Some(excludes), Some(hash_alg), tx1).await },
    );

    let (tx2, mut rx2) = mpsc::channel(32);
    let conn2 = conn.clone();
    task_set.spawn(async move { save_file_records(&conn2, backup_uuid, rx1, tx2).await });

    let storage3 = storage.to_path_buf();
    task_set.spawn(async move { copy_files(&conn, &storage3, hash_alg, rx2).await });

    while let Some(result) = task_set.join_next().await {
        match result {
            Ok(_) => {}
            Err(e) => error!("Task error: {:?}", e),
        }
    }
    info!("Backup done");

    // open_db_by_dir
    Ok(())
}

async fn copy_files(
    conn: &Connection,
    storage_path: &Path,
    hash_alg: HashAlg,
    mut rx: mpsc::Receiver<FileRecord>,
) -> AnyHowResult<()> {
    // , tx: mpsc::Sender<FileRecord>
    let tmp_path = storage_path.join("pulled_file");
    while let Some(mut file_record) = rx.recv().await {
        if file_record.kind != FileKind::FILE {
            continue;
        }
        // 1. Copy the file to a provisory location
        let res = adb_copy_file(&file_record.full_path, &tmp_path).await;
        if let Err(err) = res {
            error!("failed to copy file {:?}: {:?}", file_record.full_path, err);
            continue;
        }
        // 2. Hash the file and get file size again
        let acquired_hash = hash_alg.hash_file(&tmp_path).await?;
        file_record.acquired_hash = Some(acquired_hash.clone());
        let actual_file_size = i64::try_from(fs::metadata(&tmp_path)?.len()).unwrap();
        if file_record.size != actual_file_size {
            warn!(
                "File size inconsistency for {:?}, expected {} but got {}",
                file_record.full_path, file_record.size, actual_file_size
            );
            file_record.size = actual_file_size;
        }

        // 3. Save the found hash and size
        file_record = replace_file_record(conn, file_record).await?;

        // 4. Save blob record
        save_blob_record(conn, &acquired_hash, file_record.size).await?;

        // 5. Move the file
        let dir_to_make = blob_parent_path(storage_path, &acquired_hash);
        let blob_path = blob_full_path(storage_path, &acquired_hash);
        debug!("making dir {:?}", dir_to_make);
        fs::create_dir_all(dir_to_make)?;
        if blob_path.is_file() {
            let stored_blob_size = i64::try_from(fs::metadata(&blob_path)?.len()).unwrap();
            if stored_blob_size != actual_file_size {
                warn!("Inconsistent blob size for {}, expected {} but got {}. Blob will be overwritten", acquired_hash, actual_file_size, stored_blob_size);
            }
            fs::remove_file(&blob_path)?;
        }
        if blob_path.is_file() {
            // blob already stored, just delete tmp file
            fs::remove_file(&tmp_path)?;
        } else {
            fs::rename(&tmp_path, &blob_path)?;
        }
        info!("stored blob {}", acquired_hash);
    }
    Ok(())
}

async fn save_file_records<T: FindLineCoreTrait>(
    conn: &Connection,
    backup_uuid: String,
    mut rx: mpsc::Receiver<T>,
    tx: mpsc::Sender<FileRecord>,
) -> AnyHowResult<()> {
    let mut uuid_map = HashMap::<PathBuf, String>::new();
    while let Some(message) = rx.recv().await {
        let mut file_record = message.to_file_record();
        if uuid_map.contains_key(&file_record.full_path) {
            // Make sure we don't try to save the same file twice
            continue;
        }
        info!(
            "scanned file {:?} {} {} {}",
            file_record.full_path,
            file_record.kind.to_char(),
            file_record.size,
            file_record.scanned_hash.as_ref().map_or("", |s| s)
        );
        let parent_uuid = match file_record.full_path.parent().map(|p| uuid_map.get(p)) {
            Some(None) => None,
            Some(p) => p,
            None => None,
        };
        file_record = insert_file_record(&conn, &backup_uuid, parent_uuid, file_record).await?;
        uuid_map.insert(
            file_record.full_path.clone(),
            file_record.uuid.clone().unwrap(),
        );
        tx.send(file_record).await?;
    }
    Ok(())
}
