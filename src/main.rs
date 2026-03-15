use anyhow::Error as AnyHowError;
use anyhow::Result as AnyHowResult;
use clap::{Arg, ArgAction, ArgMatches, Command};
use rusqlite::Connection;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::sync::mpsc;

#[macro_use]
extern crate log;

mod adb_utils;
mod database;
mod find_utils;
mod utils;
mod log_hack;
use crate::find_utils::FindLineCoreTrait;
use adb_utils::{adb_full_scanner, adb_quick_scanner};
use database::{new_backup_record, open_db_by_dir, save_file_record};
use utils::{HashAlg, UrlLike};

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
    let hash_alg = HashAlg::from(hash_alg_raw);

    let conn = database::open_db_by_dir(&storage_path).expect("failed to open db");

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
    hash_alg: Option<HashAlg>,
    name: Option<&str>,
    description: Option<&str>,
    mut excludes: HashSet<PathBuf>,
) -> Result<(), AnyHowError> {
    excludes.insert(PathBuf::from("/dev"));
    excludes.insert(PathBuf::from("/proc"));
    excludes.insert(PathBuf::from("/sys"));

    let source_fancy = format!("adb://{}", source.to_str().unwrap());
    let backup_uuid = new_backup_record(&conn, name, description, &source_fancy)?;

    let (tx1, mut rx1) = mpsc::channel(32);
    let source1 = source.to_path_buf();
    tokio::spawn(async move {
        adb_full_scanner(&source1, Some(excludes), hash_alg, tx1)
            .await
            .unwrap();
    });
    // let (tx2, mut rx2) = mpsc::channel(32);
    // tokio::spawn(async move {
    //     filter_find_lines(excludes, rx1, tx2).await;
    // });
    let mut uuid_map = HashMap::<PathBuf, String>::new();
    while let Some(message) = rx1.recv().await {
        let mut file_record = message.to_file_record();
        if uuid_map.contains_key(&file_record.full_path) {
            // Make sure we don't try to save the same file twice
            continue;
        }
        info!("{:?} {} {} {}", file_record.full_path, file_record.kind.to_char(), file_record.size, file_record.hash_val.as_ref().map_or("", |s| s));
        let parent_uuid = match file_record.full_path.parent().map(|p| uuid_map.get(p)) {
            Some(None) => None,
            Some(p) => p,
            None => None,
        };
        let file_record = save_file_record(&conn, &backup_uuid, parent_uuid, file_record)?;
        uuid_map.insert(file_record.full_path, file_record.uuid.unwrap());
    }
    // let (tx3, mut rx3) = mpsc::channel(32);
    // let source2 = source.to_path_buf();
    // tokio::spawn(async move {
    //     adb_full_scanner(&source2, tx3, Some(HashAlg::SHA256)).await.unwrap();
    // });
    // while let Some(message) = rx3.recv().await {
    //     println!("GOT = {:?}", message);
    // }
    // open_db_by_dir
    Ok(())
}
