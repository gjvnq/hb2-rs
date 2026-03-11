use tokio::sync::mpsc;
use anyhow::Error as AnyHowError;
use clap::{Parser, Subcommand};
use std::{os::linux::raw, sync::OnceLock};
use clap::{Command, Arg, ArgAction, ArgMatches};
use url::Url;
use regex::Regex;

mod utils;
mod adb_utils;
use utils::HashAlg;
use adb_utils::{adb_quick_scanner, adb_full_scanner};

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
        .arg(Arg::new("SOURCE")
            .help("Path to backup. Use a scheme use adb:// or file:// to avoid ambiguities.")
            .required(true)
            .index(1))
        .arg(Arg::new("name")
            .help("Name of the backup. Defaults to the basename of SOURCE.")
            .action(ArgAction::Set)
            .long("name"))
        .arg(Arg::new("description")
            .help("Description of the backup.")
            .action(ArgAction::Set)
            .long("desc"))
        .arg(Arg::new("STORAGE")
            .help("Where to save the backups")
            .required(true)
            .index(2))
        .arg(Arg::new("alg")
            .default_value("SHA256")
            .action(ArgAction::Set)
            .long("alg")
            .value_parser(["MD5", "SHA1", "SHA224", "SHA384", "SHA256", "SHA512"])
            .help("Selects the hash algorithm"))
        .arg(Arg::new("force-color")
            .long("force-color")
            .action(ArgAction::SetTrue)
            .help("Forces the use of colours even when STDOUT is redirected"))
        .arg(Arg::new("debug")
            .long("debug")
            .action(ArgAction::SetTrue)
            .help("Prints additional debugging info"))
        .arg(Arg::new("no-file-flags")
            .long("no-file-flags")
            .action(ArgAction::SetTrue)
            .help("If present, hb2-rs won't even attempt to get the file flags"));

    let verify_blobs_cmd = Command::new("verify-blobs")
        .about("Verifies the stores blobs to see if the file sizes and hashes make sense");

    let import_log_cmd = Command::new("import-log")
        .about("Imports a backup log file into the SQLITE db");

    let main_cmd = Command::new("Hash Based Backup tool")
        .version(VERSION)
        .long_version(get_long_version().as_str())
        .author(AUTHORS)
        .about(DESCRIPTION)
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .after_help("Use HB2_LOG environment variable to control verbosity (options: ERROR, WARN, INFO, DEBUG, TRACE)")
        .subcommand(backup_cmd)
        .subcommand(verify_blobs_cmd)
        .subcommand(import_log_cmd);

    let matches = main_cmd.get_matches();

    match matches.subcommand() {
        Some(("backup", sub_matches)) => main_backup(sub_matches).await?,
        _ => unreachable!("Exhausted list of subcommands and subcommand_required prevents `None`"),
    };

    // database::open_by_dir(storage_path).expect("failed to open db");

    // // database::open_by_dir(storage_path).expect("failed to open db");
    // let (tx, mut rx) = mpsc::channel(32);
    // tokio::spawn(async move {
    //     adb_quick_scanner("/bin", tx).await.unwrap();
    // });
    // while let Some(message) = rx.recv().await {
    //     println!("GOT = {:?}", message);
    // }
    // let (tx2, mut rx2) = mpsc::channel(32);
    // tokio::spawn(async move {
    //     adb_full_scanner("/sdcard/Download/Seal", tx2, Some(HashAlg::SHA256)).await.unwrap();
    // });
    // while let Some(message) = rx2.recv().await {
    //     println!("GOT = {:?}", message);
    // }
    Ok(())
}

#[derive(Debug)]
enum UrlLike {
    File(String),
    ADB(String),
    HTTP(Url),
    FTP(Url),
    SSH(Url),
}

impl UrlLike {
    fn parse(raw_url: &str) -> Result<UrlLike, AnyHowError> {
        let pattern = r"^([\w+]+):\/\/(.+)";
        let re = Regex::new(pattern).expect("Invalid regex pattern");
        if let Some(caps) = re.captures(raw_url) {
            let scheme = &caps[1];
            let main_part = &caps[2];
            if scheme == "adb" || scheme == "adbfs" || scheme == "android" {
                return Ok(UrlLike::ADB(main_part.to_string()));
            } else if scheme == "http" || scheme == "https" {
                return Ok(UrlLike::HTTP(Url::parse(raw_url)?));
            } else if scheme == "ftp" || scheme == "ftps" {
                return Ok(UrlLike::HTTP(Url::parse(raw_url)?));
            } else if scheme == "ssh" || scheme == "sshfs" {
                return Ok(UrlLike::SSH(Url::parse(raw_url)?));
            } else if scheme == "" || scheme == "file" {
                return Ok(UrlLike::File(main_part.to_string()));
            } else {
                unreachable!("unexpected URL scheme");
            }
        } else {
            return Ok(UrlLike::File(raw_url.to_string()));
        }
    }
}

async fn main_backup(sub_matches: &ArgMatches) -> Result<(), AnyHowError> {
    println!("{:?}", sub_matches);
    let source_raw: &String = sub_matches.get_one("SOURCE").unwrap();
    let source = UrlLike::parse(source_raw)?;
    println!("{:?}", source);
    Ok(())
}