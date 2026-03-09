use tokio::sync::mpsc;
use anyhow::Error as AnyHowError;
use clap::{Parser, Subcommand};
use std::sync::OnceLock;
use clap::{Command, Arg, ArgAction};
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
    let matches = Command::new("Hash Based Backup tool")
        .version(VERSION)
        .long_version(get_long_version().as_str())
        .author(AUTHORS)
        .about(DESCRIPTION)
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
            .help("If present, hb2-rs won't even attempt to get the file flags"))
        .after_help("Use HB2_LOG environment variable to control verbosity (options: ERROR, WARN, INFO, DEBUG, TRACE)")
        .get_matches();
    println!("{:?}", matches);
    let source_raw: &String = matches.get_one("SOURCE").unwrap();
    let pattern = r"^[\w+]+:\/\/";
    let re = Regex::new(pattern).expect("Invalid regex pattern");
    let source_raw2 = match re.is_match(source_raw) {
        true => source_raw.clone(),
        false => format!("file://{}", source_raw)
    };
    let source_url = Url::parse(&source_raw2)?;
    println!("{:?}", source_url);
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
