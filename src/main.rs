use tokio::sync::mpsc;
use anyhow::Error as AnyHowError;

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
    // database::open_by_dir(storage_path).expect("failed to open db");
    let (tx, mut rx) = mpsc::channel(32);
    tokio::spawn(async move {
        adb_quick_scanner("/bin", tx).await.unwrap();
    });
    while let Some(message) = rx.recv().await {
        println!("GOT = {:?}", message);
    }
    let (tx2, mut rx2) = mpsc::channel(32);
    tokio::spawn(async move {
        adb_full_scanner("/sdcard/Download/Seal", tx2, Some(HashAlg::SHA256)).await.unwrap();
    });
    while let Some(message) = rx2.recv().await {
        println!("GOT = {:?}", message);
    }
    Ok(())
}
