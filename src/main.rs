#[macro_use]
extern crate simple_error;

extern crate clap;
use std::error::Error;
use std::path::PathBuf;
use std::io::Write as IoWriter;
use std::fs::File;
use std::fmt::Write as FmtWritter;
use std::path::Path;
use std::fs;
use e2p_fileflags::{FileFlags};
use chrono::{Utc, DateTime, SecondsFormat};
extern crate env_logger;
use snailquote::escape;
use std::os::linux::fs::MetadataExt;
use std::io;
use std::env;
use openssl::nid::Nid;
use openssl::hash::{Hasher, MessageDigest};
use std::process::Command;



#[macro_use] extern crate log;

mod log_hack;
mod database;

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

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    let long_version: String = format!("\nVersion: {VERSION}\nBuild info: {BUILD_SEMVER} built at {BUILD_TIMESTAMP}\nGit info: {GIT_SEMVER} from commit {GIT_SHA} date {GIT_COMMIT_TIMESTAMP} at branch {GIT_BRANCH}\nRustc info: {RUSTC_CHANNEL} {RUSTC_SEMVER} {RUSTC_HOST_TRIPLE} with LLVM {RUSTC_LLVM_VERSION} (rustc commit {RUSTC_COMMIT_HASH})");

    let matches = clap::App::new("Hash Based Backup tool")
        .version(VERSION)
        .long_version(long_version.as_str())
        .author(AUTHORS)
        .about(DESCRIPTION)
        .arg(clap::Arg::with_name("SOURCE")
            .help("Path to backup")
            .required(true)
            .index(1))
        .arg(clap::Arg::with_name("name")
            .help("Name of the backup. Defaults to the basename of SOURCE.")
            .takes_value(true)
            .long("name"))
        .arg(clap::Arg::with_name("description")
            .help("Description of the backup.")
            .takes_value(true)
            .long("desc"))
        .arg(clap::Arg::with_name("STORAGE")
            .help("Where to save the backups")
            .required(true)
            .index(2))
        .arg(clap::Arg::with_name("ADB PATH PREFIX")
            .help("Path prefix to add to use for ADB based hashing")
            .takes_value(true)
            .long("adb-prefix"))
        .arg(clap::Arg::with_name("hash-via-adb")
            .help("Use ADB to hash files instead of doing so locally")
            .long("hash-via-abd")
            .takes_value(false))
        .arg(clap::Arg::with_name("alg")
            .default_value("SHA256")
            .takes_value(true)
            .long("alg")
            .possible_values(&["SHA256"])
            .help("Selects the hash algorithm"))
        .arg(clap::Arg::with_name("force-color")
            .long("force-color")
            .takes_value(false)
            .help("Forces the use of colours even when STDOUT is redirected"))
        .arg(clap::Arg::with_name("debug")
            .long("debug")
            .takes_value(false)
            .help("Prints additional debugging info"))
        .arg(clap::Arg::with_name("no-file-flags")
            .long("no-file-flags")
            .takes_value(false)
            .help("If present, hb2-rs won't even attempt to get the file flags"))
            // .hide_default_value(true)
        .after_help("Use HB2_LOG environment variable to control verbosity (options: ERROR, WARN, INFO, DEBUG, TRACE)")
        .get_matches();

    let force_color = matches.is_present("force-color");
    let debug = matches.is_present("debug");
    let file_flags = !matches.is_present("no-file-flags");
    log_hack::start_logger(force_color, debug);
    debug!("started log");

    let adb_hashing = matches.is_present("hash-via-adb");
    let adb_prefix = Path::new(matches.value_of("ADB PATH PREFIX").unwrap_or("/"));

    let source_path = Path::new(matches.value_of("SOURCE").unwrap());
    let storage_path = Path::new(matches.value_of("STORAGE").unwrap());
    let alg = Nid::SHA256;

    database::open_by_dir(storage_path).expect("failed to open db");

    let mut n_errs = 0;
    let mut list = start_backup(source_path, storage_path, alg).unwrap();
    do_backup(source_path, source_path, storage_path, alg, file_flags, &mut list, &mut n_errs, adb_hashing, adb_prefix);
    finish_backup(list);

    if n_errs != 0 {
        error!("Total errors: {}", n_errs);
    }
}

fn start_backup(source: &Path, storage: &Path, alg: Nid) -> Result<File, std::io::Error> {
    trace!("start_backup - begin");
    let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    debug!("Considering now as {}", now_str);
    let list_path = storage.clone().join(now_str+".txt");
    debug!("Backup list path: {:?}", list_path);

    let mut list = File::create(&list_path)?;
    let alg_str = alg.short_name().unwrap();
    trace!("Created file {:?}", list_path);
    writeln!(list, "# SOURCE: {}", source.to_str().unwrap())?;
    writeln!(list, "# HASH:   {}", alg_str)?;
    list.sync_all()?;

    let mut path_backup_parent = PathBuf::from(storage);
    path_backup_parent.push(alg_str);
    if !path_backup_parent.exists() {
        match fs::create_dir(&path_backup_parent) {
            Ok(_) => {},
            Err(err) => {
                error!("Failed to create directory {:?}: {}", &path_backup_parent, err);
                return Err(err)
            }
        };
    }

    trace!("start_backup - end");
    Ok(list)
}


fn lsattr2str(flags: e2p_fileflags::Flags) -> String {
    use e2p_fileflags::Flags;
    let mut ans = String::new();
    let flag_chars = [(Flags::SECRM, "s"), (Flags::UNRM, "u" ), (Flags::SYNC, "S"), (Flags::DIRSYNC, "D"), (Flags::IMMUTABLE, "i"), (Flags::APPEND, "a"), (Flags::NODUMP, "d"), (Flags::NOATIME, "A"), (Flags::COMPR, "c"), (Flags::ENCRYPT, "E"), (Flags::JOURNAL_DATA, "j"), (Flags::INDEX, "I"), (Flags::NOTAIL, "t"), (Flags::TOPDIR, "T"), (Flags::EXTENTS, "e"), (Flags::NOCOW, "C"), (Flags::CASEFOLD, "F"), (Flags::INLINE_DATA, "N"), (Flags::PROJINHERIT, "P"), (Flags::VERITY, "V")];
    for pair in &flag_chars {
        if flags.contains(pair.0) {
            ans.push_str(pair.1);
        } else {
            ans.push_str("-");
        }
    }
    return ans
}

fn get_backup_path_by_hash(storage: &Path, alg: Nid, hash: &str) -> PathBuf {
    trace!("get_backup_path_by_hash (storage: {:?}, alg: {:?}, hash: {:?})", storage, alg, hash);
    let mut ans = PathBuf::from(storage);
    let alg_name = alg.short_name().unwrap();
    ans.push(alg_name);
    ans.push(&hash[0..2]);
    ans.push(hash);
    trace!("get_backup_path_by_hash return {:?}", ans);
    return ans
}

fn hash_file_directly(path: &Path, path_striped: &str, alg: Nid, metadata: &fs::Metadata, n_errs: &mut i32) -> Result<String, Box<dyn Error>>{
    let mut file = match fs::File::open(&path) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to open file {}: {}", path_striped, err);
            *n_errs += 1;
            return Err(Box::new(err));
        }
    };
    let md = MessageDigest::from_nid(alg).unwrap();
    let mut hasher = Hasher::new(md)?;
    let n = match io::copy(&mut file, &mut hasher) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed hash file {}: {}", path_striped, err);
            *n_errs += 1;
            return Err(Box::new(err));
        }
    };
    let hash = hasher.finish()?;

    // Check size and consistency
    let size = metadata.len();
    if size != n {
        *n_errs += 1;
        let tmp = format!("Number of hashed bytes doesn't match the file size: {} and {}, respectively", n, size);
        error!("{}", tmp);
        bail!(tmp)
    }

    return Ok(hex::encode(hash));
}

fn hash_file_via_adb(path_striped: &str, alg: Nid, adb_prefix: &Path) -> Result<String, Box<dyn Error>> {
    let path_in_android = adb_prefix.join(path_striped);
    let core_cmd = format!("sha256sum {:?}", path_in_android);
    let output = Command::new("adb").arg("shell").arg(core_cmd).output().expect("failed to execute process");
    let s = match std::str::from_utf8(&output.stdout) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    let hash = &s[..64];
    return Ok(hash.to_string());
}

fn backup_single_file(path: &Path, path_striped: &str, storage: &Path, alg: Nid, list: &mut File, metadata: fs::Metadata, mod_date: &str, perm: &str, n_errs: &mut i32, adb_hashing: bool, adb_prefix: &Path) -> Result<(), Box<dyn Error>> {
    //  Hash file
    let hash = match adb_hashing {
        false => hash_file_directly(path, path_striped, alg, &metadata, n_errs)?,
        true => hash_file_via_adb(path_striped, alg, adb_prefix)?
    };

    // Check if backuped file already exists
    let size = metadata.len();
    let path_backup = get_backup_path_by_hash(storage, alg, &hash);
    let mut should_copy = false;
    if path_backup.exists() {
        debug!("File {:?} already exists", path_backup);
        // check size
        let metadata = match fs::metadata(&path_backup) {
            Ok(v) => v,
            Err(err) => {
                *n_errs += 1;
                error!("Failed to get metadata for {:?}: {}", path_backup, err);
                return Err(Box::new(err));
            }
        };
        let backuped_size = metadata.len();
        if size == backuped_size {
            debug!("File {:?} has the correct size: {}", path_backup, size);
        } else if backuped_size > size  {
            error!("Files {:?} and {:?} are supposed to have same hash, but the latter is larger than the first. The second file HAS NOT been overwritten.", path_striped, path_backup);
            *n_errs += 1;
        } else if backuped_size < size  {
            warn!("Files {:?} and {:?} are supposed to have same hash, but the latter is smaller than the first. This looks like an interrupted copy. The second file will be overwritten.", path_striped, path_backup);
            should_copy = true;
        }
    } else {
        debug!("File does not {:?} exist", path_backup);
        should_copy = true;
    }

    if should_copy {
        // Check if parent folder exist
        let path_backup_parent = path_backup.as_path().parent().unwrap();
        if !path_backup_parent.exists() {
            match fs::create_dir(path_backup_parent) {
                Ok(_) => {},
                Err(err) => {
                    *n_errs += 1;
                    error!("Failed to create directory {:?}: {}", path_backup_parent, err);
                    return Err(Box::new(err));
                }
            };
        }

        match fs::copy(&path, &path_backup) {
            Ok(_) => {},
            Err(err) => {
                error!("Failed to copy file {:?} to {:?}: {}", path, path_backup, err);
                *n_errs += 1;
                return Err(Box::new(err));
            }
        };
    }

    // Write
    writeln!(list, "F {:12} {} {} {} {}", size, mod_date, perm, hash, path_striped)?;

    return Ok(());
}

fn do_item(base_source: &Path, storage: &Path, item_path: &Path, alg: Nid, file_flags: bool, list: &mut File, n_errs: &mut i32, adb_hashing: bool, adb_prefix: &Path) -> Result<(), Box<dyn Error>> {
    let path_striped = escape(item_path.strip_prefix(base_source).unwrap_or(item_path).to_str().unwrap());
    debug!("Processing {}", path_striped);

    let metadata = match fs::symlink_metadata(item_path) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to get metadata for {}: {}", path_striped, err);
            return Err(Box::new(err))
        }
    };
    let mod_date = DateTime::<Utc>::from(metadata.modified()?).to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut perm = String::new();
    let lsattr: String = match file_flags {
        true => match item_path.flags() {
            Ok(flags) => lsattr2str(flags),
            Err(err) => {
                warn!("Failed to get lsattr for {}: {}", path_striped, err);
                "????????????????????".to_string()
            },
        },
        false => "????????????????????".to_string()
    };
    write!(perm, "{}:{} {:o} {}",
        metadata.st_uid(),
        metadata.st_gid(),
        metadata.st_mode(),
        lsattr)?;

    if metadata.file_type().is_symlink() {
        debug!("{} is a link", path_striped);
        let target_path = match item_path.read_link() {
            Ok(v) => v,
            Err(err) => {
                error!("Failed to read {:?} as a symlink: {}", item_path, err);
                return Err(Box::new(err))
            }
        };
         if target_path.starts_with(base_source) {
            // If the link targets something inside the base_source, just record the link and don't even read the file as the target will be found separately.
            let target_path_striped = escape(item_path.strip_prefix(&target_path)?.to_str().unwrap());
            writeln!(list, "L {} {} {} -> {}", mod_date, perm, path_striped, target_path_striped)?;
        } else {
            info!("{} is an EXTERNAL link to {:?}. This link will be followed and its contents backed up", path_striped, target_path);
            writeln!(list, "L {} {} {} -> {}", mod_date, perm, path_striped, escape(target_path.to_str().unwrap()))?;
            do_item(base_source, storage, &target_path, alg, file_flags, list, n_errs, adb_hashing, adb_prefix)?;
        }
    } else if metadata.file_type().is_dir() {
        // Recursion time!
        debug!("{} is a directory", path_striped);
        writeln!(list, "D {} {} {}", mod_date, perm, path_striped)?;
        do_backup(base_source, &item_path, storage, alg, file_flags, list, n_errs, adb_hashing, adb_prefix);
    } else if metadata.file_type().is_file() {
        debug!("{} is a file", path_striped);
        backup_single_file(&item_path, &path_striped, storage, alg, list, metadata, &mod_date, &perm, n_errs, adb_hashing, adb_prefix)?;
    } else {
        unimplemented!("File type {:?} is not supported", metadata.file_type());
    }
    return Ok(());
}

fn do_backup(base_source: &Path, source: &Path, storage: &Path, alg: Nid, file_flags: bool, list: &mut File, n_errs: &mut i32, adb_hashing: bool, adb_prefix: &Path) {
    trace!("on  {:?}", source);
    let entries = match fs::read_dir(source) {
        Ok(e) => e,
        Err(err) => {
            error!("{}", err);
            *n_errs += 1;
            trace!("end {:?}", source);
            return
        }
    };
    for entry in entries {
        let entry = entry.unwrap();
        let item_path = entry.path();
        match do_item(base_source, storage, &item_path, alg, file_flags, list, n_errs, adb_hashing, adb_prefix) {
            Err(err) => {
                *n_errs += 1;
                error!("Unexpected error on {:?}: {}", item_path, err);
            }
            Ok(_) => {}
        };
    }
    trace!("end {:?}", source);
}

fn finish_backup(list: File) {
    list.sync_data().unwrap();
}
