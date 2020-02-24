extern crate clap;
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
use openssl::nid::Nid;
use openssl::hash::{Hasher, MessageDigest};



#[macro_use] extern crate log;

mod log_hack;

fn main() {
    log_hack::start_logger();
    debug!("started log");

    let matches = clap::App::new("Hash Based Backup tool")
        .version("0.1.0")
        .author("G. Queiroz <gabrieljvnq@gmail.com>")
        .about("Simple hash based backup tool")
        .arg(clap::Arg::with_name("SOURCE")
            .help("Path to backup")
            .required(true)
            .index(1))
        .arg(clap::Arg::with_name("STORAGE")
            .help("Where to save the backups")
            .required(true)
            .index(2))
        .arg(clap::Arg::with_name("alg")
            .default_value("SHA256")
            .takes_value(true)
            .long("alg")
            .possible_values(&["SHA256"])
            .help("Selects the hash algorithm"))
        .after_help("Use HB2_LOG environment variable to control verbosity (options: ERROR, WARN, INFO, DEBUG, TRACE)")
        .get_matches();

    let source_path = Path::new(matches.value_of("SOURCE").unwrap());
    let storage_path = Path::new(matches.value_of("STORAGE").unwrap());
    let alg = Nid::SHA256;

    let mut n_errs = 0;
    let mut list = start_backup(source_path, storage_path, alg).unwrap();
    do_backup(source_path, source_path, storage_path, alg, &mut list, &mut n_errs);
    finish_backup(list);

    if n_errs != 0 {
        error!("Total errors: {}", n_errs);
    }
}

fn start_backup(source: &Path, storage: &Path, alg: Nid) -> Result<File, std::io::Error> {
    trace!("start_backup");
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

fn backup_single_file(path: &Path, path_striped: &str, storage: &Path, alg: Nid, list: &mut File, metadata: fs::Metadata, mod_date: &str, perm: &str, n_errs: &mut i32) {
    //  Hash file
    let mut file = match fs::File::open(&path) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to open file {}: {}", path_striped, err);
            *n_errs += 1;
            return;
        }
    };
    let md = MessageDigest::from_nid(alg).unwrap();
    let mut hasher = Hasher::new(md).unwrap();
    let n = match io::copy(&mut file, &mut hasher) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed hash file {}: {}", path_striped, err);
            *n_errs += 1;
            return;
        }
    };
    let hash = hex::encode(hasher.finish().unwrap());

    // Check size and consistency
    let size = metadata.len();
    if size != n {
        *n_errs += 1;
        error!("Number of hashed bytes doesn't match the file size: {} and {}, respectively", n, size);
        return;
    }

    // Check if backuped file already exists
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
                return;
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
                    return;
                }
            };
        }

        match fs::copy(&path, &path_backup) {
            Ok(_) => {},
            Err(err) => {
                error!("Failed to copy file {:?} to {:?}: {}", path, path_backup, err);
                *n_errs += 1;
                return;
            }
        };
    }

    // Write
    writeln!(list, "F {:12} {} {} {} {}", size, mod_date, perm, hash, path_striped).unwrap();
}

fn do_backup(base_source: &Path, source: &Path, storage: &Path, alg: Nid, list: &mut File, n_errs: &mut i32) {
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
        let path = entry.path();
        let path_striped = escape(path.strip_prefix(base_source).unwrap().to_str().unwrap());
        debug!("Processing {}", path_striped);

        let metadata = fs::metadata(entry.path()).unwrap();
        let mod_date = DateTime::<Utc>::from(metadata.modified().unwrap()).to_rfc3339_opts(SecondsFormat::Millis, true);
        let mut perm = String::new();
        write!(perm, "{}:{} {:o} {}",
            metadata.st_uid(),
            metadata.st_gid(),
            metadata.st_mode(),
            lsattr2str(path.flags().unwrap())).unwrap();

        if path.is_dir() {
            // Recursion time!
            writeln!(list, "D {} {} {}", mod_date, perm, path_striped).unwrap();
            do_backup(base_source, &path, storage, alg, list, n_errs);
        } else {
            backup_single_file(&path, &path_striped, storage, alg, list, metadata, &mod_date, &perm, n_errs);
        }
    }
    trace!("end {:?}", source);
}

fn finish_backup(list: File) {
    list.sync_data().unwrap();
}
