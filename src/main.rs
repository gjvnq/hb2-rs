extern crate clap;
use std::io::Write as IoWriter;
use std::fs::File;
use std::fmt::Write as FmtWritter;
use std::path::Path;
use std::fs;
use e2p_fileflags::{FileFlags,Flags};
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
        .after_help("Use RUST_LOG environment variable to control verbosity (options: ERROR, WARN, INFO, DEBUG, TRACE)")
        .get_matches();
    // pretty_env_logger::init();

    let source_path = Path::new(matches.value_of("SOURCE").unwrap());
    let storage_path = Path::new(matches.value_of("STORAGE").unwrap());
    let alg = matches.value_of("alg").unwrap();

    let mut n_errs = 0;
    let mut list = start_backup(source_path, storage_path, alg).unwrap();
    do_backup(source_path, source_path, storage_path, Nid::SHA256, &mut list, &mut n_errs);
    finish_backup(list);

    if n_errs != 0 {
        error!("Total errors: {}", n_errs);
    }
}

fn start_backup(source: &Path, storage: &Path, alg: &str) -> Result<File, std::io::Error> {
    trace!("start_backup");
    let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    debug!("Considering now as {}", now_str);
    let list_path = storage.clone().join(now_str+".txt");
    debug!("Backup list path: {:?}", list_path);

    let mut list = File::create(&list_path)?;
    trace!("Created file {:?}", list_path);
    writeln!(list, "# SOURCE: {}", source.to_str().unwrap())?;
    writeln!(list, "# HASH:   {}", alg)?;
    list.sync_all()?;

    Ok(list)
}


fn lsattr2str(flags: Flags) -> String {
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
            writeln!(list, "D {} {} {}", mod_date, perm, path_striped).unwrap();
            do_backup(base_source, &path, storage, alg, list, n_errs);
        } else {
            let mut file = fs::File::open(&path).unwrap();
            let md = MessageDigest::from_nid(alg).unwrap();
            let mut hasher = Hasher::new(md).unwrap();
            let n = io::copy(&mut file, &mut hasher).unwrap();
            let hash = hex::encode(hasher.finish().unwrap());

            let size = metadata.len();
            if size != n {
                *n_errs += 1;
                error!("Number of hashed bytes doesn't match the file size: {} and {}, respectively", n, size);
                continue;
            }
            writeln!(list, "F {:12} {} {} {} {}", size, mod_date, perm, hash, path_striped).unwrap();
        }
    }
    trace!("end {:?}", source);
}

fn finish_backup(list: File) {
    list.sync_data().unwrap();
}
