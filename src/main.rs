extern crate clap;
use std::fs::File;
use std::path::Path;
use std::io::prelude::*;
use chrono::{Utc};
extern crate env_logger;

#[macro_use] extern crate log;

mod log_hack;

fn main() {
    log_hack::start_logger();
    debug!("started log");
    info!("such information");
    warn!("o_O");
    error!("boom1");


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

    info!("such information");
    warn!("o_O");
    error!("boom");

    start_backup(source_path, storage_path);
}

fn start_backup(source: &Path, storage: &Path) -> Result<i32, std::io::Error> {
    trace!("start_backup");
    let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();

    // let file = OpenOptions::new().read(true).open("foo.txt");
    let list_path = storage.clone().join(now_str+".txt");
    let mut list = File::create(&list_path).expect("Failed to create list file");
    list.write_all(source.to_str().unwrap().as_bytes())?;
    // let mut list = match File::create(&list_path);

    Ok(0)
}