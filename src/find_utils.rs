use crate::utils::{FileKind, HashAlg};
use anyhow::Error as AnyHowError;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

const ASCII_US: char = '\x1F';
const ASCII_US_BYTE: u8 = b'\x1F';
const ASCII_NULL: char = '\x00';
const ASCII_NULL_BYTE: u8 = b'\x00';
const FIND_ASCII_NULL: &str = "\\\\0";
const FIND_INODE: &str = "%i";
const FIND_SIZE: &str = "%s";
const FIND_MODE_OCTAL: &str = "%m";
const FIND_MODE_TEXT: &str = "%M";
const FIND_UID_NUM: &str = "%U";
const FIND_UID_TEXT: &str = "%u";
const FIND_GID_NUM: &str = "%G";
const FIND_GID_TEXT: &str = "%g";
const FIND_MOD_TIME: &str = "%T@";
const FIND_SEC_CTX: &str = "%Z";
const FIND_PATH: &str = "%p";
const FIND_LINK_TO: &str = "%l";
const FIND_ASCII_NEW_LINE: &str = "\\\\n";

pub trait FindLineCoreTrait: Debug + Sized + Send + Clone {
    fn get_full_path(&self) -> &Path;
    fn get_kind(&self) -> FileKind;
}

pub trait FindLineTrait: FindLineCoreTrait {
    fn parse(line: &str) -> Result<Self, AnyHowError>;
    fn find_printf(extra_cmd: bool) -> String;
}

#[derive(Debug, Clone)]
pub struct FindLineGeneric {
    inode: Option<u64>,
    size: u64,
    kind: FileKind,
    mode_num: Option<u16>,
    mode_text: Option<String>,
    uid_num: Option<u64>,
    uid_text: Option<String>,
    gid_num: Option<u64>,
    gid_text: Option<String>,
    mod_time: Option<DateTime<Utc>>,
    sec_ctx: Option<String>,
    full_path: PathBuf,
    link_path: Option<PathBuf>,
    hash_val: Option<String>,
}

impl FindLineCoreTrait for FindLineGeneric {
    fn get_full_path(&self) -> &Path {
        &self.full_path
    }

    fn get_kind(&self) -> FileKind {
        self.kind
    }
}

impl From<FindLineMinimal> for FindLineGeneric {
    fn from(src: FindLineMinimal) -> Self {
        FindLineGeneric {
            inode: Some(src.inode),
            size: src.size,
            kind: src.kind,
            mode_num: None,
            mode_text: None,
            uid_num: None,
            uid_text: None,
            gid_num: None,
            gid_text: None,
            mod_time: None,
            sec_ctx: None,
            full_path: src.full_path,
            link_path: None,
            hash_val: None,
        }
    }
}

impl From<FindLineADB> for FindLineGeneric {
    fn from(src: FindLineADB) -> Self {
        FindLineGeneric {
            inode: Some(src.inode),
            size: src.size,
            kind: src.kind,
            mode_num: Some(src.mode_num),
            mode_text: Some(src.mode_text),
            uid_num: Some(src.uid_num),
            uid_text: Some(src.uid_text),
            gid_num: Some(src.gid_num),
            gid_text: Some(src.gid_text),
            mod_time: Some(src.mod_time),
            sec_ctx: Some(src.sec_ctx),
            full_path: src.full_path,
            link_path: src.link_path,
            hash_val: src.hash_val,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FindLineMinimal {
    inode: u64,
    size: u64,
    kind: FileKind,
    full_path: PathBuf,
}

impl FindLineCoreTrait for FindLineMinimal {
    fn get_full_path(&self) -> &Path {
        &self.full_path
    }

    fn get_kind(&self) -> FileKind {
        self.kind
    }
}

impl FindLineTrait for FindLineMinimal {
    fn parse(line: &str) -> Result<Self, AnyHowError> {
        let mut split_iter = line.split(ASCII_US);
        let inode = (split_iter.next().expect("missing inode number")).parse::<u64>()?;
        let size = (split_iter.next().expect("missing size")).parse::<u64>()?;
        let mode_text = (split_iter.next().expect("missing mode text")).to_string();
        let full_path = PathBuf::from(split_iter.next().expect("missing file path"));

        let kind = match mode_text.chars().next().unwrap() {
            'd' => FileKind::DIRECTORY,
            '-' => FileKind::FILE,
            'l' => FileKind::LINK,
            _ => unreachable!(),
        };
        Ok(FindLineMinimal {
            inode,
            size,
            kind,
            full_path,
        })
    }

    fn find_printf(extra_cmd: bool) -> String {
        let mut printf = String::from("");
        printf.push_str(FIND_INODE);
        printf.push(ASCII_US);
        printf.push_str(FIND_SIZE);
        printf.push(ASCII_US);
        printf.push_str(FIND_MODE_TEXT);
        printf.push(ASCII_US);
        printf.push_str(FIND_PATH);
        if extra_cmd {
            printf.push(ASCII_US);
        } else {
            printf.push_str(FIND_ASCII_NEW_LINE);
        }
        return printf;
    }
}

#[derive(Debug, Clone)]
pub struct FindLineADB {
    inode: u64,
    size: u64,
    kind: FileKind,
    mode_num: u16,
    mode_text: String,
    uid_num: u64,
    uid_text: String,
    gid_num: u64,
    gid_text: String,
    mod_time: DateTime<Utc>,
    sec_ctx: String,
    full_path: PathBuf,
    link_path: Option<PathBuf>,
    hash_val: Option<String>,
}

impl FindLineCoreTrait for FindLineADB {
    fn get_full_path(&self) -> &Path {
        &self.full_path
    }

    fn get_kind(&self) -> FileKind {
        self.kind
    }
}
impl FindLineTrait for FindLineADB {
    fn parse(line: &str) -> Result<Self, AnyHowError> {
        let mut split_iter = line.split(ASCII_US);
        let inode = (split_iter.next().expect("missing inode number")).parse::<u64>()?;
        let size = (split_iter.next().expect("missing size")).parse::<u64>()?;
        let mode_num = u16::from_str_radix(split_iter.next().expect("missing mode octal"), 8)?;
        let mode_text = (split_iter.next().expect("missing mode text")).to_string();
        let uid_num = (split_iter.next().expect("missing user id")).parse::<u64>()?;
        let uid_text = (split_iter.next().expect("missing user name")).to_string();
        let gid_num = (split_iter.next().expect("missing group id")).parse::<u64>()?;
        let gid_text = (split_iter.next().expect("missing group name")).to_string();
        let mod_time_str = split_iter.next().expect("missing modification time");
        let sec_ctx = (split_iter.next().expect("missing security context")).to_string();
        let full_path = PathBuf::from(split_iter.next().expect("missing file path"));
        let link_path = PathBuf::from(split_iter.next().expect("missing link to path"));

        let mut mod_time_split_iter = mod_time_str.split('.');
        let mod_time_seconds = mod_time_split_iter
            .next()
            .expect("missing seconds part in modification time")
            .parse::<i64>()?;
        let mod_time_nanoseconds = match mod_time_split_iter.next() {
            Some(ns_chunk) => ns_chunk.parse::<u32>()?,
            None => 0,
        };
        let mod_time = DateTime::from_timestamp(mod_time_seconds, mod_time_nanoseconds).unwrap();

        let hash_raw_str = match split_iter.next() {
            Some(v) => Some(v.split(" ").next().unwrap().to_string()),
            None => None,
        };

        let kind = match mode_text.chars().next().unwrap() {
            'd' => FileKind::DIRECTORY,
            '-' => FileKind::FILE,
            'l' => FileKind::LINK,
            _ => unreachable!(),
        };
        let link_path = if link_path.to_str().unwrap().len() != 0 || kind == FileKind::LINK {
            Some(link_path)
        } else {
            None
        };
        Ok(FindLineADB {
            inode,
            size,
            kind,
            mode_num,
            mode_text,
            uid_num,
            uid_text,
            gid_num,
            gid_text,
            mod_time,
            sec_ctx,
            full_path,
            link_path: link_path,
            hash_val: hash_raw_str,
        })
    }

    fn find_printf(extra_cmd: bool) -> String {
        let mut printf = String::from("");
        printf.push_str(FIND_INODE);
        printf.push(ASCII_US);
        printf.push_str(FIND_SIZE);
        printf.push(ASCII_US);
        printf.push_str(FIND_MODE_OCTAL);
        printf.push(ASCII_US);
        printf.push_str(FIND_MODE_TEXT);
        printf.push(ASCII_US);
        printf.push_str(FIND_UID_NUM);
        printf.push(ASCII_US);
        printf.push_str(FIND_UID_TEXT);
        printf.push(ASCII_US);
        printf.push_str(FIND_GID_NUM);
        printf.push(ASCII_US);
        printf.push_str(FIND_GID_TEXT);
        printf.push(ASCII_US);
        printf.push_str(FIND_MOD_TIME);
        printf.push(ASCII_US);
        printf.push_str(FIND_SEC_CTX);
        printf.push(ASCII_US);
        printf.push_str(FIND_PATH);
        printf.push(ASCII_US);
        printf.push_str(FIND_LINK_TO);
        if extra_cmd {
            printf.push(ASCII_US);
        } else {
            printf.push_str(FIND_ASCII_NEW_LINE);
        }
        return printf;
    }
}

pub fn filter_excludes(base_path: &Path, excludes: &HashSet<PathBuf>) -> HashSet<PathBuf> {
    let mut new_excludes: HashSet<PathBuf> = HashSet::new();
    for exclude_path in excludes {
        if exclude_path.starts_with(base_path) {
            new_excludes.insert(exclude_path.clone());
        }
    }
    return new_excludes;
}
