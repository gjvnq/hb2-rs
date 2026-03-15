use crate::database::FileRecord;
use crate::utils::FileKind;
use anyhow::Error as AnyHowError;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

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

fn extract_basename(full_path: &Path) -> String {
    full_path
        .file_name()
        .map_or(full_path.to_str(), |p| p.to_str())
        .unwrap()
        .to_string()
}

pub trait FindLineCoreTrait: Debug + Sized + Send + Clone + Sync {
    fn get_full_path(&self) -> &Path;
    fn get_kind(&self) -> FileKind;
    fn to_file_record(&self) -> FileRecord;
}

pub trait FindLineTrait: FindLineCoreTrait {
    fn parse(line: &str, hash_alg_prefix: &str) -> Result<Self, AnyHowError>;
    fn find_printf(extra_cmd: bool) -> String;
}

#[derive(Debug, Clone)]
pub struct FindLineMinimal {
    inode: i64,
    size: i64,
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

    fn to_file_record(&self) -> FileRecord {
        FileRecord {
            uuid: None,
            backup_uuid: None,
            parent_uuid: None,
            inode: Some(self.inode),
            name: extract_basename(&self.full_path),
            size: self.size,
            kind: self.kind,
            mode_num: None,
            mode_text: None,
            uid_num: None,
            uid_text: None,
            gid_num: None,
            gid_text: None,
            mod_time: None,
            sec_ctx: None,
            lsattr: None,
            full_path: self.full_path.clone(),
            link_path: None,
            scanned_hash: None,
            acquired_hash: None,
        }
    }
}

impl FindLineTrait for FindLineMinimal {
    fn parse(line: &str, _hash_alg_prefix: &str) -> Result<Self, AnyHowError> {
        let mut split_iter = line.split(ASCII_US);
        let inode = (split_iter.next().expect("missing inode number")).parse::<i64>()?;
        let size = (split_iter.next().expect("missing size")).parse::<i64>()?;
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
    inode: i64,
    size: i64,
    kind: FileKind,
    mode_num: u16,
    mode_text: String,
    uid_num: i64,
    uid_text: String,
    gid_num: i64,
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

    fn to_file_record(&self) -> FileRecord {
        FileRecord {
            uuid: None,
            backup_uuid: None,
            parent_uuid: None,
            inode: Some(self.inode),
            name: extract_basename(&self.full_path),
            size: self.size,
            kind: self.kind,
            mode_num: Some(self.mode_num),
            mode_text: Some(self.mode_text.clone()),
            uid_num: Some(self.uid_num),
            uid_text: Some(self.uid_text.clone()),
            gid_num: Some(self.gid_num),
            gid_text: Some(self.gid_text.clone()),
            mod_time: Some(self.mod_time),
            sec_ctx: Some(self.sec_ctx.clone()),
            lsattr: None,
            full_path: self.full_path.clone(),
            link_path: self.link_path.clone(),
            scanned_hash: self.hash_val.clone(),
            acquired_hash: None,
        }
    }
}
impl FindLineTrait for FindLineADB {
    fn parse(line: &str, hash_alg_prefix: &str) -> Result<Self, AnyHowError> {
        let mut split_iter = line.split(ASCII_US);
        let inode = (split_iter.next().expect("missing inode number")).parse::<i64>()?;
        let size = (split_iter.next().expect("missing size")).parse::<i64>()?;
        let mode_num = u16::from_str_radix(split_iter.next().expect("missing mode octal"), 8)?;
        let mode_text = (split_iter.next().expect("missing mode text")).to_string();
        let uid_num = (split_iter.next().expect("missing user id")).parse::<i64>()?;
        let uid_text = (split_iter.next().expect("missing user name")).to_string();
        let gid_num = (split_iter.next().expect("missing group id")).parse::<i64>()?;
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
        let hash_val = hash_raw_str.map(|val| format!("{}{}", hash_alg_prefix, val));

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
            hash_val: hash_val,
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
