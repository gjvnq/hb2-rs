use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use core::hash;
use std::process::Stdio;
use chrono::{DateTime, Utc};
//use std::error::Error;
use std::fmt::Debug;
use tokio::sync::mpsc;
use anyhow::Error as AnyHowError;

#[tokio::main]
async fn main() -> Result<(), AnyHowError> {
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

#[derive(Debug, PartialEq, Clone, Copy)]
enum FileKind {
    FILE,
    DIRECTORY,
    LINK
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum HashAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl HashAlg {
    fn shell_command(&self) -> &'static str {
        match self {
            HashAlg::MD5 => "md5sum",
            HashAlg::SHA1 => "sha1sum",
            HashAlg::SHA224 => "sha224sum",
            HashAlg::SHA256 => "sha256sum",
            HashAlg::SHA384 => "sha384sum",
            HashAlg::SHA512 => "sha512sum",
        }
    }
}

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

trait AdbLine: Debug + Sized {
    fn parse(line: &str) -> Result<Self, AnyHowError>;
    fn find_printf(extra_cmd: bool) -> String;
}

#[derive(Debug, Clone)]
struct AdbQuickLine {
    inode: u64,
    size: u64,
    kind: FileKind,
}

impl AdbLine for AdbQuickLine {
    fn parse(line: &str) -> Result<Self, AnyHowError> {
        let mut split_iter = line.split(ASCII_US);
        let inode = (split_iter.next().expect("missing inode number")).parse::<u64>()?;
        let size = (split_iter.next().expect("missing size")).parse::<u64>()?;
        let mode_text = (split_iter.next().expect("missing mode text")).to_string();

        let kind = match mode_text.chars().next().unwrap() {
            'd' => FileKind::DIRECTORY,
            '-' => FileKind::FILE,
            'l' => FileKind::LINK,
            _ => unreachable!()
        };
        Ok(AdbQuickLine { inode, size, kind })
    }

    fn find_printf(extra_cmd: bool) -> String {
        let mut printf = String::from("");
        printf.push_str(FIND_INODE);
        printf.push(ASCII_US);
        printf.push_str(FIND_SIZE);
        printf.push(ASCII_US);
        printf.push_str(FIND_MODE_TEXT);
        if extra_cmd {
            printf.push(ASCII_US);
        } else {
            printf.push_str(FIND_ASCII_NEW_LINE);
        }
        return printf;
    }
}

#[derive(Debug, Clone)]
struct AdbFullLine {
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
    full_path: String,
    link_path: Option<String>,
    hash_val: Option<String>,
}

impl AdbLine for AdbFullLine {
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
        let full_path = (split_iter.next().expect("missing file path")).to_string();
        let link_path = (split_iter.next().expect("missing link to path")).to_string();

        let mut mod_time_split_iter = mod_time_str.split('.');
        let mod_time_seconds = mod_time_split_iter.next().expect("missing seconds part in modification time").parse::<i64>()?;
        let mod_time_nanoseconds = match mod_time_split_iter.next() {
            Some(ns_chunk) => ns_chunk.parse::<u32>()?,
            None => 0
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
            _ => unreachable!()
        };
        let link_path = if link_path.len() != 0 || kind == FileKind::LINK {
            Some(link_path)
        } else {
            None
        };
        Ok(AdbFullLine { inode, size, kind, mode_num, mode_text, uid_num, uid_text, gid_num, gid_text, mod_time, sec_ctx, full_path, link_path: link_path, hash_val: hash_raw_str })
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

async fn adb_quick_scanner(base_path: &str, tx: mpsc::Sender<AdbQuickLine>) -> Result<(), AnyHowError> {
    adb_scanner::<AdbQuickLine>(base_path, tx, None, None).await
}

async fn adb_full_scanner(base_path: &str, tx: mpsc::Sender<AdbFullLine>, hash_alg: Option<HashAlg>) -> Result<(), AnyHowError> {
    adb_scanner::<AdbFullLine>(base_path, tx, hash_alg, None).await
}

async fn adb_scanner<AdbLineT: AdbLine>(base_path: &str, tx: mpsc::Sender<AdbLineT>, hash_alg: Option<HashAlg>, max_depth: Option<i32>) -> Result<(), AnyHowError> {
    let find_printf = AdbLineT::find_printf(hash_alg.is_some());
    let mut max_depth_str: String;

    let mut cmd_parts = Vec::from(["shell", "find", "-H", base_path]);

    if let Some(max_depth) = max_depth {
        cmd_parts.push("-maxdepth");
        max_depth_str = format!("{}", max_depth);
        cmd_parts.push(&max_depth_str);
    }

    cmd_parts.push("-printf");
    cmd_parts.push(&find_printf);

    if let Some(hash_alg) = hash_alg {
        cmd_parts.push("-exec");
        cmd_parts.push(hash_alg.shell_command());
        cmd_parts.push("{}");
        cmd_parts.push("\\;");
    }

    let mut child = Command::new("adb")
        .args(cmd_parts)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let adb_line = AdbLineT::parse(&line);
        if let Ok(adb_line) = adb_line {
            tx.send(adb_line).await;
        } else {
            println!("{}", line);
            println!("adb_line error: {:?}", adb_line.unwrap_err())
        }
    }
    Ok(())
}
