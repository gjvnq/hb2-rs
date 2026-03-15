use crate::{AnyHowError, AnyHowResult};
use anyhow::bail;
use core::hash;
use openssl::x509::store::File;
use regex::Regex;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use url::Url;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FileKind {
    FILE,
    DIRECTORY,
    LINK,
}

impl FileKind {
    pub fn to_char(&self) -> char {
        match self {
            FileKind::DIRECTORY => 'D',
            FileKind::FILE => 'F',
            FileKind::LINK => 'L',
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            FileKind::DIRECTORY => "D",
            FileKind::FILE => "F",
            FileKind::LINK => "L",
        }
    }
}

impl Serialize for FileKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_str())
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum HashAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl HashAlg {
    pub fn from(val: &str) -> Option<Self> {
        match val {
            "MD5" => Some(HashAlg::MD5),
            "SHA1" => Some(HashAlg::SHA1),
            "SHA224" => Some(HashAlg::SHA224),
            "SHA384" => Some(HashAlg::SHA384),
            "SHA256" => Some(HashAlg::SHA256),
            "SHA512" => Some(HashAlg::SHA512),
            _ => None,
        }
    }
    pub fn shell_command(&self) -> &'static str {
        match self {
            HashAlg::MD5 => "md5sum",
            HashAlg::SHA1 => "sha1sum",
            HashAlg::SHA224 => "sha224sum",
            HashAlg::SHA256 => "sha256sum",
            HashAlg::SHA384 => "sha384sum",
            HashAlg::SHA512 => "sha512sum",
        }
    }
    pub fn prefix(&self) -> &'static str {
        match self {
            HashAlg::MD5 => "md5:",
            HashAlg::SHA1 => "sha1:",
            HashAlg::SHA224 => "sha224:",
            HashAlg::SHA256 => "sha256:",
            HashAlg::SHA384 => "sha384:",
            HashAlg::SHA512 => "sha512:",
        }
    }
    pub async fn hash_file(&self, file_path: &Path) -> AnyHowResult<String> {
        let output = Command::new(self.shell_command())
            .args([file_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            error!(
                "failed to hash file ({:?}): {:?}",
                file_path,
                String::from_utf8_lossy(&output.stderr).to_string()
            );
            bail!("failed to hash file");
        }
        let hash_val =
            String::from_utf8(output.stdout.split(|&b| b == b' ').next().unwrap().to_vec())?;
        Ok(format!("{}{}", self.prefix(), hash_val))
    }
}

pub fn blob_path_maker(storage_path: &Path, hash_val: &str, full_path: bool) -> PathBuf {
    let mut parts = hash_val.split(":");
    let alg = PathBuf::from(parts.next().unwrap().to_ascii_uppercase());
    let hash_part = parts.next().unwrap();
    let first_two_bytes = hash_part.chars().take(2).collect::<String>();
    let first_two_bytes = PathBuf::from(first_two_bytes);
    let output = storage_path.join(alg).join(first_two_bytes);
    if full_path {
        output.join(Path::new(hash_part))
    } else {
        output
    }
}

pub fn blob_parent_path(storage_path: &Path, hash_val: &str) -> PathBuf {
    blob_path_maker(storage_path, hash_val, false)
}

pub fn blob_full_path(storage_path: &Path, hash_val: &str) -> PathBuf {
    blob_path_maker(storage_path, hash_val, true)
}

#[derive(Debug)]
pub enum UrlLike {
    File(PathBuf),
    ADB(PathBuf),
    HTTP(Url),
    FTP(Url),
    SSH(Url),
}

impl UrlLike {
    pub fn parse(raw_url: &str) -> Result<UrlLike, AnyHowError> {
        let pattern = r"^([\w+]+):\/\/(.+)";
        let re = Regex::new(pattern).expect("Invalid regex pattern");
        if let Some(caps) = re.captures(raw_url) {
            let scheme = &caps[1];
            let main_part = &caps[2];
            if scheme == "adb" || scheme == "adbfs" || scheme == "android" {
                return Ok(UrlLike::ADB(PathBuf::from(main_part)));
            } else if scheme == "http" || scheme == "https" {
                return Ok(UrlLike::HTTP(Url::parse(raw_url)?));
            } else if scheme == "ftp" || scheme == "ftps" {
                return Ok(UrlLike::HTTP(Url::parse(raw_url)?));
            } else if scheme == "ssh" || scheme == "sshfs" {
                return Ok(UrlLike::SSH(Url::parse(raw_url)?));
            } else if scheme == "" || scheme == "file" {
                return Ok(UrlLike::File(PathBuf::from(main_part)));
            } else {
                unreachable!("unexpected URL scheme");
            }
        } else {
            return Ok(UrlLike::File(PathBuf::from(raw_url)));
        }
    }
}
