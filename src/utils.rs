use url::Url;
use regex::Regex;
use std::path::PathBuf;
use crate::AnyHowError;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FileKind {
    FILE,
    DIRECTORY,
    LINK
}

impl FileKind {
    pub fn to_char(&self) -> char {
        match self {
            FileKind::DIRECTORY => 'd',
            FileKind::FILE => 'f',
            FileKind::LINK => 'l',
        }
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