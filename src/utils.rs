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
