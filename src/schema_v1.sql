BEGIN;

CREATE TABLE `blobs` (
    `hash` BLOB PRIMARY KEY,
    `size` INTEGER,
    `added_at` DATE
);

CREATE TABLE `backups` (
    `uuid` TEXT PRIMARY KEY,
    `name` TEXT,
    `description` TEXT,
    `source_dir` TEXT,
    `total_size` INTEGER,
    `started_at` DATE NOT NULL,
    `finished_at` DATE
);

CREATE TABLE `files` (
    `uuid` TEXT PRIMARY KEY,
    `backup_uuid` TEXT NOT NULL,
    `parent_uuid` TEXT,
    `inode` INTEGER,
    `name` TEXT,
    `mode` INTEGER,
    `size` INTEGER,
    `kind` TEXT NOT NULL, -- 'F', 'L', 'D'
    `uid_num` INTEGER,
    `gid_num` INTEGER,
    `uid_str` TEXT,
    `gid_str` TEXT,
    `mod_time` DATE NOT NULL,
    `sec_ctx` TEXT,
    `lsattr` TEXT,
    `full_path` TEXT,
    `link_path` TEXT, -- only used for links
    `scanned_hash` BLOB, -- null on directories and links
    `acquired_hash` BLOB -- null on directories and links
);

COMMIT;