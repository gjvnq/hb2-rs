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
    `backup_uuid` TEXT NOT NULL REFERENCES `backups`(`uuid`),
    `parent_uuid` TEXT  REFERENCES `files`(`uuid`),
    `inode` INTEGER,
    `name` TEXT NOT NULL,
    `mode` INTEGER,
    `size` INTEGER,
    `kind` TEXT NOT NULL, -- 'F', 'L', 'D'
    `uid_num` INTEGER,
    `gid_num` INTEGER,
    `uid_str` TEXT,
    `gid_str` TEXT,
    `mod_time` DATE,
    `sec_ctx` TEXT,
    `lsattr` TEXT,
    `full_path` TEXT NOT NULL,
    `link_path` TEXT, -- only used for links
    `scanned_hash` BLOB, -- null on directories and links
    `acquired_hash` BLOB, -- null on directories and links
    CONSTRAINT uq_file UNIQUE (backup_uuid, full_path)
);

COMMIT;