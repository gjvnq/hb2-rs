BEGIN;

CREATE TABLE `blobs` (
    `hash` BLOB PRIMARY KEY,
    `size` INTEGER,
    `added_at` DATE
);

CREATE TABLE `backups` (
    `id` INTEGER PRIMARY KEY,
    `name` TEXT NOT NULL,
    `desc` TEXT NOT NULL,
    `source_dir` TEXT,
    `total_size` INTEGER NOT NULL,
    `started_at` DATE NOT NULL,
    `finished_at` DATE
);

CREATE TABLE `files` (
    `id` INTEGER PRIMARY KEY,
    `backup_id` INTEGER NOT NULL,
    `kind` TEXT NOT NULL, -- 'F', 'L', 'D'
    `hash` BLOB, -- null on directories and links
    `name` TEXT NOT NULL,
    `target` TEXT, -- only for links
    `modified_at` DATE NOT NULL,
    `uid` INTEGER,
    `gid` INTEGER,
    `mode` INTEGER, -- file mode
    `lsattr` TEXT
);

COMMIT;