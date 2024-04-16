--- Delete remants DROP INDEX IF EXISTS file_id_idx on copy_logs(file_id);
DROP INDEX IF EXISTS created_idx;
DROP INDEX IF EXISTS owners_idx;
DROP INDEX IF EXISTS groups_idx;
DROP INDEX IF EXISTS file_id_idx;
DROP INDEX IF EXISTS files_latest_idx;
DROP INDEX IF EXISTS files_owner_idx;
DROP INDEX IF EXISTS foldername_idx;
DROP INDEX IF EXISTS folders_hash_idx;
DROP INDEX IF EXISTS drives_guid_idx;
DROP TABLE IF EXISTS copy_logs;
DROP TABLE IF EXISTS file_group;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS prohibits;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS owners;

--- File owner
CREATE TABLE owners (
	id integer primary key autoincrement,
	sid varchar(255) not null,
	name varchar(255)
);
CREATE INDEX owners_idx on owners(sid);

--- File group
CREATE TABLE groups (
	id integer primary key autoincrement,
	sid integer not null,
	name varchar(255)
);
CREATE INDEX groups_idx on groups(sid);

--- Prohibit folders
CREATE TABLE prohibits (
	id integer primary key autoincrement,
	foldername varchar(1024) not null
);
CREATE INDEX foldername_idx on prohibits(foldername);
INSERT INTO prohibits (foldername) VALUES ('Program Files'), ('Program Files (x86)'), ('Windows'), ('Users');

--- Folder to Hash table
CREATE TABLE folders (
	id integer primary key autoincrement,
	guid varchar(256) not null,
	folder_path varchar(2048) default "",
	owner_id integer
);
CREATE INDEX folders_hash_idx on folders(guid, folder_path);

--- File to Hash table
CREATE TABLE files (
	id integer primary key autoincrement,
	folder_id integer not null,
	filename varchar(1024) not null,
	hash_name varchar(64) unique not null,
	latest_copy_log_id integer
);
CREATE INDEX files_latest_idx on files(folder_id, hash_name);

--- Copy File Log table
CREATE TABLE copy_logs (
	id integer primary key autoincrement,
	file_id integer not null,
	owner_id integer,
	hash varchar(64) not null,
	mtime datetime not null,
	flg_symbolic integer(1) default 0,
	flg_folder integer(1) default 0,
	flg_remove integer(1) default 0,
	flg_archive integer(1) default 0,
	flg_hidden integer(1) default 0,
	created_at datetime not null default current_timestamp
);
CREATE INDEX file_id_idx on copy_logs(file_id);
CREATE INDEX created_idx on copy_logs(mtime);

--- File for group
CREATE TABLE file_group (
	copy_id integer not null,
	file_group_id integer not null
);

