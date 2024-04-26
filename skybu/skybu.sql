--- Delete remants
DROP INDEX IF EXISTS file_id_idx;
DROP INDEX IF EXISTS created_idx;
DROP INDEX IF EXISTS owners_idx;
DROP INDEX IF EXISTS groups_idx;
DROP INDEX IF EXISTS file_id_idx;
DROP INDEX IF EXISTS files_latest_idx;
DROP INDEX IF EXISTS files_owner_idx;
DROP INDEX IF EXISTS foldername_idx;
DROP INDEX IF EXISTS folders_hash_idx;
DROP INDEX IF EXISTS date_tag_idx;
DROP TABLE IF EXISTS copy_logs;
DROP TABLE IF EXISTS file_group;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS drives;
DROP TABLE IF EXISTS prohibits;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS owners;
DROP TABLE IF EXISTS backup_history;
DROP TABLE IF EXISTS files_to_copy;

--- history of backup execution
CREATE TABLE backup_history (
	id integer primary key autoincrement,
	date_tag date not null,
	start_at datetime not null default current_timestamp,
	end_at datetime default null
);

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

--- Drive tables ---
CREATE TABLE drives (
	id integer primary key autoincrement,
	guid varchar(256) not null,
	letter varchar(1) not null
);

--- Folder to Hash table
CREATE TABLE folders (
	id integer primary key autoincrement,
	drive_id integer not null,
	folder_path varchar(2048) default "",
	parent_id integer, 
	owner_id integer
);
CREATE INDEX folders_hash_idx on folders(drive_id, folder_path);

--- File to Hash table
CREATE TABLE files (
	id integer primary key autoincrement,
	folder_id integer not null,
	filename varchar(1024),
	hash_name varchar(64),
	latest_copy_log_id integer
);
CREATE UNIQUE INDEX files_latest_idx on files(folder_id, hash_name);

--- Copy File Log table
CREATE TABLE copy_logs (
	id integer primary key autoincrement,
	file_id integer not null,
	owner_id integer,
	mtime datetime not null,
	flg_symbolic integer(1) default 0,
	flg_directory integer(1) default 0,
	flg_remove integer(1) default 0,
	flg_archive integer(1) default 0,
	flg_hidden integer(1) default 0,
	date_tag date not null,
	created_at datetime not null default current_timestamp
);
CREATE INDEX file_id_idx on copy_logs(file_id);
CREATE INDEX created_idx on copy_logs(mtime);
CREATE INDEX date_tag_idx on copy_logs(date_tag);

--- File for group
CREATE TABLE file_group (
	copy_id integer not null,
	file_group_id integer not null
);

--- list of files to copy
CREATE TABLE files_to_copy (
	id integer primary key autoincrement,
	date_tag date not null,
	folder_id integer not null,
	file_id integer not null,
	flg_symbolic integer(1) default 0,
	flg_directory integer(1) default 0,
	flg_archive integer(1) default 0,
	flg_hidden integer(1) default 0,
	hash_name varchar(64) not null,
	created_at datetime not null default current_timestamp
);
