--- path informations
CREATE TABLE pathinfos (
	id integer primary key autoincrement,
	file_path varchar(2048) not null unique,
	sha256 varchar(128) not null,
	flg_white integer not null default 1,
);
CREATE INDEX pathinfos_file ON pathinfos(file_path);

--- exe/dll relations
CREATE TABLE relations (
	created_at datetime not null,
	parent_id integer not null,
	child_id integer not null
);
CREATE INDEX relations_slice_at ON relations(created_at);
