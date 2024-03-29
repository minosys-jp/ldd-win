#include "pch.h"
#include "common.h"
#include <iostream>
#include <fstream>

using namespace std;

BCRYPT_ALG_HANDLE hAlg;
wstring hostname;
wstring szRoot;
wstring szSource;
wstring dateTag;
char* sqlite3_temp_directory;

// ディレクトリをベクタに分解する
vector<wstring> splitString(const wstring& ss, wchar_t delim) {
	wstringstream wss(ss);
	wstring item;
	vector<wstring> vec;
	while (getline(wss, item, delim)) {
		if (!item.empty()) {
			vec.push_back(item);
		}
	}
	return vec;
}

wstring joinString(const vector<wstring>& svec, wchar_t delim) {
	wostringstream ss;
	for (const wstring s : svec) {
		ss.put(delim);
		ss.write(s.data(), s.length());
	}
	ss.flush();
	return ss.str();
}

BOOL FindRoot(vector<wstring>& v, const wstring &arg) {
	WIN32_FIND_DATA ffd;
	TCHAR szDir[MAX_PATH];
	size_t lengthOfArg;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	StringCchLength(arg.c_str(), MAX_PATH, &lengthOfArg);
	if (lengthOfArg <= (MAX_PATH - 3)) {
		StringCchCopy(szDir, MAX_PATH, arg.c_str());
		StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
		hFind = FindFirstFile(szDir, &ffd);
		do {
			if (hFind != INVALID_HANDLE_VALUE) {
				if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					if (_tcscmp(ffd.cFileName, TEXT(".")) != 0
						&& _tcscmp(ffd.cFileName, TEXT("..")) != 0) {
						v.push_back(ffd.cFileName);
					}
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);
		if (hFind != INVALID_HANDLE_VALUE && GetLastError() == ERROR_NO_MORE_FILES) {
			FindClose(hFind);
		}
	}
	return !v.empty();
}

// ホスト名を取得する
wstring  whoAmI() {
	LPTSTR str = new TCHAR[MAX_COMPUTERNAME_LENGTH];
	DWORD csize = MAX_COMPUTERNAME_LENGTH;
	if (GetComputerNameEx(ComputerNameDnsHostname, str, &csize)) {
		wstring ws = wstring(str, csize);
		delete[] str;
		return ws;
	}
	delete[] str;
	return TEXT("<unknown>");
}

// ドライブ文字を GUID に変換する
wstring driveToGuid(TCHAR driveLetter) {
	TCHAR drive[] = TEXT("c:\\");
	drive[0] = driveLetter;
	LPTSTR guid = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
	if (guid && GetVolumeNameForVolumeMountPoint(drive, guid, MAX_PATH)) {
		wstring wguid = wstring(guid);
		(void)HeapFree(GetProcessHeap(), 0, guid);
		return wguid;
	}
	(void)HeapFree(GetProcessHeap(), 0, guid);
	return wstring(L"");
}

// ファイル名からドライブ名を取り出す
wstring GetDriveNameFromPath(const wstring &pathName) {
	int drvNum = PathGetDriveNumber(pathName.c_str());
	if (drvNum == -1) {
		return TEXT("");
	}
	wchar_t buff[4];
	(void)PathBuildRoot(buff, drvNum);
	return wstring() + buff[0];
}

//ファイル名からディレクトリ名を取り出す
wstring GetDirNameFromPath(const wstring& pathName, int64_t parent) {
	vector<wstring> vNames(splitString(pathName, L'\\'));

	// source, hostname, drive-name をスキップする
	if (vNames.size() >= 3) {
		vNames.erase(vNames.begin(), vNames.begin() + 3);
	}
	// parent ではない場合は最後はファイル名なのでスキップする
	if (!vNames.empty() && parent != -1LL) {
		vNames.pop_back();
	}
	// joinString の先頭のバックスラッシュを取り除く
	wstring rws = joinString(vNames, L'\\');
	return rws.empty() ? rws : rws.substr(1);
}

wstring GetPathWithoutHostname(const wstring& pathName) {
	vector<wstring> svec = splitString(pathName, L'\\');
	vector<wstring>::iterator it = svec.begin();
	if (svec.size() > 0 && svec[0].empty()) {
		svec.erase(it, it + 1);
		it = svec.begin();
	}
	if (svec.size() > 0) {
		svec.erase(it, it + 1);
	}
	return joinString(svec, L'\\');
}

// ファイル名からファイル部分を取り出す
LPCTSTR GetFileNameFromPath(const wstring &path) {
	return PathFindFileName(path.c_str());
}

// UTF16からUTF8への変換
string utf16_to_utf8(const std::wstring& s) {
	int cb = WideCharToMultiByte(CP_UTF8, 0, s.data(), s.length(), nullptr, 0, nullptr, nullptr);
	char* pTmp = (char*)HeapAlloc(GetProcessHeap(), 0, cb);
	if (pTmp) {
		WideCharToMultiByte(CP_UTF8, 0, s.data(), s.length(), pTmp, cb, nullptr, nullptr);
		std::string sret(pTmp, cb);
		HeapFree(GetProcessHeap(), 0, pTmp);
		return sret;
	}
	else {
		return std::string();
	}
}

// ストリームのSHA256を取る
wstring hashStream(istream& is) {
	DWORD cbHash, cbHashObject, cbData;
	wstringstream ws;

	if (!BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) {
		PBYTE pHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
		if (!BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)) {
			PBYTE pHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
			BCRYPT_HASH_HANDLE hHash = NULL;
			if (!BCryptCreateHash(hAlg, &hHash, pHashObject, cbHashObject, NULL, 0, 0)) {
				char* szBuff = (char*)HeapAlloc(GetProcessHeap(), 0, 1024);
				int count = 0;
				int cc = 0;
				assert(szBuff);
				while (true) {
					int cc = is.get();
					if (cc == EOF) {
						break;
					}
					if (count < 1024) {
						*(szBuff + count++) = (char)cc;
						continue;
					}
					(void)BCryptHashData(hHash, (PBYTE)szBuff, 1024, 0);
					count = 0;
				}
				if (count > 0) {
					(void)BCryptHashData(hHash, (PBYTE)szBuff, count, 0);
				}
				(void)BCryptFinishHash(hHash, pHash, cbHash, 0);
				for (uint64_t i = 0; i < cbHash; i++) {
					ws << std::hex << pHash[i];
				}
				HeapFree(GetProcessHeap(), 0, szBuff);
				BCryptDestroyHash(hHash);
			}
			HeapFree(GetProcessHeap(), 0, pHash);
		}
		HeapFree(GetProcessHeap(), 0, pHashObject);
	}
	return ws.str();
}

/*
// ファイル名のSHA256を取る
wstring hashDirName(const wstring &guid, const wstring &dirName, bool flg_root) {
	wstring dir = GetDirNameFromPath(dirName, flg_root);
	wstring s = guid + TEXT("\\") + dir;
	stringstream ss = stringstream(utf16_to_utf8(s));
	return hashStream(ss);
}
*/

wstring hashFileName(const MyFile& file, bool flg_root) {
	wstring s = file.drive.guid + TEXT("\\") + file.path;
	stringstream ss = stringstream(utf16_to_utf8(s));
	return hashStream(ss);
}

// ファイルのSHA256を取る
wstring hashFile(const wstring &pathName) {
	ifstream ifs(pathName, std::ios::binary);
	return hashStream(ifs);
}

// DB schema を定義する
BOOL CreateSql3Database(LPCTSTR lpctFile) {
	if (!PathFileExists(lpctFile)) {
		sqlite3* sql3Handle = NULL;
		if (sqlite3_open16(lpctFile, &sql3Handle) != SQLITE_OK) {
			wcout << TEXT("Failed to open ") << DATABASE_SCHEMA << TEXT(".") << endl;
			return FALSE;
		}
		ifstream ifs;
		ifs.open(DATABASE_SCHEMA);
		if (ifs.fail()) {
			wcout << TEXT("Failed to open schema file.") << endl;
			return FALSE;
		}
		stringstream ss;
		ss << ifs.rdbuf();
		ifs.close();
		if (sqlite3_exec(sql3Handle, ss.str().c_str(), NULL, NULL, NULL) != SQLITE_OK) {
			wcout << TEXT("Failed to create database schema.") << endl;
			return FALSE;
		}
		sqlite3_close(sql3Handle);
	}
	return TRUE;
}

// drive 情報を更新する
void MyDrive::UpdateDrives(sqlite3* sql, const wstring& arg, const wstring &drv) {
	this->name = drv;
	this->name[0] = this->name[0] & ~0x0020;
	this->guid = hostname + L"\\" + name;
	/*
	// arg からドライブ番号を取得する
	this->name = GetDriveNameFromPath(arg);
	if (this->name.empty()) {
		return;
	}
	this->guid = driveToGuid(this->name.at(0));
	*/

	sqlite3_stmt* stmt;
	if (sqlite3_prepare16_v3(sql,
		L"SELECT id FROM drives WHERE guid=?",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return;
	}
	sqlite3_bind_text16(stmt, 1, guid.data(), guid.length() * sizeof(TCHAR), NULL);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		// drive は登録済み
		this->id = sqlite3_column_int64(stmt, 0);
		sqlite3_finalize(stmt);
		sqlite3_prepare16_v3(sql, L"UPDATE drives SET letter=? WHERE id=?", -1, 0, &stmt, NULL);
		sqlite3_bind_text16(stmt, 1, this->name.data(), sizeof(TCHAR), NULL);
		sqlite3_bind_int64(stmt, 2, id);
		sqlite3_step(stmt);
	}
	else {
		// drive は新規登録
		sqlite3_finalize(stmt);
		sqlite3_prepare16_v3(sql, L"INSERT INTO drives (guid, letter) VALUES (?, ?)", -1, 0, &stmt, NULL);
		sqlite3_bind_text16(stmt, 1, guid.data(), guid.length() * sizeof(TCHAR), NULL);
		sqlite3_bind_text16(stmt, 2, this->name.data(), sizeof(TCHAR), NULL);
		sqlite3_step(stmt);
		this->id = sqlite3_last_insert_rowid(sql);
	}
	sqlite3_finalize(stmt);
}

void MyFile::setFname(const MyFile &parent, const wstring &filename) {
	if (filename.empty()) {
		this->path = TEXT("");
		this->fname = filename;
	} else {
		LPTSTR lpLongData = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_LONG_PATH + 1) * sizeof(TCHAR));
		wstring szMerged = parent.getPath() + TEXT("\\") + filename;
		GetLongPathName(szMerged.c_str(), lpLongData, MAX_LONG_PATH + 1);
		vector<wstring> vPath = splitString(lpLongData, L':');
		vPath = splitString(vPath.at(1), L'\\');
		if (vPath.at(0).empty()) {
			vPath.erase(vPath.begin(), vPath.begin() + 1);
		}
		vPath.erase(vPath.begin(), vPath.begin() + 2);
		this->path = joinString(vPath, L'\\');
		this->fname = PathFindFileName(lpLongData);
		HeapFree(GetProcessHeap(), 0, lpLongData);
	}
}

void MyFile::setFlags(DWORD dwFlags) {
	if (dwFlags & FILE_ATTRIBUTE_ARCHIVE) {
		this->attr.flg_archive = true;
	}
	if (dwFlags & FILE_ATTRIBUTE_DIRECTORY) {
		this->attr.flg_directory = true;
	}
	if (dwFlags & FILE_ATTRIBUTE_HIDDEN) {
		this->attr.flg_hidden = true;
	}
	if (dwFlags & FILE_ATTRIBUTE_REPARSE_POINT) {
		this->attr.flg_symbolic = true;
	}

	DWORD dwFflag = (dwFlags & FILE_ATTRIBUTE_DIRECTORY) ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
	HANDLE hFile = CreateFile(this->getPath().c_str(), 0, 0, NULL, OPEN_EXISTING, dwFflag, NULL);
	FILETIME mtime;
	SYSTEMTIME msystem;
	BOOL r1 = GetFileTime(hFile, NULL, NULL, &mtime);
	BOOL r2 = FileTimeToSystemTime(&mtime, &msystem);
	TCHAR szDateTime[21];
	// UTC Time
	StringCbPrintf(szDateTime, sizeof(szDateTime), L"%04d-%02d-%02d %02d:%02d:%02d",
		msystem.wYear, msystem.wMonth, msystem.wDay,
		msystem.wHour, msystem.wMinute, msystem.wSecond);
	this->attr.mtime = szDateTime;
	CloseHandle(hFile);
	if (!(dwFlags & FILE_ATTRIBUTE_DIRECTORY)) {
		this->attr.hash = hashFile(this->path.c_str());
	}
}

// 指定されたファイル情報設定する
void MyFile::setData(const MyFile &parent, const wstring &filename, DWORD dwFlags) {
	setFname(parent, filename);
	setFlags(dwFlags);
}

// 指定されたファイル情報を取得する
void MyFile::setData(const MyFile &parent, const wstring &filename) {
	setFname(parent, filename);
	DWORD dwFlags = GetFileAttributes(this->getPath().c_str());
	setFlags(dwFlags);
}

// 新規または更新されているフォルダを登録
void MyFile::recordDirIfChanged(sqlite3* sql3, const MyFile &root, int64_t parent, const wstring &dateTag) {
	sqlite3_stmt* stmt;
	// folder_id を検索する
	if (sqlite3_prepare16_v3(sql3,
		L"SELECT id FROM folders WHERE drive_id=? AND folder_path=?",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return;
	}
	wstring rpath = root.path.empty() ? TEXT("?root?") : root.path;
	sqlite3_bind_int64(stmt, 1, root.drive.id);
	sqlite3_bind_text16(stmt, 2, rpath.data(), rpath.length() * sizeof(TCHAR), NULL);
	int64_t folder_id = -1;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		// 登録済みのパス
		folder_id = sqlite3_column_int64(stmt, 0);
	}
	else {
		// パスを新規登録する
		sqlite3_finalize(stmt);
		sqlite3_prepare16_v3(sql3,
			L"INSERT INTO folders (drive_id, folder_path, parent_id) VALUES (?, ?, ?)",
			-1, 0, &stmt, NULL);
		sqlite3_bind_int64(stmt, 1, root.drive.id);
		sqlite3_bind_text16(stmt, 2, rpath.data(), rpath.length() * sizeof(TCHAR), NULL);
		if (parent == -1LL) {
			sqlite3_bind_null(stmt, 3);
		}
		else {
			sqlite3_bind_int64(stmt, 3, parent);
		}
		sqlite3_step(stmt);
		folder_id = sqlite3_last_insert_rowid(sql3);
	}
	sqlite3_finalize(stmt);

	// files::id を検索する
	if (sqlite3_prepare16_v3(sql3,
		L"SELECT id FROM files WHERE folder_id=? AND filename IS NULL",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return;
	}
	sqlite3_bind_int64(stmt, 1, folder_id);
	int64_t file_id = -1;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		// ファイル存在
		file_id = sqlite3_column_int64(stmt, 0);
	}
	else {
		// 新規ファイル
		sqlite3_stmt *stmt2;
		sqlite3_prepare16_v3(sql3,
			L"INSERT INTO files (folder_id, filename) VALUES (?, ?)",
			-1, 0, &stmt2, NULL);
		sqlite3_bind_int64(stmt2, 1, folder_id);
		sqlite3_bind_null(stmt2, 2);
		sqlite3_step(stmt2);
		file_id = sqlite3_last_insert_rowid(sql3);
		sqlite3_finalize(stmt2);
	}
	sqlite3_finalize(stmt);

	if (sqlite3_prepare16_v3(sql3,
		L"SELECT l.* FROM copy_logs l \
		INNER JOIN (SELECT file_id, max(id) id FROM copy_logs GROUP BY file_id) lm \
		ON lm.file_id=l.file_id AND l.id=lm.id WHERE l.file_id=?",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return;
	}
	sqlite3_bind_int64(stmt, 1, file_id);
	int64_t cl_id = -1LL;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		// 登録済みフォルダ
		string orgMtime((const char *)sqlite3_column_text(stmt, 4));
		string mtime = utf16_to_utf8(attr.mtime);
		if (orgMtime != mtime) {
			// 何らかの変更があった
			int64_t file_id = sqlite3_column_int64(stmt, 1);
			cl_id = createNewLogDB(sql3, file_id, dateTag);
		}
	}
	else {
		// 新規フォルダ
		cl_id = createNewLogDB(sql3, file_id, dateTag);
	}
	sqlite3_finalize(stmt);
	if (cl_id >= 0LL) {
		if (sqlite3_prepare16_v3(sql3,
			L"UPDATE files SET latest_copy_log_id=? WHERE id=?",
			-1, 0, &stmt, NULL) != SQLITE_OK) {
			return;
		}
		sqlite3_bind_int64(stmt, 1, cl_id);
		sqlite3_bind_int64(stmt, 2, file_id);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
}

// 新規 or 更新ならバックアップ
void MyFile::backupFileIfChanged(sqlite3* sql3, int64_t parent, const wstring& hashPath, const wstring& hashValue, const wstring &dateTag) {
	sqlite3_stmt* stmt;
	if (sqlite3_prepare16_v3(sql3,
		L"SELECT l.*, f.folder_id FROM copy_logs l \
		INNER JOIN files f ON f.id=l.file_id \
		INNER JOIN (SELECT file_id, max(id) as id FROM copy_logs GROUP BY file_id) lm \
		ON lm.file_id=l.file_id WHERE f.hash_name=?",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return;
	}
	sqlite3_bind_text16(stmt, 1, hashPath.data(), hashPath.length() * sizeof(TCHAR), NULL);
	int64_t folder_id = -1;
	int64_t file_id = -1;
	int64_t log_id = -1;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		wstring hashOld = (LPCTSTR)sqlite3_column_text16(stmt, 3);
		if (hashOld != hashValue) {
			// 更新ファイル
			folder_id = sqlite3_column_int64(stmt, 11);
			file_id = sqlite3_column_int64(stmt, 1);
			log_id = createNewLogDB(sql3, file_id, hashValue, dateTag);
		}
	}
	else {
		// 新規ファイル
		folder_id = createNewFolderDB(sql3, parent);
		file_id = createNewFileDB(sql3, folder_id, hashPath, hashValue);
		log_id = createNewLogDB(sql3, file_id, hashValue, dateTag);
	}

	sqlite3_finalize(stmt);
	if (log_id != -1) {
		sqlite3_prepare16_v3(sql3,
			L"UPDATE files SET latest_copy_log_id=? WHERE id=?",
			-1, 0, &stmt, NULL
		);
		sqlite3_bind_int64(stmt, 1, log_id);
		sqlite3_bind_int64(stmt, 2, file_id);
		while (sqlite3_step(stmt) != SQLITE_DONE) {}
		sqlite3_finalize(stmt);
		backup(hashFileName(*this, false));
	}
}

int64_t MyFile::createNewFolderDB(sqlite3* sql3, int64_t parent) {
	wstring szLongPath = GetPathWithoutHostname(GetDirNameFromPath(this->getPath(), parent));
	sqlite3_stmt* stmt;
	szLongPath = szLongPath.empty() ? TEXT("?root?") : szLongPath;
	sqlite3_prepare16_v3(sql3, L"SELECT id FROM folders WHERE drive_id=? AND folder_path=?", -1, 0, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, this->drive.id);
	sqlite3_bind_text16(stmt, 2, szLongPath.data(), szLongPath.length() * sizeof(TCHAR), NULL);
	int64_t id;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		// folder 登録済み
		id = sqlite3_column_int64(stmt, 0);
	}
	else {
		sqlite3_prepare16_v3(sql3,
			L"INSERT INTO folders (drive_id, folder_path, parent_id) VALUES (?, ?, ?)",
			-1, 0, &stmt, NULL);
		sqlite3_bind_int64(stmt, 1, this->drive.id);
		sqlite3_bind_text16(stmt, 2, szLongPath.data(), szLongPath.length() * sizeof(TCHAR), NULL);
		if (parent != -1LL) {
			sqlite3_bind_int64(stmt, 3, parent);
		}
		else {
			sqlite3_bind_null(stmt, 3);
		}
		sqlite3_step(stmt);
		id = sqlite3_last_insert_rowid(sql3);
	}
	sqlite3_finalize(stmt);
	return id;
}

int64_t MyFile::createNewFileDB(sqlite3* sql3, int64_t folder_id, const wstring& hashPath, const wstring& hashValue) {
	LPTSTR lpPath = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_LONG_PATH + 1) * sizeof(TCHAR));
	_tcscpy_s(lpPath, MAX_LONG_PATH, this->getPath().c_str());
	LPTSTR lpLongPath = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_LONG_PATH + 1) * sizeof(TCHAR));
	GetLongPathName(lpPath, lpLongPath, MAX_LONG_PATH);
	LPCTSTR lpOnlyFile = PathFindFileName(lpLongPath);
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3,
		L"INSERT INTO files (folder_id, filename, hash_name) VALUES (?, ?, ?)",
		-1, 0, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, folder_id);
	sqlite3_bind_text16(stmt, 2, lpOnlyFile, _tcslen(lpOnlyFile) * sizeof(TCHAR), NULL);
	sqlite3_bind_text16(stmt, 3, hashPath.data(), hashPath.length() * sizeof(TCHAR), NULL);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	HeapFree(GetProcessHeap(), NULL, lpPath);
	HeapFree(GetProcessHeap(), NULL, lpLongPath);
	return sqlite3_last_insert_rowid(sql3);
}

// directory 登録
int64_t MyFile::createNewLogDB(sqlite3* sql3, int64_t file_id, const wstring &dateTag) {
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3,
		L"INSERT INTO copy_logs (file_id, mtime, flg_symbolic, flg_archive, flg_hidden, flg_directory, date_tag) \
		VALUES (?, ?, ?, ?, ?, ?, ?)",
		-1, 0, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, file_id);
	string mtime = utf16_to_utf8(attr.mtime);
	sqlite3_bind_text(stmt, 2, mtime.data(), mtime.length(), NULL);
	sqlite3_bind_int(stmt, 3, attr.flg_symbolic);
	sqlite3_bind_int(stmt, 4, attr.flg_archive);
	sqlite3_bind_int(stmt, 5, attr.flg_hidden);
	sqlite3_bind_int(stmt, 6, 1 /* attr.flg_directory */);
	string dateTag8 = utf16_to_utf8(dateTag);
	sqlite3_bind_text(stmt, 7, dateTag8.data(), dateTag8.length(), NULL);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return sqlite3_last_insert_rowid(sql3);
}

// file 登録
int64_t MyFile::createNewLogDB(sqlite3* sql3, int64_t file_id, const wstring& hashValue, const wstring &dateTag) {
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3,
		L"INSERT INTO copy_logs (file_id, hash_value, mtime, flg_symbolic, flg_archive, flg_hidden, date_tag) \
		VALUES (?, ?, ?, ?, ?, ?, ?)",
		-1, 0, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, file_id);
	sqlite3_bind_text16(stmt, 2, hashValue.data(), hashValue.length() * sizeof(TCHAR), NULL);
	string mtime = utf16_to_utf8(attr.mtime);
	sqlite3_bind_text(stmt, 3, mtime.data(), mtime.length(), NULL);
	sqlite3_bind_int(stmt, 4, attr.flg_symbolic);
	sqlite3_bind_int(stmt, 5, attr.flg_archive);
	sqlite3_bind_int(stmt, 6, attr.flg_hidden);
	string dateTag8 = utf16_to_utf8(dateTag);
	sqlite3_bind_text(stmt, 7, dateTag8.data(), dateTag8.length(), NULL);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return sqlite3_last_insert_rowid(sql3);
}

// ファイルバックアップ
void MyFile::backup(const wstring& hashFile) {
	TCHAR first[3] = { hashFile.at(0), hashFile.at(1), L'\0' };
	TCHAR second[3] = { hashFile.at(2), hashFile.at(3), L'\0' };
	if (!PathIsDirectory(szRoot.c_str())) {
		CreateDirectory(szRoot.c_str(), NULL);
	}
	wstring dir = szRoot + L"\\" + first;
	if (!PathIsDirectory(dir.c_str())) {
		CreateDirectory(dir.c_str(), NULL);
	}
	dir = dir + L"\\" + second;
	if (!PathIsDirectory(dir.c_str())) {
		CreateDirectory(dir.c_str(), NULL);
	}
	wstring file = dir + L"\\" + hashFile + L".data";
	CopyFileEx(this->getPath().c_str(), file.c_str(), NULL, NULL, NULL, COPY_FILE_COPY_SYMLINK);
}
