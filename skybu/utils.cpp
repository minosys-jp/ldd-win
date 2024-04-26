#include "pch.h"
#include "common.h"
#include <iostream>
#include <fstream>

using namespace std;

BCRYPT_ALG_HANDLE hAlg;
wstring hostname;
wstring szRoot;
wstring szSource;
string dateTag;
char* sqlite3_temp_directory;
boolean isLastFinished;
string last_startTime;

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

extern bool timedOut;

// 処理終了時間に呼び出されるコールバック関数
VOID CALLBACK finishTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
	timedOut = true;
	wcout << TEXT("Time has come.") << endl;
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
void MyFile::recordDirIfChanged(sqlite3* sql3, const MyFile &root, int64_t parent, const string &dateTag) {
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
		string orgMtime((const char *)sqlite3_column_text(stmt, 3));
		string mtime = utf16_to_utf8(attr.mtime);
		if (orgMtime != mtime) {
			// 何らかの変更があった
			int64_t file_id = sqlite3_column_int64(stmt, 1);
			cl_id = createNewLogDBDir(sql3, file_id, dateTag);
		}
	}
	else {
		// 新規フォルダ
		cl_id = createNewLogDBDir(sql3, file_id, dateTag);
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
	wcout << L"root_path=" << root.path << L", file_id=" << file_id << L", copy_log_id=" << cl_id << endl;
}

// 未完了ファイル一覧テーブルにレコードを登録する
void MyFile::recordFileDir(sqlite3* sql3, const string& dateTag, int64_t folder_id, int64_t file_id, const wstring& hashFile) {
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3,
		L"INSERT INTO files_to_copy (date_tag, folder_id, file_id, flg_symbolic, flg_archive, flg_hidden, hash_name) VALUES(?, ?, ?, ?, ?, ?, ?)", -1, 0, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, dateTag.data(), dateTag.length(), NULL);
	sqlite3_bind_int64(stmt, 2, folder_id);
	sqlite3_bind_int64(stmt, 3, file_id);
	sqlite3_bind_int(stmt, 4, attr.flg_symbolic);
	sqlite3_bind_int(stmt, 5, attr.flg_archive);
	sqlite3_bind_int(stmt, 6, attr.flg_hidden);
	sqlite3_bind_text16(stmt, 7, hashFile.data(), hashFile.length() * sizeof(TCHAR), NULL);
	sqlite3_step(stmt);
}

// 新規 or 更新ならバックアップ
void MyFile::recordFileIfChanged(sqlite3* sql3, int64_t parent, const wstring& hashPath, const string &dateTag) {
	sqlite3_stmt* stmt;
	if (sqlite3_prepare16_v3(sql3,
		L"SELECT l.*, f.folder_id FROM copy_logs l \
		INNER JOIN files f ON f.id=l.file_id \
		INNER JOIN (SELECT file_id, max(id) as id FROM copy_logs GROUP BY file_id) lm \
		ON lm.file_id=l.file_id  AND l.id=lm.id WHERE f.hash_name=?",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return;
	}
	sqlite3_bind_text16(stmt, 1, hashPath.data(), hashPath.length() * sizeof(TCHAR), NULL);
	int64_t folder_id = -1;
	int64_t file_id = -1;
	boolean isChanged = false;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		string mtimeOld = (const char *)sqlite3_column_text(stmt, 3);
		string created_at = (const char*)sqlite3_column_text(stmt, 10);
		if ((mtimeOld != utf16_to_utf8(this->attr.mtime)) &&
			(isLastFinished || (last_startTime.compare(utf16_to_utf8(this->attr.mtime)) >= 0))) {
			// 更新ファイル
			folder_id = sqlite3_column_int64(stmt, 11);
			file_id = sqlite3_column_int64(stmt, 1);
			isChanged = true;
		}
	}
	else {
		if (isLastFinished || (last_startTime.compare(utf16_to_utf8(this->attr.mtime)) >= 0)) {
			// 新規ファイル
			folder_id = createNewFolderDB(sql3, parent);
			file_id = createNewFileDB(sql3, folder_id, hashPath);
			isChanged = true;
		}
	}

	sqlite3_finalize(stmt);
	if (isChanged) {
		recordFileDir(sql3, dateTag, folder_id, file_id, hashFileName(*this, false));
	}
}

// バックアップを実行する
BOOL DoBackup(sqlite3* sql3, const MyFile& root, int64_t parent, const string& dateTag) {

	sqlite3_stmt* stmt;
	if (sqlite3_prepare16_v3(sql3, L"SELECT file.id, file.date_tag, \
		CASE WHEN folders.folder_path = '?root?' THEN '' ELSE folders.folder_path END, \
		file.filename, file.file_id, file.hash_name, \
		file.flg_archive, file.flg_directory, file.flg_hidden, file.flg_symbolic \
		FROM folders \
		INNER JOIN( \
			SELECT tc.*, files.filename \
			FROM files \
			INNER JOIN files_to_copy tc \
			ON tc.hash_name IS NOT NULL AND files.hash_name = tc.hash_name) file \
		ON file.folder_id = folders.id ORDER BY file.created_at;", -1, 0, &stmt, NULL) != SQLITE_OK) {
		return FALSE;
	}

	// バックアップを実行する
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		MyFile file(root.drive);
		int64_t id = sqlite3_column_int64(stmt, 0);
		file.path = (const TCHAR*)sqlite3_column_text16(stmt, 2);
		file.path += TEXT("\\");
		file.path += (const TCHAR*)sqlite3_column_text16(stmt, 3);
		int64_t file_id = sqlite3_column_int64(stmt, 4);
		const wstring hash_name = (const TCHAR*)sqlite3_column_text16(stmt, 5);
		DWORD dwFlags = 0;
		if (sqlite3_column_int64(stmt, 6) == 1) {
			dwFlags |= FILE_ATTRIBUTE_ARCHIVE;
		}
		if (sqlite3_column_int64(stmt, 7) == 1) {
			dwFlags |= FILE_ATTRIBUTE_DIRECTORY;
			file.attr.flg_directory = true;
		}
		if (sqlite3_column_int64(stmt, 8) == 1) {
			dwFlags |= FILE_ATTRIBUTE_HIDDEN;
			file.attr.flg_hidden = true;
		}
		if (sqlite3_column_int64(stmt, 9) == 1) {
			dwFlags |= FILE_ATTRIBUTE_REPARSE_POINT;
		}
		file.setFlags(dwFlags);

		int64_t log_id = file.createNewLogDBFile(sql3, file_id, dateTag);

		sqlite3_stmt* sub_stmt;
		sqlite3_prepare16_v3(sql3,
			L"UPDATE files SET latest_copy_log_id=? WHERE id=?",
			-1, 0, &sub_stmt, NULL
		);
		sqlite3_bind_int64(sub_stmt, 1, log_id);
		sqlite3_bind_int64(sub_stmt, 2, file_id);
		while (sqlite3_step(sub_stmt) != SQLITE_DONE) {}
		sqlite3_finalize(sub_stmt);

		wcout << TEXT("copying: ") << file.path << endl;
		file.backup(hash_name);

		// バックアップ予定一覧から削除
		if (sqlite3_prepare16_v3(sql3, L"DELETE FROM files_to_copy where id=?", -1, 0, &sub_stmt, NULL) != SQLITE_OK) {
			return FALSE;
		}
		sqlite3_bind_int64(sub_stmt, 1, id);
		sqlite3_step(sub_stmt);
		int rowCount = sqlite3_changes(sql3);
		// cout << rowCount << " rows deleted by DELETE for " << id << endl;

		if (timedOut) {
			return FALSE;
		}
	}

	return TRUE;
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

int64_t MyFile::createNewFileDB(sqlite3* sql3, int64_t folder_id, const wstring& hashPath) {
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
int64_t MyFile::createNewLogDBDir(sqlite3* sql3, int64_t file_id, const string &dateTag) {
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
	sqlite3_bind_text(stmt, 7, dateTag.data(), dateTag.length(), NULL);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return sqlite3_last_insert_rowid(sql3);
}

// file 登録
int64_t MyFile::createNewLogDBFile(sqlite3* sql3, int64_t file_id, const string &dateTag) {
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3,
		L"INSERT INTO copy_logs (file_id, mtime, flg_symbolic, flg_archive, flg_hidden, date_tag) \
		VALUES (?, ?, ?, ?, ?, ?)",
		-1, 0, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, file_id);
	string mtime = utf16_to_utf8(attr.mtime);
	sqlite3_bind_text(stmt, 2, mtime.data(), mtime.length(), NULL);
	sqlite3_bind_int(stmt, 3, attr.flg_symbolic);
	sqlite3_bind_int(stmt, 4, attr.flg_archive);
	sqlite3_bind_int(stmt, 5, attr.flg_hidden);
	sqlite3_bind_text(stmt, 6, dateTag.data(), dateTag.length(), NULL);
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

// バックアップ履歴を登録する
int64_t createBackupHistory(sqlite3* sql3, const string& dateTag) {
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3, L"INSERT INTO backup_history (date_tag) VALUES (?)", -1, 0, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, dateTag.data(), dateTag.length(), NULL);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return sqlite3_last_insert_rowid(sql3);
}

// 今回のバックアップ履歴に終了日時を登録する
void finalizeBackupHistory(sqlite3* sql3, int64_t sessionId) {
	sqlite3_stmt* stmt;
	sqlite3_prepare16_v3(sql3, L"UPDATE backup_history SET end_at=CURRENT_TIMESTAMP WHERE id=?", -1, 0, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, sessionId);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}

// スキップ判定に使う情報をバックアップ履歴から取得する
//
// ret_val: 0:前回は完了した/履歴がなかった
//          1:前回は完了しなかった
//         -1:エラー発生
// start_time: 未完了のバックアップの初回の開始日時（前回完了しなかった場合のみ有効）
// date_tag  : 未完了のバックアップの初回のdate_tag（前回完了しなかった場合のみ有効）
tuple<int, string, string> getBackupHistory(sqlite3* sql3)
{
	sqlite3_stmt* stmt;
	int ret_value = -1;
	string start_time= "";
	string end_time = "";
	string date_tag = "";

	if (sqlite3_prepare16_v3(sql3,
		L"SELECT backup_history.start_at, backup_history.end_at, backup_history.date_tag \
		FROM backup_history \
		INNER JOIN(SELECT date_tag, start_at, max(end_at) AS end_at FROM backup_history) finished \
		ON IIF (finished.end_at IS NOT NULL, backup_history.start_at>=finished.start_at, TRUE) \
		ORDER BY backup_history.start_at \
		LIMIT 2",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return forward_as_tuple(ret_value, start_time, date_tag);
	}

	// 1件目は直近の完了回、または完了したことがない状態での初回
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		start_time= (const char*)sqlite3_column_text(stmt, 0);
		end_time = (sqlite3_column_type(stmt, 1) != SQLITE_NULL) ? (const char*)sqlite3_column_text(stmt, 1) : "";
		date_tag = (const char*)sqlite3_column_text(stmt, 2);
		ret_value = (end_time != "") ? 0 : 1;

		// 2件目が直近の未完了バックアップの初回（1件目は直近の完了回）
		if (ret_value == 0) {
			if (sqlite3_step(stmt) == SQLITE_ROW) {
				start_time = ((const char*)sqlite3_column_text(stmt, 0));
				date_tag = ((const char*)sqlite3_column_text(stmt, 2));
				ret_value = 1;
			}
		}
	}
	else {
		// 履歴が1件もなければ前回完了と同じ扱いにする
		ret_value = 0;
	}

	sqlite3_finalize(stmt);

	return forward_as_tuple(ret_value, start_time, date_tag);
}
