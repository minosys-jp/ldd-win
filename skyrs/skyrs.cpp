#include "common.h"
#include <iostream>

using namespace std;

int show_dir_list(int argc, LPCTSTR* argv);
int restore_dir(int argc, LPCTSTR* argv);

int _tmain(int argc, LPCTSTR *lpArgv)
{
	if (argc >= 2 && _tcscmp(lpArgv[1], L"--list") == 0) {
		return show_dir_list(argc - 2, lpArgv + 2);
	}
	else if (argc > 3) {
		hostname = lpArgv[1];
		szSrcDrive = lpArgv[2];
		szDstDrive = lpArgv[3];
		if (!szSrcDrive.empty() && !szDstDrive.empty()) {
			szSrcDrive = szSrcDrive.at(0) & ~0x0020;
			szDstDrive = szDstDrive.at(0) & ~0x0020;
			szDstDrive += lpArgv[3] + 1;
		}
		return restore_dir(argc - 4, lpArgv + 4);
	}
	std::wcout << TEXT("Usage:") << endl
		<< TEXT("skyrs.exe --list <hostname>") << endl
		<< TEXT("skyrs.exe <hostname> <src drive> <dst drive> [<date>]") << endl;
	return 1;
}

// 指定されたホストのルートを表示する
int show_dir_list(int argc, LPCTSTR* argv) {
	hostname = argv[0];
	hostname += DATABASE_NAME;

	sqlite3* sql;
	if (sqlite3_open16(hostname.c_str(), &sql) != SQLITE_OK) {
		std::wcout << TEXT("Failed to open ") << hostname << TEXT(".") << endl;
		return 1;
	}
	sqlite3_stmt* stmt;
	if (sqlite3_prepare16_v3(sql,
		L"SELECT d.guid, d.letter, f.folder_path FROM folders f \
		INNER JOIN drives d ON d.id=f.drive_id WHERE f.parent_id IS NULL \
		ORDER BY d.letter ASC, f.folder_path ASC",
		-1, 0, &stmt, NULL) == SQLITE_OK) {
		while (sqlite3_step(stmt) == SQLITE_ROW) {
			wstring stmp = (LPCTSTR)sqlite3_column_text16(stmt, 2);
			stmp = (stmp == TEXT("?root?")) ? TEXT("\\") : stmp;
			std::wcout << (LPCTSTR)sqlite3_column_text16(stmt, 1) << TEXT(":")
			    << stmp << endl;
		}
		sqlite3_finalize(stmt);
	}
	sqlite3_close(sql);
	return 0;
}

// parent に合致する drives.id, folders.id を取得する
int GetParentDir(sqlite3* db, vector<MyDid> &vDid) {
	sqlite3_stmt* stmt;
	if (sqlite3_prepare16_v3(db,
		L"SELECT d.id, fd.id FROM drives d INNER JOIN folders fd ON d.id=fd.drive_id \
		WHERE d.letter=? AND fd.parent_id IS NULL",
		-1, 0, &stmt, NULL) != SQLITE_OK) {
		return 1;
	}
		sqlite3_bind_text16(stmt, 1, szSrcDrive.data(), szSrcDrive.length() * sizeof(TCHAR), NULL);
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int64_t did_p = sqlite3_column_int64(stmt, 0);
		int64_t fdid_p = sqlite3_column_int64(stmt, 1);
		vDid.push_back(MyDid(did_p, fdid_p));
	}
	sqlite3_finalize(stmt);
	return 0;
}

int RestoreDirs(sqlite3 *db, sqlite3_stmt* stmt) {
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		wstring path((const TCHAR *)sqlite3_column_text16(stmt, 0));
		wcout << "Restore:" << path << endl;
		if (CreateDirectoryRecursive(db, path) == FALSE) {
			return 1;
		}
	}
	return 0;
}

wstring replaceStr(const wstring& s, const wstring& src, const wstring& dst) {
	size_t pos = s.find(src);
	if (pos == wstring::npos) {
		return s;
	}
	wstring rs = s.substr(pos + src.length());
	return s.substr(0, pos) + dst + replaceStr(rs, src, dst);
}

wstring sqlIn(const wstring& s, const vector<MyDid>& vDids) {
	vector<wstring> fdids;
	TCHAR dtmp[32];
	for (MyDid did : vDids) {
		_stprintf_p(dtmp, sizeof(dtmp), L"%I64d", did.fdid);
		fdids.push_back(dtmp);
	}
	wstring js = joinString(fdids, L'\\');
	js = js.empty() ? L"-1" : js.substr(1);
	return replaceStr(s, L"%id%", js);
}

// 最新時刻の directory リスト処理を実施する
int RestoreDirsLast(sqlite3* db, const vector<MyDid>& vDids) {
	sqlite3_stmt* stmt;
	vector<wstring> fdids;
	wstring sql = L"SELECT fd.folder_path FROM copy_logs cl \
		INNER JOIN files f ON f.id=cl.file_id \
		INNER JOIN folders fd ON fd.id=f.folder_id \
		WHERE fd.parent_id IN (%id%) AND cl.flg_directory=1 AND f.latest_copy_log_id=cl.id";
	sql = sqlIn(sql, vDids);
	if (sqlite3_prepare16_v3(db,
		sql.data(),
		sql.length() * sizeof(TCHAR), 0, &stmt, NULL) != SQLITE_OK) {
		return 1;
	}
	int res = RestoreDirs(db, stmt);
	sqlite3_finalize(stmt);
	return res;
}

// 特定日付の状態に directory を巻き戻す
int RestoreDirsDate(sqlite3* db, vector<MyDid> vDids) {
	string rsDate(utf16_to_utf8(restoreDate));
	sqlite3_stmt* stmt;
	wstring sql = L"SELECT fd.folder_path FROM copy_logs cl \
		INNER JOIN files f ON f.id=cl.file_id \
		INNER JOIN folders fd ON fd.id=f.folder_id \
		INNER JOIN (SELECT max(cl.id) cid, cl.file_id fid FROM copy_logs cl \
			WHERE cl.date_tag <= ? GROUP BY cl.file_id) fcl \
			ON fcl.fid=f.id AND fcl.cid=cl.id \
		WHERE fd.parent_id IN (%id%) AND cl.flg_directory=1";
	sql = sqlIn(sql, vDids);
	if (sqlite3_prepare16_v3(db,
		sql.data(),
		sql.length() * sizeof(TCHAR), 0, &stmt, NULL) != SQLITE_OK) {
		return 1;
	}
	sqlite3_bind_text(stmt, 1, rsDate.data(), rsDate.length(), NULL);

	int res = RestoreDirs(db, stmt);
	sqlite3_finalize(stmt);
	return res;
}

wstring addHashDir(const wstring& hash) {
	wstring dir1 = hash.substr(0, 2);
	wstring dir2 = hash.substr(2, 2);
	return dir1 + TEXT("\\") + dir2 + TEXT("\\") + hash;
}

// ファイルを書き戻す
int RestoreFiles(sqlite3_stmt* stmt) {
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		wstring fname((const TCHAR*)sqlite3_column_text16(stmt, 0));
		wstring fdpath((const TCHAR*)sqlite3_column_text16(stmt, 1));
		wstring hashname((const TCHAR*)sqlite3_column_text16(stmt, 2));
		string mtime((const char*)sqlite3_column_text(stmt, 3));
		string dateTag((const char*)sqlite3_column_text(stmt, 4));
		int flg_archive = sqlite3_column_int(stmt, 5);
		int flg_hidden = sqlite3_column_int(stmt, 6);
		int flg_symbol = sqlite3_column_int(stmt, 7);

		wstring srcFile = hostname + L"\\" + utf8_to_utf16(dateTag) + L"\\" + addHashDir(hashname) + L".data";
		fdpath = joinString(splitString(fdpath, L'\\'));
		wstring dstFile = TEXT("\\\\?\\") + szDstDrive + fdpath + TEXT("\\") + fname;
		if (!PathFileExists(dstFile.c_str())
			|| (flg_symbol ||  mtime != GetFileTime(dstFile))) {
			// ファイルを元に戻す
			CopyFileEx(srcFile.c_str(), dstFile.c_str(), NULL, NULL, NULL, COPY_FILE_COPY_SYMLINK);
			DWORD dwAttr = (flg_archive ? FILE_ATTRIBUTE_ARCHIVE : 0)
				| (flg_hidden ? FILE_ATTRIBUTE_HIDDEN : 0);
			if (!dwAttr) dwAttr = FILE_ATTRIBUTE_NORMAL;
			SetFileAttributes(dstFile.c_str(), dwAttr);
			TouchFileTime(dstFile, mtime, false);
		}
		else {
			// ファイル内容が同じ場合は属性をチェックする
			DWORD dwOldAttr = GetFileAttributes(dstFile.c_str());
			DWORD dwAttr = (flg_archive ? FILE_ATTRIBUTE_ARCHIVE : 0)
				| (flg_hidden ? FILE_ATTRIBUTE_HIDDEN : 0);
			DWORD dwXor = (dwOldAttr ^ dwAttr) & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN);
			if (dwXor) {
				// 属性が異なるので再設定し、時刻も再定義する
				SetFileAttributes(dstFile.c_str(), dwAttr);
				TouchFileTime(dstFile, mtime, false);
			}
			// ファイル内容が同じで属性値も同じ場合は何もしない
		}
	}
	return 0;
}

// 最新時刻の files リスト処理を実施する
int RestoreFilesLast(sqlite3* db, const vector<MyDid> &vDids) {
	sqlite3_stmt* stmt;
	wstring sql = L"SELECT f.filename, fd.folder_path, f.hash_name, cl.mtime, cl.date_tag, cl.flg_archive, cl.flg_hidden, cl.flg_symbolic \
		FROM copy_logs cl INNER JOIN files f ON cl.file_id=f.id \
		INNER JOIN folders fd ON fd.id=f.folder_id \
		WHERE (fd.parent_id IN (%id%) OR fd.id IN (%id%)) AND cl.flg_directory=0 AND cl.id=f.latest_copy_log_id";
	sql = sqlIn(sql, vDids);
	if (sqlite3_prepare16_v3(db,
		sql.data(),
		sql.length() * sizeof(TCHAR), 0, &stmt, NULL) != SQLITE_OK) {
		return 1;
	}
	int res = RestoreFiles(stmt);
	sqlite3_finalize(stmt);
	return res;
}

// ファイルを特定の日付に巻き戻す
int RestoreFilesDate(sqlite3* db, const vector<MyDid> vDids) {
	string rsDate(utf16_to_utf8(restoreDate));
	sqlite3_stmt* stmt;
	wstring sql = L"SELECT f.filename, fd.folder_path, f.hash_name, cl.mtime, cl.date_tag, cl.flg_archive, cl.flg_hidden, cl.flg_symbolic \
		FROM copy_logs cl INNER JOIN files f ON cl.file_id=f.id \
		INNER JOIN folders fd ON fd.id=f.folder_id \
		INNER JOIN (SELECT max(cl.id) cid, cl.file_id fid FROM copy_logs cl \
			WHERE cl.date_tag <= ? GROUP BY cl.file_id) fcl \
			ON fcl.fid=f.id AND fcl.cid=cl.id \
		WHERE (fd.parent_id IN (%id%) OR fd.id IN (%id%)) AND cl.flg_directory=0";
	sql = sqlIn(sql, vDids);
	if (sqlite3_prepare16_v3(db,
		sql.data(),
		sql.length() * sizeof(TCHAR), 0, &stmt, NULL) != SQLITE_OK) {
		return 1;
	}
	sqlite3_bind_text(stmt, 1, rsDate.data(), rsDate.length(), NULL);
	int res = RestoreFiles(stmt);
	sqlite3_finalize(stmt);
	return res;
}

// リストア処理を実行する
// [hostname] [src drive] [dst drive] ([date])
int restore_dir(int argc, LPCTSTR* argv) {
	if (argc > 0) {
		restoreDate = argv[0];
	}

	LPTSTR zPath = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(TCHAR));
	GetTempPath(MAX_PATH + 1, zPath);
	char* zPathChar = (char*)HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(TCHAR));
	WideCharToMultiByte(CP_UTF8, 0, zPath, -1, zPathChar, (MAX_PATH + 1) * sizeof(TCHAR),
		NULL, NULL);
	sqlite3_temp_directory = sqlite3_mprintf("%s", zPathChar);
	(void)HeapFree(GetProcessHeap(), 0, zPathChar);
	(void)HeapFree(GetProcessHeap(), 0, zPath);

	// SHA256 ハンドルを取得する
	if (BCryptOpenAlgorithmProvider(&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0))
	{
		std::wcout << TEXT("failed to open SHA256 handle.") << endl;
		return 1;
	}

	// sqlite3 をオープンする
	sqlite3* db;
	{
		wstring dbfile = hostname + DATABASE_NAME;
		if (sqlite3_open16(dbfile.c_str(), &db) != SQLITE_OK) {
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return 1;
		}
	}

	CreateDirectory(szDstDrive.c_str(), NULL);

	sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);

	// parent_id を取得する
	vector<MyDid> vDids;
	if (GetParentDir(db, vDids)) {
		sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
		sqlite3_close(db);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return 1;
	}

	/*
	// szTarget を作成する
	if (!CreateDirectoryW(szTarget.c_str(), NULL)) {
		wcout << L"Failed to create target directory:" << szTarget << endl;
		sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
		sqlite3_close(db);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return 1;
	}
	*/

	if (restoreDate.empty()) {
		// 最新時刻のフォルダを復元する
		if (RestoreDirsLast(db, vDids)) {
			sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
			sqlite3_close(db);
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return 1;
		}

		// 最新時刻のファイルを復元する
		RestoreFilesLast(db, vDids);
	}
	else {
		// 指定時刻のフォルダを復元する
		if (RestoreDirsDate(db, vDids)) {
			sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
			sqlite3_close(db);
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return 1;
		}

		// 指定時刻のファイルを復元する
		RestoreFilesDate(db, vDids);
	}

	// sqlite3 をクローズする
	sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
	sqlite3_close(db);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	wcout << L"Files restored." << endl;
	return 0;
}
