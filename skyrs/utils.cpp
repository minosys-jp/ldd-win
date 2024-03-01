#include "pch.h"
#include "common.h"
#include <fstream>

using namespace std;

char* sqlite3_temp_directory;
BCRYPT_ALG_HANDLE hAlg;
wstring hostname;
wstring szSrcDrive, szDstDrive;
wstring restoreDate;

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

// ファイルのSHA256を取る
wstring hashFile(const wstring& pathName) {
	ifstream ifs(pathName, std::ios::binary);
	return hashStream(ifs);
}

// ファイル名からドライブ名を取り出す
wstring GetDriveNameFromPath(const wstring& pathName) {
	wstring r;
	if (pathName.substr(0, 4) == TEXT("\\\\?\\")) {
		if (pathName.length() > 4) {
			r = pathName.at(4) & ~0x0020;
		}
	}
	else if (pathName.length() > 0) {
		r = pathName.at(0) & ~0x0020;
	}
	return r;
}

// modified time を設定する
void TouchFileTime(const wstring& fname, const string& mtime, bool isDir) {
	SYSTEMTIME stTime;
	sscanf_s(mtime.c_str(), "%04d-%02d-%02d %02d:%02d:%02d",
		&stTime.wYear, &stTime.wMonth, &stTime.wDay,
		&stTime.wHour, &stTime.wMinute, &stTime.wSecond);
	FILETIME ftTime;
	SystemTimeToFileTime(&stTime, &ftTime);

	DWORD dwFflag = isDir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
	HANDLE h = CreateFile(fname.c_str(), 0, 0, NULL, OPEN_EXISTING, dwFflag, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		SetFileTime(h, &ftTime, &ftTime, &ftTime);
		CloseHandle(h);
	}
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

// UTF8からUTF16への変換
wstring utf8_to_utf16(const string& s) {
	int cb = MultiByteToWideChar(CP_UTF8, 0, s.data(), s.length(), nullptr, 0);
	wchar_t* pTmp = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, cb * sizeof(TCHAR));
	if (pTmp) {
		MultiByteToWideChar(CP_UTF8, 0, s.data(), s.length(), pTmp, cb);
		std::wstring sret(pTmp, cb);
		HeapFree(GetProcessHeap(), 0, pTmp);
		return sret;
	}
	else {
		return std::wstring();
	}
}

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

wstring joinString(const vector<wstring>& svec, const TCHAR sep) {
	wostringstream ss;
	for (const wstring s : svec) {
		if (s == TEXT("?root?")) {
			continue;
		}
		ss.put(sep);
		ss.write(s.data(), s.length());
	}
	ss.flush();
	return ss.str();
}

// ディレクトリを作成する
BOOL CreateDirectoryRecursive(sqlite3 *sql, const wstring& dirName) {
	vector<wstring> dirVec = splitString(dirName);
	wstring currentDir = wstring(L"\\\\?\\") + szDstDrive;
	wstring myDir;
	for (wstring dir : dirVec) {
		if (dir.empty() || dir == TEXT("?root?")) {
			continue;
		}
		currentDir = currentDir + L"\\" +dir;
		myDir = myDir + L"\\" + dir;
		if (!PathFileExists(currentDir.c_str())) {
			// パスなし
			if (!CreateDirectory(currentDir.c_str(), NULL)) {
				if (GetLastError() != ERROR_ALREADY_EXISTS) {
					return FALSE;
				}
			}
			else {
				// ディレクトリの属性を設定する
				sqlite3_stmt* stmt;
				if (sqlite3_prepare16_v3(sql,
					L"SELECT cl.flg_archive, cl.flg_hidden, cl.mtime FROM copy_logs cl \
					INNER JOIN files f ON f.latest_copy_log_id=cl.id \
					INNER JOIN folders d ON d.id=f.folder_id \
					WHERE d.folder_path=? AND cl.flg_directory=?",
					-1, 0, &stmt, NULL) == SQLITE_OK) {
					sqlite3_bind_text16(stmt, 1, myDir.data(), myDir.length() * sizeof(TCHAR), NULL);
					sqlite3_bind_int(stmt, 2, 1);
					if (sqlite3_step(stmt) == SQLITE_ROW) {
						int flg_archive = sqlite3_column_int(stmt, 0);
						int flg_hidden = sqlite3_column_int(stmt, 1);
						DWORD dwAttr = (flg_archive ? FILE_ATTRIBUTE_ARCHIVE : 0)
							| (flg_hidden ? FILE_ATTRIBUTE_HIDDEN : 0);
						if (!dwAttr) dwAttr = FILE_ATTRIBUTE_NORMAL;
						SetFileAttributes(currentDir.c_str(), dwAttr);

						string smtime((const char *)sqlite3_column_text(stmt, 2));
						TouchFileTime(currentDir, smtime, true);
					}
					sqlite3_finalize(stmt);
				}
			}
		}
		else {
			// パスあり: directory かどうかをチェック
			DWORD dwAttr = GetFileAttributes(currentDir.c_str());
			if (dwAttr == INVALID_FILE_ATTRIBUTES) {
				return FALSE;
			}
			if (!(dwAttr & FILE_ATTRIBUTE_DIRECTORY)) {
				// ディレクトリでなかったらエラー終了する
				return FALSE;
			}
		}
	}
	return TRUE;
}

// ファイル名からファイル部分を取り出す
wstring GetFileNameFromPath(const wstring& path) {
	return PathFindFileName(path.c_str());
}
