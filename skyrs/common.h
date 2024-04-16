#include "pch.h"

using namespace std;

wstring utf8_to_utf16(const std::string& s);
string utf16_to_utf8(const std::wstring& ws);
wstring GetDriveNameFromPath(const wstring &pathName);
wstring GetFileNameFromPath(const wstring &pathName);
BOOL CreateDirectoryRecursive(sqlite3 *sql, const wstring& dirName);
void TouchFileTime(const wstring &fname, const string& ftDate, bool isDir);
vector<wstring> splitString(const wstring& ws, wchar_t delim = L'\\');
wstring joinString(const vector<wstring>& svec, const TCHAR sep = L'\\');
string GetFileTime(const wstring& fname);
#define DATABASE_NAME L"\\skybu.db"
#define MAX_LONG_PATH 32768

extern BCRYPT_ALG_HANDLE hAlg;
extern wstring hostname;
extern wstring szSrcDrive, szDstDrive;
extern wstring restoreDate;

struct MyDid {
	int64_t did;
	int64_t fdid;
	MyDid(int64_t did, int64_t fdid) : did(did), fdid(fdid) {}
};

struct MySid {
	SID sid;
	wstring name;
};

struct MyFileAttribute {
	MySid owner;
	vector<MySid> groups;
	wstring mtime;
	wstring hash;
	boolean flg_create;
	boolean flg_remove;
	boolean flg_archive;
	boolean flg_directory;
	boolean flg_hidden;
	boolean flg_symbolic;
	boolean flg_root;
	MyFileAttribute() : flg_create(false), flg_remove(false), flg_archive(false),
		flg_directory(false), flg_hidden(false), flg_symbolic(false), flg_root(false) {}
	void setMtime(SYSTEMTIME& st) {
		TCHAR szDate[11];
		wsprintf(szDate, L"%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
		mtime = wstring(szDate);
	}
};

struct MyFile {
	wstring dir;
	wstring fname;
	MyFileAttribute attr;
	bool operator < (const MyFile& mf) const {
		return fname == mf.fname ? attr.mtime < mf.attr.mtime : fname < mf.fname;
	}
	wstring getPath() {
		return TEXT("\\\\?\\") + szDstDrive + dir + L"\\" + fname;
	}
};