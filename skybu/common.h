#include "pch.h"

using namespace std;

struct MyDrive {
	int64_t id;
	wstring guid;
	wstring name;
	MyDrive() : id(-1LL), guid(), name(L"D") {}
	void UpdateDrives(sqlite3* sql, const wstring& arg, const wstring &drv);
};

struct MyFile;

BOOL FindRoot(vector<wstring>& v, const wstring &arg);
wstring  whoAmI();
wstring driveToGuid(TCHAR driveLetter);
string utf16_to_utf8(const std::wstring& s);
//wstring hashDirName(const wstring& guid, const wstring& dirName, bool flg_root);
wstring hashFileName(const MyFile& file, bool flg_root);
//wstring hashFile(const wstring &fileName);
wstring GetDriveNameFromPath(const wstring &pathName);
wstring GetDirNameFromPath(const wstring &pathName, int64_t parent);
wstring GetPathWithoutHostname(const wstring& pathName);
LPCTSTR GetFileNameFromPath(const wstring &pathName);
BOOL CreateSql3Database(LPCTSTR lpctDB);
#define DATABASE_SCHEMA L"skybu.sql"
#define DATABASE_NAME L"skybu.db"
#define MAX_LONG_PATH 32768

extern BCRYPT_ALG_HANDLE hAlg;
extern wstring hostname;
extern wstring szRoot;
extern wstring szSource;
extern string dateTag;

struct MySid {
	SID sid;
	wstring name;
};

struct MyFileAttribute {
	MySid owner;
	vector<MySid> groups;
	wstring mtime;
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
	MyDrive drive;
	wstring path;
	wstring fname;
	MyFileAttribute attr;
	MyFile(const MyDrive& drive) : drive(drive) {}
	MyFile() {}
	bool operator < (const MyFile& mf) const {
		return fname == mf.fname ? attr.mtime < mf.attr.mtime : fname < mf.fname;
	}
	const wstring getPath() const {
		return TEXT("\\\\?\\") + szSource + TEXT("\\") + drive.name + path;
	}
	void setFname(const MyFile &parent, const wstring &filename);
	void setFlags(DWORD dwFlags);
	void setData(const MyFile &parent, const wstring &filename);
	void setData(const MyFile &parent, const wstring &filename, DWORD dwFlags);
	void backupFileIfChanged(sqlite3* sql3, int64_t parent, const wstring& hashPath, const string &dateTag);
	void recordDirIfChanged(sqlite3* sql3, const MyFile &root, int64_t parent, const string &dateTag);
	void backup(const wstring& hashPath);
	int64_t createNewFolderDB(sqlite3* sql3, int64_t parent);
	int64_t createNewFileDB(sqlite3* sql3, int64_t folder_id, const wstring& hashPath);
	int64_t createNewLogDBFile(sqlite3* sql3, int64_t file_id, const string &dateTag);
	int64_t createNewLogDBDir(sqlite3* sql3, int64_t file_id, const string &dateTag);
};