#include "pch.h"
#include <Psapi.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include "common.h"

using namespace std;
BOOL BackupStart(sqlite3* sql3, BCRYPT_ALG_HANDLE hAlg, const MyFile &dir, int64_t parent, const string &datetag);

bool timedOut = false;
VOID CALLBACK finishTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired);

int _tmain(int argc, LPCTSTR *argv)
{
	setlocale(LC_ALL, "Japanese");

	// Usage の確認
	if (argc < 2) {
		wcout << TEXT("Usage: skybu <source directory> [time to finish(in minutes)]") << endl;
		return 1;
	}

	// 処理時間の設定があればタイマーを開始する
	HANDLE hTimerQueue = NULL;
	HANDLE hTimer = NULL;
	if (argc >= 3) {
		int timeToFinish = 0;
		try {
			timeToFinish = stoi(argv[2]);
		}
		catch (const invalid_argument& e) {
			wcout << TEXT("Invalid Time.") << std::endl;
			return 1;
		}
		catch (const out_of_range& e) {
			wcout << TEXT("Time is out of range.") << endl;
			return 1;
		}
		if (timeToFinish > 0) {
			hTimerQueue = CreateTimerQueue();
			if (hTimerQueue == NULL) {
				wcout << TEXT("CreateTimerQueue failed(") << GetLastError() << TEXT(")") << endl;
				return 1;
			}
			if (!CreateTimerQueueTimer(&hTimer, hTimerQueue,
				(WAITORTIMERCALLBACK)finishTimerCallback, NULL, timeToFinish * 60 * 1000, 0, 0)) {
				wcout << TEXT("CreateTimerQueueTimer failed(") << GetLastError() << TEXT(")") << endl;
				return 1;
			}
			wcout << TEXT("Time to finish = ") << argv[2] << endl;
		}
	}

	if (!PathIsDirectory(argv[1])) {
		wcout << TEXT("Source must be directory name.") << endl;
		return 1;
	}
	szSource = argv[1];

	// Hostname を取得
	//hostname = whoAmI();
	hostname = GetFileNameFromPath(szSource);
	wcout << TEXT("host name=") << hostname << endl;

	// Hostname フォルダが作成されているかチェック
	if (!PathIsDirectory(hostname.c_str())) {
		if (!CreateDirectory(hostname.c_str(), NULL)) {
			wcout << TEXT("Failed to create hostname directory.") << endl;
			return 1;
		}
	}

	// sqlite3 database file をチェック
	LPTSTR zPath = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(TCHAR));
	GetTempPath(MAX_PATH + 1, zPath);
	char *zPathChar = (char*)HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(TCHAR));
	WideCharToMultiByte(CP_UTF8, 0, zPath, -1, zPathChar, (MAX_PATH + 1) * sizeof(TCHAR),
		NULL, NULL);
	sqlite3_temp_directory = sqlite3_mprintf("%s", zPathChar);
	(void)HeapFree(GetProcessHeap(), 0, zPathChar);
	(void)HeapFree(GetProcessHeap(), 0, zPath);

	LPTSTR databasePath = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(TCHAR));
	if (databasePath == NULL) {
		wcout << TEXT("Failed to allocate memory.") << endl;
		return 1;
	}
	wcsncpy_s(databasePath, MAX_PATH + 1, hostname.data(), hostname.length());
	PathCchAppend(databasePath, MAX_PATH, DATABASE_NAME);
	if (!PathFileExists(databasePath)) {
		if (!CreateSql3Database(databasePath)) {
			wcout << TEXT("Failed to create sql3 database.") << endl;
			return 1;
		}
	}

	{
		LPTSTR szRootB = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
		if (szRootB == NULL) {
			wcout << TEXT("Failed to allocate memory.") << endl;
			return 1;
		}

		SYSTEMTIME systime;
		GetLocalTime(&systime);
		TCHAR szCurrent[11];
		wsprintf(szCurrent, L"%04d-%02d-%02d", systime.wYear, systime.wMonth, systime.wDay);
		PathCchCombine(szRootB, MAX_PATH + 1, hostname.c_str(), szCurrent);
		if (!PathFileExists(szRootB)) {
			if (!CreateDirectory(szRootB, NULL)) {
				wcout << TEXT("Failed to create ") << szCurrent << " folder." << endl;
				HeapFree(GetProcessHeap(), 0, szRootB);
				return 1;
			}
		}
		szRoot = szRootB;
		dateTag = utf16_to_utf8(szCurrent);
		HeapFree(GetProcessHeap(), 0, szRootB);
	}

	// SQLite3 ハンドルを取得する
	sqlite3* sql3 = NULL;
	if (sqlite3_open16(databasePath, &sql3) != SQLITE_OK) {
		wcout << TEXT("Failed to open database") << endl;
		return 1;
	}

	// SHA256 ハンドルを取得する
	if (BCryptOpenAlgorithmProvider(&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0))
	{
		wcout << TEXT("failed to open SHA256 handle.") << endl;
		sqlite3_close(sql3);
		return 1;
	}

	// 過去のバックアップ履歴からスキップ判定に使う変数の値を決める
	int ret;
	string last_dateTag;
	std::tie(ret, last_startTime, last_dateTag) = getBackupHistory(sql3);
	if (ret < 0) {
		wcout << TEXT("failed to get history data.") << endl;
		sqlite3_close(sql3);
		return 1;
	} else {
		isLastFinished = (ret == 0);
		// 前回未完了ならdateTagを引き継ぐ
		if (!isLastFinished) {
			dateTag = last_dateTag;
		}
	}

	vector<wstring> vecRoots;
	if (FindRoot(vecRoots, szSource)) {
		for (wstring drvstr : vecRoots) {
			if (drvstr.length() != 1) {
				continue;
			}
			sqlite3_exec(sql3, "BEGIN TRANSACTION", NULL, NULL, NULL);
			int64_t sessionId = createBackupHistory(sql3, dateTag);
			MyFile root;
			root.drive.UpdateDrives(sql3, szSource, drvstr);
			// Root 登録
			int64_t parent = root.createNewFolderDB(sql3, -1LL);
			if (!BackupStart(sql3, hAlg, root, parent, dateTag)) {
				sqlite3_exec(sql3, "ROLLBACK", NULL, NULL, NULL);
			}
			else {
				if (!timedOut) {
					finalizeBackupHistory(sql3, sessionId);
				}
				sqlite3_exec(sql3, "COMMIT", NULL, NULL, NULL);
			}
		}
	}

	if (hTimerQueue != NULL) {
		DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
		DeleteTimerQueueEx(hTimerQueue, NULL);
	}
	sqlite3_close(sql3);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	return 0;
}

// バックアップ本体
BOOL BackupStart(sqlite3* sql3, BCRYPT_ALG_HANDLE hAlg, const MyFile &root, int64_t parent, const string &dateTag) {
	set<MyFile> fileSet;
	set<MyFile> dirSet;
	set<wstring> exSet;
	exSet.insert(TEXT("wsl"));
	exSet.insert(TEXT("ext4.vhdx"));
	exSet.insert(TEXT("OneDrive"));
	exSet.insert(TEXT("マイドライブ"));
	exSet.insert(TEXT("LocalState"));
	exSet.insert(TEXT("Temp"));
	exSet.insert(TEXT(".."));
	exSet.insert(TEXT("$RECYCLE.BIN"));

	// szTarget ディレクトリの一覧を取得する
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	wstring target = root.getPath() + L"\\*";
	hFind = FindFirstFile(target.c_str(), &ffd);
	if (hFind == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	do {
		MyFile file(root.drive);
		if (wstring(L".") == ffd.cFileName) {
			// フォルダ自身を指定した場合
			file.setData(root, L"", ffd.dwFileAttributes);
			file.recordDirIfChanged(sql3, root, parent, dateTag);
		} 
		else if (exSet.find(ffd.cFileName) == exSet.cend()) {
			file.setData(root, ffd.cFileName, ffd.dwFileAttributes);
			if (!file.attr.flg_directory) {
				// 取得したファイルがディレクトリだったら fileSet に追加する
				fileSet.insert(file);
			}
			else if (file.attr.flg_directory) {
				// 取得したファイルがディレクトリだったら dirSet に追加する
				dirSet.insert(file);
			}
		}
		if (timedOut) {
			FindClose(hFind);
			return TRUE;
		}
	} while (FindNextFile(hFind, &ffd) != 0);
	FindClose(hFind);

	// ハッシュフォルダが構成されていなかったらフォルダ作成

	// その場合は DB にも記録する

	// set が空でない場合、BackupStart() を再帰的に呼び出す
	for (MyFile dir : dirSet) {
		wcout << TEXT("directory=") << dir.path << endl;
		BackupStart(sql3, hAlg, dir, parent, dateTag);

		if (timedOut) {
			return TRUE;
		}
	}

	// fileSet が空でない場合、ファイル単位でバックアップする
	for (MyFile file : fileSet) {
		// ファイルが通常orリンクファイルだったらファイル名をハッシュしてバックアップファイル名を得る
		wstring hashPathName = hashFileName(file, false);

		// 新規または以前と内容が変わっていたらファイルバックアップ
		file.backupFileIfChanged(sql3, parent, hashPathName, dateTag);

		if (timedOut) {
			return TRUE;
		}
	}
	return TRUE;
}
