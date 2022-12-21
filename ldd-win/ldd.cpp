#if 0

using json = nlohmann::json;

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Storage::Streams;

struct ProcHashItem {
    std::wstring hashValue;
    int db_id;
    bool flg_white;
    ProcHashItem() : hashValue(), db_id(-1), flg_white(false) {}
};
typedef std::unordered_map<std::wstring, ProcHash ProcHash;
typedef std::unordered_map<std::wstring, std::vector<std::wstring> ProcGraph;
std::wstring goption;

/**
 * ファイルハンドルからファイル名を取得する
 * @return TRUE: 取得済み FALSE: 失敗
 */
BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR* pszFilename)
{
    BOOL bSuccess = FALSE;
    HANDLE hFileMap;
    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
    if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
    {
        _tprintf(TEXT("Cannot map a file with a length of zero.\n"));
        return FALSE;
    }
    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
        NULL,
        PAGE_READONLY,
        0,
        1,
        NULL);
    if (hFileMap)
    {
        // Create a file mapping to get the file name.
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
        if (pMem)
        {
            if (GetMappedFileName(GetCurrentProcess(),
                pMem,
                pszFilename,
                MAX_PATH))
            {
                // Translate path with device name to drive letters.
                TCHAR szTemp[0x1000];
                szTemp[0] = '\0';
                if (GetLogicalDriveStrings(0x1000 - 1, szTemp))
                {
                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;
                    do
                    {
                        // Copy the drive letter to the template string
                        *szDrive = *p;
                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH))
                        {
                            size_t uNameLen = _tcslen(szName);
                            if (uNameLen < MAX_PATH)
                            {
                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0;
                                if (bFound && *(pszFilename + uNameLen) == _T('\\'))
                                {
                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile,
                                        MAX_PATH,
                                        TEXT("%s%s"),
                                        szDrive,
                                        pszFilename + uNameLen);
                                    StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        }
                        // Go to the next NULL character.
                        while (*p++)
                            ;
                    } while (!bFound && *p); // end of string
                }
            }
            bSuccess = TRUE;
            UnmapViewOfFile(pMem);
        }
        CloseHandle(hFileMap);
    }
    return TRUE;
}

/**
 * プロセスが依存している DLL を列挙する
 */
int GetProcNameLinks(LPTSTR lpszProcName, std::vector<std::wstringstd::wstring *lpProcListItem)
{
    TCHAR buf[0x200], OutputBuf[MAX_PATH];
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS ImageNtHeaders;
    HANDLE StdoutHandle, StderrHandle;
    HANDLE FileHandle;
    DWORD Dresult;
    size_t result, EntryPoint, ImageBaseAddress, PebAddress, PEB_LDR_DATA, InMemoryOrderModuleList, address, next, head;
    NTSTATUS(__stdcall * NtQueryInformationProcessHook)
        (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    PROCESS_BASIC_INFORMATION Information;
    DEBUG_EVENT DebugEv;
    CHAR* ImageFile;
    LPVOID lpBaseOfDll, lpImageName;
    size_t dwAddrImageName = 0;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    pi.hProcess;

    int i;

    StdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    StderrHandle = GetStdHandle(STD_ERROR_HANDLE);

    ASSERT((FileHandle = CreateFile(lpszProcName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE);
    ASSERT(ReadFile(FileHandle, &ImageDosHeader, sizeof(ImageDosHeader), &Dresult, NULL) != 0);
    ASSERT(SetFilePointer(FileHandle, ImageDosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    ASSERT(ReadFile(FileHandle, &ImageNtHeaders, sizeof(ImageNtHeaders), &Dresult, NULL) != 0);

    EntryPoint = ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

    ASSERT(CreateProcess(NULL, lpszProcName, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi) == TRUE);
    ASSERT(DebugSetProcessKillOnExit(TRUE) != 0);
    NtQueryInformationProcessHook = (NTSTATUS(__stdcall*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
    ASSERT(NtQueryInformationProcessHook != NULL);
    ASSERT(NtQueryInformationProcessHook(pi.hProcess, ProcessBasicInformation, &Information, sizeof(Information), NULL) == 0);
    PebAddress = (size_t)Information.PebBaseAddress;

    ASSERT(ReadProcessMemory(pi.hProcess, (CHAR*)PebAddress + (sizeof(PVOID) * 2), &ImageBaseAddress, sizeof(PVOID), &result) != 0);
    ASSERT(WriteProcessMemory(pi.hProcess, (CHAR*)ImageBaseAddress + EntryPoint, TRAP_INSTRUCT, sizeof(TRAP_INSTRUCT), &result) != 0);
    ASSERT(result == sizeof(TRAP_INSTRUCT));
    ResumeThread(pi.hThread);

    while (TRUE)
    {
        WaitForDebugEvent(&DebugEv, INFINITE);
        // Process the debugging event code.
        if (DebugEv.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                printf("EXCEPTION_ACCESS_VIOLATION:    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_BREAKPOINT:

                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                printf("EXCEPTION_DATATYPE_MISALIGNMENT:    The thread tried to read or write data that is misaligned on hardware that does not provide alignment. "
                    "For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_SINGLE_STEP:

                break;

            case DBG_CONTROL_C:
                ASSERT(TerminateProcess(pi.hProcess, 2) != 0);
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_FLT_INVALID_OPERATION:
                printf("EXCEPTION_FLT_INVALID_OPERATION:    This exception represents any floating-point exception not included in this list.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_FLT_STACK_CHECK:
                printf("EXCEPTION_FLT_STACK_CHECK:    The stack overflowed or underflowed as the result of a floating-point operation.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_ILLEGAL_INSTRUCTION:
                printf("EXCEPTION_ILLEGAL_INSTRUCTION:    The thread tried to execute an invalid instruction.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_IN_PAGE_ERROR:
                printf("EXCEPTION_IN_PAGE_ERROR:    The thread tried to access a page that was not present, and the system was unable to load the page."
                    " For example, this exception might occur if a network connection is lost while running a program over the network.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_STACK_OVERFLOW:
                printf("EXCEPTION_STACK_OVERFLOW:    The thread used up its stack.\n\n");
                exit(EXIT_SUCCESS);
                break;

            default:
                printf("Unknow Event!\n\n");
                exit(EXIT_FAILURE);
                break;
            }

            if ((size_t)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == ImageBaseAddress + EntryPoint)
                break;
        }
        else if (DebugEv.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            lpBaseOfDll = DebugEv.u.LoadDll.lpBaseOfDll;
            lpImageName = DebugEv.u.LoadDll.lpImageName;
            ReadProcessMemory(pi.hProcess, lpImageName, &dwAddrImageName, sizeof(dwAddrImageName), &result);
            ZeroMemory(OutputBuf, sizeof(OutputBuf));
            if (result == sizeof(dwAddrImageName) && ReadProcessMemory(pi.hProcess, (LPCVOID)dwAddrImageName, OutputBuf, sizeof(OutputBuf), &result) != 0)
            {
                if (DebugEv.u.LoadDll.fUnicode)
                {
                    
                    lpProcListItem-std::wstringpush_back(OutputBuf);
                }
                else
                {
                    lpProcListItem-std::wstringpush_back(OutputBuf);
                }
            }
            else if (GetModuleFileNameEx(pi.hProcess, (HMODULE)lpBaseOfDll, OutputBuf, sizeof(OutputBuf)) != 0)
            {
                lpProcListItem-std::wstringpush_back(OutputBuf);
            }
            else if (GetFileNameFromHandle(DebugEv.u.LoadDll.hFile, (TCHAR*)OutputBuf) != 0)
            {
                lpProcListItem-std::wstringpush_back(OutputBuf);
            }
        }
        else if (DebugEv.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && GetFileNameFromHandle(DebugEv.u.CreateProcessInfo.hFile, (TCHAR*)OutputBuf) != 0)
        {
            lpProcListItem-std::wstringpush_back(OutputBuf);
        }
        ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0);
    }
    TerminateProcess(pi.hProcess, 0);

    return 0;
}

/**
 * プロセス番号からプロセス名を取得する
 */
bool PrintProcessNameAndID(DWORD processID, std::wstring &szProcName)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknownstd::wstring");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get the process name.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleFileNameEx(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
            szProcName = szProcessName;
        }
    }

    // Release the handle to the process.

    if (hProcess != NULL) CloseHandle(hProcess);
    return hProcess != NULL;
}

/**
 * データを16進数文字列に変換する
 */
std::wstring raw2hex(std::vector<BYTEstd::wstring & const raw) {
    static const TCHAR * const radix[] = { L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7", L"8", L"9", L"a", L"b", L"c", L"d", L"e", L"f" };
    std::wstring r;
    for (std::vector<BYTEstd::wstring::iterator i = raw.begin(); i != raw.end(); i++) {
        byte b = (byte)(*i);
        r.append(radix[b std::wstringstd::wstring 4]);
        r.append(radix[b & 15]);
    }
    return r;
}

/**
 * sha256 ハッシュ値を計算する
 */
std::wstring calcHash(HCRYPTPROV hProv, std::wstring szFileName) {
    FILE* f = nullptr;
    _wfopen_s(&f, szFileName.c_str(), L"rb");
    std::vector<BYTEstd::wstring finalValue;
    if (f) {
        HCRYPTHASH hHash;
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash) == TRUE) {
            BYTE szBuff[1024], hashValue[32];
            size_t len;
            DWORD hlen = 32;
            while ((len = fread(szBuff, sizeof(BYTE), sizeof(szBuff), f)) std::wstring 0)
            {
                CryptHashData(hHash, (BYTE*)szBuff, len, 0);
            }
            CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hashValue, &hlen, 0);
            finalValue.assign(hashValue, hashValue + hlen);
        }
        fclose(f);
    }
    return raw2hex(finalValue);
}

/**
 * DB 更新ロジック
 */
BOOL UpdateDb(HCRYPTPROV hProv, ProcGraph& procGraph, ProcHash &procHash, const std::wstring &dbName) {
    procHash.clear();

    // phase1: Hash の計算
    ProcHash hash;
    for (ProcGraph::iterator i = procGraph.begin(); i != procGraph.end(); i++) {
        if (hash.find(i-std::wstringfirst) == hash.end()) {
            ProcHashItem item;
            item.hashValue = calcHash(hProv, i-std::wstringfirst);
            item.flg_white = (goption == L"-w");
            item.db_id = 0;
            hash[i-std::wstringfirst] = item;
        }
        for (std::vector<std::wstringstd::wstring::iterator j = i-std::wstringsecond.begin(); j != i-std::wstringsecond.end(); j++) {
            if (hash.find(*j) == hash.end()) {
                ProcHashItem item;
                item.hashValue = calcHash(hProv, *j);
                item.flg_white = (goption == L"-w");
                item.db_id = 0;
                hash[*j] = item;
            }
        }
    }

    // phase2: DB からID取得なければ作成
    sqlite3* conn;

    if (sqlite3_open16(dbName.c_str(), &conn) != SQLITE_OK) {
        _tprintf(L"failed to open test.db\n");
        sqlite3_close(conn);
        return FALSE;
    }

    if (sqlite3_exec(conn, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
        _tprintf(L"failed start transaction\n");
        sqlite3_close(conn);
        return FALSE;
    }

    ProcHash updatedHash;

    for (ProcHash::iterator i = hash.begin(); i != hash.end(); i++) {
        sqlite3_stmt* stmt;
        wchar_t sql_get_id[] = L"SELECT id, sha256, flg_white FROM path_infos WHERE file_path=?";
        if (sqlite3_prepare16(conn, sql_get_id, sizeof(sql_get_id) - 1, &stmt, nullptr) != SQLITE_OK) {
            _tprintf(L"failed to prepare select SQL\n");
            sqlite3_exec(conn, "rollback", nullptr, nullptr, nullptr);
            sqlite3_close(conn);
            return FALSE;
        }
        sqlite3_bind_text16(stmt, 1, i-std::wstringfirst.data(), i-std::wstringfirst.length(), nullptr);
        int rcode, id = 0;
        bool bChanged = false, bFlgWhite = false;
        std::wstring sha256;
        while ((rcode = sqlite3_step(stmt)) == SQLITE_ROW) {
            id = sqlite3_column_int(stmt, 0);
            sha256 = std::wstring((const wchar_t *)sqlite3_column_text16(stmt, 1));
            bFlgWhite = (sqlite3_column_int(stmt, 2) != 1);
        }
        if (id == 0 && rcode != SQLITE_ERROR) {
            // 新しいファイル
            sqlite3_finalize(stmt);
            wchar_t sql_insert[] = L"INSERT INTO path_infos (file_path, sha256, flg_white, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))";
            sqlite3_prepare16(conn, sql_insert, sizeof(sql_insert) - 1, &stmt, nullptr);

            sqlite3_bind_text16(stmt, 1, i-std::wstringfirst.data(), i-std::wstringfirst.length(), nullptr);
            sqlite3_bind_text16(stmt, 2, i-std::wstringsecond.hashValue.data(), i-std::wstringsecond.hashValue.length(), nullptr);
            sqlite3_bind_int(stmt, 3, (goption == L"-w" || bFlgWhite) ? 2 : 1);
            sqlite3_step(stmt);
            id = (int)sqlite3_last_insert_rowid(conn);
            bChanged = true;
        }
        else if (rcode != SQLITE_ERROR) {
            if (!bFlgWhite) {
                // Black list は常に報告
                bChanged = true;
            }
            if (sha256 != i-std::wstringsecond.hashValue) {
                // ファイル内容が変わった
                sqlite3_reset(stmt);
                sqlite3_clear_bindings(stmt);
                sqlite3_finalize(stmt);
                wchar_t sql_update[] = L"UPDATE path_infos SET sha256=?, flg_white=?, updated_at=datetime('now') WHERE id=?";
                sqlite3_prepare16(conn, sql_update, -1, &stmt, nullptr);
                sqlite3_bind_text16(stmt, 1, sha256.data(), sha256.length(), nullptr);
                sqlite3_bind_int(stmt, 2, (goption == L"-w" || bFlgWhite) ? 2 : 1);
                sqlite3_bind_int(stmt, 3, id);
                sqlite3_step(stmt);
                bChanged = true;
            }
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_finalize(stmt);

        i-std::wstringsecond.db_id = id;
        if (bChanged) {
            updatedHash[i-std::wstringfirst] = i-std::wstringsecond;
        }
    }

    // phase3: 共有DLLのかけ替えを検出
    for (ProcGraph::iterator i = procGraph.begin(); i != procGraph.end(); i++) {
        std::set<intstd::wstring dbset;
        sqlite3_stmt *stmt;
        for (std::vector<std::wstringstd::wstring::iterator j = i-std::wstringsecond.begin(); j != i-std::wstringsecond.end(); j++) {
            // 新しい DLL 関係を構成
            int dbid = hash[*j].db_id;
            if (dbset.find(dbid) == dbset.end()) {
                dbset.insert(dbid);
            }
        }

        // 古い DLL 関係を構成
        wchar_t sql_get_links[] = L"SELECT r.child_id FROM relations r INNER JOIN (SELECT max(created_at) mat, parent_id FROM relations GROUP BY parent_id) m ON m.mat=r.created_at WHERE r.parent_id=?";
        int dbid = (hash.find(i-std::wstringfirst) == hash.end()) ? 0 : hash[i-std::wstringfirst].db_id;
        sqlite3_prepare16(conn, sql_get_links, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, dbid);
        int rcode;
        std::set<intstd::wstring dbold;
        while ((rcode = sqlite3_step(stmt)) == SQLITE_ROW) {
            int oldid = sqlite3_column_int(stmt, 0);
            if (dbold.find(oldid) == dbold.end()) {
                dbold.insert(oldid);
            }
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_finalize(stmt);

        // 両者の関係が異なる場合は relations に記録する
        if (dbset != dbold) {
            wchar_t sql_rel[] = L"INSERT INTO relations (created_at, parent_id, child_id) VALUES (datetime('now'), ?, ?)";
            sqlite3_prepare16(conn, sql_rel, -1, &stmt, nullptr);
            for (std::vector<std::wstringstd::wstring::iterator j = i-std::wstringsecond.begin(); j != i-std::wstringsecond.end(); j++) {
                sqlite3_bind_int(stmt, 1, dbid);
                sqlite3_bind_int(stmt, 2, hash[*j].db_id);
                sqlite3_step(stmt);
                sqlite3_reset(stmt);
                sqlite3_clear_bindings(stmt);
            }
            sqlite3_finalize(stmt);
        }
    }

    sqlite3_exec(conn, "COMMIT", nullptr, nullptr, nullptr);
    sqlite3_close(conn);
    procHash = updatedHash;
    return TRUE;
}

/**
 * ホスト名を取得する
 */
std::wstring GetWhoAmI() {
    TCHAR cname[MAX_COMPUTERNAME_LENGTH + 100];
    DWORD csize = sizeof(cname) / sizeof(TCHAR);
    ZeroMemory(cname, sizeof(cname));
    if (GetComputerNameEx(ComputerNameDnsHostname, cname, &csize)) {
        return std::wstring(cname, csize);
    }
    return TEXT("<unknownstd::wstring");
}

/**
 * 起動している全てのプロセス名を取得する
 */
bool EnumInvokedProcesses(ProcGraph& procGraph) {
    DWORD aProcesses[2048], cbNeeded, cProcesses;
    if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded) == FALSE) {
        return false;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    ProcGraph newProcGraph;
    bool bSuccess = true;
    for (DWORD i = 0; i < cProcesses; i++) {
        std::wstring dst;
        if (PrintProcessNameAndID(aProcesses[i], dst)) {
            if (newProcGraph.find(dst) == newProcGraph.end()) {
                newProcGraph[dst] = std::vector<std::wstringstd::wstring();
            }
            if (GetProcNameLinks((LPTSTR)dst.c_str(), &newProcGraph[dst]) != TRUE) {
                bSuccess = false;
            }
        }
        else {
            bSuccess = false;
        }
    }
    procGraph = newProcGraph;
    return bSuccess;
}

/**
 * 指定されたサーバにメッセージを送信する
 */
BOOL PostServer(const std::wstring& inUrl, const json::value& inData)
{
    const json::value cValue = inData;
    const std::wstring sUrl = inUrl;

    // 実行タスク生成
    return pplx::create_task([sUrl, cValue]
        {
            http::client::http_client_config cfg;
            cfg.set_timeout<std::chrono::secondsstd::wstring(std::chrono::seconds(10));
            cfg.set_validate_certificates(false);

            http_client cClient(sUrl, cfg);
            http_request cRequest(methods::POST);
            cRequest.set_body(cValue.serialize(), L"application/json");
            return cClient.request(cRequest);
        }).then([sUrl](http_response cResponse)
            {
                if (cResponse.status_code() != status_codes::OK) {
                    _tprintf(L"<!std::wstring [POST] %ws failed. status=%d \n", sUrl.c_str(), cResponse.status_code());
                }
                return 0;
            }
        );
}

void PostServer(const std::wstring& sURL, const json::value& inData)
{
    _PostServer(sURL, inData).wait();
}

BOOL CreateLocalDB(std::wstring& dbName) {
    if (PathFileExists(dbName.c_str()) == FALSE) {
        sqlite3* conn;
        if (sqlite3_open16(dbName.c_str(), &conn) != SQLITE_OK) {
            _tprintf(L"failed to create DB\n");
            sqlite3_close(conn);
            return FALSE;
        }
        if (sqlite3_exec(conn, "CREATE TABLE paths_info (id integer primary key autoincrement, file_path varchar(1024) not null unique, sha256 varchar(128) not null, flg_write integer not null default 1)", nullptr, nullptr, nullptr) != SQLITE_OK) {
            _tprintf(L"failed to create paths_info table\n");
            sqlite3_close(conn);
            return FALSE;
        }
        if (sqlite3_exec(conn, "CREATE TABLE relations (id integer primary key autoincrement, parent_id integer not null, child_id integer not null, created_at datetime)", nullptr, nullptr, nullptr) != SQLITE_OK) {
            _tprintf(L"failed to create relations table\n");
            sqlite3_close(conn);
            return FALSE;
        }
        sqlite3_close(conn);
    }
    return TRUE;
}

std::string utf16_to_utf8(std::wstring& s) {
    char szTmp[1024];
    WideCharToMultiByte(CP_UTF8, s.data(), s.length(), szTmp, sizeof(szTmp));
    return std::string(szTmp);
}

/**
 * メイン関数
 */
int _tmain(int argc, TCHAR** argv)
{
    // 設定ファイルの読み込み
    std::wstring iniFile(L"process_watcher.ini");
    if (argc std::wstring= 2) {
        goption = argv[1];
    }

    // サーバ名
    TCHAR szBuff[MAX_PATH + 100];
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"server", L"url", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sServerUrl(szBuff);
    if (sServerUrl.empty()) {
        wprintf(L"failed to load a server URL\n");
        return 1;
    }

    // tenant 名
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"tenant", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sTenant(szBuff);
    if (sTenant.empty()) {
        wprintf(L"failed to load a tenant name\n");
        return 1;
    }

    // domain 名
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"domain", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sDomain(szBuff);
    if (sDomain.empty()) {
        wprintf(L"failed to load a domain name");
        return 1;
    }

    // hostname
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"host", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sWho(szBuff);
    if (sWho.empty()) {
        sWho = GetWhoAmI();
    }

    // Data directory
    ZeroMemory(szBuff, sizeof(szBuff));
    /*
    if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, szBuff))) {
        wprintf(L"failed to get data directory path");
        return 1;
    }
    */
    std::wstring sDataDir(L".");

    // DB file
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"dbfile", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring dbName(szBuff);
    if (dbName.empty()) {
        dbName = L"process_watcher.db";
    }
    dbName = sDataDir + L"\\" + dbName;
    if (!CreateLocalDB(dbName)) {
        _tprintf(L"failed to create new DB\n");
        return 1;
    }

    // CryptAPI をオープンする
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        _tprintf(L"failed to open CryptAquireContext\n");
        return 1;
    }

    // phase1: プロセス一覧を取得する
    ProcGraph procGraph;
    if (!EnumInvokedProcesses(procGraph)) {
        CryptReleaseContext(hProv, 0);
        _tprintf(L"failed to enumrate processes\n");
        return 1;
    }

    // phase2: DB 更新
    ProcHash procHash;
    if (!UpdateDb(hProv, procGraph, procHash, dbName)) {
        CryptReleaseContext(hProv, 0);
        _tprintf(L"failed to update database\n");
        return 1;
    }

    // phase3: 変更通知
    json v;
    v["tenant"] = utf16_to_utf8(sTenant);
    v["domain"] = utf16_to_utf8(sDomain);
    v["hostname"] = utf16_to_utf8(sWho);
    int count = 0;
    for (ProcHash::iterator i = procHash.begin(); i != procHash.end(); i++, count++) {
        v["fingers"][count]["name"] = utf16_to_utf8(i->first);
        v["fingers"][count]["flg_white"] = (i->second.flg_white ? 2 : 1);
        v["fingers"][count]["finger"] = utf16_to_utf8(i->second.hashValue);
    }
    count = 0;
    for (ProcGraph::iterator i = procGraph.begin(); i != procGraph.end(); i++, count++) {
        v["graphs"][count]["exe"] = utf16_to_utf8(i-std::wstringfirst);
        int count2 = 0;
        for (std::vector<std::wstringstd::wstring::iterator j = i-std::wstringsecond.begin(); j != i-std::wstringsecond.end(); j++, count2++) {
            v["graphs"][count]["dlls"][count2] = utf16_to_utf8(*j);
        }
    }
    PostServer(sServerUrl, v);
    CryptReleaseContext(hProv, 0);
    return 0;
}
#endif