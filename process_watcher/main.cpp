#include "pch.h"
#include <Psapi.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <winternl.h>

using json = nlohmann::json;

struct ProcHashItem {
    std::wstring filename;
    std::wstring hashValue;
    DWORD proc_id;
    int db_id;
    std::set<int> child_inds;   // vector index
    std::set<int> child_ids;    // DB id   
    ProcHashItem() : filename(), hashValue(), proc_id(0), db_id(0), child_inds(), child_ids() {}
    ProcHashItem(const std::wstring& filename, DWORD proc_id) : filename(filename), proc_id(proc_id), db_id(0), hashValue(), child_inds(), child_ids() {}
};
typedef std::vector<ProcHashItem> ProcHash;
typedef std::unordered_map <std::wstring, int> ProcReverseHash;

std::string utf16_to_utf8(const std::wstring& s);
std::wstring utf8_to_utf16(const std::string& s);
std::string tls_post(const std::wstring& url, const std::wstring &auth, const json & json);
void append8(const char* fmt, ...);
void append16(const TCHAR* fmt, ...);

void clear16() {
    FILE* f;
    if (_tfopen_s(&f, L"process_watcher.log", L"w") == 0 && f != nullptr) {
        fclose(f);
    }
}

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
        append8("Cannot map a file with a length of zero.\n");
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

#define ASSERT(x) if (!(x)) { return FALSE; }
char TRAP_INSTRUCT[] = { (char)0xcc };

/**
 * プロセスが依存している DLL を列挙する
 */
int GetProcNameLinks(LPTSTR lpszProcName, std::set <std::wstring>* lpProcListItem)
{
    TCHAR buf[0x200], OutputBuf[MAX_PATH];
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS ImageNtHeaders;
    HANDLE StdoutHandle, StderrHandle;
    HANDLE FileHandle;
    DWORD Dresult;
    SIZE_T result, EntryPoint, ImageBaseAddress, PebAddress, PEB_LDR_DATA, InMemoryOrderModuleList, address, next, head;
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
    std::pair<std::set<std::wstring>::iterator, bool> res(lpProcListItem->end(), false);

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
        WaitForDebugEvent(&DebugEv, 5000);
        // Process the debugging event code.
        if (DebugEv.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                append8("EXCEPTION_ACCESS_VIOLATION:    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_BREAKPOINT:

                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                append8("EXCEPTION_DATATYPE_MISALIGNMENT:    The thread tried to read or write data that is misaligned on hardware that does not provide alignment. "
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
                append8("EXCEPTION_FLT_INVALID_OPERATION:    This exception represents any floating-point exception not included in this list.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_FLT_STACK_CHECK:
                append8("EXCEPTION_FLT_STACK_CHECK:    The stack overflowed or underflowed as the result of a floating-point operation.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_ILLEGAL_INSTRUCTION:
                append8("EXCEPTION_ILLEGAL_INSTRUCTION:    The thread tried to execute an invalid instruction.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_IN_PAGE_ERROR:
                append8("EXCEPTION_IN_PAGE_ERROR:    The thread tried to access a page that was not present, and the system was unable to load the page."
                    " For example, this exception might occur if a network connection is lost while running a program over the network.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_STACK_OVERFLOW:
                append8("EXCEPTION_STACK_OVERFLOW:    The thread used up its stack.\n\n");
                exit(EXIT_SUCCESS);
                break;

            default:
                append8("Unknow Event: %d!\n\n", DebugEv.u.Exception.ExceptionRecord.ExceptionCode);
                //exit(EXIT_FAILURE);
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

                    res = lpProcListItem->insert(OutputBuf);
                }
                else
                {
                    res = lpProcListItem->insert(utf8_to_utf16((LPCSTR)OutputBuf));
                }
            }
            else if (GetModuleFileNameEx(pi.hProcess, (HMODULE)lpBaseOfDll, OutputBuf, sizeof(OutputBuf) / sizeof(TCHAR)) != 0)
            {
                res = lpProcListItem->insert(OutputBuf);
            }
            else if (GetFileNameFromHandle(DebugEv.u.LoadDll.hFile, (TCHAR*)OutputBuf) != 0)
            {
                res = lpProcListItem->insert(OutputBuf);
            }
        }
        else if (DebugEv.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && GetFileNameFromHandle(DebugEv.u.CreateProcessInfo.hFile, (TCHAR*)OutputBuf) != 0)
        {
            res = lpProcListItem->insert(OutputBuf);
        }
        if (res.second) {
            std::string b = utf16_to_utf8(OutputBuf);
            append8("module:%s\n", b.c_str());
        }
        ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0);
    }
    TerminateProcess(pi.hProcess, 0);
    append8("\n");
    return TRUE;
}

/**
 * プロセス番号からプロセス名を取得する
 */
bool PrintProcessNameAndID(DWORD processID, std::wstring& szProcName)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    append8("Process ID: %d\n", processID);

    // Get the process name.
    bool ret = false;
    if (NULL != hProcess)
    {
        HMODULE hMod[1];
        DWORD cbNeeded;

        if (EnumProcessModulesEx(hProcess, hMod, sizeof(hMod),
            &cbNeeded, LIST_MODULES_ALL))
        {
            GetModuleFileNameEx(hProcess, hMod[0], szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
            szProcName = szProcessName;
            std::string sp = utf16_to_utf8(szProcessName);
            append8("Process Name:%s\n", sp.c_str());
        }
        ret = true;
    }

    // Release the handle to the process.
    if (hProcess != NULL) CloseHandle(hProcess);
    return ret;
}

/**
 * データを16進数文字列に変換する
 */
std::wstring raw2hex(const std::vector <BYTE>& raw) {
    static const TCHAR* const radix[] = { L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7", L"8", L"9", L"a", L"b", L"c", L"d", L"e", L"f" };
    std::wstring r;
    for (std::vector <BYTE>::const_iterator i = raw.begin(); i != raw.end(); i++) {
        byte b = (byte)(*i);
        r.append(radix[b >> 4]);
        r.append(radix[b & 15]);
    }
    return r;
}

/**
 * sha256 ハッシュ値を計算する
 */
std::wstring calcHash(BCRYPT_ALG_HANDLE hProv, std::wstring szFileName) {
    FILE* f = nullptr;
    _wfopen_s(&f, szFileName.c_str(), L"rb");
    std::vector <BYTE> finalValue;
    size_t total_len = 0;
    DWORD cbHashObject, cbData, cbHash;

    if (f) {
        if (!BCryptGetProperty(hProv, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) {
            PBYTE pHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
            if (!BCryptGetProperty(hProv, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)) {
                PBYTE pHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
                BCRYPT_HASH_HANDLE hHash = NULL;
                if (!BCryptCreateHash(hProv, &hHash, pHashObject, cbHashObject, NULL, 0, 0)) {
                    BYTE szBuff[1024];
                    size_t len;
                    while ((len = fread(szBuff, sizeof(BYTE), sizeof(szBuff), f)) != 0)
                    {
                        total_len += len;
                        BCryptHashData(hHash, (PBYTE)szBuff, len, 0);
                    }
                    BCryptFinishHash(hHash, pHash, cbHash, 0);
                    finalValue.assign(pHash, pHash + cbHash);
                    BCryptDestroyHash(hHash);
                }
                else {
                    append8("failed to BCryptGetProperty\n");
                }
                HeapFree(GetProcessHeap(), 0, pHash);
            }
            else {
                append8("failed to BCryptGetProperty\n");
            }
            HeapFree(GetProcessHeap(), 0, pHashObject);
        }
        else {
            append8("failed to BCryptGetProperty\n");
        }
        fclose(f);
    }
    else {
        std::string s = utf16_to_utf8(szFileName);
        append8("failed to open %s\n", s.c_str());
    }
    std::wstring hex(raw2hex(finalValue));
    std::string sf, sh;
    sf = utf16_to_utf8(szFileName);
    sh = utf16_to_utf8(hex);
    append8("%s: sha256[%s]\n", sf.c_str(), sh.c_str());
    return hex;
}

/**
 * DB 更新ロジック
 */
sqlite3* UpdateDb(BCRYPT_ALG_HANDLE hProv, ProcHash& procHash, ProcReverseHash &procRevHash, const std::wstring& dbName) {
    // phase1: Hash の計算
    for (ProcHash::iterator i = procHash.begin(); i != procHash.end(); i++) {
        i->hashValue = calcHash(hProv, i->filename);
    }

    // phase2: DB からID取得なければ作成
    sqlite3* conn = NULL;

    if (sqlite3_open16(dbName.c_str(), &conn) != SQLITE_OK) {
        append8("failed to open test.db\n");
        sqlite3_close(conn);
        return NULL;
    }

    if (sqlite3_exec(conn, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
        append8("failed start transaction\n");
        sqlite3_close(conn);
        return NULL;
    }

    ProcHash updatedHash;
    std::unordered_map<int, int> updatedRevHash;

    for (ProcHash::iterator i = procHash.begin(); i != procHash.end(); i++) {
        sqlite3_stmt* stmt;
        wchar_t sql_get_id[] = L"SELECT id, sha256 FROM path_infos WHERE file_path=?";
        if (sqlite3_prepare16(conn, sql_get_id, sizeof(sql_get_id) - 1, &stmt, nullptr) != SQLITE_OK) {
            append8("failed to prepare select SQL\n");
            sqlite3_exec(conn, "ROLLBACK", nullptr, nullptr, nullptr);
            sqlite3_close(conn);
            return NULL;
        }
        sqlite3_bind_text16(stmt, 1, i->filename.data(), i->filename.length(), nullptr);
        int rcode, id = 0;
        bool bChanged = false;
        std::wstring sha256;
        while ((rcode = sqlite3_step(stmt)) == SQLITE_ROW) {
            id = sqlite3_column_int(stmt, 0);
            sha256 = std::wstring((const wchar_t*)sqlite3_column_text16(stmt, 1));
        }
        std::string s = utf16_to_utf8(sha256);
        if (id != 0) {
            append8("found id : %d, sha256: %s\n", id, s.c_str());
        }

        SYSTEMTIME systime;
        GetLocalTime(&systime);
        TCHAR wsystimeStr[30];
        _snwprintf(wsystimeStr, 30, L"%04d-%02d-%02d %02d:%02d:%02d",
            systime.wYear, systime.wMonth, systime.wDay,
            systime.wHour, systime.wMinute, systime.wSecond);
        if (id == 0 && rcode != SQLITE_ERROR) {
            // 新しいファイル
            sqlite3_finalize(stmt);
            wchar_t sql_insert[] = L"INSERT INTO path_infos (file_path, sha256, updated_at) VALUES (?, ?, ?)";
            sqlite3_prepare16(conn, sql_insert, sizeof(sql_insert) - 1, &stmt, nullptr);

            sqlite3_bind_text16(stmt, 1, i->filename.data(), i->filename.length() * sizeof(wchar_t), nullptr);
            sqlite3_bind_text16(stmt, 2, i->hashValue.data(), i->hashValue.length() * sizeof(wchar_t), nullptr);
            sqlite3_bind_text16(stmt, 3, wsystimeStr, _tcslen(wsystimeStr) * sizeof(wchar_t), nullptr);
            sqlite3_step(stmt);
            id = (int)sqlite3_last_insert_rowid(conn);
            bChanged = true;
            std::string htmp = utf16_to_utf8(i->hashValue);
            append8("New file: id:%d, sha256: %s\n", id, htmp.c_str());
        }
        else if (id != 0) {
            // 既出の場合は時刻を更新する
            sqlite3_finalize(stmt);
            wchar_t sql_insert[] = L"UPDATE path_infos SET updated_at=? WHERE id=?";
            sqlite3_prepare16(conn, sql_insert, sizeof(sql_insert) - 1, &stmt, nullptr);
            sqlite3_bind_text16(stmt, 1, wsystimeStr, _tcslen(wsystimeStr) * sizeof(wchar_t), nullptr);
            sqlite3_bind_int(stmt, 2, id);
            sqlite3_step(stmt);
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_finalize(stmt);

        i->db_id = id;
        updatedHash.push_back(*i);
        updatedRevHash[i->db_id] = updatedHash.size() - 1;
    }
    append8("#phase2 finished\n");

    procHash = updatedHash;
    append8("DB updated\n");
    return conn;
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
    return TEXT("<unknown>");
}

/**
 * 起動している全てのプロセス名を取得する
 */
bool EnumInvokedProcesses(ProcHash &procHash, ProcReverseHash &procRevHash) {
    DWORD aProcesses[2048], cbNeeded, cProcesses;
    if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded) == FALSE) {
        append8("failed to EnumProcess\n");
        return false;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < cProcesses; i++) {
        std::wstring dst;
        if (PrintProcessNameAndID(aProcesses[i], dst)) {
            if (procRevHash.find(dst) == procRevHash.end()) {
                procHash.push_back(ProcHashItem(dst, aProcesses[i]));
                procRevHash[dst] = procHash.size() - 1;
            }
            std::set<std::wstring> children;
            // Cortana が勝手に活性化されるのを防止するおまじない
            if (dst.find(L"Cortana") == std::string::npos) {
                if (GetProcNameLinks((LPTSTR)dst.c_str(), &children) != TRUE) {
                    append8("GetProcNameLinks failed for %d\n", aProcesses[i]);
                }
                else {
                    int p_index = procRevHash.find(dst)->second;
                    for (std::set<std::wstring>::const_iterator j = children.cbegin(); j != children.cend(); j++) {
                        if (procRevHash.find(*j) == procRevHash.end()) {
                            procHash.push_back(ProcHashItem(*j, 0));
                            procRevHash[*j] = procHash.size() - 1;
                        }
                        int d_index = procRevHash.find(*j)->second;
                        if (procHash[p_index].child_inds.find(d_index) == procHash[p_index].child_inds.end()) {
                            procHash[p_index].child_inds.insert(d_index);
                        }
                    }
                }
            }
        }
        else {
            append8("PrintProcessNameAndId failed for %d\n", aProcesses[i]);
        }
    }
    return true;
}

BOOL CreateLocalDB(const std::wstring& dbName) {
    if (PathFileExists(dbName.c_str()) == FALSE) {
        sqlite3* conn;
        if (sqlite3_open16(dbName.c_str(), &conn) != SQLITE_OK) {
            append8("failed to create DB\n");
            sqlite3_close(conn);
            return FALSE;
        }
        if (sqlite3_exec(conn, "CREATE TABLE path_infos (id integer primary key autoincrement, file_path varchar(1024) not null unique, sha256 varchar(128) not null, flg_white integer not null default 1, updated_at datetime not null)", nullptr, nullptr, nullptr) != SQLITE_OK) {
            append8("failed to create paths_info table\n");
            sqlite3_close(conn);
            return FALSE;
        }
        sqlite3_close(conn);
    }
    return TRUE;
}

void killBlackProcesses(json json) {
    auto blacks = json.find("kill_black_processes");
    for (auto black = blacks->cbegin(); blacks != blacks->cend(); blacks++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
            PROCESS_TERMINATE |
            PROCESS_VM_READ,
            FALSE, *black);
        if (hProcess) {
            TerminateProcess(hProcess, 255);
            CloseHandle(hProcess);
        }
    }
}

int toxdigit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return 0;
}
size_t getChunkLen(std::string::const_iterator& src, const std::string& s) {
    size_t len = 0;
    while (src != s.cend() && isxdigit(*src)) {
        len *= 16;
        len += toxdigit(*src);
        src++;
    }
    if (src != s.cend() && *src == '\r') src++;
    if (src != s.cend() && *src == '\n') src++;
    return len;
}

std::string decodeChunkedStr(const std::string& src) {
    std::string dst;
    std::string::const_iterator i = src.cbegin();
    size_t len = 0;
    while ((len = getChunkLen(i, src)) > 0) {
        src.substr(i - src.cbegin(), len);
        i += len;
    }
    return dst;
}

/**
 * メイン関数
 */
int _tmain(int argc, TCHAR** argv)
{
    setlocale(LC_ALL, "Japanese");
    clear16();

    // 設定ファイルの読み込み
    std::wstring iniFile(L"process_watcher.ini");

    // サーバ名
    TCHAR szBuff[MAX_PATH + 100];
    ZeroMemory(szBuff, sizeof(szBuff));
    GetCurrentDirectory(sizeof(szBuff) / sizeof(TCHAR), szBuff);
    PathAppend(szBuff, iniFile.c_str());
    iniFile = std::wstring(szBuff);

    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"server", L"url", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sServerUrl(szBuff);
    if (sServerUrl.empty()) {
        append8("failed to load a server URL\n");
        return 1;
    }

    // authorization header
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"server", L"auth", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sAuth(szBuff);

    // tenant 名
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"tenant", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sTenant(szBuff);
    if (sTenant.empty()) {
        append8("failed to load a tenant name\n");
        return 1;
    }

    // domain 名
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"domain", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sDomain(szBuff);
    if (sDomain.empty()) {
        append8("failed to load a domain name");
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
    /*;
    if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, szBuff))) {
        wprintf(L"failed to get data directory path");
        return 1;
    }
    */
    TCHAR szBuffDir[MAX_PATH + 100];
    ZeroMemory(szBuffDir, sizeof(szBuffDir));
    GetCurrentDirectory(sizeof(szBuffDir) / sizeof(TCHAR), szBuffDir);

    // DB file
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"dbfile", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring dbName(szBuff);
    if (dbName.empty()) {
        dbName = L"process_watcher.db";
        PathAppend(szBuffDir, dbName.c_str());
        dbName = std::wstring(szBuffDir);
    }
    else if (dbName.at(0) != L'\\' && dbName.at(0) != L'/') {
        PathAppend(szBuffDir, dbName.c_str());
        dbName = std::wstring(szBuffDir);
    }
    if (!CreateLocalDB(dbName)) {
        append8("failed to create new DB\n");
        return 1;
    }

    // CryptAPI をオープンする
    BCRYPT_ALG_HANDLE hProv;
    if (BCryptOpenAlgorithmProvider(&hProv,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0))
    {
        append8("failed to open CryptAquireContext\n");
        return 1;
    }

    // phase1: プロセス一覧を取得する
    ProcHash procHash;
    ProcReverseHash procRevHash;

    if (!EnumInvokedProcesses(procHash, procRevHash)) {
        BCryptCloseAlgorithmProvider(hProv, 0);
        append8("failed to enumerate processes\n");
        return 1;
    }

    // phase2: DB 更新
    sqlite3* conn;
    if ((conn = UpdateDb(hProv, procHash, procRevHash, dbName)) == NULL) {
       BCryptCloseAlgorithmProvider(hProv, 0);
        append8("failed to update database\n");
        return 1;
    }

    // phase3: 変更通知
    append8("#Phase3 started\n");
    json v;
    append8("pass1\n");
    v["tenant"] = utf16_to_utf8(sTenant);
    v["domain"] = utf16_to_utf8(sDomain);
    v["hostname"] = utf16_to_utf8(sWho);
    int count = 0;
    for (ProcHash::iterator i = procHash.begin(); i != procHash.end(); i++, count++) {
        v["fingers"][count]["dbid"] = i->db_id;
        v["fingers"][count]["name"] = utf16_to_utf8(i->filename);
        if (!i->hashValue.empty()) {
            v["fingers"][count]["finger"] = utf16_to_utf8(i->hashValue);
        }
        else {
            v["fingers"][count]["finger"] = "";
        }
    }
    count = 0;
    for (ProcHash::iterator i = procHash.begin(); i != procHash.end(); i++) {
        if (i->proc_id != (DWORD)0) {
            v["graphs"][count]["exe"] = i->db_id;
            if (!i->child_ids.empty()) {
                v["graphs"][count]["dlls"] = i->child_ids;
            }
            else {
                v["graphs"][count]["dlls"] = json::array();
            }
            count++;
        }
    }
    append8("passed: %s\n", v.dump().c_str());
    count = 0;
    for (count = 0; count < 10; count++) {
        std::string r = tls_post(sServerUrl, sAuth, v);
        append8("Result: %s\n", r.c_str());
        if (r.length() > 0) {
            size_t tpos = r.find(std::string("\r\n\r\n"));
            std::string headerStr = r.substr(0, tpos);
            std::string jsonStr = r.substr(tpos + 4);
            if (headerStr.find("chunked") > 0) {
                jsonStr = decodeChunkedStr(jsonStr);
            }
            json json = json::parse(jsonStr);
            if (json[0] == true) {
                // phase4: Black process の抹消
                if (json[1].find("kill_black_processes") != json[1].cend()) {
                    killBlackProcesses(json[1]);
                }
            }
            count++;
            break;
        }
        Sleep(2000);
    }
    BCryptCloseAlgorithmProvider(hProv, 0);
    if (count > 0) {
        sqlite3_exec(conn, "COMMIT", nullptr, nullptr, nullptr);
    }
    else {
        sqlite3_exec(conn, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    sqlite3_close(conn);
    append8("Terminated\n");
    return 0;
}
