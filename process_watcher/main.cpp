#include "pch.h"
#include <Psapi.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <winternl.h>
#include <tlhelp32.h>

using json = nlohmann::json;

struct ProcHashItem {
    std::wstring filename;
    std::wstring hashValue;
    DWORD proc_id;
    std::set<DWORD> proc_ids;
    int db_id;
    bool bExe;
    std::set<int> child_ids;    // vector id   
    ProcHashItem() : filename(), hashValue(), proc_id(0), proc_ids(), db_id(0), bExe(true), child_ids() {}
    ProcHashItem(const std::wstring& filename, DWORD proc_id, int db_id, bool bExe) : filename(filename), proc_id(proc_id), db_id(db_id), hashValue(), bExe(bExe), child_ids() {
        this->proc_ids.insert(proc_id);
    }
};
typedef std::vector<ProcHashItem> ProcHash;
typedef std::unordered_map <std::wstring, int> ProcReverseHash;

std::string utf16_to_utf8(const std::wstring& s);
std::wstring utf8_to_utf16(const std::string& s);
void json_post(std::string& r, const std::wstring& url, const std::wstring &auth, const json & json, const std::wstring &proxy);
void append8(const char* fmt, ...);
void append16(const TCHAR* fmt, ...);
void clear16();
std::wstring asFilename16(LPCTSTR fname);

/**g
 * ファイルハンドルからファイル名を取得する
 * @return TRUE: 取得済み FALSE: 失敗
 */
/*
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
*/

/*
#define ASSERT(x) if (!(x)) { \
if (pi.hProcess != NULL) { append8("Close pi.hProcess, "); TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); } \
if (FileHandle != INVALID_HANDLE_VALUE) { append8("Close FileHandle, "); CloseHandle(FileHandle); } \
append8("assertion failed:%s\n", #x); \
return FALSE; }

char TRAP_INSTRUCT[] = { (char)0xcc };
*/

/**
 * プロセスが依存している DLL を列挙する
 */
/*
int GetProcNameLinks(LPTSTR lpszProcName, std::set <std::wstring>* lpProcListItem)
{
    TCHAR buf[0x200], OutputBuf[MAX_PATH] ;
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS ImageNtHeaders;
    HANDLE StdoutHandle, StderrHandle;
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    SIZE_T result, EntryPoint, ImageBaseAddress, PebAddress, PEB_LDR_DATA, InMemoryOrderModuleList, address, next, head;
    NTSTATUS(__stdcall * NtQueryInformationProcessHook)
        (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    PROCESS_BASIC_INFORMATION Information;
    DEBUG_EVENT DebugEv;
    CHAR* ImageFile;
    LPVOID lpBaseOfDll, lpImageName;
    size_t dwAddrImageName = 0;
    DWORD Dresult;

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
        ZeroMemory(OutputBuf, sizeof(OutputBuf));
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
                append8("Unknown Event: %d!\n\n", DebugEv.u.Exception.ExceptionRecord.ExceptionCode);
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
            std::wstring ss(OutputBuf, _tcslen(OutputBuf));
            std::string b = utf16_to_utf8(ss);
            append8("module:%.*s\n", b.length(), b.data());
        }
        ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0);
    }
    ASSERT(TerminateProcess(pi.hProcess, 0));
    //WaitForSingleObject(pi.hProcess, 1000LL);
    ASSERT(CloseHandle(pi.hProcess));
    ASSERT(CloseHandle(pi.hThread));
    ASSERT(CloseHandle(FileHandle));
    append8("Exit ProcNameLinks\n");
    return TRUE;
}
*/

/**
 * プロセス番号からプロセス名を取得する
 */
/*
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
*/

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
 * ハッシュ更新ロジック
 */
bool UpdateHash(BCRYPT_ALG_HANDLE hProv, ProcHash& procHash, ProcReverseHash &procRevHash) {
    // phase1: Hash の計算
    for (ProcHash::iterator i = procHash.begin(); i != procHash.end(); i++) {
        i->hashValue = calcHash(hProv, i->filename);
    }

    append8("#phase1 finished\n");
    return true;
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

/*
bool isExcludedExe(const std::wstring& dst, const std::wstring& sExclude) {
    std::wstringstream w(sExclude);
    std::wstring s;
    while (std::getline(w, s, L',')) {
        if (dst.find(s) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}
*/

/*
* 指定したプロセスが読み込む DLL を取得する
 */
void EnumDLLChildren(HANDLE hModSnap, int db_id, ProcHash& procHash, ProcReverseHash &procRevHash) {
    MODULEENTRY32 me32 = {};
    me32.dwSize = sizeof(me32);

    while (Module32Next(hModSnap, &me32)) {
        auto f = procRevHash.find(me32.szExePath);
        if (f == procRevHash.end()) {
            ProcHashItem child(me32.szExePath, 0, procHash.size(), false);
            append16(L"New DLL:%ws: %d\n", me32.szExePath, procHash.size());
            procHash[db_id].child_ids.insert(procHash.size());
            procRevHash[me32.szExePath] = procHash.size();
            procHash.push_back(child);
        }
        else {
            procHash[db_id].child_ids.insert(procHash[f->second].db_id);
            append16(L"DLL: %ws: %d\n", me32.szExePath, procHash[f->second].db_id);
        }
    }
    append16(L"\n");
}

/**
 * 起動している全てのプロセス名を取得する
 */
bool EnumInvokedProcesses(ProcHash& procHash, ProcReverseHash& procRevHash) {
    HANDLE hProcSnap;
    HANDLE hProc;
    PROCESSENTRY32 pe32 = {};

    // プロセス一覧を取得する
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        return false;
    }
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return false;
    }
    do {
        HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
        if (hModSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32 = {};
            me32.dwSize = sizeof(me32);
            if (Module32First(hModSnap, &me32)) {
                auto i = procRevHash.find(me32.szExePath);
                if (i == procRevHash.end()) {
                    ProcHashItem item(me32.szExePath, pe32.th32ProcessID, procHash.size(), true);
                    procRevHash[me32.szExePath] = procHash.size();
                    append16(L"====>Process:%ws(%ld) as %d\n", me32.szExePath, pe32.th32ProcessID, procHash.size());
                    procHash.push_back(item);
                    // 読み込んでいる DLL 一覧を取得する
                    EnumDLLChildren(hModSnap, item.db_id, procHash, procRevHash);
                }
                else {
                    procHash[i->second].proc_ids.insert(pe32.th32ProcessID);
                }
            }
            CloseHandle(hModSnap);
        }
    } while (Process32Next(hProcSnap, &pe32));

    CloseHandle(hProcSnap);
    append16(L"finished EnumInvokedProcesses\n");
    return true;
}

/*
bool EnumInvokedProcesses(ProcHash &procHash, ProcReverseHash &procRevHash, const std::wstring &sExclude) {
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
            else {
                // すでに収録済みのプロセスは再収録しない
                continue;
            }
            std::set<std::wstring> children;
            // Cortana が勝手に活性化されるのを防止するおまじない
            if (!isExcludedExe(dst, sExclude)) {
                if (GetProcNameLinks((LPTSTR)dst.c_str(), &children) != TRUE) {
                    append8("GetProcNameLinks failed for %d\n", aProcesses[i]);
                }
                else {
                    int p_index = procRevHash.find(dst)->second;
                    for (std::set<std::wstring>::const_iterator j = children.cbegin(); j != children.cend(); j++) {
                        append16(L"%ws: children:%ws\n", dst.c_str(), j->c_str());
                        if (procRevHash.find(*j) == procRevHash.end()) {
                            procHash.push_back(ProcHashItem(*j, 0));
                            procRevHash[*j] = procHash.size() - 1;
                        }
                        int d_index = procRevHash.find(*j)->second;
                        if (procHash[p_index].child_inds.find(d_index) == procHash[p_index].child_inds.end()) {
                            procHash[p_index].child_inds.insert(d_index);
                            append8("p_index:%d append d_index=%d\n", p_index, d_index);
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
*/

/*
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
*/

void killBlackProcesses(json json, ProcHash &procHash) {
    auto blacks = json.find("kill_black_processes");
    if (blacks == json.cend()) {
        return;
    }
    append8("killBlackProcesses:#1\n");
    for (auto black = blacks->cbegin(); black != blacks->cend(); black++) {
        const ProcHashItem& item = procHash[black->get<int>()];
        append16(L"kill %ws\n", item.filename.c_str());
        for (DWORD proc_id : item.proc_ids) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                PROCESS_TERMINATE |
                PROCESS_VM_READ,
                FALSE, proc_id);
            if (hProcess) {
                append8("Terminate process: proc_id\n", proc_id);
                TerminateProcess(hProcess, 255);
                CloseHandle(hProcess);
            }
        }
    }
    append8("killBlackProcesses:#2\n");
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
        auto chunk = src.substr(i - src.cbegin(), len);
        append8("chunk:%.*s", len, chunk.data());
        dst += chunk;
        i += len;
    }
    return dst;
}

SERVICE_STATUS gSvcStatus;
SERVICE_STATUS_HANDLE gSvcStatusHandle;
HANDLE ghSvcStopEvent = NULL;
DWORD gdwTimeOut = 10;
int gbPublish = 1;
TCHAR gsMyName[MAX_PATH], gsDrive[MAX_PATH], gsDir[MAX_PATH], gsFilename[MAX_PATH], gsExt[MAX_PATH];
DWORD WINAPI SvcCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
VOID SvcMain(DWORD, LPTSTR*);

VOID ReportSvcStatus(DWORD, DWORD, DWORD);
VOID SvcInit(DWORD, LPTSTR*);
VOID SvcMainLoop(DWORD, LPTSTR*);
VOID SvcEnd(DWORD, LPTSTR*);

void UpdatePublish(int nPub) {
    int gbPublishNew = (nPub == 0 ? 0 : 1);
    if (gbPublish != gbPublishNew) {
        append8("gbPublish:%d\n", gbPublish);
        TCHAR szFile[MAX_PATH];
        ZeroMemory(szFile, sizeof(szFile));
        GetCurrentDirectory(MAX_PATH, szFile);
        PathAppend(szFile, L"process_watcher.no");

        if (gbPublishNew) {
            DeleteFile(szFile);
        }
        else {
            HANDLE h = CreateFile(szFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
            else {
                append16(L"CreateFile failed\n");
            }
        }
    }
    gbPublish = gbPublishNew;
    append8("New gbPushlish=%d\n", gbPublish);
}

#define SVCNAME (L"Skyster Monitor Process")

/**
 * ループ内実行関数
 */
int myMain()
{
    setlocale(LC_ALL, "Japanese");

    // 設定ファイルの読み込み
    std::wstring iniFile(asFilename16(L"process_watcher.ini"));

    // サーバ名
    TCHAR szBuff[MAX_PATH + 100];
    ZeroMemory(szBuff, sizeof(szBuff));
    GetCurrentDirectory(sizeof(szBuff) / sizeof(TCHAR), szBuff);
    PathAppend(szBuff, iniFile.c_str());
    iniFile = std::wstring(szBuff);

    // 非通知フラグの有無
    std::wstring noPubFile(asFilename16(L"process_watcher.no"));
    ZeroMemory(szBuff, sizeof(szBuff));
    GetCurrentDirectory(sizeof(szBuff) / sizeof(TCHAR), szBuff);
    PathAppend(szBuff, noPubFile.c_str());
    gbPublish = PathFileExists(szBuff) ? 0 : 1;
    append16(L"gbPublish(%ws):%d\n", szBuff, gbPublish);

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

    // https proxy
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"server", L"proxy", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sProxy(szBuff);

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

    // exclude Exes
    ZeroMemory(szBuff, sizeof(szBuff));
    GetPrivateProfileString(L"system", L"exclude", nullptr, szBuff, sizeof(szBuff) / sizeof(TCHAR), iniFile.c_str());
    std::wstring sExclude(szBuff);

    // Data directory
    /*
    ZeroMemory(szBuff, sizeof(szBuff));
    if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, szBuff))) {
        wprintf(L"failed to get data directory path");
        return 1;
    }
    */
    /*
    TCHAR szBuffDir[MAX_PATH + 100];
    ZeroMemory(szBuffDir, sizeof(szBuffDir));
    GetCurrentDirectory(sizeof(szBuffDir) / sizeof(TCHAR), szBuffDir);
    */
    // DB file
    /*
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
    */

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

    if (gbPublish) {
        if (!EnumInvokedProcesses(procHash, procRevHash)) {
            BCryptCloseAlgorithmProvider(hProv, 0);
            append8("failed to enumerate processes\n");
            return 1;
        }

        // phase2: ハッシュ更新
        if (!UpdateHash(hProv, procHash, procRevHash)) {
            BCryptCloseAlgorithmProvider(hProv, 0);
            append8("failed to update database\n");
            return 1;
        }
    }
    else {
        append16(L"No process watching; just check server command.\n");
    }

    // phase3: 変更通知
    append8("#Phase3 started\n");
    json v;
    append8("pass1\n");
    v["tenant"] = utf16_to_utf8(sTenant);
    v["domain"] = utf16_to_utf8(sDomain);
    v["hostname"] = utf16_to_utf8(sWho);
    v["flg_publish"] = gbPublish;
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
        if (i->bExe) {
            v["graphs"][count]["exe"] = i->db_id;
            append16(L"Proc:%ws: %d(%d)\n", i->filename.c_str(), i->db_id, i->child_ids.size());
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
    for (count = 10; count >= 0; count--) {
        std::string r;
        json_post(r, sServerUrl, sAuth, v, sProxy);
        append8("CP#4\n");
        append8("Result: %lu\n", (uint32_t)r.length());
        if (r.length() > 0) {
            size_t tpos = r.find(std::string("\r\n\r\n"));
            std::string headerStr = r.substr(0, tpos);
            std::string jsonStr = r.substr(tpos + 4);
            if (headerStr.find("chunked") != std::string::npos) {
                jsonStr = decodeChunkedStr(jsonStr);
            }
            append8("returned chunk:%.*s\n", jsonStr.length(), jsonStr.data());
            json json = json::parse(jsonStr);
            if (json[0] == true) {
                // phase4: Black process の抹消
                if (json[1].find("kill_black_processes") != json[1].cend()) {
                    killBlackProcesses(json[1], procHash);
                }
                if (json[1].find("flg_publish") != json[1].cend()) {
                    UpdatePublish(json[1].find("flg_publish")->get<int>());
                }
            }
            else {
                append8("%s", json[1].get<std::string>().c_str());
            }
            append8("kill black processes terminated");
            break;
        }
        Sleep(2000);
    }
    BCryptCloseAlgorithmProvider(hProv, 0);
    append8("Terminated\n");
    return 0;
}

int __cdecl wmain(int argc, TCHAR** argv) {
    if (GetModuleFileNameW(NULL, gsMyName, _countof(gsMyName)) != 0LL) {
        _tsplitpath(gsMyName, gsDrive, gsDir, gsFilename, gsExt);
        _tcscat(gsDrive, gsDir);
    }

    append16(L"program started\n");
    for (int i = 1; i < argc; i++) {
        if (_tcscmp(argv[i], L"-f") == 0) {
            append16(L"service executor mode:%ws\n", argv[i]);
            return myMain();
        }
        if (_tcscmp(argv[i], L"-e") == 0) {
            // フロントエンドモード
            wprintf(L"front end mode\n");
            append16(L"front end mode:%ws\n", argv[i]);
            return myMain();
        }
        if (_tcscmp(argv[1], L"-t") == 0 && i + 1 < argc) {
            i++;
            gdwTimeOut = _ttoi(argv[i]);
        }
        append16(L"%d:%ws\n", i, argv[i]);
    }

    // サービス登録モード
    SERVICE_TABLE_ENTRY DispatchTable[] = {
        { (LPTSTR)SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain},
        { NULL, NULL }
    };

    BOOL dwRet = StartServiceCtrlDispatcherW(DispatchTable);
    append16(L"Registration:%d\n", dwRet);
    return (dwRet == 0) ? 253 : 0;
}

// サービス状態変化時に呼び出される関数
DWORD WINAPI SvcCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        // サービス終了を通知
        SetEvent(ghSvcStopEvent);
        ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);

    default:;
        // Nothing to do
    }
    return NO_ERROR;
}

VOID SvcMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    gSvcStatusHandle = RegisterServiceCtrlHandlerEx(SVCNAME, SvcCtrlHandler, NULL);
    if (gSvcStatusHandle == NULL) {
        append8("failed RegisterServiceCtrlHandlerEx\n");
        return;
    }

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwServiceSpecificExitCode = 0;

    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    SvcInit(dwArgc, lpszArgv);

    SvcMainLoop(dwArgc, lpszArgv);
}

VOID SvcInit(DWORD dwArgc, LPTSTR* lpszArgv) {
    ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ghSvcStopEvent == NULL) {
        ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        append8("failed CreateEvent\n");
        return;
    }

    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
}

BOOL StartChild(PROCESS_INFORMATION &pi) {
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    TCHAR szArg[MAX_PATH];
    _stprintf(szArg, L"%ws -f", gsMyName);
//    _stprintf(szArg, L"c:\\Skyster\\process_watcher\\HelloWorld.exe -ff");
    if (!CreateProcess(NULL, szArg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        append16(L"%ws failed\n", szArg);
        return FALSE;
    }
    clear16();
    append16(L"\"%ws\" started:%lx\n", szArg, GetLastError());
    return TRUE;
}

// メインループ: デフォルトは1周5分。引数 -t <min> で変更可能。
VOID SvcMainLoop(DWORD dwArgc, LPTSTR* lpszArgv) {
    append8("Enter SvcMainLoop\n");
    PROCESS_INFORMATION pi;
    while (1) {
        if (!StartChild(pi)) {
            break;
        }
        // 5 分待つ
        HANDLE hHandles[] = {ghSvcStopEvent, pi.hProcess};
        DWORD r = WaitForMultipleObjects(2, hHandles, FALSE, gdwTimeOut * 60 * 1000);
        if (r == WAIT_TIMEOUT) {
            // タイマー満了
            append16(L"Timeout\n");
            TerminateProcess(pi.hProcess, 0);
            break;
        }
        else if (r == WAIT_OBJECT_0) {
            // 終了イベント
            break;
        }
        else if (r == WAIT_OBJECT_0 + 1) {
            // 子プロセス終了
            DWORD exitCode = (DWORD)-1;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            append16(L"exit code:%lx\n", exitCode);
        }
        else {
            break;
        }

        // 5分待つ
        r = WaitForSingleObject(ghSvcStopEvent, gdwTimeOut * 60 * 1000);
        if (r != WAIT_TIMEOUT) {
            break;
        }
    }
    if (pi.hProcess != NULL) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(ghSvcStopEvent);
    append16(L"Exit SvcMainLoop\n");
    SvcEnd(dwArgc, lpszArgv);
}

VOID SvcEnd(DWORD dwArgc, LPTSTR* lpszArgv) {
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwExitStateCode, DWORD dwWaitHint) {
    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwExitStateCode;
    gSvcStatus.dwWaitHint = dwWaitHint;

    gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP
        | SERVICE_ACCEPT_PAUSE_CONTINUE;
    
    if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED) {
        gSvcStatus.dwCheckPoint = 0;
    }
    else {
        gSvcStatus.dwCheckPoint++;
    }

    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}