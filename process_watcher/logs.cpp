#include "pch.h"
#include <fstream>

std::wstring asFilename16(LPCTSTR fname) {
    TCHAR buf[MAX_PATH];
    int len = _snwprintf_s(buf, _countof(buf), L"%ws%ws", &gsDrive[0], fname);
//    int len = _snwprintf_s(buf, _countof(buf), L"%ws%ws", L"c:\\Skyster\\process_watcher\\", fname);
    return std::wstring(buf, len);
}

std::string asFilename8(LPCSTR fname) {
    char buf[MAX_PATH];
    int len = _snprintf_s(buf, _countof(buf), "%ws%s", &gsDrive[0], fname);
//    int len = _snprintf_s(buf, _countof(buf), "%ws%s", L"c:\\Skyster\\process_watcher\\", fname);
    return std::string(buf, len);
}

void append16(const TCHAR* format, ...) {
    va_list va;
    FILE* f;
    SYSTEMTIME sysTime;
    GetLocalTime(&sysTime);
    va_start(va, format);
    if (_tfopen_s(&f, asFilename16(L"process_watcher.log").c_str(), L"a") == 0 && f != nullptr) {
        fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] ", sysTime.wYear, sysTime.wMonth, sysTime.wDay,
            sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
        vfwprintf(f, format, va);
        fclose(f);
    }
    va_end(va);
}

void append8(const char* format, ...) {
    va_list va;
    FILE* f;
    SYSTEMTIME sysTime;
    GetLocalTime(&sysTime);
    va_start(va, format);
    if (fopen_s(&f, asFilename8("process_watcher.log").c_str(), "a") == 0) {
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ", sysTime.wYear, sysTime.wMonth, sysTime.wDay,
            sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
        vfprintf(f, format, va);
        fclose(f);
    }
    va_end(va);
}

void clear16() {
    FILE* f;
    if (_tfopen_s(&f, asFilename16(L"process_watcher.log").c_str(), L"w") == 0 && f != nullptr) {
        fclose(f);
    }
}

