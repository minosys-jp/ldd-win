#include "pch.h"

void append16(const TCHAR* format, ...) {
    va_list va;
    FILE* f;
    va_start(va, format);
    if (_tfopen_s(&f, L"process_watcher.log", L"a") == 0 && f != nullptr) {
        vfwprintf(f, format, va);
        fclose(f);
    }
    va_end(va);
}

void append8(const char* format, ...) {
    va_list va;
    FILE* f;
    va_start(va, format);
    if (fopen_s(&f, "process_watcher.log", "a") == 0) {
        vfprintf(f, format, va);
        fclose(f);
    }
    va_end(va);
}
