#pragma once
#include <winsock2.h>
#include <windows.h>
#include "sqlite3.h"
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdarg.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <unordered_map>
#include <regex>
#include <set>
#include <assert.h>

#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")
