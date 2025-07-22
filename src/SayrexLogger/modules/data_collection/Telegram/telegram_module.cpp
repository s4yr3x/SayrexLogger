// telegram_module.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "telegram_module.h"

#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <psapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

std::wstring GetAppDataPath() {
    wchar_t path[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path);
    return std::wstring(path);
}

bool KillTelegramProcessAndGetPath(fs::path& outPath) {
    // [TelegramModule] This functionality is part of the full version only.
    return true;
}

bool ExtractTelegramSession() {
    // [TelegramModule] This functionality is part of the full version only.
    return true;
}