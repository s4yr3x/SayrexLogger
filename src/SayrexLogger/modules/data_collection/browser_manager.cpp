// browser_manager.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "browser_manager.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <filesystem>

using namespace std::filesystem;

static const struct {
    const wchar_t* type;
    const wchar_t* paths[2]; 
} kBrowserCatalog[] = {
    { L"chrome", {
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    }},
    { L"brave", {
        L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    }},
    { L"edge", {
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    }}
};

static bool IsProcessRunning(const std::wstring& exeName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }
    do {
        if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return false;
}

std::vector<BrowserInfo> DetectBrowsers()
{
    std::vector<BrowserInfo> result;
    for (auto& b : kBrowserCatalog)
    {
        for (auto* path : b.paths)
        {
            if (path && exists(path))
            {
                std::wstring exeName = std::filesystem::path(path).filename().wstring();
                bool running = IsProcessRunning(exeName);
                result.push_back({ b.type, path, running });
                break;
            }
        }
    }
    return result;
}
