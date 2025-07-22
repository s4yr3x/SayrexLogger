// browser_inject.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <tlhelp32.h>
#include <Rpc.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <optional>
#include <map>
#include <memory>
#include "syscalls.h"
#include <cstdint>

#define CHACHA20_IMPLEMENTATION
#include "..\..\..\libs\chacha\chacha20.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static const uint8_t g_decryptionKey[32] = {
    // [BrowserInject] This functionality is part of the full version only. 
    };

static const uint8_t g_decryptionNonce[12] = {
    // [BrowserInject] This functionality is part of the full version only.
    };

namespace fs = std::filesystem;

constexpr DWORD DLL_COMPLETION_TIMEOUT_MS = 60000;
constexpr DWORD BROWSER_INIT_WAIT_MS = 3000;
constexpr DWORD INJECTOR_REMOTE_THREAD_WAIT_MS = 15000;
constexpr DWORD EDGE_INIT_WAIT_MS = 15000;

struct HandleGuard
{
    HANDLE h_ = nullptr;
    HandleGuard() = default;
    explicit HandleGuard(HANDLE h) : h_((h == INVALID_HANDLE_VALUE) ? nullptr : h) {}
    ~HandleGuard()
    {
        if (h_)
            CloseHandle(h_);
    }
    HANDLE get() const { return h_; }
    void reset(HANDLE h = nullptr)
    {
        if (h_)
            CloseHandle(h_);
        h_ = (h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }
    explicit operator bool() const { return h_ != nullptr; }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    HandleGuard& operator=(HandleGuard&& other) noexcept
    {
        if (this != &other)
        {
            if (h_)
                CloseHandle(h_);
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }
};

namespace Injector
{

    struct Configuration
    {
        bool autoStartBrowser = false;
        bool verbose = false;
        fs::path outputPath;
        std::string browserDisplayName;
        std::wstring browserType;
        std::wstring browserProcessName;
        std::wstring browserDefaultExePath;
    };

    namespace Utils
    {
        std::string WStringToUtf8(std::wstring_view w_sv)
        {
            // [BrowserInject] This functionality is part of the full version only.
        }

        struct EmbeddedResource
        {
            LPVOID pData;
            DWORD dwSize;
        };

        std::optional<EmbeddedResource> GetEmbeddedResource(LPCWSTR lpName, LPCWSTR lpType)
        {
            // [BrowserInject] This functionality is part of the full version only.
            //return EmbeddedResource{  pData, dwSize};
            return EmbeddedResource{};
        }

        void ChaCha20Decrypt(std::vector<BYTE>& data)
        {
            if (data.empty())
                return;
            chacha20_xor(g_decryptionKey, g_decryptionNonce, data.data(), data.size(), 0);
        }

        std::wstring GenerateUniquePipeName()
        {
            // [BrowserInject] This functionality is part of the full version only.
        }

        std::string PtrToHexStr(const void* ptr)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
            return oss.str();
        }

        std::string NtStatusToString(NTSTATUS status)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << status;
            return oss.str();
        }

        std::string Capitalize(std::string s)
        {
            if (!s.empty())
            {
                s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
            }
            return s;
        }
    }

    namespace Process
    {
        constexpr USHORT MyArch =
#if defined(_M_IX86)
            IMAGE_FILE_MACHINE_I386
#elif defined(_M_X64)
            IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM64)
            IMAGE_FILE_MACHINE_ARM64
#else
            IMAGE_FILE_MACHINE_UNKNOWN
#endif
            ;

        const char* ArchName(USHORT m)
        {
            switch (m)
            {
            case IMAGE_FILE_MACHINE_I386:
                return "x86";
            case IMAGE_FILE_MACHINE_AMD64:
                return "x64";
            case IMAGE_FILE_MACHINE_ARM64:
                return "ARM64";
            default:
                return "Unknown";
            }
        }

        bool GetProcessArchitecture(HANDLE hProc, USHORT& arch)
        {
            auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
            if (fnIsWow64Process2)
            {
                USHORT processMachine = 0, nativeMachine = 0;
                if (!fnIsWow64Process2(hProc, &processMachine, &nativeMachine))
                    return false;
                arch = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processMachine;
                return true;
            }
            BOOL isWow64 = FALSE;
            if (!IsWow64Process(hProc, &isWow64))
                return false;
#if defined(_M_X64)
            arch = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
            arch = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_IX86)
            arch = IMAGE_FILE_MACHINE_I386;
#else
            return false;
#endif
            return true;
        }

        bool CheckArchMatch(HANDLE hProc)
        {
            USHORT targetArch = 0;
            if (!GetProcessArchitecture(hProc, targetArch))
            {
                return false;
            }
            if (targetArch != MyArch)
            {
                return false;
            }
            return true;
        }

        std::optional<DWORD> GetProcessIdByName(const std::wstring& procName)
        {
            HandleGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!snap)
                return std::nullopt;

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snap.get(), &entry))
            {
                do
                {
                    if (procName == entry.szExeFile)
                    {
                        return entry.th32ProcessID;
                    }
                } while (Process32NextW(snap.get(), &entry));
            }
            return std::nullopt;
        }

        std::string GetProcessVersion(const std::wstring& exePath)
        {
            // [BrowserInject] This functionality is part of the full version only.
            return "N/A";
        }

        bool StartProcess(const std::wstring& exePath, DWORD& outPid)
        {
            // [BrowserInject] This functionality is part of the full version only.
        }

        namespace RDI
        {
            DWORD RvaToOffset(DWORD rva, PIMAGE_NT_HEADERS64 ntHeaders, LPCVOID fileBase)
            {
                // [BrowserInject] This functionality is part of the full version only.
                return 0;
            }

            DWORD GetReflectiveLoaderFileOffset(LPCVOID fileBuffer, USHORT expectedMachine)
            {
                // [BrowserInject] This functionality is part of the full version only.
                return 0;
            }

            bool Inject(HANDLE proc, const std::vector<BYTE>& dllBuffer, USHORT targetArch, LPVOID lpDllParameter)
            {
                // [BrowserInject] This functionality is part of the full version only.
            }
        }

        class PipeCommunicator
        {
        public:
            explicit PipeCommunicator(const std::wstring& pipeName) : m_pipeName(pipeName),
                m_pipeNameUtf8(Utils::WStringToUtf8(pipeName)) {
            }

            bool Create()
            {
                // [BrowserInject] This functionality is part of the full version only.
                return true;
            }

            bool WaitForConnection()
            {
                // [BrowserInject] This functionality is part of the full version only.
                return true;
            }

            bool SendInitialData(bool isVerbose, const fs::path& outputPath)
            {
                // [BrowserInject] This functionality is part of the full version only.

                return true;
            }

            void RelayMessagesUntilComplete()
            {
                // [BrowserInject] This functionality is part of the full version only.
            }

        private:
            bool WritePipeMessage(const std::string& msg)
            {
                DWORD bytesWritten = 0;
                if (!WriteFile(m_pipeHandle.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &bytesWritten, nullptr) ||
                    bytesWritten != (msg.length() + 1))
                {
                    return false;
                }
                return true;
            }

            std::wstring m_pipeName;
            std::string m_pipeNameUtf8;
            HandleGuard m_pipeHandle;
        };

        std::optional<Configuration> ParseArguments(int argc, wchar_t* argv[])
        {
            Configuration config;

            for (int i = 1; i < argc; ++i)
            {
                std::wstring_view arg = argv[i];
                if (arg == L"-s")
                    config.autoStartBrowser = true;
                else if (config.browserType.empty() && !arg.empty() && arg[0] != L'-')
                    config.browserType = arg;
                else
                {
                    return std::nullopt;
                }
            }

            if (config.browserType.empty())
            {
                return std::nullopt;
            }
            std::transform(config.browserType.begin(), config.browserType.end(), config.browserType.begin(), ::towlower);

            const std::map<std::wstring, std::pair<std::wstring, std::wstring>> browserMap = {
                {L"chrome", {L"chrome.exe", L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}},
                {L"brave", {L"brave.exe", L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}},
                {L"edge", {L"msedge.exe", L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"}} };

            auto it = browserMap.find(config.browserType);
            if (it == browserMap.end())
            {
                return std::nullopt;
            }
            config.browserProcessName = it->second.first;
            config.browserDefaultExePath = it->second.second;
            config.browserDisplayName = Utils::Capitalize(Utils::WStringToUtf8(config.browserType));

            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);
            config.outputPath = fs::path(tempPath) / "Browser_log";

            return config;
        }

    }
        int Run(int argc, wchar_t* argv[])
        {
            // [BrowserInject] This functionality is part of the full version only.
            return 0;
        }
    }
int InjectMain(int argc, wchar_t* argv[])
{
    return Injector::Run(argc, argv);
}