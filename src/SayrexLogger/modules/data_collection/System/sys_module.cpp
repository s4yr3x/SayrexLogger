//sys_module.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <tchar.h>
#include <sysinfoapi.h>
#include <VersionHelpers.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <comdef.h>
#include <Wbemidl.h>
#include <Lmcons.h>
#include <winreg.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace fs = std::filesystem;

std::string GetUsername() {
    char username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    GetUserNameA(username, &size);
    return std::string(username);
}

std::string GetComputerNameStr() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    return std::string(computerName);
}

std::string GetLocalIP() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) return "Unavailable";

    addrinfo hints{}, * info;
    hints.ai_family = AF_INET;

    if (getaddrinfo(hostname, NULL, &hints, &info) != 0) return "Unavailable";

    char ip[INET_ADDRSTRLEN];
    sockaddr_in* addr = (sockaddr_in*)info->ai_addr;
    inet_ntop(AF_INET, &(addr->sin_addr), ip, sizeof(ip));
    freeaddrinfo(info);
    return std::string(ip);
}

std::string GetMAC() {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD bufLen = sizeof(AdapterInfo);
    if (GetAdaptersInfo(AdapterInfo, &bufLen) != NO_ERROR) return "Unavailable";

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;

    char mac[18];
    sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
        pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2],
        pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

    return std::string(mac);
}

std::string GetOSInfo() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    std::ostringstream ss;

    if (IsWindows10OrGreater()) {
        ss << "Windows 10 or later";
    }
    else if (IsWindows8Point1OrGreater()) {
        ss << "Windows 8.1 or later";
    }
    else if (IsWindows8OrGreater()) {
        ss << "Windows 8 or later";
    }
    else if (IsWindows7OrGreater()) {
        ss << "Windows 7 or later";
    }
    else if (IsWindowsVistaOrGreater()) {
        ss << "Windows Vista or later";
    }
    else if (IsWindowsXPOrGreater()) {
        ss << "Windows XP or later";
    }
    else {
        ss << "Unknown Windows version";
    }

    ss << ", Build " << si.dwProcessorType;
    ss << ", " << (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");

    return ss.str();
}

std::string GetCPUName() {
    HKEY hKey;
    char cpuName[128];
    DWORD bufLen = sizeof(cpuName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)cpuName, &bufLen);
        RegCloseKey(hKey);
        return cpuName;
    }
    return "Unknown CPU";
}

std::string GetRAMAmount() {
    MEMORYSTATUSEX statex{};
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    DWORDLONG memMB = statex.ullTotalPhys / (1024 * 1024);
    return std::to_string(memMB) + " MB";
}

std::string GetSystemUptime() {
    DWORD uptime_ms = GetTickCount();
    int seconds = uptime_ms / 1000;
    int minutes = seconds / 60;
    int hours = minutes / 60;
    int days = hours / 24;

    char buffer[64];
    sprintf_s(buffer, "%d days, %d hours, %d minutes", days, hours % 24, minutes % 60);
    return buffer;
}

std::string GetAntivirusName() {
    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return "Unavailable";

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) return "Unavailable";

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) return "Unavailable";

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"),
        NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) return "Unavailable";

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM AntiVirusProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);

    std::string result = "None";
    if (SUCCEEDED(hres)) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (!uReturn) break;

            VARIANT vtProp;
            hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                result = _bstr_t(vtProp.bstrVal);
                VariantClear(&vtProp);
            }
            pclsObj->Release();
        }
    }

    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    CoUninitialize();

    return result;
}

std::string GetHWID() {
    HKEY hKey;
    char buffer[256];
    DWORD size = sizeof(buffer);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return buffer;
        }
        RegCloseKey(hKey);
    }
    return "Unknown";
}

void DumpSystemInfo() {
    try {
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        fs::path system_log_dir = fs::path(tempPath) / "System_log";
        fs::create_directories(system_log_dir);

        std::ofstream out(system_log_dir / "info.txt");

        out << "[User Information]\n";
        out << "Username: " << GetUsername() << "\n";
        out << "Computer Name: " << GetComputerNameStr() << "\n\n";

        out << "[System Information]\n";
        out << "OS: " << GetOSInfo() << "\n";
        out << "CPU: " << GetCPUName() << "\n";
        out << "RAM: " << GetRAMAmount() << "\n";
        out << "Uptime: " << GetSystemUptime() << "\n";
        out << "HWID: " << GetHWID() << "\n";
        out << "Antivirus: " << GetAntivirusName() << "\n\n";

        out << "[Network Information]\n";
        out << "Local IP: " << GetLocalIP() << "\n";
        out << "MAC Address: " << GetMAC() << "\n";

        out.close();
    }
    catch (...) {
        MessageBoxA(0, "Failed to collect system info", "System Log", MB_ICONERROR);
    }
}
