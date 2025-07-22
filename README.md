# SayrexLogger

## 🚀 Overview

![C++17](https://img.shields.io/badge/language-C++17-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20ARM64-lightgrey.svg)
![Admin Rights](https://img.shields.io/badge/admin%20privileges-NOT%20REQUIRED-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Educational](https://img.shields.io/badge/purpose-educational-red)

## 📌 Project Overview

**SayrexLogger** is a modern, modular C++17-based data extraction utility designed to showcase low-level system interaction, cryptographic analysis, and secure data retrieval — all without relying on third-party frameworks or requiring administrative privileges.

Unlike most open-source "grabber" projects, SayrexLogger emphasizes **offline logging**, not webhook exfiltration. Data is cleanly stored in `%TEMP%` using structured `.txt` and `.json` formats, separated by target application and purpose.

The project demonstrates deep integration with protected storage mechanisms in Chromium-based browsers, Discord, and Telegram, using native Windows cryptographic APIs and key extraction techniques. SayrexLogger serves as both a proof of concept and a flexible educational platform for analyzing endpoint security.

## ⚠️ Disclaimer

> 🧪 This is a **stripped-down PoC version** of SayrexLogger.  
> All potentially malicious modules — such as Discord token grabbing, browser password/cookie/card extraction, Telegram session theft, and advanced bypasses — have been **intentionally removed** from this public release.

This version is focused on showcasing the **overall architecture**, **modular layout**, and **offline logging mechanisms** for educational and demonstration purposes only. No real credential or session data is extracted here.

💡 **Interested in the full version?**  
If you're involved in **red teaming**, **offensive security**, or just curious about the full capabilities (including all private modules) — feel free to reach out:

📬 **Contact**: [@thes4yr3x](https://t.me/thes4yr3x)

> Full access may be granted under certain conditions — for research, education, or professional use.  
> 💰 *Support for this project is appreciated.*

---

## 🧠 Key Features

* ✅ **Runs without administrator rights**
* 🔍 **App-Bound Encryption (ABE) bypass**:

  * Extracts the `master_key` from Chromium's `Local State`
  * Decrypts AES-256-GCM payloads using `CryptUnprotectData` (DPAPI)
* 🧩 **Modular architecture**:

  * Independent modules for Discord, Telegram, Browsers, System fingerprinting
* 🌐 **Browser extraction (Chromium-based)**:

  * Saved cookies (`Cookies` DB)
  * Stored passwords (`Login Data`)
  * Credit card info (`Web Data`)
* 🧪 **Advanced Discord token extraction**:

  * Scans LevelDB for tokens
  * Supports decryption via AES-GCM + DPAPI
  * Validates tokens via Discord API and fetches full user profile
* 📦 **Telegram session theft (tdata)**:

  * Automatically detects and copies session folder
  * Can terminate `Telegram.exe` if active
* 💻 **System fingerprinting**:

  * OS version, architecture, RAM/CPU
  * HWID, MAC, IP address
  * Active antivirus vendor via WMI queries

## ⚙️ Technical Details

*   **Language**: C++17 (compiled with MSVC / Visual Studio)
*   **Dependencies**: None — statically linked, native Windows API usage only
*   **Target platform**: Windows 7+ (tested on Windows 10/11 and ARM64 builds)
*   **Stealth features**: No registry keys, no scheduled tasks, no process injection
*   **Output format**:

  * `.json` for structured browser data (cookies, passwords, cards)
  * `.txt` for system, Discord, Telegram logs


## 🔐 Cryptography Implementation

SayrexLogger implements native, self-contained cryptographic routines including:

* **AES-256-GCM**:

  * Native Windows `bcrypt.dll`-based GCM decryptor
  * Handles SHA1-based Additional Authenticated Data (AAD)
* **DPAPI**:

  * Decrypts master keys and encrypted values using `CryptUnprotectData`
* **Base64 decoding**:

  * Custom base64 decoder to avoid library dependencies
* **ChaCha20**:

  * Used internally for encrypting embedded payloads (via `.rc` resources)

All embedded modules are loaded at runtime using:

```cpp
FindResource → LoadResource → LockResource
```
This enables in-memory execution of DLLs or shellcode without ever touching the disk.

# 🧩 Detailed Module Breakdown

## 🟣 Discord Module

The Discord module performs **disk-level** extraction of tokens across all installations of Discord (stable, PTB, Canary, and custom builds).

**LevelDB scanning**:
- Iterates through `.ldb` and `.log` files in LevelDB directories of:
- Discord (Stable) `%APPDATA%\discord\Local Storage\leveldb\`
- Discord Canary `%APPDATA%\discordcanary\Local Storage\leveldb\`
- Discord PTB `%APPDATA%\discordptb\Local Storage\leveldb\`
- Google Chrome `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Storage\leveldb\`
- Microsoft Edge `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Storage\leveldb\`
- Brave Browser `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb\`
- Opera `%APPDATA%\Opera Software\Opera Stable\Local Storage\leveldb\`
- Opera GX `%APPDATA%\Opera Software\Opera GX Stable\Local Storage\leveldb\`
- Yandex Browser `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Default\Local Storage\leveldb\`
-   Identifies potential tokens via a regex signature: `dQw4w9WgXcQ:[^\"]+`
-   Parses and decrypts tokens encrypted with AES-256-GCM.

**Decryption pipeline**:

1. Parses Chromium-style `Local State` for `encrypted_key`.
2. Decodes the key using Base64 and removes DPAPI header (`DPAPI` prefix).
3. Applies `CryptUnprotectData()` to decrypt the raw AES key.
4. Decrypts each token value using AES-256-GCM:
   - 12-byte IV (nonce)
   - 16-byte authentication tag
   - Additional Authenticated Data (SHA-1 derived)

**Token validation**:

- Sends a `GET https://discord.com/api/v9/users/@me` request with the token in the `Authorization` header.
- Confirms token validity and retrieves the user's email, phone number, Nitro status, billing methods, and badges.


## 🌐 Browser Module – Modern ABE-Bypassing Architecture

This module targets Chromium-based browsers to extract and decrypt sensitive user data:

- **Google Chrome**
- **Microsoft Edge**
- **Brave**
- **Yandex Browser**

### 🎯 Extraction Targets

- 🔑 Saved passwords (`Login Data`)
- 🍪 Cookies (`Cookies`)
- 💳 Payment methods (`Web Data`)
- 🧪 AES master key (`Local State`)


### 🔬 Modern Technical Workflow

Decryption is performed entirely **in-memory**, using **reflective DLL injection** into the browser process. This bypasses user-mode security mechanisms and defeats **App-Bound Encryption (ABE)** via COM impersonation.

#### 🔹 AES Key Extraction (ABE Bypass)

1. The injector (`browser_inject.exe`) uses a **direct syscall engine** to evade API hooks.
2. A ChaCha20-encrypted payload DLL is embedded inside the injector.
3. At runtime, the DLL is decrypted and **reflectively injected** into the target browser process.
4. The in-memory payload loads the browser's internal `IElevator` COM interface.
5. It invokes the `DecryptData` method using the process's own identity, bypassing ABE.
6. The decrypted **AES-256-GCM master key** is returned to the payload.

#### 🔹 Data Decryption Flow

1. The payload scans for all user profiles (`Default`, `Profile 1`, etc.).
2. It locates and opens the following SQLite files in each profile:
   - `Login Data`
   - `Cookies`
   - `Web Data`
3. Using the decrypted master key, it performs **AES-GCM decryption** of:
   - Login credentials
   - Cookie values
   - Credit card data

All decryption follows Chromium's conventions:
- 12-byte IV (`nonce`)
- 16-byte authentication tag
- Optional AAD (Additional Authenticated Data)


### 🛡️ Core Technical Features

| Feature | Description |
|--------|-------------|
| 💻 **Fileless Operation** | The payload DLL is never written to disk |
| ⚙️ **Reflective DLL Injection** | Stealthy loading without `LoadLibrary` |
| 🧬 **Direct Syscalls** | EDR/AV hook evasion using `Nt*` calls |
| 🧠 **COM Hijack for ABE** | Executes COM calls from a trusted browser context |
| 🔐 **User-Mode Only** | No admin rights required |
| 📁 **Multi-Profile Support** | Automatically scans all browser profiles |
| 📦 **JSON Output** | All extracted data is formatted into structured JSON |


## 💬 Telegram Module

This module extracts Telegram Desktop session data from `%APPDATA%\Telegram Desktop\tdata`.

### 🔍 Key Characteristics

- Telegram stores session information in the `tdata` folder with no encryption or obfuscation.
- Critical session files include `map*.dat` and directories like `D877F783D5D3EF8C`.
- Copying the entire `tdata` directory allows full session hijack — no password or 2FA required.
- Deleting `tdata` forces re-authentication.

### ⚙️ Module Behavior

- Waits briefly to avoid race conditions on startup.
- Looks for the `tdata` folder in the default path:  
  `%APPDATA%\Telegram Desktop\tdata`
- If Telegram is running and locks the folder:
  - Detects the active `Telegram.exe` process
  - Terminates it cleanly
  - Retrieves the install path from the running process to locate `tdata`
- Copies the entire `tdata` directory to a temporary log folder:  
  `%TEMP%\Telegram_log\tdata`
- Preserves full folder structure and data integrity.
- Leaves no user-visible traces or prompts.

## 💻 System Module

This module collects detailed system information for profiling, fingerprinting, or diagnostics. It gathers both hardware and software environment data and stores the results in a readable log.

### 📂 Output

Creates a directory:
`%TEMP%\System_log`

And writes all gathered information to:
`%TEMP\System_log\info.txt`

### 🧾 Collected Data

#### 🧑 User Information
- **Username** (via `GetUserNameA`)
- **Computer name** (via `GetComputerNameA`)

#### 🖥 System Information
- **Operating System version & architecture** (via `GetNativeSystemInfo` + `IsWindowsXxxOrGreater`)
- **CPU model name** (via `RegQueryValueExA` on `HKEY_LOCAL_MACHINE\...\CentralProcessor\0`)
- **RAM size in MB** (via `GlobalMemoryStatusEx`)
- **System uptime** in days, hours, minutes (via `GetTickCount`)
- **HWID** (based on `MachineGuid` from registry)
- **Antivirus name** (via WMI: `SELECT * FROM AntiVirusProduct`)

#### 🌐 Network Information
- **Local IP address** (via `gethostname` + `getaddrinfo`)
- **MAC address** (via `GetAdaptersInfo`)

### 🔧 HWID Logic

- The HWID is taken from the `MachineGuid` in the Windows registry:
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`
- It's a consistent unique identifier for the machine, used for tracking or linking sessions.

## 📁 Output Structure & Logging Format

All extracted data is saved **locally** in an offline, segmented structure under the `%TEMP%` directory. The data is organized to support modular analysis, simplify exfiltration, and avoid detection by security software through centralized logging.

### 📂 Root Structure

```
%TEMP%/
│
├── Browser_log/
│   └── Chrome/              (Example, it can be Yandex, Edge, Brave etc)
│       ├── Default (example of profile)
│           ├── passwords.json
│           ├── cookies.json
│           └── payments.json
│       ├── Profile 1 (example of profile)
│           ├── passwords.json
│           ├── cookies.json
│           └── payments.json
│   └── Edge/
│       ├── Default (example of profile)
│           ├── passwords.json
│           ├── cookies.json
│           └── payments.json
├── Discord_log/
│   └── info.txt
│
├── Telegram_log/
│   └── tdata/              (entire copied directory)
│       ├── D877F783D5D3EF8C/
│       └── map*.dat
│
└── System_log/
    └── info.txt
```


### 🔐 `Browser_log/`

Each file in this directory is written **line-by-line**, decrypted using AES-256-GCM + DPAPI. Values are structured for both readability and post-processing.

- `passwords.json`:  
  ```
  [
    {
      "origin":"https://twitter.com/",
      "username":"example",
      "password":"jngfeurhfdbvugyiurfbgyeifw"
    }
  ]
  ```

- `cookies.json`:  
  ```
  [
    {
    "domain": "example.com",
    "expirationDate": 1753043108,
    "hostOnly": true,
    "httpOnly": true,
    "name": "bqv_example_csrf",
    "path": "/v1",
    "secure": true,
    "session": false,
    "storeId": "0",
    "value": "MTc1Mjk5OTkwNHxJbmx0WlM5aFYybDBSemRrTHpWQ2NrVkVjVzFOWlZkS2FXTllibUY1ZUV",
    "id": 1
    }
  ]
  ```

- `payments.json`:  
  ```
  [
    {
  "name_on_card":"GITHUB S4YR3X",
  "expiration_month":7,"expiration_year":2028,
  "card_number":"5168752020899189","cvc":"133"
    }
  ]
  ```

All browser data is filtered to exclude empty or null entries after decryption.


### 🟣 `Discord_log/`

- `info.txt`: Full metadata dump in TXT format per token:
  
```txt
==== Discord Token #1 ====
Token: MTM5MjQzODU1NTA2MTXXXXXXXXX.GjXyAXrfXNbWJXXzuTkXXXzE0XXXT1Q8siXXXzxuO_nhM
ID: 1392438555061780531
Username: s4yr3x#0
Email: example@gmail.com
Phone: None
2FA: False
Nitro: False
Billing: False
Source: Discord
Guilds: 3
Admin Guilds: 0
Owned Guilds: 0
```


### 💬 `Telegram_log/`

- Contains the entire copied `tdata` folder, including session keys, device fingerprints, and message queues.
- Usable in forensic environments or sandboxed Telegram clients to gain access without password or code.


### 💻 `System_log/`

- `info.txt`: Plain text dump of system fingerprint:

  ```
  [User Information]
  Username: s4yr3x
  Computer Name: DESKTOP-KRQ1J5D

  [System Information]
  OS: Windows 10 or later, Build 22H2, x64
  CPU: 12th Gen Intel(R) Core(TM) i5-12500H
  RAM: 6206 MB
  Uptime: 0 days, 0 hours, 2 minutes
  HWID: 06522753-7f64-493c-b002-147f6630243d
  Antivirus: Windows Defender

  [Network Information]
  Local IP: 192.168.1.60
  MAC Address: 00:0C:29:75:6A:6F
### 🧾 Logging Characteristics

- All files are written with UTF-8 encoding.
- No network exfiltration occurs by default — all data remains on disk unless custom code is added.
- Logger operates **stealthily**, without UAC prompts or window popups.
- Files are written sequentially and closed immediately to avoid detection by AV sandbox heuristics.

## ⚙️ Building, Compilation & Anti-Analysis

### 🛠️ Compilation Notes

The project is written in **pure C++17**, structured into modular `.cpp` and `.h` files for portability and compatibility across most Windows systems.

- **Compiler**: Visual Studio 2019+ with v142+ toolset
- **Platform**: x64
- **CRT**: Static (/MT) preferred for portability
- **Entry Point**: `WinMainCRTStartup` to suppress console window

For optimal stealth, all debugging symbols and manifest files should be stripped from the final binary. Full PDB-free builds are encouraged for AV evasion.

## 🔍 Anti-Analysis & Obfuscation Techniques

While the project is open-source and unprotected by default, the codebase is designed to support several anti-analysis and binary-hardening strategies:

### ✅ ABE Bypass (Chrome, Brave, Edge)

> **Asynchronous Browser Extraction (ABE)** prevents user-mode processes from reading key browser databases while the browser is running. It enforces access restrictions using file locking and App-Bound Encryption, where the AES master key is encrypted and tied to the browser's process identity.

This project circumvents ABE through:

- 💉 **Reflective DLL Injection** into a live browser process to inherit its security context.
- 🧩 **COM interface invocation from inside the trusted process**, passing Chrome’s path-validation.
- 🔑 **Decryption of `app_bound_encrypted_key`** using `IElevator::DecryptData()` from within browser memory.
- 📁 **Unlocked access to SQLite databases** (`Cookies`, `Login Data`, `Web Data`) by cloning them in-memory after key retrieval.
- 🛠️ No disk artifacts and no Admin rights required — all browser interaction is via **direct syscalls**, bypassing common AV/EDR hooks.

### ✅ COM Bypass (Microsoft Edge)

> Microsoft Edge adds an additional layer to App-Bound Encryption via a protected COM interface (`IElevatorEdge`), requiring internal browser context and path validation for key decryption.

Implemented Edge-specific techniques include:

- 🧬 **In-memory COM instantiation** via `CoCreateInstance`, directly from the injected payload.
- 🧼 **Registry-free COM usage** — no registration or CLSID persistence on disk.
- 🔁 **Fallback to DPAPI** when COM access fails, using traditional `CryptUnprotectData()` APIs.
- 🔐 **Precise interface stubbing** built by reverse engineering Edge's vtable and type libraries, enabling compatibility across versions.

### 🧱 Binary Hardening (Optional)

For production builds, you can wrap the binary with:

- [VMProtect / Themida / TitanHide]: For anti-debugging & virtualization
- [PECompact or UPX (with modification)]: For size reduction and import table scrambling
- Inline obfuscation using `opaque predicates`, `bogus control flow`, and `decoy logic`

None of them are included in the open repository to avoid a ban from GitHub.


### 🦠 Antivirus Evasion

> ⚠️ Disclaimer: This software is **for educational purposes only**. If you attempt to compile and test it on a live environment, be aware that some AVs may flag it based on behavior heuristics.

However, the code is designed with:

- No static signatures
- No usage of `system()`, `popen()`, `PowerShell`, or script-based loaders
- No direct calls to `URLDownloadToFile` or `WinInet` API unless added manually

If obfuscated properly and packed, detection is typically low — though **runtime behavior** (file I/O, memory access) may still trigger sandboxes.

## 📌 Final Notes & Legal Disclaimer

SayrexLogger was created for **educational and research purposes only**. It aims to demonstrate the real-world techniques used in modern credential theft, cryptographic key recovery, interprocess memory extraction, and bypassing user-mode mitigations in Chromium-based browsers and messenger clients.

This tool is a practical example of how endpoint protection, encryption APIs, and session management mechanisms can be audited and stress-tested by offensive security researchers.

### ✅ What SayrexLogger Demonstrates

- **Cross-browser credential decryption** with AES-GCM, SHA1 AAD and DPAPI
- **Session token extraction** from Discord, Telegram files and Chromium memory
- **Filesystem and registry forensics** evasion via stealth techniques
- **Defensive evasion strategies** against user-mode anti-cheat and sandbox analysis
- Realistic post-exploitation data aggregation and logging to isolated containers

### ⚠️ Legal & Ethical Use

You are **strictly forbidden** from using this project for:

- Unauthorized data access
- Distribution of malware
- Commercial credential theft
- Targeted espionage or corporate spying
- Any use violating the [Computer Fraud and Abuse Act](https://www.law.cornell.edu/uscode/text/18/1030) (18 U.S. Code § 1030) or similar local regulations

By cloning or using any part of this repository, you agree to be **solely responsible** for your actions.

### 🤝 Contribution & Extensions

This project is modular and designed for **extensibility**. You’re welcome to:

- Add support for new browsers or apps
- Implement persistence mechanisms
- Extend the crypto engine to support non-DPAPI scenarios
- Contribute bypasses for new versions of Chromium or Edge

> Pull requests are welcome only for **educational or PoC** purposes. Binary blobs, packers, and malicious infrastructure will be rejected.

## ✍️ My Personal Note

I’ve been away from GitHub since early June, and today — July 22st — I’m publishing this project.

This is my **first large-scale, modular project** in the field of programming and cybersecurity.

Through building SayrexLogger, I significantly deepened my understanding of:

- Cryptographic mechanisms and Windows-specific data encryption (e.g., DPAPI, AES-GCM)
- Protection bypass techniques (ABE, COM, injection vectors)
- Structured malware architecture and modular development

The project is cleanly organized and built for clarity and flexibility.

This work means a lot to me, and I would greatly appreciate any feedback, thoughts, or constructive criticism.  
I plan to **continuously improve and expand** its functionality in the future.

Thank you for reading this far 🙌

🧠 *Security through transparency. The more we understand how these threats work — the better we can defend against them.*

