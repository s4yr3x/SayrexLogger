@echo off
setlocal
:: make.bat
:: github: s4yr3x
:: Licensed under the MIT License. See LICENSE file in the project root for full license information.
del /Q chrome_decrypt.dll chrome_decrypt.lib chrome_decrypt.exp *.obj 2>nul

echo [*] Compiling Reflective Loader...
cl /nologo /c ^
   /O2 /MT /GS- /GR- /Gm- ^
   /W3 /std:c++17 ^
   reflective_loader.c

echo [*] Compiling SQLite3...
cl /nologo /c ^
   /O2 /MT /GS- /GR- /Gm- ^
   /W3 /std:c11 ^
   sqlite3.c

echo [*] Compiling browser_decrypt.cpp...
cl /nologo /c ^
   /O2 /MT /GS- /GR- /Gm- ^
   /W3 /std:c++17 ^
   /I. ^
   browser_decrypt.cpp

echo [*] Linking in DLL...
link /nologo /DLL ^
   /OUT:chrome_decrypt.dll ^
   browser_decrypt.obj reflective_loader.obj sqlite3.obj ^
   Crypt32.lib bcrypt.lib ole32.lib shell32.lib OleAut32.lib

echo.
echo [+] Done: browser_decrypt.dll
endlocal
pause