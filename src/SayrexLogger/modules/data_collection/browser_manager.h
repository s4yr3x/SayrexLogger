// browser_manager.h
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once
#include <string>
#include <vector>

struct BrowserInfo
{
    std::wstring type;
    std::wstring exePath;
    bool isRunning;        
};

std::vector<BrowserInfo> DetectBrowsers();