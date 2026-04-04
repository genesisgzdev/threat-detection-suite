#include "RegistryDetector.h"
#include <iostream>
#include <algorithm>
#include "../Logger.h"

namespace TDS {

void RegistryDetector::ScanAutoRunKeys() {
    const std::vector<std::wstring> runKeys = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    };

    for (const auto& key : runKeys) {
        ScanKey(HKEY_CURRENT_USER, key);
        ScanKey(HKEY_LOCAL_MACHINE, key);
    }
}

bool RegistryDetector::IsMaliciousPath(const std::wstring& path) {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    static const std::vector<std::wstring> patterns = {
        L"svchost.exe", L"windowsupdate", L"driver.exe", L"spy.exe", L"amsi.dll"
    };

    for (const auto& p : patterns) {
        if (lowerPath.find(p) != std::wstring::npos) return true;
    }
    return false;
}

void RegistryDetector::ScanKey(HKEY hKeyRoot, const std::wstring& subKey) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD index = 0;
    WCHAR valueName[256];
    BYTE valueData[1024];
    DWORD nameLen, dataLen, type;

    while (true) {
        nameLen = sizeof(valueName) / sizeof(WCHAR);
        dataLen = sizeof(valueData);
        
        LONG result = RegEnumValueW(hKey, index, valueName, &nameLen, NULL, &type, valueData, &dataLen);
        
        if (result == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::wstring path = reinterpret_cast<WCHAR*>(valueData);
                if (IsMaliciousPath(path)) {
                    std::string desc = "Malicious registry persistence detected in " + std::string(subKey.begin(), subKey.end());
                    std::string ioc = std::string(path.begin(), path.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_REGISTRY_ANOMALY, desc, ioc, 0);
                }
            }
            index++;
        } else if (result == ERROR_MORE_DATA) {
            index++;
        } else {
            break;
        }
    }

    RegCloseKey(hKey);
}

} // namespace TDS
