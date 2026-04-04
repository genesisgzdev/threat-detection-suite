#include "RegistryDetector.h"
#include <iostream>
#include <algorithm>
#include <wintrust.h>
#include <softpub.h>
#include "../Logger.h"

#pragma comment(lib, "wintrust.lib")

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
    if (path.empty()) return false;

    // Check 1: Authenticode Signature (WinVerifyTrust)
    WINTRUST_FILE_INFO fileData;
    ZeroMemory(&fileData, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = path.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    WINTRUST_DATA trustData;
    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileData;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    if (status != ERROR_SUCCESS) {
        // Not trusted / unsigned
        return true;
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
                // Strip quotes if present
                if (path.length() >= 2 && path.front() == L'\"' && path.back() == L'\"') {
                    path = path.substr(1, path.length() - 2);
                }
                
                if (IsMaliciousPath(path)) {
                    std::string desc = "Unsigned binary in AutoRun registry: " + std::string(subKey.begin(), subKey.end());
                    std::string ioc = std::string(path.begin(), path.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_REGISTRY_ANOMALY, desc, ioc, 0);
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
