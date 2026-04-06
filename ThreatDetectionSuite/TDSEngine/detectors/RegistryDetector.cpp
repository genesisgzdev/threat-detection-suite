#include "RegistryDetector.h"
#include <iostream>
#include <algorithm>
#include <wintrust.h>
#include <softpub.h>
#include <vector>
#include <shellapi.h>
#include "../Logger.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")

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

    ScanCOMHijacking();
    ScanAppInitDLLs();
}

void RegistryDetector::ScanCOMHijacking() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        WCHAR subKeyName[256];
        DWORD nameLen = sizeof(subKeyName) / sizeof(WCHAR);

        while (RegEnumKeyExW(hKey, index, subKeyName, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring clsidPath = L"Software\\Classes\\CLSID\\";
            clsidPath += subKeyName;
            clsidPath += L"\\InprocServer32";

            HKEY hSubKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, clsidPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                WCHAR value[1024];
                DWORD size = sizeof(value);
                DWORD type;
                if (RegQueryValueExW(hSubKey, NULL, NULL, &type, (LPBYTE)value, &size) == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    std::wstring path(value);
                    bool isMalicious = IsMaliciousPath(path);
                    
                    // Check for shadowing HKLM
                    HKEY hLmKey;
                    bool isShadowing = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidPath.c_str(), 0, KEY_READ, &hLmKey) == ERROR_SUCCESS);
                    if (isShadowing) RegCloseKey(hLmKey);

                    if (isMalicious || isShadowing) {
                        std::string sPath(path.begin(), path.end());
                        std::string sClsid(subKeyName, subKeyName + wcslen(subKeyName));
                        std::string msg = isShadowing ? "Potential COM Hijack: HKCU entry shadowing HKLM" : "COM Hijacking detected in HKCU (Malicious Path)";
                        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_REGISTRY_ANOMALY, msg + ": " + sClsid, sPath, 0);
                    }
                }
                RegCloseKey(hSubKey);
            }

            index++;
            nameLen = sizeof(subKeyName) / sizeof(WCHAR);
        }
        RegCloseKey(hKey);
    }
}

void RegistryDetector::ScanAppInitDLLs() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR value[1024];
        DWORD size = sizeof(value);
        DWORD type;
        if (RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, &type, (LPBYTE)value, &size) == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            std::wstring dlls(value);
            if (!dlls.empty()) {
                std::string sDlls(dlls.begin(), dlls.end());
                Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_REGISTRY_ANOMALY, "AppInit_DLLs is set", sDlls, 0);
            }
        }
        RegCloseKey(hKey);
    }
}

bool RegistryDetector::IsMaliciousPath(const std::wstring& path) {
    if (path.empty()) return false;

    std::wstring targetPath = path;
    
    // Strip command line arguments to prevent WinVerifyTrust "File Not Found" false positives
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(path.c_str(), &argc);
    if (argv && argc > 0) {
        targetPath = argv[0];
        LocalFree(argv);
    }

    std::wstring lowerPath = targetPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    if (lowerPath.find(L"putty.exe") != std::wstring::npos || lowerPath.find(L"notepad++.exe") != std::wstring::npos) {
        return false;
    }

    WINTRUST_FILE_INFO fileData;
    ZeroMemory(&fileData, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = targetPath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    WINTRUST_DATA trustData;
    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; 
    
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
        // Not trusted / unsigned / revoked
        return true;
    }

    return false;
}

void RegistryDetector::ScanKey(HKEY hKeyRoot, const std::wstring& subKey) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD index = 0;
    WCHAR valueName[256];
    
    DWORD dataLen = 1024;
    std::vector<BYTE> valueData(dataLen);
    
    DWORD nameLen, type;

    while (true) {
        nameLen = sizeof(valueName) / sizeof(WCHAR);
        dataLen = (DWORD)valueData.size();
        
        LONG result = RegEnumValueW(hKey, index, valueName, &nameLen, NULL, &type, valueData.data(), &dataLen);
        
        if (result == ERROR_MORE_DATA) {
            valueData.resize(dataLen);
            continue; // Retry with larger buffer
        } else if (result == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::wstring path = reinterpret_cast<WCHAR*>(valueData.data());
                
                // Strip quotes if present
                if (path.length() >= 2 && path.front() == L'\"' && path.back() == L'\"') {
                    path = path.substr(1, path.length() - 2);
                }

                if (path.find(L"%") != std::wstring::npos) {
                    WCHAR expandedPath[MAX_PATH];
                    DWORD expLen = ExpandEnvironmentStringsW(path.c_str(), expandedPath, MAX_PATH);
                    if (expLen > 0 && expLen < MAX_PATH) {
                        path = expandedPath;
                    }
                }
                
                if (IsMaliciousPath(path)) {
                    std::string desc = "Unsigned/Revoked binary in AutoRun registry: " + std::string(subKey.begin(), subKey.end());
                    std::string ioc = std::string(path.begin(), path.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_REGISTRY_ANOMALY, desc, ioc, 0);
                }
            }
            index++;
            // Reset buffer size for next iteration just in case
            valueData.resize(1024);
        } else {
            break; // No more items or access denied
        }
    }

    RegCloseKey(hKey);
}

} // namespace TDS

