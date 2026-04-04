#pragma once
#include <windows.h>
#include <vector>
#include <string>

namespace TDS {

class RegistryDetector {
public:
    static void ScanAutoRunKeys();
    static void ScanCOMHijacking();
    static void ScanAppInitDLLs();

private:
    static void ScanKey(HKEY hKeyRoot, const std::wstring& subKey);
    static bool IsMaliciousPath(const std::wstring& path);
};

} // namespace TDS
