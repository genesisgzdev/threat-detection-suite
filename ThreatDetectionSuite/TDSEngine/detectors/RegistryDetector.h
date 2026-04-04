#pragma once
#include <windows.h>
#include <vector>
#include <string>

namespace TDS {

class RegistryDetector {
public:
    static void ScanAutoRunKeys();

private:
    static void ScanKey(HKEY hKeyRoot, const std::wstring& subKey);
    static bool IsMaliciousPath(const std::wstring& path);
};

} // namespace TDS
