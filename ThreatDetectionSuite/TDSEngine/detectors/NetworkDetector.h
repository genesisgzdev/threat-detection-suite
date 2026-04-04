#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

namespace TDS {

class NetworkDetector {
public:
    static void ScanActiveConnections();

private:
    static bool IsSuspiciousPort(USHORT port);
};

} // namespace TDS
