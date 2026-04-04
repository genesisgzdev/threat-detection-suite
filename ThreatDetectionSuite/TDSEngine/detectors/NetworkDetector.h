#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../../TDSCommon/TDSCommon.h"

namespace TDS {

class NetworkDetector {
public:
    static bool IsSuspiciousPort(USHORT port);
    static void AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data);
};

} // namespace TDS
