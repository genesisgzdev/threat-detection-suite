#pragma once

#include "../TDSCommon/TDSCommon.h"
#include <vector>
#include <string>
#include <map>
#include <set>
#include <chrono>

namespace TDS {

struct NetworkConnection {
    DWORD processId;
    std::wstring remoteIp;
    uint16_t remotePort;
    std::vector<std::chrono::steady_clock::time_point> timestamps;
};

class TDSEngine {
public:
    TDSEngine();
    ~TDSEngine() = default;

    // LOLBAS Detection
    bool IsLolbasBinary(const std::wstring& imagePath);

    // Advanced Persistence Detection
    void ScanPersistenceLocations();
    bool DetectAdsInFile(const std::wstring& filePath);
    bool CheckWmiPersistence();

    // Registry Content Analysis
    bool AnalyzeRegistryValue(const std::wstring& keyPath, const std::wstring& valueName, const std::wstring& data);

    // Network Beaconing Analysis
    void RecordNetworkConnection(DWORD processId, const std::wstring& remoteIp, uint16_t remotePort);
    bool DetectBeaconing(DWORD processId);

private:
    std::set<std::wstring> m_lolbasBinaries;
    std::map<DWORD, std::vector<NetworkConnection>> m_networkHistory;
    
    void InitializeLolbasList();
    
    // Helper for case-insensitive search
    bool CaseInsensitiveContains(const std::wstring& haystack, const std::wstring& needle);
};

} // namespace TDS
