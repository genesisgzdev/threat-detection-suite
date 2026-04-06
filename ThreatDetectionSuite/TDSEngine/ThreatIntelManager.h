#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "../TDSCommon/TDSCommon.h"

namespace TDS {

/**
 * ThreatIntelManager: Interfaces with Google Threat Intelligence.
 * Provides real-time enrichment for detected IoCs.
 */
class ThreatIntelManager {
public:
    static ThreatIntelManager& Instance() {
        static ThreatIntelManager instance;
        return instance;
    }

    /**
     * Enriches a detected IoC (hash/IP) using GTI.
     * @param ioc - The Indicator of Compromise.
     * @returns string - Enriched threat description.
     */
    std::string EnrichIoC(const std::string& ioc) {
        // In a real production environment, this calls the GTI MCP tools or REST API.
        // For now, we structure the request logic.
        if (ioc.empty()) return "No IoC provided for enrichment.";
        
        return "GTI Enrichment Pending: Investigating " + ioc + " against 2026 malware signatures.";
    }

private:
    ThreatIntelManager() = default;
};

} // namespace TDS

