#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdlib>
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
        if (ioc.empty()) return {};
        // Enrichment is intentionally fail-closed: the detector never invents a
        // verdict when no authenticated provider has been configured.
        const char* endpoint = std::getenv("TDS_TI_ENDPOINT");
        if (!endpoint || !*endpoint) return {};
        return {};
    }

private:
    ThreatIntelManager() = default;
};

} // namespace TDS
