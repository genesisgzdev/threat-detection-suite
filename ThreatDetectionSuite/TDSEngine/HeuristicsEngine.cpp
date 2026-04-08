#include "HeuristicsEngine.h"
#include "Logger.h"
#include "ips/IPSManager.h"
#include <iostream>

namespace TDS {

void HeuristicsEngine::ProcessEvent(const Event& event) {
    auto& ctx = m_processContexts[event.Pid];
    ctx.Pid = event.Pid;
    ctx.LastActivity = std::chrono::steady_clock::now();

    switch (event.Type) {
        case TDSEventRegistrySet:
            // Incremental scoring for potential persistence
            ctx.Score += 20;
            ctx.HasSuspiciousPersistence = true;
            break;

        case TDSEventRemoteThread:
            ctx.Score += 40;
            ctx.HasRemoteThreadActivity = true;
            break;

        case TDSEventRansomwareActivity:
            ctx.Score += 50;
            ctx.HasHighEntropyWrites = true;
            break;

        case TDSEventVssDeletion:
            ctx.Score += 60;
            break;

        case TDSEventNetworkConnect:
            ctx.Score += 15;
            break;

        case TDSEventProcessTerminate:
            m_processContexts.erase(event.Pid);
            return;
    }

    EvaluateRisk(event.Pid);
}

void HeuristicsEngine::EvaluateRisk(uint32_t pid) {
    auto it = m_processContexts.find(pid);
    if (it != m_processContexts.end() && it->second.Score >= THREAT_THRESHOLD) {
        std::string reason = "Behavioral anomaly detected: Threat Score " + std::to_string(it->second.Score);
        
        Logger::Instance().LogThreat(
            TDS_SEVERITY_CRITICAL,
            CAT_PROCESS_BEHAVIOR,
            reason,
            "BehavioralHeuristics",
            pid
        );

        TriggerRemediation(pid, reason);
        
        // Reset score after intervention to prevent duplicate alerts
        it->second.Score = 0; 
    }
}

void HeuristicsEngine::TriggerRemediation(uint32_t pid, const std::string& reason) {
    std::cout << "[IPS] Remediating PID " << pid << " due to: " << reason << std::endl;
    IPSManager::ContainProcess(pid);
    IPSManager::TerminateMaliciousProcess(pid);
}

} // namespace TDS
