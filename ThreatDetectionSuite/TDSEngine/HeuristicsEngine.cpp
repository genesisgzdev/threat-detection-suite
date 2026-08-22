#include "HeuristicsEngine.h"
#include "Logger.h"
#include "ips/IPSManager.h"
#include <iostream>

namespace TDS {

void HeuristicsEngine::ProcessEvent(const Event& event) {
    uint32_t attributedPid = event.Pid;
    if (event.Type == TDSEventRemoteThread || event.Type == TDSEventApcInjection ||
        event.Type == TDSEventEtwTiApcInjection) {
        if (const auto* injection = std::get_if<RemoteThreadEvent>(&event.Data)) {
            attributedPid = injection->TargetPid;
        }
    }
    auto& ctx = m_processContexts[attributedPid];
    ctx.Pid = attributedPid;
    ctx.LastActivity = std::chrono::steady_clock::now();

    switch (event.Type) {
        case TDSEventRegistrySet:
            // Only increment if it's a persistence key (simplified for now)
            ctx.Score += 20;
            ctx.HasSuspiciousPersistence = true;
            break;

        case TDSEventRemoteThread:
        case TDSEventApcInjection:
        case TDSEventEtwTiApcInjection:
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

    EvaluateRisk(attributedPid);
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

        TriggerRemediation(pid, it->second.Score, reason);
        
        // Reset score after alert to prevent spamming, or erase context
        it->second.Score = 0; 
    }
}

void HeuristicsEngine::TriggerRemediation(uint32_t pid, int score, const std::string& reason) {
    if (m_responsePolicy.AllowsTermination(score)) {
        std::cout << "[IPS] Terminating PID " << pid << " due to: " << reason << std::endl;
        IPSManager::ContainProcess(pid);
        IPSManager::TerminateMaliciousProcess(pid);
    } else if (m_responsePolicy.AllowsContainment(score)) {
        std::cout << "[IPS] Containing PID " << pid << " due to: " << reason << std::endl;
        IPSManager::ContainProcess(pid);
    } else {
        std::cout << "[IPS] Observe-only decision for PID " << pid << ": " << reason << std::endl;
    }
}

} // namespace TDS
