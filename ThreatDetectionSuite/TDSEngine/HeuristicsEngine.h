#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include "../TDSCommon/TDSCommon.h"
#include "../TDSCommon/TDSEvents.h"

namespace TDS {

struct BehavioralContext {
    uint32_t Pid;
    int Score;
    bool HasSuspiciousPersistence;
    bool HasRemoteThreadActivity;
    bool HasHighEntropyWrites;
    bool HasC2PatternNetwork;
    std::chrono::steady_clock::time_point LastActivity;
};

/**
 * HeuristicsEngine: State-machine based behavioral analysis.
 * Scores processes based on attack chain patterns rather than static IOCs.
 */
class HeuristicsEngine {
public:
    static HeuristicsEngine& Instance() {
        static HeuristicsEngine instance;
        return instance;
    }

    void ProcessEvent(const Event& event);

private:
    HeuristicsEngine() = default;
    std::map<uint32_t, BehavioralContext> m_processContexts;
    const int THREAT_THRESHOLD = 70;

    void EvaluateRisk(uint32_t pid);
    void TriggerRemediation(uint32_t pid, const std::string& reason);
};

} // namespace TDS
