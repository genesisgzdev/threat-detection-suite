#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include "../TDSCommon/TDSCommon.h"
#include "../TDSCommon/TDSEvents.h"
#include "ResponsePolicy.h"

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
    ResponsePolicy m_responsePolicy = ResponsePolicy::FromEnvironment();
    const int THREAT_THRESHOLD = 70;

    void EvaluateRisk(uint32_t pid, bool responseTargetKnown = true);
    void TriggerRemediation(uint32_t pid, int score, const std::string& reason, bool responseTargetKnown);
};

} // namespace TDS
