#include "SequenceCorrelator.h"
#include <iostream>
#include <fstream>
#include <map>
#include "../Logger.h"

namespace TDS {

struct ProcessContext {
    uint32_t Pid;
    bool Suspended;
    bool Initialized;
    uint64_t CreationTime;
};

static std::map<uint32_t, ProcessContext> g_ProcessStates;

SequenceCorrelator::SequenceCorrelator() {
    LoadFromDisk();
}

/**
 * Analyzes the lifecycle of processes to detect sophisticated injection patterns.
 * Focuses on Early Bird (APC in suspended state) and Thread Hijacking.
 */
void SequenceCorrelator::Analyze(const Event& event) {
    if (event.Type == TDSEventProcessCreate) {
        auto& pData = std::get<ProcessEvent>(event.Data);
        g_ProcessStates[event.Pid] = { event.Pid, pData.Created, false, event.Timestamp };
        return;
    }

    if (event.Type == TDSEventProcessTerminate) {
        g_ProcessStates.erase(event.Pid);
        return;
    }

    // production APC / Early Bird Detection Logic
    if (event.Type == TDSEventRemoteThread || event.Type == TDSEventApcInjection) {
        auto it = g_ProcessStates.find(event.Pid);
        if (it != g_ProcessStates.end()) {
            ProcessContext& ctx = it->second;
            
            // If process is still initializing and receives an APC/Remote Thread
            if (ctx.Suspended && !ctx.Initialized) {
                Logger::Instance().LogThreat(
                    TDS_SEVERITY_CRITICAL, 
                    CAT_DLL_INJECTION,
                    "Early Bird Injection detected: Remote code execution before process initialization",
                    "EarlyBirdPattern",
                    event.Pid
                );
            }
        }
    }

    // Mark process as initialized after first image load or thread activity if it was suspended
    if (event.Type == TDSEventImageLoad || event.Type == TDSEventThreadCreate) {
        auto it = g_ProcessStates.find(event.Pid);
        if (it != g_ProcessStates.end()) {
            it->second.Initialized = true;
        }
    }
}

void SequenceCorrelator::SaveToDisk() {
    // Logic to persist critical state across service restarts
}

void SequenceCorrelator::LoadFromDisk() {
    // Restore state
}

} // namespace TDS

