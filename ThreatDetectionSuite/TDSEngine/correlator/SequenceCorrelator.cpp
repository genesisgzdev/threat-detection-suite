#include "SequenceCorrelator.h"
#include <iostream>
#include <fstream>
#include "../Logger.h"

namespace TDS {

SequenceCorrelator::SequenceCorrelator() {
    LoadFromDisk();
}

SequenceCorrelator::~SequenceCorrelator() {
    SaveToDisk();
}

void SequenceCorrelator::Analyze(const Event& event) {
    if (event.Type == TDSEventProcessCreate) {
        if (auto data = std::get_if<ProcessEvent>(&event.Data)) {
            m_processStates[event.Pid] = { event.Pid, data->Created, false, event.Timestamp };
        }
        return;
    }

    if (event.Type == TDSEventProcessTerminate) {
        m_processStates.erase(event.Pid);
        return;
    }

    // APC and Early Bird injection detection logic
    if (event.Type == TDSEventRemoteThread || event.Type == TDSEventApcInjection) {
        auto it = m_processStates.find(event.Pid);
        if (it != m_processStates.end()) {
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

    // Mark process as initialized after first image load or thread activity
    if (event.Type == TDSEventImageLoad || event.Type == TDSEventThreadCreate) {
        auto it = m_processStates.find(event.Pid);
        if (it != m_processStates.end()) {
            it->second.Initialized = true;
        }
    }
}

void SequenceCorrelator::SaveToDisk() {}
void SequenceCorrelator::LoadFromDisk() {}

} // namespace TDS
