#include "SequenceCorrelator.h"
#include <iostream>
#include <fstream>
#include "../Logger.h"

namespace TDS {

void SequenceCorrelator::Analyze(const Event& event) {
    if (event.Type == TDSEventProcessCreate) {
        if (auto data = std::get_if<ProcessEvent>(&event.Data)) {
            m_processStates[event.Pid] = { event.Pid, false, false, event.Timestamp };
        }
        return;
    }

    if (event.Type == TDSEventProcessTerminate) {
        m_processStates.erase(event.Pid);
        return;
    }

    // Correlate against the target process, not the process that emitted the
    // telemetry. ETW and remote-thread records can have different source and
    // target PIDs.
    if (event.Type == TDSEventRemoteThread || event.Type == TDSEventApcInjection ||
        event.Type == TDSEventEtwTiApcInjection) {
        const auto* injection = std::get_if<RemoteThreadEvent>(&event.Data);
        if (event.Type == TDSEventEtwTiApcInjection) {
            const auto* etw = std::get_if<EtwApcEvent>(&event.Data);
            if (!etw || !etw->TargetKnown) return;
            auto it = m_processStates.find(etw->TargetPid);
            if (it == m_processStates.end()) return;
            ProcessContext& ctx = it->second;
            if (!ctx.Initialized) {
                Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_DLL_INJECTION,
                    "APC or remote-thread activity during process initialization",
                    "EarlyInitializationPattern", etw->TargetPid);
            }
            return;
        }
        const uint32_t targetPid = injection ? injection->TargetPid : event.Pid;
        auto it = m_processStates.find(targetPid);
        if (it != m_processStates.end()) {
            ProcessContext& ctx = it->second;

            // The current contract does not expose a reliable suspended flag.
            // Use observable ordering until native ETW ground truth exists.
            if (!ctx.Initialized) {
                Logger::Instance().LogThreat(
                    TDS_SEVERITY_CRITICAL, 
                    CAT_DLL_INJECTION,
                    "APC or remote-thread activity during process initialization",
                    "EarlyInitializationPattern",
                    targetPid
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

} // namespace TDS
