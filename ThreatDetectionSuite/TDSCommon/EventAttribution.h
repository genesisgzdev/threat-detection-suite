#pragma once
#include <optional>
#include "TDSEvents.h"

namespace TDS {
// Attribution is an evidence boundary; a missing target never falls back to
// the emitter PID of an injection event.
inline std::optional<uint32_t> ResponseTarget(const Event& event) {
    uint32_t target = event.Pid;
    if (event.Type == TDSEventRemoteThread || event.Type == TDSEventApcInjection || event.Type == TDSEventEtwTiApcInjection) {
        if (const auto* remote = std::get_if<RemoteThreadEvent>(&event.Data)) target = remote->TargetPid;
        else if (const auto* etw = std::get_if<EtwApcEvent>(&event.Data)) {
            if (!etw->TargetKnown) return std::nullopt;
            target = etw->TargetPid;
        } else return std::nullopt;
    }
    return target == 0 ? std::nullopt : std::optional<uint32_t>(target);
}
}
