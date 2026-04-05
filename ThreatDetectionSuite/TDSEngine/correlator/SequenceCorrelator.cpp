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

void SequenceCorrelator::HandleEvent(uint32_t pid, TDS_EVENT_TYPE type) {
    if (type == TDSEventProcessTerminate) {
        processEvents.erase(pid);
        return;
    }

    if (type == TDSEventProcessCreate) {
        // Prevent state corruption from OS PID reuse
        processEvents[pid].clear();
    }

    auto& events = processEvents[pid];
    events.push_back({type, GetTickCount64()});

    if (events.size() > 10) events.pop_front();

    // Pattern matching for multi-stage attacks using formal enum types
    bool hasCreate = false, hasNet = false;
    for (const auto& ev : events) {
        if (ev.Type == TDSEventProcessCreate) hasCreate = true;
        if (ev.Type == TDSEventNetworkConnect && hasCreate) hasNet = true;
        if (ev.Type == TDSEventRegistryOp && hasNet) {
            Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_PROCESS_BEHAVIOR, 
                "High-confidence attack sequence: Execution -> Network -> Persistence", "Correlation", pid);
        }
    }
}

void SequenceCorrelator::SaveToDisk() {
    std::ofstream ofs(m_persistenceFile, std::ios::binary | std::ios::trunc);
    if (!ofs) return;

    size_t mapSize = processEvents.size();
    ofs.write(reinterpret_cast<const char*>(&mapSize), sizeof(mapSize));

    for (const auto& [pid, events] : processEvents) {
        ofs.write(reinterpret_cast<const char*>(&pid), sizeof(pid));
        size_t dequeSize = events.size();
        ofs.write(reinterpret_cast<const char*>(&dequeSize), sizeof(dequeSize));
        for (const auto& ev : events) {
            ofs.write(reinterpret_cast<const char*>(&ev), sizeof(ev));
        }
    }
}

void SequenceCorrelator::LoadFromDisk() {
    std::ifstream ifs(m_persistenceFile, std::ios::binary);
    if (!ifs) return;

    size_t mapSize = 0;
    if (!ifs.read(reinterpret_cast<char*>(&mapSize), sizeof(mapSize))) return;

    for (size_t i = 0; i < mapSize; i++) {
        uint32_t pid = 0;
        size_t dequeSize = 0;
        if (!ifs.read(reinterpret_cast<char*>(&pid), sizeof(pid))) break;
        if (!ifs.read(reinterpret_cast<char*>(&dequeSize), sizeof(dequeSize))) break;
        
        std::deque<EventInfo> events;
        for (size_t j = 0; j < dequeSize; j++) {
            EventInfo ev;
            if (!ifs.read(reinterpret_cast<char*>(&ev), sizeof(ev))) break;
            events.push_back(ev);
        }
        processEvents[pid] = std::move(events);
    }
}

} // namespace TDS
