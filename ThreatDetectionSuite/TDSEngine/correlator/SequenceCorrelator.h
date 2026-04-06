#pragma once
#include <windows.h>
#include <map>
#include <deque>
#include <string>
#include "../../TDSCommon/TDSCommon.h"

namespace TDS {

struct EventInfo {
    TDS_EVENT_TYPE Type;
    uint64_t Timestamp;
};

class SequenceCorrelator {
public:
    SequenceCorrelator();
    ~SequenceCorrelator();

    void HandleEvent(uint32_t pid, TDS_EVENT_TYPE type);

private:
    void SaveToDisk();
    void LoadFromDisk();

    std::map<uint32_t, std::deque<EventInfo>> processEvents;
    const std::string m_persistenceFile = "tds_correlator.db"; 
};

} // namespace TDS

