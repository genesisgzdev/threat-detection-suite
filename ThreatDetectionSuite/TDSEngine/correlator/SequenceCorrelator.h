#pragma once
#include <windows.h>
#include <map>
#include <deque>
#include <string>
#include "../../TDSCommon/TDSCommon.h"
#include "../../TDSCommon/TDSEvents.h"

namespace TDS {

class SequenceCorrelator {
public:
    SequenceCorrelator();
    ~SequenceCorrelator();

    void Analyze(const Event& event);

private:
    void SaveToDisk();
    void LoadFromDisk();

    struct ProcessContext {
        uint32_t Pid;
        bool Suspended;
        bool Initialized;
        uint64_t CreationTime;
    };

    std::map<uint32_t, ProcessContext> m_processStates;
    const std::string m_persistenceFile = "tds_correlator.db"; 
};

} // namespace TDS
