#pragma once
#include <windows.h>
#include <string>
#include <variant>
#include <vector>
#include <cstdint>
#include "TDSCommon.h"

namespace TDS {

struct ProcessEvent {
    uint32_t ParentPid;
    bool Created;
    std::wstring ImagePath;
    std::wstring CommandLine;
};

struct ImageLoadEvent {
    uint64_t LoadAddress;
    uint64_t ImageSize;
    std::wstring ImagePath;
};

struct RemoteThreadEvent {
    uint32_t TargetPid;
};

struct NetworkEvent {
    uint8_t AddressFamily;
    uint8_t Protocol;
    uint16_t RemotePort;
    uint32_t RemoteAddress;
    uint8_t Ipv6Address[16];
};

struct HandleOpEvent {
    uint32_t TargetPid;
    uint32_t DesiredAccess;
};

struct FileEvent {
    uint8_t Operation;
    std::wstring FilePath;
    std::wstring TargetPath;
};

struct RegistryEvent {
    uint32_t Type;
    uint32_t DataSize;
    std::wstring KeyPath;
    std::wstring ValueName;
    std::vector<uint8_t> Data;
};

// C++17 variant for type-safe polymorphic data holding
using EventData = std::variant<
    std::monostate,
    ProcessEvent,
    ImageLoadEvent,
    RemoteThreadEvent,
    NetworkEvent,
    HandleOpEvent,
    FileEvent,
    RegistryEvent
>;

struct Event {
    TDS_EVENT_TYPE Type;
    uint64_t Timestamp;
    uint32_t Pid;
    uint32_t Tid;
    EventData Data;
};

} // namespace TDS
