# Contributing to Threat Detection Suite

## Build Requirements
- **Compiler**: Microsoft Visual C++ (MSVC) or Clang-cl.
- **WDK**: Windows Driver Kit for the target Windows SDK.
- **Language Standards**: C11 for TDSDriver.sys, C++17 for user-mode components.

## Kernel Programming Standards
1. **Concurrency**: The use of KSPIN_LOCK in high-frequency dispatch routines (like IRP_MJ_WRITE) is prohibited. All telemetry queuing must use SLIST_HEADER and the Interlocked*SList API family.
2. **Memory Allocation**: Direct calls to ExAllocatePool for repetitive events are banned due to kernel pool fragmentation. Use ExAllocateFromNpagedLookasideList.
3. **IRQL Assertions**: Operations requiring page faults or string manipulation must be gated with KeGetCurrentIrql() == PASSIVE_LEVEL.
4. **Exception Handling**: All IOCTL handlers must implement __try / __except blocks. If METHOD_NEITHER is used, the user-mode buffer must be validated with ProbeForRead and ProbeForWrite inside the __try block.

## User-Mode Programming Standards
- The engine uses a polymorphic Event bus (std::variant in <variant>).
- Blocking the main analysis thread is strictly forbidden. Heavy operations, such as calculating Shannon Entropy for large files, must be constrained to a reasonable byte limit or dispatched to a separate thread pool.
