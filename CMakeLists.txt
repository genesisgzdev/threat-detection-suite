cmake_minimum_required(VERSION 3.20)
project(ThreatDetectionSuite VERSION 4.3.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Security Hardening Flags (Professional EDR Standards)
if(MSVC)
    add_compile_options(/GS /guard:cf /W4 /WX /sdl)
    add_link_options(/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF /CETCOMPAT)
endif()

# Common headers
include_directories(ThreatDetectionSuite/TDSCommon)
include_directories(ThreatDetectionSuite/TDSEngine)
include_directories(ThreatDetectionSuite/TDSEngine/ips)
include_directories(ThreatDetectionSuite/TDSScanner)

# Userland Engine
add_executable(TDSService 
    ThreatDetectionSuite/TDSEngine/TDSService.cpp 
    ThreatDetectionSuite/TDSEngine/TDSEngine.cpp
    ThreatDetectionSuite/TDSEngine/ips/IPSManager.cpp
    ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp
    ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp
    ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.cpp
    ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.cpp
    ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.cpp
    ThreatDetectionSuite/TDSScanner/MemoryScanner.cpp
    ThreatDetectionSuite/TDSScanner/Entropy.cpp
)
target_link_libraries(TDSService wbemuuid taskschd comsuppw advapi32 ntdll ws2_32 iphlpapi wintrust tdh)

# Integration Bridge & Test Utility
add_executable(TDSBridge tools/bridge/TDSBridge.cpp)
target_link_libraries(TDSBridge advapi32 ws2_32 iphlpapi wintrust)

# Installation Target
install(TARGETS TDSService TDSBridge
    RUNTIME DESTINATION bin
)

# Testing Configuration
enable_testing()
# add_test(NAME IntegrationTest COMMAND TDSBridge --test)
