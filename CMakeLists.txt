cmake_minimum_required(VERSION 3.20)
project(ThreatDetectionSuite VERSION 5.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Security Hardening Flags (Standard EDR Practices)
if(MSVC)
    add_compile_options(/GS /guard:cf /W4 /WX /sdl /wd4324 /wd4100 /wd4244)
    add_link_options(/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF /CETCOMPAT)
endif()

# External Dependencies (YARA)
set(YARA_INCLUDE_DIR "C:/Tools/libyara_sdk/lib/native/include")
set(YARA_LIB_DIR "C:/Tools/libyara_sdk/lib/native/x64/lib")

# Common headers
include_directories(ThreatDetectionSuite/TDSCommon)
include_directories(ThreatDetectionSuite/TDSEngine)
include_directories(ThreatDetectionSuite/TDSEngine/ips)
include_directories(ThreatDetectionSuite/TDSScanner)
include_directories(${YARA_INCLUDE_DIR})

link_directories(${YARA_LIB_DIR})

# Shared Core Library (Internal)
add_library(TDSCore OBJECT
    ThreatDetectionSuite/TDSEngine/TDSEngine.cpp
    ThreatDetectionSuite/TDSEngine/HeuristicsEngine.cpp
    ThreatDetectionSuite/TDSEngine/ips/IPSManager.cpp
    ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp
    ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp
    ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.cpp
    ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.cpp
    ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.cpp
    ThreatDetectionSuite/TDSScanner/MemoryScanner.cpp
    ThreatDetectionSuite/TDSScanner/Entropy.cpp
)

set(TDS_EXTERNAL_LIBS wbemuuid taskschd comsuppw advapi32 ntdll ws2_32 iphlpapi wintrust tdh dbghelp libyara libcrypto libssl crypt32)

# Userland Engine
add_executable(TDSService 
    ThreatDetectionSuite/TDSEngine/TDSService.cpp 
    $<TARGET_OBJECTS:TDSCore>
)
target_link_libraries(TDSService ${TDS_EXTERNAL_LIBS})

# Integration Bridge & Test Utility
add_executable(TDSBridge 
    tools/bridge/TDSBridge.cpp
    $<TARGET_OBJECTS:TDSCore>
)
target_link_libraries(TDSBridge ${TDS_EXTERNAL_LIBS})

# Installation Target
install(TARGETS TDSService TDSBridge
    RUNTIME DESTINATION bin
)

# Testing Configuration
enable_testing()
# add_test(NAME IntegrationTest COMMAND TDSBridge --test)
