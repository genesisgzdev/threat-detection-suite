cmake_minimum_required(VERSION 3.20)
project(ThreatDetectionSuite VERSION 5.6.7 LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "ThreatDetectionSuite user-mode build requires Windows; use build.sh for repository-only checks")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Security Hardening Flags (Standard EDR Practices)
if(MSVC)
    add_compile_options(/GS /guard:cf /W4 /WX /sdl /wd4324 /wd4100 /wd4244 /wd4267)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_link_options(/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF /CETCOMPAT)
endif()

# External Dependencies (YARA). The path is supplied by the build environment;
# no developer workstation path is part of the project configuration.
option(TDS_ENABLE_YARA "Enable YARA memory scanning" OFF)
set(TDS_YARA_ROOT "" CACHE PATH "Root of the YARA SDK")
if(TDS_ENABLE_YARA)
    find_path(YARA_INCLUDE_DIR yara.h
        HINTS "${TDS_YARA_ROOT}/include" "${TDS_YARA_ROOT}/lib/native/include")
    find_library(YARA_LIBRARY NAMES yara libyara
        HINTS "${TDS_YARA_ROOT}/lib" "${TDS_YARA_ROOT}/lib/native/x64/lib")
    if(NOT YARA_INCLUDE_DIR OR NOT YARA_LIBRARY)
        message(FATAL_ERROR "YARA SDK not found. Set -DTDS_YARA_ROOT=<path> or disable TDS_ENABLE_YARA")
    endif()
    add_compile_definitions(TDS_HAS_YARA=1)
else()
    set(YARA_INCLUDE_DIR "")
    set(YARA_LIBRARY "")
endif()

# Common headers
include_directories(ThreatDetectionSuite/TDSCommon)
include_directories(ThreatDetectionSuite/TDSEngine)
include_directories(ThreatDetectionSuite/TDSEngine/ips)
include_directories(ThreatDetectionSuite/TDSScanner)
include_directories(${YARA_INCLUDE_DIR})

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

set(TDS_EXTERNAL_LIBS wbemuuid taskschd comsuppw advapi32 ntdll ws2_32 iphlpapi wintrust tdh dbghelp crypt32 ${YARA_LIBRARY})

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
set_target_properties(TDSCore TDSService TDSBridge PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_target_properties(TDSCore PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_custom_target(TDSDriverBuild
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File
        "${CMAKE_SOURCE_DIR}/tools/build-driver.ps1"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building Threat Detection Suite kernel driver with WDK")
