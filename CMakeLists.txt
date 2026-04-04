cmake_minimum_required(VERSION 3.10)
project(NexusEDR)

set(CMAKE_CXX_STANDARD 17)

# Common headers
include_directories(NexusEDR/common)

# Userland Engine
add_executable(NexusService 
    NexusEDR/engine/NexusService.cpp 
    NexusEDR/engine/collectors/EtwCollector.cpp
    NexusEDR/engine/correlator/SequenceCorrelator.cpp
    NexusEDR/engine/detectors/PersistenceDetector.cpp
)
target_link_libraries(NexusService wbemuuid taskschd comsuppw advapi32)

# Driver (Conceptual - usually requires WDK MSBuild or specialized CMake toolchain)
# add_library(NexusEDR_Driver SHARED NexusEDR/driver/NexusEDR.c)
# set_target_properties(NexusEDR_Driver PROPERTIES SUFFIX ".sys")
