cmake_minimum_required(VERSION 3.10)
project(ThreatDetectionSuite)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /std:latest /W4")
    add_compile_options(/permissive-)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -std=c++17")
endif()

add_executable(ThreatDetectionSuite ThreatDetectionSuitee.cpp)

if(WIN32)
    target_link_libraries(ThreatDetectionSuite PRIVATE
        ws2_32
        advapi32
        shell32
        psapi
        iphlpapi
        ntdll
    )
endif()

if(MSVC)
    target_compile_options(ThreatDetectionSuite PRIVATE /W4 /WX)
else()
    target_compile_options(ThreatDetectionSuite PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(ThreatDetectionSuite PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
