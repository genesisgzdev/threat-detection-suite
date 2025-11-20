#!/bin/bash

set -e

COMPILER=${CXX:-clang++}
SOURCE="ThreatDetectionSuitee.cpp"
OUTPUT="ThreatDetectionSuite"

echo "Threat Detection Suite - Build"
echo

if ! command -v "$COMPILER" &> /dev/null; then
    echo "Error: C++ compiler not found ($COMPILER)"
    echo "Install GCC, Clang, or set CXX environment variable"
    exit 1
fi

echo "Using compiler: $COMPILER"
echo "Compiling $SOURCE..."

CXXFLAGS="-std=c++17 -Wall -Wextra -Wpedantic -O2"

if [[ "$OSTYPE" == "mingw"* ]] || [[ "$OSTYPE" == "cygwin"* ]]; then
    LDFLAGS="-lws2_32 -ladvapi32 -lshell32 -lpsapi -liphlpapi -lntdll"
else
    LDFLAGS=""
fi

$COMPILER $CXXFLAGS $SOURCE $LDFLAGS -o $OUTPUT

if [ $? -ne 0 ]; then
    echo
    echo "Compilation failed"
    exit 1
fi

echo
echo "Build successful: $OUTPUT"
echo
echo "To run:"
echo "  ./$OUTPUT"
echo
echo "Note: Requires administrator/root privileges"
