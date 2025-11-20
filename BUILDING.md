# Building Threat Detection Suite

## Requirements

- Windows 7 SP1 or later (for execution)
- C++17 capable compiler
- 50MB disk space

## Windows (MSVC)

### Method 1: Batch Script

Open Visual Studio x64 Native Tools Command Prompt and run:

```cmd
build.bat
```

This will compile ThreatDetectionSuite.exe in the current directory.

### Method 2: Manual Compilation

```cmd
cl.exe /EHsc /std:latest /W4 /permissive- /O2 ThreatDetectionSuitee.cpp ^
    /link ws2_32.lib advapi32.lib shell32.lib psapi.lib iphlpapi.lib ntdll.lib ^
    /OUT:ThreatDetectionSuite.exe
```

### Method 3: CMake

```cmd
mkdir build
cd build
cmake -G "Visual Studio 16 2019" -A x64 ..
cmake --build . --config Release
```

Output: build\Release\ThreatDetectionSuite.exe

### Method 4: Makefile

Requires MSVC tools in PATH:

```cmd
nmake /f Makefile
```

## Linux/Unix (GCC/Clang)

### Method 1: Shell Script

```bash
chmod +x build.sh
./build.sh
```

### Method 2: Manual Compilation

```bash
g++ -std=c++17 -Wall -Wextra -Wpedantic -O2 ThreatDetectionSuitee.cpp -o ThreatDetectionSuite
```

Or with Clang:

```bash
clang++ -std=c++17 -Wall -Wextra -Wpedantic -O2 ThreatDetectionSuitee.cpp -o ThreatDetectionSuite
```

### Method 3: CMake

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Verification

After compilation, verify the executable exists:

Windows:
```cmd
dir ThreatDetectionSuite.exe
```

Linux:
```bash
ls -la ThreatDetectionSuite
```

## Execution

Windows (requires admin):
```cmd
ThreatDetectionSuite.exe
```

Linux (requires root):
```bash
sudo ./ThreatDetectionSuite
```

## Compilation Flags

### MSVC Flags
- `/EHsc`: Enable C++ exception handling
- `/std:latest`: Use latest C++ standard
- `/W4`: Enable level 4 warnings
- `/permissive-`: Strict standard conformance
- `/O2`: Optimize for speed

### GCC/Clang Flags
- `-std=c++17`: C++17 standard
- `-Wall`: Enable all warnings
- `-Wextra`: Enable extra warnings
- `-Wpedantic`: Enable pedantic warnings
- `-O2`: Optimize for speed

## Library Dependencies

### Windows (Linked automatically)
- ws2_32.lib: Winsock2 (networking)
- advapi32.lib: Registry and security APIs
- shell32.lib: Shell utilities (folder paths)
- psapi.lib: Process API
- iphlpapi.lib: IP helper (TCP tables)
- ntdll.lib: Native API (PEB parsing)

## Troubleshooting

### MSVC Compiler Not Found
- Ensure you're using "x64 Native Tools Command Prompt for VS"
- Or add MSVC to PATH manually

### Missing Libraries
- Windows: Libraries should be built-in with MSVC
- Linux: Install build-essential package

### Compilation Errors
- Ensure C++17 support
- Check for typos in command
- Review CMakeLists.txt or Makefile

## Cross-Compilation Notes

Note: This is a Windows-specific tool. Linux compilation provided for compatibility only.

Full functionality requires Windows API calls and will not work on non-Windows platforms.
