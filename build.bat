@echo off
setlocal enabledelayedexpansion

echo [*] Starting Threat Detection Suite v5.0.0 Build Process
echo [!] Ensuring professional engineering environment...

:: 1. Load Visual Studio Environment
set "VCVARS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "!VCVARS_PATH!" set "VCVARS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"

if exist "!VCVARS_PATH!" (
    echo [*] Loading Visual Studio Environment...
    call "!VCVARS_PATH!" x64
)

:: 2. Userland Components Build
echo [*] Configuring Userland Components (NMake)...
if not exist build mkdir build
cd build
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ..
if %errorlevel% neq 0 (
    echo [-] CMake configuration failed.
    exit /b 1
)

echo [*] Compiling Userland Suite (Release)...
nmake
if %errorlevel% neq 0 (
    echo [-] Userland compilation failed.
    exit /b 1
)
cd ..

:: 3. Kernel Driver Build (WDK / MSBuild)
echo [*] Compiling ThreatDetectionKernel (WDK)...
msbuild ThreatDetectionSuite\TDSDriver\TDSDriver.vcxproj /p:Configuration=Release /p:Platform=x64
if %errorlevel% neq 0 (
    echo [!] Driver compilation failed. Ensure WDK Extension for VS is installed.
) else (
    echo [^+] Driver compiled successfully.
)

echo [*] Build Process Finalized.
pause
