@echo off
setlocal enabledelayedexpansion

echo [*] Starting Threat Detection Suite v5.0.0 Build Process
echo [!] Ensuring professional engineering environment...

:: 1. Check for CMake
cmake --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Error: CMake not found. Please install CMake 3.20+.
    exit /b 1
)

:: 2. Check for Windows SDK / WDK Environment
if "%WindowsSdkDir%"=="" (
    echo [!] Warning: WindowsSdkDir not set. Driver build may fail.
    echo [*] Hint: Run this script from "Developer Command Prompt for VS 2022".
)

:: 3. Userland Components Build
echo [*] Configuring Userland Components (CMake)...
if not exist build mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
if %errorlevel% neq 0 (
    echo [-] CMake configuration failed.
    exit /b 1
)

echo [*] Compiling Userland Suite (Release)...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo [-] Userland compilation failed.
    exit /b 1
)
cd ..

:: 4. Kernel Driver Build (WDK / MSBuild)
echo [*] Locating MSBuild...
for /f "usebackq tokens=*" %%i in (`vswhere.exe -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
    set MSBUILD_PATH=%%i\MSBuild\Current\Bin\MSBuild.exe
)

if not exist "!MSBUILD_PATH!" (
    set MSBUILD_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
)

if exist "!MSBUILD_PATH!" (
    echo [*] Compiling ThreatDetectionKernel (WDK)...
    !MSBUILD_PATH! ThreatDetectionSuite\TDSDriver\TDSDriver.vcxproj /p:Configuration=Release /p:Platform=x64
    if !errorlevel! neq 0 (
        echo [!] Driver compilation failed. Ensure WDK Extension for VS 2022 is installed.
    ) else (
        echo [^+] Driver compiled successfully.
    )
) else (
    echo [-] Error: MSBuild not found. Skipping driver build.
)

echo [*] Build Process Finalized.
echo [INFO] Binaries available in bin/Release and TDSDriver/x64/Release
pause

