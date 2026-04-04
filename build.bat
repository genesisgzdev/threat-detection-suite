@echo off
setlocal enabledelayedexpansion

echo [*] Starting Threat Detection Suite v4.0 Build Process
echo [!] Ensuring high-standard engineering environment...

:: Check for CMake
cmake --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Error: CMake not found. Please install CMake.
    exit /b 1
)

:: Userland Components Build
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

:: Kernel Driver Build (WDK / MSBuild)
echo [*] Searching for MSBuild (WDK Support)...
for /f "usebackq tokens=*" %%i in (`vswhere.exe -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
    set MSBUILD_PATH=%%i\MSBuild\Current\Bin\MSBuild.exe
)

if not exist "!MSBUILD_PATH!" (
    echo [!] Warning: MSBuild not found via vswhere. Attempting standard path...
    set MSBUILD_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
)

if exist "!MSBUILD_PATH!" (
    echo [*] Compiling ThreatDetectionKernel (WDK)...
    !MSBUILD_PATH! ThreatDetectionSuite\TDSDriver\ThreatDetectionKernel.vcxproj /p:Configuration=Release /p:Platform=x64
    if !errorlevel! neq 0 (
        echo [!] Driver compilation failed. Ensure WDK is installed.
    )
) else (
    echo [-] Error: MSBuild not found. Skipping driver build.
)

echo [*] Build Process Finalized.
echo [INFO] Binaries available in build\Release and TDSDriver\x64\Release
pause
