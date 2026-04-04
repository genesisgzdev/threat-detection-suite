@echo off
setlocal enabledelayedexpansion

:: Threat Detection Suite v4.0 - Automated Build Script (Windows)
:: Requirements: Visual Studio 2022, WDK, CMake

echo [*] Initializing Threat Detection Suite Build Process...

:: Check for Visual Studio environment
if "%VCINSTALLDIR%" == "" (
    echo [!] Visual Studio Developer Command Prompt not detected.
    echo [*] Attempting to locate vcvars64.bat...
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do (
        set "VS_PATH=%%i"
    )
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" (
        call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo [!] Could not locate vcvars64.bat. Please run from a Developer Command Prompt.
        exit /b 1
    )
)

:: 1. Build User-Mode Components with CMake
echo [*] Building User-Mode Components (Service, Engine, Scanner)...
if not exist "build" mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
if %errorlevel% neq 0 (
    echo [!] CMake configuration failed.
    exit /b %errorlevel%
)

cmake --build . --config Release
if %errorlevel% neq 0 (
    echo [!] User-mode build failed.
    exit /b %errorlevel%
)
cd ..

:: 2. Build Kernel-Mode Driver with MSBuild
echo [*] Building Kernel-Mode Driver (ThreatDetectionKernel)...
cd ThreatDetectionSuite\driver
msbuild ThreatDetectionKernel.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild
if %errorlevel% neq 0 (
    echo [!] Driver build failed.
    exit /b %errorlevel%
)
cd ..\..

echo [CORE] Threat Detection Suite Build Complete.
echo [INFO] Binaries: build\bin\Release\
echo [INFO] Driver: ThreatDetectionSuite\driver\x64\Release\ThreatDetectionKernel.sys
exit /b 0
