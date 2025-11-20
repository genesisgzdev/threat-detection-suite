@echo off
setlocal enabledelayedexpansion

set "COMPILER=cl.exe"
set "OUTPUT=ThreatDetectionSuite.exe"
set "SOURCE=ThreatDetectionSuitee.cpp"

echo Threat Detection Suite - Windows Build
echo.

where /q cl.exe
if errorlevel 1 (
    echo Error: MSVC compiler (cl.exe) not found
    echo Please run this from Visual Studio x64 Native Tools Command Prompt
    exit /b 1
)

echo Compiling %SOURCE%...
%COMPILER% /EHsc /std:latest /W4 /permissive- /O2 %SOURCE% ^
    /link ws2_32.lib advapi32.lib shell32.lib psapi.lib iphlpapi.lib ntdll.lib ^
    /OUT:%OUTPUT%

if errorlevel 1 (
    echo.
    echo Compilation failed
    exit /b 1
)

echo.
echo Build successful: %OUTPUT%
echo.
echo To run:
echo   %OUTPUT%
echo.
echo Note: Requires administrator privileges
