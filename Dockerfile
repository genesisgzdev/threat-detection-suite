# Threat Detection Suite - CI Build Environment (Windows Server Core 2022)
FROM mcr.microsoft.com/windows/servercore:ltsc2022

LABEL maintainer="security@genzt.dev"
LABEL version="4.2.0"

WORKDIR /app
COPY . .

# Multi-stage userland build
RUN cmake -B build -S . -G "Visual Studio 17 2022" -A x64
RUN cmake --build build --config Release

# Note: Kernel driver build requires WDK which is typically not pre-installed in servercore
CMD ["build/bin/Release/TDSService.exe"]

