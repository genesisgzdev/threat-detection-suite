# Use a Windows base image with build tools
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Install CMake and MSVC Build Tools (Conceptual - usually requires manual setup or Chocolatey)
# For this task, we assume the environment has the necessary tools to build or we provide the Dockerfile structure.

WORKDIR /app
COPY . .

# Build the userland service
RUN cmake -B build -S .
RUN cmake --build build --config Release

# Output binaries will be in /app/build/Release
CMD ["NexusService.exe"]
