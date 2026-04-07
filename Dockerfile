# Stage 1: Build Environment using Windows Server Core
FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS build
WORKDIR /src

# Copy source code to the build environment
COPY . .

# Example build process (adjust according to the actual tech stack, e.g. dotnet publish, msbuild)
# RUN msbuild /p:Configuration=Release
# Or for .NET: RUN dotnet publish -c Release -o /out
# We copy to a generic /out directory for the runtime stage
RUN echo "Simulating build..." && mkdir C:\out && copy * C:\out\

# Stage 2: Runtime Environment using Nano Server for minimal footprint
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022 AS runtime
WORKDIR /app

# Copy the build artifacts from the builder stage
COPY --from=build /out/ .

# Ensure running as non-root user; ContainerUser is standard in Nano Server
USER ContainerUser

# Optional healthcheck using curl (available in newer Nano Server images)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD ["curl.exe", "-f", "http://localhost:8080/health"]

# Define the entrypoint for the Threat Detection Suite
ENTRYPOINT ["threat-detection-suite.exe"]