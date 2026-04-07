# TDS Real-Time SOC Watcher
# Monitors EDR logs and triggers the GitHub SOC Bot immediately.

$logPath = "C:\ProgramData\TDS\threats.jsonl"
$botScript = "C:\Users\Genesisif\.gemini\tmp\system32\threat-detection-suite\tools\soc\soc_bot.py"

if (-not (Test-Path $logPath)) {
    New-Item -ItemType File -Path $logPath -Force
}

Write-Host "[*] Initializing Real-Time SOC Pipeline..." -ForegroundColor Cyan

# Tail the log file and process new lines as they arrive
Get-Content $logPath -Wait -Tail 0 | ForEach-Object {
    $line = $_
    if ($line -match '^{.*}$') {
        Write-Host "[!] Threat Detected! Triggering GitHub SOC Bot..." -ForegroundColor Yellow
        # Execute the bot with the JSON payload
        python $botScript "$line"
    }
}
