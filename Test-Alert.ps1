param(
    [string]$TaskName = 'Codex Hourly Security Review',
    [string]$Marker = "CODEX_TEST_IOC_TRIGGER_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
)

$ErrorActionPreference = 'Stop'

$testText = "$Marker EncodedCommand DownloadString wevtutil cl vssadmin delete shadows - codex hourly security review test string only"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output '$testText'"

Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($task.State -eq 'Running') {
    "Scheduled task '$TaskName' is already running. Marker written: $Marker"
    return
}

Start-ScheduledTask -TaskName $TaskName
"Started scheduled task '$TaskName' after writing harmless IOC test marker: $Marker"
