param(
    [string]$TaskName = 'Codex Hourly Security Review',
    [string]$Marker = "CODEX_TEST_IOC_TRIGGER_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
)

$ErrorActionPreference = 'Stop'

$testText = "$Marker EncodedCommand DownloadString wevtutil cl vssadmin delete shadows - harmless scheduled monitor validation string only"
$escapedTestText = $testText -replace "'", "''"
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$escapedTestText'"))
powershell.exe -NoProfile -EncodedCommand $encodedCommand

Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($task.State -eq 'Running') {
    "Scheduled task '$TaskName' is already running. Marker written: $Marker"
    return
}

Start-ScheduledTask -TaskName $TaskName
"Started scheduled task '$TaskName' after writing harmless IOC test marker: $Marker"
