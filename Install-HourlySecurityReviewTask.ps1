param(
    [string]$TaskName = 'Codex Hourly Security Review',
    [int]$StartDelayMinutes = 5,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json')
)

$ErrorActionPreference = 'Stop'

function Get-ReviewConfig {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        try {
            return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Could not parse config file '$Path'; using defaults. $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{}
}

function Get-ConfigValue {
    param(
        [object]$Config,
        [string]$Name,
        [object]$Default
    )

    if ($Config -and $Config.PSObject.Properties.Name -contains $Name) {
        $value = $Config.$Name
        if ($null -ne $value -and ![string]::IsNullOrWhiteSpace([string]$value)) {
            return $value
        }
    }
    return $Default
}

$Config = Get-ReviewConfig -Path $ConfigPath
$MonitorRoot = Get-ConfigValue -Config $Config -Name 'MonitorRoot' -Default $PSScriptRoot
$MonitorScript = Join-Path $MonitorRoot 'Run-HourlySecurityReview.ps1'
$ActionLog = Get-ConfigValue -Config $Config -Name 'ActionLogPath' -Default (Join-Path $MonitorRoot 'actions-taken.txt')

if (!(Test-Path -LiteralPath $MonitorScript)) {
    throw "Monitor script not found: $MonitorScript"
}

function Add-ActionLog {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    Add-Content -LiteralPath $ActionLog -Value "[$ts] $Message" -Encoding UTF8
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$MonitorScript`" -ConfigPath `"$ConfigPath`""

$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory (Split-Path -Parent $MonitorScript)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($StartDelayMinutes) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -Compatibility Win8

$description = 'Runs Codex hourly to review Windows event logs, append a running Markdown log, and show a visible alert window for actionable findings.'

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null

Add-ActionLog "Installed scheduled task '$TaskName' for hourly Codex security/event log review. User=$user; RunLevel=Highest; LogonType=Interactive; routine window hidden; script=$MonitorScript."

Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State, Description
