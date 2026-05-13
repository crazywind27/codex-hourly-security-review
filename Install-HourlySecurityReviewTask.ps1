param(
    [string]$TaskName = 'Codex Hourly Security Review',
    [string]$WeeklyTaskName = 'Codex Weekly Security Report',
    [int]$StartDelayMinutes = 5,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch]$SkipAclCheck,
    [switch]$DisableWeeklyReportTask
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
$WeeklyReportScript = Join-Path $MonitorRoot 'New-WeeklySecurityReport.ps1'
$HiddenLauncher = Join-Path $MonitorRoot 'Start-HourlySecurityReviewHidden.vbs'
$WeeklyHiddenLauncher = Join-Path $MonitorRoot 'Start-WeeklySecurityReportHidden.vbs'
$ActionLog = Get-ConfigValue -Config $Config -Name 'ActionLogPath' -Default (Join-Path $MonitorRoot 'actions-taken.txt')
$CodexCommandPath = [string](Get-ConfigValue -Config $Config -Name 'CodexCommandPath' -Default '')
$WeeklyReportEnabled = [bool](Get-ConfigValue -Config $Config -Name 'WeeklyReportEnabled' -Default $true)
$WeeklyReportDay = [string](Get-ConfigValue -Config $Config -Name 'WeeklyReportDay' -Default 'Saturday')
$WeeklyReportTime = [string](Get-ConfigValue -Config $Config -Name 'WeeklyReportTime' -Default '09:00')

if (!(Test-Path -LiteralPath $MonitorScript)) {
    throw "Monitor script not found: $MonitorScript"
}
if (!(Test-Path -LiteralPath $HiddenLauncher)) {
    throw "Hidden launcher not found: $HiddenLauncher"
}
if ($WeeklyReportEnabled -and !$DisableWeeklyReportTask -and !(Test-Path -LiteralPath $WeeklyReportScript)) {
    throw "Weekly report script not found: $WeeklyReportScript"
}
if ($WeeklyReportEnabled -and !$DisableWeeklyReportTask -and !(Test-Path -LiteralPath $WeeklyHiddenLauncher)) {
    throw "Weekly report hidden launcher not found: $WeeklyHiddenLauncher"
}

function Add-ActionLog {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    Add-Content -LiteralPath $ActionLog -Value "[$ts] $Message" -Encoding UTF8
}

function Assert-PathNotBroadlyWritable {
    param([string]$Path)

    if (!(Test-Path -LiteralPath $Path)) {
        return
    }

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop | Select-Object -First 1).Path
    $acl = Get-Acl -LiteralPath $resolved
    $broadSids = @(
        'S-1-1-0',       # Everyone
        'S-1-5-11',      # Authenticated Users
        'S-1-5-32-545'   # Users
    )
    $writeRights = [System.Security.AccessControl.FileSystemRights](
        [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Modify -bor
        [System.Security.AccessControl.FileSystemRights]::FullControl -bor
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )

    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($broadSids -notcontains $rule.IdentityReference.Value) { continue }
        if (($rule.FileSystemRights -band $writeRights) -ne 0) {
            throw "Refusing to install elevated scheduled task because '$resolved' is writable by broad local principal $($rule.IdentityReference.Value). Move the monitor to a protected folder or fix ACLs. Use -SkipAclCheck only after a manual security review."
        }
    }
}

function Assert-PowerShellCanRunMonitor {
    $policy = Get-ExecutionPolicy
    if ($policy -eq 'Restricted') {
        throw "Effective PowerShell execution policy is Restricted. The scheduled task does not use ExecutionPolicy Bypass; set a script-capable policy such as RemoteSigned for CurrentUser or LocalMachine before installing."
    }

    if ($policy -eq 'AllSigned') {
        $signature = Get-AuthenticodeSignature -FilePath $MonitorScript -ErrorAction SilentlyContinue
        if (!$signature -or $signature.Status -ne 'Valid') {
            throw "Effective PowerShell execution policy is AllSigned, but '$MonitorScript' does not have a valid signature. Sign the monitor scripts or use a policy such as RemoteSigned before installing."
        }
    }

    $scriptPaths = @(
        $PSCommandPath,
        $MonitorScript,
        (Join-Path $MonitorRoot 'Launch-CodexSecurityAlert.ps1'),
        (Join-Path $MonitorRoot 'Set-CodexAlertDisposition.ps1')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $blocked = New-Object System.Collections.ArrayList
    foreach ($scriptPath in $scriptPaths) {
        try {
            $zoneStream = Get-Item -LiteralPath $scriptPath -Stream Zone.Identifier -ErrorAction SilentlyContinue
            if ($zoneStream) {
                [void]$blocked.Add($scriptPath)
            }
        } catch {
            # Alternate data streams are not available on every filesystem.
        }
    }

    if ($blocked.Count -gt 0) {
        throw "One or more monitor scripts are marked as downloaded from the internet and may be blocked by RemoteSigned policy. Run Unblock-File for these paths before installing: $($blocked -join '; ')"
    }
}

Assert-PowerShellCanRunMonitor

if (!$SkipAclCheck) {
    Assert-PathNotBroadlyWritable -Path $MonitorRoot
    Assert-PathNotBroadlyWritable -Path $MonitorScript
    Assert-PathNotBroadlyWritable -Path $WeeklyReportScript
    Assert-PathNotBroadlyWritable -Path $HiddenLauncher
    Assert-PathNotBroadlyWritable -Path $WeeklyHiddenLauncher
    Assert-PathNotBroadlyWritable -Path $ConfigPath
    if (![string]::IsNullOrWhiteSpace($CodexCommandPath)) {
        Assert-PathNotBroadlyWritable -Path $CodexCommandPath
    }
}

try {
    $weeklyDayEnum = [System.Enum]::Parse([System.DayOfWeek], $WeeklyReportDay, $true)
} catch {
    throw "WeeklyReportDay must be a day name like Monday, Tuesday, or Saturday. Value: $WeeklyReportDay"
}
try {
    $weeklyAt = [datetime]::ParseExact($WeeklyReportTime, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture)
} catch {
    throw "WeeklyReportTime must use 24-hour HH:mm format, for example 09:00 or 18:30. Value: $WeeklyReportTime"
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$wscript = Join-Path $env:SystemRoot 'System32\wscript.exe'
$arguments = "//B `"$HiddenLauncher`" `"$ConfigPath`""

$action = New-ScheduledTaskAction -Execute $wscript -Argument $arguments -WorkingDirectory (Split-Path -Parent $MonitorScript)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($StartDelayMinutes) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -Compatibility Win8

$description = 'Reviews Windows event logs hourly, appends a running Markdown log, and shows a visible alert window for actionable findings.'

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null

Add-ActionLog "Installed scheduled task '$TaskName' for hourly Codex security/event log review. User=$user; RunLevel=Highest; LogonType=Interactive; non-disruptive hidden launcher=$HiddenLauncher; script=$MonitorScript."

if ($WeeklyReportEnabled -and !$DisableWeeklyReportTask) {
    $weeklyArguments = "//B `"$WeeklyHiddenLauncher`" `"$ConfigPath`""
    $weeklyAction = New-ScheduledTaskAction -Execute $wscript -Argument $weeklyArguments -WorkingDirectory (Split-Path -Parent $WeeklyReportScript)
    $weeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $weeklyDayEnum -At $weeklyAt
    $weeklyPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $weeklySettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
        -Compatibility Win8
    $weeklyDescription = 'Generates a local weekly HTML security report and optionally sends a redacted email digest.'
    Register-ScheduledTask -TaskName $WeeklyTaskName -Action $weeklyAction -Trigger $weeklyTrigger -Principal $weeklyPrincipal -Settings $weeklySettings -Description $weeklyDescription -Force | Out-Null
    Add-ActionLog "Installed scheduled task '$WeeklyTaskName' for weekly local HTML report. User=$user; RunLevel=Limited; Day=$WeeklyReportDay; Time=$WeeklyReportTime; non-disruptive hidden launcher=$WeeklyHiddenLauncher; script=$WeeklyReportScript."
}

Get-ScheduledTask -TaskName $TaskName, $WeeklyTaskName -ErrorAction SilentlyContinue | Select-Object TaskName, State, Description
