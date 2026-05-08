param(
    [string]$TaskName = 'Codex Hourly Security Review',
    [int]$StartDelayMinutes = 5,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch]$SkipAclCheck
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
$CodexCommandPath = [string](Get-ConfigValue -Config $Config -Name 'CodexCommandPath' -Default '')

if (!(Test-Path -LiteralPath $MonitorScript)) {
    throw "Monitor script not found: $MonitorScript"
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

if (!$SkipAclCheck) {
    Assert-PathNotBroadlyWritable -Path $MonitorRoot
    Assert-PathNotBroadlyWritable -Path $MonitorScript
    Assert-PathNotBroadlyWritable -Path $ConfigPath
    if (![string]::IsNullOrWhiteSpace($CodexCommandPath)) {
        Assert-PathNotBroadlyWritable -Path $CodexCommandPath
    }
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = "-NoProfile -WindowStyle Hidden -File `"$MonitorScript`" -ConfigPath `"$ConfigPath`""

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

$description = 'Reviews Windows event logs hourly, appends a running Markdown log, and shows a visible alert window for actionable findings.'

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null

Add-ActionLog "Installed scheduled task '$TaskName' for hourly Codex security/event log review. User=$user; RunLevel=Highest; LogonType=Interactive; routine window hidden; script=$MonitorScript."

Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State, Description
