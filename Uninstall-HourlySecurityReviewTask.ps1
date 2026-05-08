param(
    [string]$TaskName = 'Codex Hourly Security Review',
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
$ActionLog = Get-ConfigValue -Config $Config -Name 'ActionLogPath' -Default (Join-Path $MonitorRoot 'actions-taken.txt')

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    Add-Content -LiteralPath $ActionLog -Value "[$ts] Uninstalled scheduled task '$TaskName'." -Encoding UTF8
    "Removed scheduled task '$TaskName'."
} else {
    "Scheduled task '$TaskName' was not found."
}
