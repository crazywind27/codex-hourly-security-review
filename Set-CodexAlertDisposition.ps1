param(
    [Parameter(Mandatory = $true)]
    [string]$AlertPath,

    [ValidateSet('Ignored','Acknowledged','Investigating','Resolved')]
    [string]$Decision = 'Ignored',

    [string]$Reason = '',

    [string[]]$Fingerprint = @(),

    [int]$ExpiresDays = 0,

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

function Get-Hash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Set-ObjectProperty {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        Add-Member -InputObject $Object -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

function Add-ActionLog {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    Add-Content -LiteralPath $ActionLog -Value "[$ts] $Message" -Encoding UTF8
}

function Load-AlertDecisions {
    if (!(Test-Path -LiteralPath $AlertDecisionsPath)) {
        return @{
            Version = 1
            Suppressions = @{}
            Decisions = @()
        }
    }
    try {
        $raw = Get-Content -LiteralPath $AlertDecisionsPath -Raw | ConvertFrom-Json
        $suppressions = @{}
        foreach ($s in @($raw.Suppressions)) {
            if ($s.Fingerprint) {
                $suppressions[[string]$s.Fingerprint] = $s
            }
        }
        return @{
            Version = if ($raw.Version) { $raw.Version } else { 1 }
            Suppressions = $suppressions
            Decisions = @($raw.Decisions)
        }
    } catch {
        throw "Could not parse alert decisions file '$AlertDecisionsPath'. $($_.Exception.Message)"
    }
}

function Save-AlertDecisions {
    param([hashtable]$AlertDecisions)
    $dir = Split-Path -Parent $AlertDecisionsPath
    if (![string]::IsNullOrWhiteSpace($dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $ordered = [ordered]@{
        Version = 1
        UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Suppressions = @($AlertDecisions.Suppressions.Values | Sort-Object CreatedUtc, Fingerprint)
        Decisions = @($AlertDecisions.Decisions)
    }
    $ordered | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $AlertDecisionsPath -Encoding UTF8 -Width 240
}

if (!(Test-Path -LiteralPath $AlertPath)) {
    throw "Alert file not found: $AlertPath"
}

$Config = Get-ReviewConfig -Path $ConfigPath
$MonitorRoot = Get-ConfigValue -Config $Config -Name 'MonitorRoot' -Default $PSScriptRoot
$AlertDecisionsPath = Get-ConfigValue -Config $Config -Name 'AlertDecisionsPath' -Default (Join-Path $MonitorRoot 'alert-decisions.json')
$ActionLog = Get-ConfigValue -Config $Config -Name 'ActionLogPath' -Default (Join-Path $MonitorRoot 'actions-taken.txt')
$AllowCriticalAlertSuppressions = [bool](Get-ConfigValue -Config $Config -Name 'AllowCriticalAlertSuppressions' -Default $false)

$resolvedAlertPath = (Resolve-Path -LiteralPath $AlertPath).Path
$RunFolder = Split-Path -Parent $resolvedAlertPath
$runSummaryPath = Join-Path $RunFolder 'run-summary.json'
$findingsPath = Join-Path $RunFolder 'findings.json'

$runSummary = $null
if (Test-Path -LiteralPath $runSummaryPath) {
    $runSummary = Get-Content -LiteralPath $runSummaryPath -Raw | ConvertFrom-Json
}

$findings = @()
if (Test-Path -LiteralPath $findingsPath) {
    $findings = @(Get-Content -LiteralPath $findingsPath -Raw | ConvertFrom-Json)
}

$selectedFindings = @()
if ($Fingerprint.Count -gt 0) {
    $fingerprintSet = @{}
    foreach ($fp in $Fingerprint) {
        if (![string]::IsNullOrWhiteSpace($fp)) {
            $fingerprintSet[$fp] = $true
        }
    }
    $selectedFindings = @($findings | Where-Object { $_.Fingerprint -and $fingerprintSet.ContainsKey([string]$_.Fingerprint) })
    $missing = @($fingerprintSet.Keys | Where-Object {
        $fp = $_
        -not @($selectedFindings | Where-Object { $_.Fingerprint -eq $fp }).Count
    })
    if ($missing.Count -gt 0) {
        Write-Warning "Some requested fingerprints were not found in findings.json: $($missing -join ', ')"
    }
} elseif ($Decision -eq 'Ignored') {
    $selectedFindings = @($findings | Where-Object { $_.Fingerprint -and -not $_.Suppressed })
    if ($selectedFindings.Count -eq 0) {
        $selectedFindings = @($findings | Where-Object { $_.Fingerprint })
    }
} else {
    $selectedFindings = @($findings | Where-Object { $_.Fingerprint })
}

if ($Decision -eq 'Ignored' -and $selectedFindings.Count -eq 0) {
    throw "No finding fingerprints were available to suppress. Expected findings file: $findingsPath"
}

if ([string]::IsNullOrWhiteSpace($Reason)) {
    $Reason = 'No reason provided.'
}

$nowUtc = (Get-Date).ToUniversalTime()
$createdUtc = $nowUtc.ToString('o')
$expiresUtc = $null
if ($ExpiresDays -gt 0) {
    $expiresUtc = $nowUtc.AddDays($ExpiresDays).ToString('o')
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$alertFingerprint = if ($runSummary -and $runSummary.alert_fingerprint) { [string]$runSummary.alert_fingerprint } else { '' }
$selectedFingerprints = @($selectedFindings | ForEach-Object { [string]$_.Fingerprint } | Sort-Object -Unique)
$selectedSuppressionKeys = @($selectedFindings | Where-Object { $_.SuppressionKey } | ForEach-Object { [string]$_.SuppressionKey } | Sort-Object -Unique)
$decisionId = 'd-' + (Get-Hash -Text (@($createdUtc, $user, $resolvedAlertPath, $Decision, ($selectedFingerprints -join '|')) -join '|')).Substring(0, 12)

$alertDecisions = Load-AlertDecisions
$suppressionIds = @()
$blockedCritical = @()

if ($Decision -eq 'Ignored') {
    foreach ($finding in $selectedFindings) {
        if ($finding.Severity -eq 'critical' -and !$AllowCriticalAlertSuppressions) {
            $blockedCritical += $finding.Fingerprint
            continue
        }

        $suppressionId = 's-' + ([string]$finding.Fingerprint).Substring(0, 12)
        $suppressionIds += $suppressionId

        if ($alertDecisions.Suppressions.ContainsKey([string]$finding.Fingerprint)) {
            $suppression = $alertDecisions.Suppressions[[string]$finding.Fingerprint]
            Set-ObjectProperty -Object $suppression -Name 'Status' -Value 'ignored'
            Set-ObjectProperty -Object $suppression -Name 'SuppressionKey' -Value ([string]$finding.SuppressionKey)
            Set-ObjectProperty -Object $suppression -Name 'Reason' -Value $Reason
            Set-ObjectProperty -Object $suppression -Name 'UpdatedUtc' -Value $createdUtc
            Set-ObjectProperty -Object $suppression -Name 'UpdatedBy' -Value $user
            Set-ObjectProperty -Object $suppression -Name 'ExpiresUtc' -Value $expiresUtc
            Set-ObjectProperty -Object $suppression -Name 'SourceAlertPath' -Value $resolvedAlertPath
            Set-ObjectProperty -Object $suppression -Name 'SourceRunFolder' -Value $RunFolder
        } else {
            $alertDecisions.Suppressions[[string]$finding.Fingerprint] = [pscustomobject]@{
                Id = $suppressionId
                Fingerprint = [string]$finding.Fingerprint
                SuppressionKey = [string]$finding.SuppressionKey
                Status = 'ignored'
                Severity = [string]$finding.Severity
                Title = [string]$finding.Title
                Detail = [string]$finding.Detail
                Reason = $Reason
                CreatedUtc = $createdUtc
                CreatedBy = $user
                UpdatedUtc = $createdUtc
                UpdatedBy = $user
                ExpiresUtc = $expiresUtc
                SourceAlertPath = $resolvedAlertPath
                SourceRunFolder = $RunFolder
                MatchCount = 0
                LastMatchedUtc = $null
                LastMatchedRunFolder = $null
            }
        }
    }
}

$decisionRecord = [pscustomobject]@{
    Id = $decisionId
    Decision = $Decision
    Reason = $Reason
    CreatedUtc = $createdUtc
    CreatedBy = $user
    AlertPath = $resolvedAlertPath
    RunFolder = $RunFolder
    AlertFingerprint = $alertFingerprint
    FindingFingerprints = $selectedFingerprints
    SuppressionKeys = $selectedSuppressionKeys
    SuppressionIds = @($suppressionIds | Sort-Object -Unique)
    ExpiresUtc = $expiresUtc
}
$alertDecisions['Decisions'] = @($alertDecisions.Decisions) + $decisionRecord
Save-AlertDecisions -AlertDecisions $alertDecisions

$dispositionPath = Join-Path $RunFolder 'alert-disposition.json'
$decisionRecord | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $dispositionPath -Encoding UTF8 -Width 240

Add-ActionLog "Recorded alert disposition. Decision=$Decision; alert=$resolvedAlertPath; fingerprints=$($selectedFingerprints -join ', '); suppressions=$($suppressionIds -join ', ')."

"Recorded decision '$Decision' for alert: $resolvedAlertPath"
"Decision id: $decisionId"
"Decision file: $AlertDecisionsPath"
if ($Decision -eq 'Ignored') {
    "Suppressed finding fingerprints: $((@($suppressionIds | Sort-Object -Unique)) -join ', ')"
    "Suppression keys: $(($selectedSuppressionKeys) -join ', ')"
    if ($blockedCritical.Count -gt 0) {
        "Critical fingerprints were recorded in the decision but not suppressed because AllowCriticalAlertSuppressions is false: $($blockedCritical -join ', ')"
    }
}
