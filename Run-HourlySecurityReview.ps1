param(
    [switch]$NoCodex,
    [switch]$NoAlertWindow,
    [switch]$ForceAlert,
    [int]$DefaultLookbackMinutes = 70,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json')
)

$ErrorActionPreference = 'Continue'

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
$DocumentsRoot = [Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($DocumentsRoot)) {
    $DocumentsRoot = Join-Path $env:USERPROFILE 'Documents'
}
$DefaultOutputRoot = Join-Path $DocumentsRoot 'Codex Hourly Security Review'

$WorkRoot = Get-ConfigValue -Config $Config -Name 'WorkRoot' -Default $PSScriptRoot
$MonitorRoot = Get-ConfigValue -Config $Config -Name 'MonitorRoot' -Default $PSScriptRoot
$RunsRoot = Join-Path $MonitorRoot 'runs'
$StatePath = Join-Path $MonitorRoot 'state.json'
$SchemaPath = Join-Path $MonitorRoot 'codex-security-review.schema.json'
$AlertScript = Join-Path $MonitorRoot 'Launch-CodexSecurityAlert.ps1'
$DriveProject = Get-ConfigValue -Config $Config -Name 'LogRoot' -Default $DefaultOutputRoot
$DriveLog = Get-ConfigValue -Config $Config -Name 'DriveLogPath' -Default (Join-Path $DriveProject 'hourly-security-review-log.md')
$DriveLogDir = Split-Path -Parent $DriveLog
$ActionLog = Get-ConfigValue -Config $Config -Name 'ActionLogPath' -Default (Join-Path $MonitorRoot 'actions-taken.txt')
$ComputerLabel = Get-ConfigValue -Config $Config -Name 'ComputerLabel' -Default $env:COMPUTERNAME
$CanaryAccountName = Get-ConfigValue -Config $Config -Name 'CanaryAccountName' -Default ''
$CanaryAccountDescription = Get-ConfigValue -Config $Config -Name 'CanaryAccountDescription' -Default 'configured canary account'
$SecurityProductName = Get-ConfigValue -Config $Config -Name 'SecurityProductName' -Default 'security product'
$SecurityServicePattern = Get-ConfigValue -Config $Config -Name 'SecurityServicePattern' -Default 'WinDefend|mpssvc|Security Center|wscsvc|EventLog'
$SecurityProductServicePattern = Get-ConfigValue -Config $Config -Name 'SecurityProductServicePattern' -Default $SecurityServicePattern
$AlertDecisionsPath = Get-ConfigValue -Config $Config -Name 'AlertDecisionsPath' -Default (Join-Path $MonitorRoot 'alert-decisions.json')
$AllowCriticalAlertSuppressions = [bool](Get-ConfigValue -Config $Config -Name 'AllowCriticalAlertSuppressions' -Default $false)

New-Item -ItemType Directory -Path $MonitorRoot, $RunsRoot, $DriveLogDir -Force | Out-Null

function Add-ActionLog {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    Add-Content -LiteralPath $ActionLog -Value "[$ts] $Message" -Encoding UTF8
}

function Get-SeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'critical' { 5 }
        'high' { 4 }
        'medium' { 3 }
        'low' { 2 }
        'info' { 1 }
        default { 0 }
    }
}

function ConvertFrom-EventXml {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $map = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) {
                $map[$d.Name] = [string]$d.'#text'
            }
        }
    } catch {
    }
    return $map
}

function Get-ShortMessage {
    param([string]$Message, [int]$Max = 1200)
    if ([string]::IsNullOrWhiteSpace($Message)) { return '' }
    $clean = (($Message -replace "`r?`n", ' ') -replace '\s+', ' ').Trim()
    if ($clean.Length -gt $Max) { return $clean.Substring(0, $Max) + '...' }
    return $clean
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

function Get-NormalizedFingerprintText {
    param([string]$Text, [int]$Max = 900)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = Get-ShortMessage -Message $Text -Max $Max
    $clean = $clean -replace '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<guid>'
    $clean = $clean -replace '\b\d{8}-\d{6}\b', '<runstamp>'
    $clean = $clean -replace '\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z| ?[+-]\d{2}:?\d{2})?\b', '<timestamp>'
    $clean = $clean -replace '\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?\b', '<timestamp>'
    $clean = $clean -replace '\bRecordId\s*[:=]\s*\d+\b', 'RecordId=<id>'
    $clean = $clean -replace '\bProcessId\s*[:=]\s*\d+\b', 'ProcessId=<pid>'
    $clean = $clean -replace '\bPID\s*[:=]\s*\d+\b', 'PID=<pid>'
    $clean = $clean -replace '\s+', ' '
    return $clean.Trim()
}

function Get-SuspiciousTokenSummary {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $tokens = New-Object System.Collections.Generic.List[string]
    $checks = [ordered]@{
        'encodedcommand' = '(?i)(encodedcommand|\s-enc\s)'
        'base64' = '(?i)frombase64string'
        'downloadstring' = '(?i)downloadstring'
        'invoke-webrequest' = '(?i)(invoke-webrequest|\biwr\b)'
        'invoke-expression' = '(?i)(invoke-expression|\biex\b)'
        'execution-bypass' = '(?i)\s-bypass\b'
        'hidden-window' = '(?i)(\s-windowstyle\s+hidden|\s-w\s+hidden)'
        'regsvr32-http' = '(?i)regsvr32.+/i:http'
        'mshta-http' = '(?i)mshta\s+http'
        'rundll32-javascript' = '(?i)rundll32.+javascript'
        'certutil-transfer' = '(?i)certutil.+(-urlcache|-decode)'
        'bitsadmin-transfer' = '(?i)bitsadmin.+/transfer'
        'wmic-process-create' = '(?i)wmic.+process.+call.+create'
        'schtasks-create' = '(?i)schtasks.+/create'
        'service-create' = '(?i)sc(\.exe)?\s+create'
        'user-add' = '(?i)net(\.exe)?\s+user.+/add'
        'admin-add' = '(?i)net(\.exe)?\s+localgroup.+administrators.+/add'
        'shadow-delete' = '(?i)vssadmin.+delete.+shadows'
        'backup-delete' = '(?i)wbadmin.+delete'
        'recovery-disable' = '(?i)bcdedit.+recoveryenabled\s+no'
        'eventlog-clear' = '(?i)wevtutil.+\scl\s'
        'run-key' = '(?i)reg(\.exe)?\s+add.+\\(run|runonce)'
        'defender-disable' = '(?i)set-mppreference.+disablerealtimemonitoring'
        'defender-exclusion' = '(?i)add-mppreference.+exclusion'
        'security-service-stop' = '(?i)(net(\.exe)?|sc(\.exe)?)\s+stop\s+(ekrn|efwd|mpssvc|windefend)'
    }
    foreach ($name in $checks.Keys) {
        if ($Text -match $checks[$name]) {
            $tokens.Add($name)
        }
    }
    if ($tokens.Count -eq 0) { return '' }
    return (@($tokens) | Sort-Object -Unique) -join ','
}

function Get-EventFingerprintSource {
    param([object]$Event)
    if ($null -eq $Event) { return '' }
    $combinedText = @($Event.Message, $Event.CommandLine, $Event.TaskContent, $Event.ServiceFileName, $Event.NewProcessName, $Event.ParentProcessName) -join ' '
    $suspiciousTokens = Get-SuspiciousTokenSummary -Text $combinedText
    $textSummary = if (![string]::IsNullOrWhiteSpace($suspiciousTokens)) {
        "tokens:$suspiciousTokens"
    } else {
        Get-NormalizedFingerprintText -Text $Event.Message -Max 500
    }
    $parts = @(
        $Event.LogName,
        $Event.ProviderName,
        $Event.Id,
        $Event.LevelDisplayName,
        $Event.TargetUserName,
        $Event.SubjectUserName,
        $Event.IpAddress,
        $Event.WorkstationName,
        $Event.LogonType,
        $Event.Status,
        $Event.SubStatus,
        $Event.ServiceName,
        (Get-NormalizedFingerprintText -Text $Event.ServiceFileName -Max 500),
        (Get-NormalizedFingerprintText -Text $Event.NewProcessName -Max 500),
        (Get-NormalizedFingerprintText -Text $Event.ParentProcessName -Max 500),
        (Get-NormalizedFingerprintText -Text $Event.CommandLine -Max 900),
        $Event.TaskName,
        (Get-NormalizedFingerprintText -Text $Event.TaskContent -Max 900),
        $Event.ObjectName,
        $Event.ShareName,
        $Event.DestAddress,
        $Event.DestPort,
        $Event.SourceAddress,
        $Event.SourcePort,
        $textSummary
    )
    return (($parts | ForEach-Object { if ($null -eq $_) { '' } else { [string]$_ } }) -join '|')
}

function Get-FindingFingerprint {
    param(
        [string]$Severity,
        [string]$Title,
        [object[]]$RelatedEvents
    )
    $eventSources = @($RelatedEvents | ForEach-Object { Get-EventFingerprintSource -Event $_ } | Sort-Object -Unique)
    $source = @($Severity, $Title, ($eventSources -join "`n")) -join "`n"
    return Get-Hash -Text $source
}

function Get-FindingSuppressionKey {
    param(
        [string]$Severity,
        [string]$Title,
        [object[]]$RelatedEvents
    )
    $eventKeys = @($RelatedEvents | ForEach-Object {
        @(
            $_.LogName,
            $_.ProviderName,
            $_.Id,
            $_.TargetUserName,
            $_.SubjectUserName,
            $_.IpAddress,
            $_.WorkstationName,
            $_.LogonType,
            $_.Status,
            $_.SubStatus,
            $_.ServiceName,
            (Get-NormalizedFingerprintText -Text $_.ServiceFileName -Max 300),
            (Get-NormalizedFingerprintText -Text $_.NewProcessName -Max 300),
            (Get-NormalizedFingerprintText -Text $_.ParentProcessName -Max 300),
            $_.TaskName,
            $_.ObjectName,
            $_.ShareName,
            $_.DestAddress,
            $_.DestPort,
            $_.SourceAddress,
            $_.SourcePort
        ) -join '|'
    } | Sort-Object -Unique)
    $source = @($Severity, $Title, ($eventKeys -join "`n")) -join "`n"
    return Get-Hash -Text $source
}

function Convert-Event {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $data = ConvertFrom-EventXml -Event $Event
    [pscustomobject]@{
        TimeCreated      = $Event.TimeCreated
        TimeCreatedUtc   = if ($Event.TimeCreated) { $Event.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
        LogName          = $Event.LogName
        ProviderName     = $Event.ProviderName
        Id               = $Event.Id
        LevelDisplayName = $Event.LevelDisplayName
        RecordId         = $Event.RecordId
        UserId           = if ($Event.UserId) { $Event.UserId.Value } else { $null }
        TargetUserName   = if ($data.ContainsKey('TargetUserName')) { $data['TargetUserName'] } else { $null }
        SubjectUserName  = if ($data.ContainsKey('SubjectUserName')) { $data['SubjectUserName'] } else { $null }
        IpAddress        = if ($data.ContainsKey('IpAddress')) { $data['IpAddress'] } else { $null }
        WorkstationName  = if ($data.ContainsKey('WorkstationName')) { $data['WorkstationName'] } else { $null }
        LogonType        = if ($data.ContainsKey('LogonType')) { $data['LogonType'] } else { $null }
        Status           = if ($data.ContainsKey('Status')) { $data['Status'] } else { $null }
        SubStatus        = if ($data.ContainsKey('SubStatus')) { $data['SubStatus'] } else { $null }
        ServiceName      = if ($data.ContainsKey('ServiceName')) { $data['ServiceName'] } else { $null }
        ServiceFileName  = if ($data.ContainsKey('ServiceFileName')) { $data['ServiceFileName'] } elseif ($data.ContainsKey('ImagePath')) { $data['ImagePath'] } else { $null }
        NewProcessName   = if ($data.ContainsKey('NewProcessName')) { $data['NewProcessName'] } elseif ($data.ContainsKey('ProcessName')) { $data['ProcessName'] } elseif ($data.ContainsKey('Application')) { $data['Application'] } else { $null }
        ParentProcessName = if ($data.ContainsKey('ParentProcessName')) { $data['ParentProcessName'] } elseif ($data.ContainsKey('CreatorProcessName')) { $data['CreatorProcessName'] } else { $null }
        CommandLine      = if ($data.ContainsKey('CommandLine')) { $data['CommandLine'] } elseif ($data.ContainsKey('ProcessCommandLine')) { $data['ProcessCommandLine'] } else { $null }
        TaskName         = if ($data.ContainsKey('TaskName')) { $data['TaskName'] } else { $null }
        TaskContent      = if ($data.ContainsKey('TaskContent')) { Get-ShortMessage -Message $data['TaskContent'] -Max 1600 } else { $null }
        ObjectName       = if ($data.ContainsKey('ObjectName')) { $data['ObjectName'] } else { $null }
        ShareName        = if ($data.ContainsKey('ShareName')) { $data['ShareName'] } else { $null }
        DestAddress      = if ($data.ContainsKey('DestAddress')) { $data['DestAddress'] } elseif ($data.ContainsKey('DestinationAddress')) { $data['DestinationAddress'] } else { $null }
        DestPort         = if ($data.ContainsKey('DestPort')) { $data['DestPort'] } elseif ($data.ContainsKey('DestinationPort')) { $data['DestinationPort'] } else { $null }
        SourceAddress    = if ($data.ContainsKey('SourceAddress')) { $data['SourceAddress'] } else { $null }
        SourcePort       = if ($data.ContainsKey('SourcePort')) { $data['SourcePort'] } else { $null }
        Message          = Get-ShortMessage -Message $Event.Message
    }
}

function Add-Finding {
    param(
        [System.Collections.ArrayList]$Findings,
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$SuggestedAction,
        [object[]]$RelatedEvents
    )
    $fingerprint = Get-FindingFingerprint -Severity $Severity -Title $Title -RelatedEvents $RelatedEvents
    $suppressionKey = Get-FindingSuppressionKey -Severity $Severity -Title $Title -RelatedEvents $RelatedEvents
    [void]$Findings.Add([pscustomobject]@{
        Fingerprint      = $fingerprint
        SuppressionKey   = $suppressionKey
        Severity        = $Severity
        Title           = $Title
        Detail          = $Detail
        SuggestedAction = $SuggestedAction
        Suppressed      = $false
        Suppression     = $null
        RelatedEvents   = @($RelatedEvents | Select-Object -First 8 | ForEach-Object {
            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                LogName = $_.LogName
                ProviderName = $_.ProviderName
                Id = $_.Id
                RecordId = $_.RecordId
                TargetUserName = $_.TargetUserName
                IpAddress = $_.IpAddress
                LogonType = $_.LogonType
                NewProcessName = $_.NewProcessName
                ParentProcessName = $_.ParentProcessName
                CommandLine = $_.CommandLine
                ServiceName = $_.ServiceName
                ServiceFileName = $_.ServiceFileName
                TaskName = $_.TaskName
                DestAddress = $_.DestAddress
                DestPort = $_.DestPort
                Message = $_.Message
            }
        })
    })
}

function Test-MonitorNoise {
    param([object]$Event)
    $text = @($Event.Message, $Event.CommandLine, $Event.TaskContent, $Event.NewProcessName) -join ' '
    return ($text -match 'hourly-security-review|Run-HourlySecurityReview|Codex Hourly Security Review|codex-security-review')
}

function Load-State {
    if (!(Test-Path -LiteralPath $StatePath)) {
        return @{
            LastRunCompletedUtc = $null
            Fingerprints = @{}
        }
    }
    try {
        $raw = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        $fps = @{}
        if ($raw.Fingerprints) {
            foreach ($p in $raw.Fingerprints.PSObject.Properties) {
                $fps[$p.Name] = $p.Value
            }
        }
        return @{
            LastRunCompletedUtc = $raw.LastRunCompletedUtc
            Fingerprints = $fps
        }
    } catch {
        return @{
            LastRunCompletedUtc = $null
            Fingerprints = @{}
        }
    }
}

function Save-State {
    param([hashtable]$State)
    $ordered = [ordered]@{
        LastRunCompletedUtc = $State.LastRunCompletedUtc
        Fingerprints = $State.Fingerprints
    }
    $ordered | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $StatePath -Encoding UTF8 -Width 240
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
        Add-ActionLog "Could not parse alert decisions file '$AlertDecisionsPath'; ignoring suppressions for this run. $($_.Exception.Message)"
        return @{
            Version = 1
            Suppressions = @{}
            Decisions = @()
        }
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

function Get-ActiveSuppression {
    param(
        [object]$Finding,
        [hashtable]$AlertDecisions,
        [DateTime]$NowUtc
    )
    if ($null -eq $Finding -or [string]::IsNullOrWhiteSpace($Finding.Fingerprint)) { return $null }
    $suppression = $null
    $matchedBy = $null
    if ($AlertDecisions.Suppressions.ContainsKey([string]$Finding.Fingerprint)) {
        $suppression = $AlertDecisions.Suppressions[[string]$Finding.Fingerprint]
        $matchedBy = 'fingerprint'
    } elseif (![string]::IsNullOrWhiteSpace($Finding.SuppressionKey)) {
        foreach ($candidate in @($AlertDecisions.Suppressions.Values)) {
            if ($candidate.SuppressionKey -and [string]$candidate.SuppressionKey -eq [string]$Finding.SuppressionKey) {
                $suppression = $candidate
                $matchedBy = 'suppression_key'
                break
            }
        }
    }
    if ($null -eq $suppression) { return $null }

    $status = if ($suppression.Status) { [string]$suppression.Status } else { 'ignored' }
    if ($status -notmatch '^(?i:ignored|active)$') { return $null }

    if ($Finding.Severity -eq 'critical' -and !$AllowCriticalAlertSuppressions) { return $null }

    if ($suppression.ExpiresUtc) {
        try {
            $expires = [DateTime]::Parse([string]$suppression.ExpiresUtc).ToUniversalTime()
            if ($expires -le $NowUtc) { return $null }
        } catch {
            return $null
        }
    }
    return [pscustomobject]@{
        Suppression = $suppression
        MatchedBy = $matchedBy
    }
}

function Apply-AlertSuppressions {
    param(
        [object[]]$Findings,
        [hashtable]$AlertDecisions,
        [DateTime]$NowUtc
    )
    $updated = $false
    foreach ($finding in @($Findings)) {
        $match = Get-ActiveSuppression -Finding $finding -AlertDecisions $AlertDecisions -NowUtc $NowUtc
        if ($null -eq $match) { continue }
        $suppression = $match.Suppression

        $finding.Suppressed = $true
        $finding.Suppression = [pscustomobject]@{
            Id = $suppression.Id
            MatchedBy = $match.MatchedBy
            Reason = $suppression.Reason
            CreatedUtc = $suppression.CreatedUtc
            ExpiresUtc = $suppression.ExpiresUtc
        }

        $matchCount = 0
        if ($suppression.MatchCount) { $matchCount = [int]$suppression.MatchCount }
        Set-ObjectProperty -Object $suppression -Name 'MatchCount' -Value ($matchCount + 1)
        Set-ObjectProperty -Object $suppression -Name 'LastMatchedUtc' -Value $NowUtc.ToString('o')
        Set-ObjectProperty -Object $suppression -Name 'LastMatchedRunFolder' -Value $RunDir
        $updated = $true
    }
    return $updated
}

function Get-CodexPath {
    $cmd = Get-Command codex.cmd -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command codex -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function New-FallbackAnalysis {
    param(
        [object[]]$Findings,
        [string]$Reason
    )
    $rank = 0
    foreach ($f in $Findings) {
        $rank = [Math]::Max($rank, (Get-SeverityRank $f.Severity))
    }
    $severity = switch ($rank) {
        5 { 'critical' }
        4 { 'high' }
        3 { 'medium' }
        2 { 'low' }
        1 { 'info' }
        default { 'none' }
    }
    $alert = $ForceAlert -or ($rank -ge 3)
    $title = if ($alert) { 'Codex hourly security review found an item to review' } else { 'Codex hourly security review found no alert-worthy issue' }
    [pscustomobject]@{
        alert = [bool]$alert
        severity = $severity
        title = $title
        summary = $Reason
        suggested_action = if ($alert -and $Findings.Count -gt 0) { $Findings[0].SuggestedAction } else { 'No immediate action.' }
        reasons = @($Findings | Select-Object -First 8 | ForEach-Object { "$($_.Severity): $($_.Title) - $($_.Detail)" })
        trend_notes = @()
        false_positive_notes = @()
        events_to_watch = @()
    }
}

$runStart = Get-Date
$runStamp = $runStart.ToString('yyyyMMdd-HHmmss')
$RunDir = Join-Path $RunsRoot $runStamp
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

Add-ActionLog "Hourly security review started. Run folder: $RunDir."

$state = Load-State
$nowUtc = (Get-Date).ToUniversalTime()
if ($state.LastRunCompletedUtc) {
    try {
        $lastUtc = [DateTime]::Parse($state.LastRunCompletedUtc).ToUniversalTime()
        $startUtc = $lastUtc.AddMinutes(-5)
        if ($startUtc -lt $nowUtc.AddHours(-24)) { $startUtc = $nowUtc.AddHours(-24) }
        if ($startUtc -gt $nowUtc) { $startUtc = $nowUtc.AddMinutes(-1 * $DefaultLookbackMinutes) }
    } catch {
        $startUtc = $nowUtc.AddMinutes(-1 * $DefaultLookbackMinutes)
    }
} else {
    $startUtc = $nowUtc.AddMinutes(-1 * $DefaultLookbackMinutes)
}
$startLocal = $startUtc.ToLocalTime()

$securityIds = @(1100,1102,4610,4611,4614,4622,4624,4625,4648,4672,4688,4697,4698,4699,4700,4701,4702,4704,4705,4719,4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4739,4740,4756,4757,4902,4906,4907,4946,4947,4948,4949,4950,4951,4952,4953,4954,4956,4957,4958,5025,5031,5140,5142,5143,5144,5145,5152,5157,6416)
$systemTargetIds = @(7036,7040,7045)
$taskSchedulerTargetIds = @(106,140,141,142)
$powershellTargetIds = @(4103,4104)
$wmiTargetIds = @(5860,5861)
$suspiciousPathRegex = '(?i)(\\users\\[^\\]+\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\programdata\\|\\downloads\\|\\temp\\)'
$suspiciousCommandRegex = '(?i)(encodedcommand|\s-enc\s|frombase64string|downloadstring|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|\s-bypass\b|\s-windowstyle\s+hidden|\s-w\s+hidden|regsvr32.+/i:http|mshta\s+http|rundll32.+javascript|certutil.+(-urlcache|-decode)|bitsadmin.+/transfer|wmic.+process.+call.+create|schtasks.+/create|sc(\.exe)?\s+create|net(\.exe)?\s+user.+/add|net(\.exe)?\s+localgroup.+administrators.+/add|vssadmin.+delete.+shadows|wbadmin.+delete|bcdedit.+recoveryenabled\s+no|wevtutil.+\scl\s|reg(\.exe)?\s+add.+\\(run|runonce)|set-mppreference.+disablerealtimemonitoring|add-mppreference.+exclusion|net(\.exe)?\s+stop\s+(ekrn|efwd|mpssvc|windefend)|sc(\.exe)?\s+stop\s+(ekrn|efwd|mpssvc|windefend))'
$records = @()

try {
    $securityEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $startLocal; Id = $securityIds } -ErrorAction SilentlyContinue
    if ($securityEvents) { $records += $securityEvents | ForEach-Object { Convert-Event $_ } }
} catch {
}

foreach ($logName in @('System','Application')) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $startLocal; Level = 1,2 } -ErrorAction SilentlyContinue
        if ($events) { $records += $events | ForEach-Object { Convert-Event $_ } }
    } catch {
    }
}

try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $startLocal; Id = $systemTargetIds } -ErrorAction SilentlyContinue
    if ($events) { $records += $events | ForEach-Object { Convert-Event $_ } }
} catch {
}

foreach ($targetLog in @('Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-WMI-Activity/Operational')) {
    try {
        $ids = switch ($targetLog) {
            'Microsoft-Windows-TaskScheduler/Operational' { $taskSchedulerTargetIds }
            'Microsoft-Windows-PowerShell/Operational' { $powershellTargetIds }
            'Microsoft-Windows-WMI-Activity/Operational' { $wmiTargetIds }
        }
        $events = Get-WinEvent -FilterHashtable @{ LogName = $targetLog; StartTime = $startLocal; Id = $ids } -ErrorAction SilentlyContinue
        if ($events) { $records += $events | ForEach-Object { Convert-Event $_ } }
    } catch {
    }
}

$records = @($records | Where-Object {
    if ($_.LogName -eq 'Microsoft-Windows-PowerShell/Operational') {
        (-not (Test-MonitorNoise $_)) -and ($_.Message -match $suspiciousCommandRegex)
    } else {
        $true
    }
} | Sort-Object TimeCreated, LogName, RecordId -Unique)
@($records) | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $RunDir 'events.json') -Encoding UTF8 -Width 240

$findings = New-Object System.Collections.ArrayList

$canarySuccess = @()
if (![string]::IsNullOrWhiteSpace($CanaryAccountName)) {
    $canarySuccess = @($records | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4624 -and $_.TargetUserName -eq $CanaryAccountName })
}
if ($canarySuccess.Count -gt 0) {
    Add-Finding $findings 'critical' "$CanaryAccountName canary account logon detected" "The $CanaryAccountDescription account '$CanaryAccountName' logged on $($canarySuccess.Count) time(s)." 'Review canary-account telemetry immediately and confirm physical custody of the computer.' $canarySuccess
}

$canaryFailed = @()
if (![string]::IsNullOrWhiteSpace($CanaryAccountName)) {
    $canaryFailed = @($records | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4625 -and $_.TargetUserName -eq $CanaryAccountName })
}
if ($canaryFailed.Count -gt 0) {
    Add-Finding $findings 'high' "Failed logon attempts against $CanaryAccountName canary account" "The $CanaryAccountDescription account '$CanaryAccountName' had $($canaryFailed.Count) failed logon attempt(s)." 'Review recent physical access and canary-account telemetry; repeated attempts against a canary account are suspicious.' $canaryFailed
}

$auditCleared = @($records | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 1102 })
if ($auditCleared.Count -gt 0) {
    Add-Finding $findings 'critical' 'Security audit log was cleared' "Security event 1102 appeared $($auditCleared.Count) time(s)." 'Investigate immediately. Confirm whether you cleared logs; if not, preserve evidence and check account activity around the event.' $auditCleared
}

$accountChanges = @($records | Where-Object { $_.LogName -eq 'Security' -and @(4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4739,4756,4757) -contains $_.Id })
if ($accountChanges.Count -gt 0) {
    Add-Finding $findings 'high' 'Local account or group membership change detected' "$($accountChanges.Count) account/group management event(s) appeared." 'Confirm each account or group change was expected. Pay special attention to Administrators membership and enabled accounts.' $accountChanges
}

$lockouts = @($records | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4740 })
if ($lockouts.Count -gt 0) {
    Add-Finding $findings 'medium' 'Account lockout detected' "$($lockouts.Count) account lockout event(s) appeared." 'Confirm whether the lockout was expected. If not, inspect failed logons and source workstation/IP.' $lockouts
}

$failedLogons = @($records | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4625 })
$failedGroups = @($failedLogons | Group-Object @{Expression = { "$($_.TargetUserName)|$($_.IpAddress)|$($_.WorkstationName)" }} | Where-Object { $_.Count -ge 5 })
foreach ($g in $failedGroups) {
    Add-Finding $findings 'medium' 'Repeated failed logons' "$($g.Count) failed logons for source key $($g.Name)." 'Confirm whether these failed logons are from you. If not, review source IP/workstation and consider password changes or network exposure.' $g.Group
}

$passwordSpray = @($failedLogons | Group-Object TargetUserName | Where-Object { $_.Name -and $_.Count -gt 0 })
if ($failedLogons.Count -ge 10 -and $passwordSpray.Count -ge 3) {
    Add-Finding $findings 'high' 'Possible password spray or broad brute-force activity' "$($failedLogons.Count) failed logons touched $($passwordSpray.Count) different user names." 'Review failed-logon sources and exposed services. If the attempts are not yours, change affected passwords and verify remote access is closed.' $failedLogons
}

$remoteInteractiveLogons = @($records | Where-Object {
    $_.LogName -eq 'Security' -and $_.Id -eq 4624 -and $_.LogonType -eq '10' -and
    $_.TargetUserName -notmatch '^(DWM-|UMFD-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$'
})
if ($remoteInteractiveLogons.Count -gt 0) {
    Add-Finding $findings 'high' 'Remote interactive logon detected' "$($remoteInteractiveLogons.Count) RDP-style logon event(s) appeared. RDP is expected to be disabled on this laptop." 'Confirm whether you intentionally used Remote Desktop or remote-assist tooling. If not, disconnect from untrusted networks and review account activity.' $remoteInteractiveLogons
}

$explicitCreds = @($records | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4648 })
if ($explicitCreds.Count -ge 5) {
    Add-Finding $findings 'medium' 'High explicit-credential use' "$($explicitCreds.Count) explicit credential logon event(s) appeared." 'Review whether these came from expected tools. Unexpected spikes can indicate lateral-movement attempts or saved credential abuse.' $explicitCreds
}

$policyTamper = @($records | Where-Object { $_.LogName -eq 'Security' -and @(4719,4902,4906,4907,4946,4947,4948,4949,4950,4951,4952,4953,4954,4956,4957,4958,5025,5031) -contains $_.Id })
if ($policyTamper.Count -gt 0) {
    Add-Finding $findings 'high' 'Security, audit, or firewall policy changed' "$($policyTamper.Count) security/audit/firewall policy event(s) appeared." 'Confirm the policy change was yours. If not, preserve evidence and inspect account/process activity around the event.' $policyTamper
}

$newServices = @($records | Where-Object {
    ($_.LogName -eq 'Security' -and $_.Id -eq 4697) -or
    ($_.LogName -eq 'System' -and $_.ProviderName -eq 'Service Control Manager' -and $_.Id -eq 7045)
})
if ($newServices.Count -gt 0) {
    $suspiciousServices = @($newServices | Where-Object { ($_.ServiceFileName -match $suspiciousPathRegex) -or ($_.Message -match $suspiciousPathRegex) })
    $sev = if ($suspiciousServices.Count -gt 0) { 'high' } else { 'medium' }
    $detail = "$($newServices.Count) new service installation event(s) appeared."
    if ($suspiciousServices.Count -gt 0) { $detail += " $($suspiciousServices.Count) reference user-writable or temporary paths." }
    Add-Finding $findings $sev 'New Windows service installed' $detail 'Confirm the service was installed by a trusted installer. Unknown services, especially from user-writable paths, are common persistence indicators.' $newServices
}

$serviceConfigChanges = @($records | Where-Object {
    $_.LogName -eq 'System' -and $_.ProviderName -eq 'Service Control Manager' -and $_.Id -eq 7040
})
if ($serviceConfigChanges.Count -gt 0) {
    $securityServiceChanges = @($serviceConfigChanges | Where-Object { $_.Message -match $SecurityServicePattern })
    if ($securityServiceChanges.Count -gt 0) {
        Add-Finding $findings 'high' 'Security-related service startup type changed' "$($securityServiceChanges.Count) service configuration change(s) mention security/logging services." 'Confirm this was expected. Unexpected security-service configuration changes can indicate defense evasion.' $securityServiceChanges
    } else {
        Add-Finding $findings 'medium' 'Windows service startup type changed' "$($serviceConfigChanges.Count) service startup-type change event(s) appeared." 'Confirm the service configuration changes were expected.' $serviceConfigChanges
    }
}

$scheduledTaskChanges = @($records | Where-Object {
    ($_.LogName -eq 'Security' -and @(4698,4699,4700,4701,4702) -contains $_.Id) -or
    ($_.LogName -eq 'Microsoft-Windows-TaskScheduler/Operational' -and @(106,140,141,142) -contains $_.Id)
})
if ($scheduledTaskChanges.Count -gt 0) {
    $suspiciousTasks = @($scheduledTaskChanges | Where-Object {
        $text = @($_.TaskName, $_.TaskContent, $_.Message) -join ' '
        $text -match $suspiciousCommandRegex -or $text -match $suspiciousPathRegex
    })
    $sev = if ($suspiciousTasks.Count -gt 0) { 'high' } else { 'medium' }
    $detail = "$($scheduledTaskChanges.Count) scheduled-task create/update/enable/delete event(s) appeared."
    if ($suspiciousTasks.Count -gt 0) { $detail += " $($suspiciousTasks.Count) include suspicious commands or user-writable paths." }
    Add-Finding $findings $sev 'Scheduled task persistence signal' $detail 'Confirm the task was created or changed by a trusted installer or by you. Unknown scheduled tasks are common persistence indicators.' $scheduledTaskChanges
}

$suspiciousProcesses = @($records | Where-Object {
    $_.LogName -eq 'Security' -and $_.Id -eq 4688 -and
    -not (Test-MonitorNoise $_) -and
    (@($_.NewProcessName, $_.CommandLine, $_.ParentProcessName) -join ' ') -match $suspiciousCommandRegex
})
if ($suspiciousProcesses.Count -gt 0) {
    Add-Finding $findings 'high' 'Suspicious process command line' "$($suspiciousProcesses.Count) process creation event(s) matched living-off-the-land, credential, log tampering, backup deletion, or security-tampering patterns." 'Review the command line and parent process. If it was not yours, preserve the run folder and investigate immediately.' $suspiciousProcesses
}

$suspiciousPowerShell = @($records | Where-Object {
    $_.LogName -eq 'Microsoft-Windows-PowerShell/Operational' -and @(4103,4104) -contains $_.Id -and
    -not (Test-MonitorNoise $_) -and
    $_.Message -match $suspiciousCommandRegex
})
if ($suspiciousPowerShell.Count -gt 0) {
    Add-Finding $findings 'high' 'Suspicious PowerShell activity' "$($suspiciousPowerShell.Count) PowerShell logging event(s) matched suspicious execution or defense-evasion patterns." 'Review the script block/module text in the run folder. If it was not yours, disconnect from untrusted networks and investigate the initiating process/account.' $suspiciousPowerShell
}

$wmiPersistence = @($records | Where-Object {
    $_.LogName -eq 'Microsoft-Windows-WMI-Activity/Operational' -and @(5860,5861) -contains $_.Id
})
if ($wmiPersistence.Count -gt 0) {
    Add-Finding $findings 'high' 'Possible WMI persistence activity' "$($wmiPersistence.Count) WMI permanent event registration event(s) appeared." 'Confirm whether WMI event consumers/filters were intentionally created. Unknown WMI consumers can be persistence.' $wmiPersistence
}

$shareChanges = @($records | Where-Object { $_.LogName -eq 'Security' -and @(5142,5143,5144) -contains $_.Id })
if ($shareChanges.Count -gt 0) {
    Add-Finding $findings 'medium' 'Windows share changed' "$($shareChanges.Count) network-share add/change/delete event(s) appeared." 'Confirm the share change was expected. Unknown new shares can expose files or indicate staging activity.' $shareChanges
}

$blockedConnections = @($records | Where-Object { $_.LogName -eq 'Security' -and @(5152,5157) -contains $_.Id })
if ($blockedConnections.Count -ge 25) {
    Add-Finding $findings 'medium' 'Firewall blocked-connection burst' "$($blockedConnections.Count) Windows Filtering Platform block events appeared in the review window." 'Review destination/source patterns. Bursts can be noisy, but may indicate scanning, malware beacon attempts, or a misbehaving app.' $blockedConnections
}

$securityProductServiceIssues = @($records | Where-Object {
    $_.LogName -eq 'System' -and
    $_.ProviderName -eq 'Service Control Manager' -and
    $_.Message -match $SecurityProductServicePattern -and
    $_.Message -match 'stopped|terminated|failed|timeout|unexpected'
})
if ($securityProductServiceIssues.Count -gt 0) {
    Add-Finding $findings 'high' "$SecurityProductName service health issue" "$($securityProductServiceIssues.Count) Service Control Manager event(s) mention security product service trouble." "Open $SecurityProductName and verify protection status. If protection is disabled or unhealthy, disconnect from risky networks and repair/update it." $securityProductServiceIssues
}

$criticalEvents = @($records | Where-Object { $_.LevelDisplayName -eq 'Critical' })
if ($criticalEvents.Count -gt 0) {
    Add-Finding $findings 'high' 'Critical System/Application event detected' "$($criticalEvents.Count) critical event(s) appeared in System/Application." 'Review the critical event details in the run folder and Event Viewer.' $criticalEvents
}

$currentFingerprints = @{}
foreach ($r in @($records | Where-Object { $_.LogName -in @('System','Application') -and ($_.LevelDisplayName -in @('Critical','Error')) })) {
    $sample = "$($r.LogName)|$($r.ProviderName)|$($r.Id)|$($r.Message)"
    $hash = Get-Hash $sample
    if (!$currentFingerprints.ContainsKey($hash)) {
        $currentFingerprints[$hash] = [pscustomobject]@{
            Count = 0
            Sample = $sample
            LogName = $r.LogName
            ProviderName = $r.ProviderName
            Id = $r.Id
            Message = $r.Message
            Events = @()
        }
    }
    $currentFingerprints[$hash].Count += 1
    $currentFingerprints[$hash].Events += $r
}

foreach ($hash in $currentFingerprints.Keys) {
    $cur = $currentFingerprints[$hash]
    if (!$state.Fingerprints.ContainsKey($hash)) {
        $state.Fingerprints[$hash] = [pscustomobject]@{
            FirstSeenUtc = $nowUtc.ToString('o')
            LastSeenUtc = $nowUtc.ToString('o')
            TotalCount = 0
            RunsSeen = 0
            LastAlertedUtc = $null
            Sample = $cur.Sample
            LogName = $cur.LogName
            ProviderName = $cur.ProviderName
            Id = $cur.Id
            Message = $cur.Message
        }
    }
    $stat = $state.Fingerprints[$hash]
    $stat.LastSeenUtc = $nowUtc.ToString('o')
    $stat.TotalCount = [int]$stat.TotalCount + [int]$cur.Count
    $stat.RunsSeen = [int]$stat.RunsSeen + 1

    $lastAlertedOk = $true
    if ($stat.LastAlertedUtc) {
        try {
            $lastAlertUtc = [DateTime]::Parse($stat.LastAlertedUtc).ToUniversalTime()
            $lastAlertedOk = $lastAlertUtc -lt $nowUtc.AddHours(-24)
        } catch {
            $lastAlertedOk = $true
        }
    }
    if ($lastAlertedOk -and ([int]$stat.RunsSeen -ge 3 -or [int]$stat.TotalCount -ge 5)) {
        Add-Finding $findings 'medium' 'Recurring error trend' "Recurring $($cur.LogName) event $($cur.ProviderName) / $($cur.Id) has appeared in $($stat.RunsSeen) run(s), total count $($stat.TotalCount)." 'Review the recurring event trend. If it is expected, document it; if not, investigate the provider and message.' $cur.Events
        $stat.LastAlertedUtc = $nowUtc.ToString('o')
    }
}

$alertDecisions = Load-AlertDecisions
$suppressionStateChanged = Apply-AlertSuppressions -Findings @($findings) -AlertDecisions $alertDecisions -NowUtc $nowUtc
$activeFindings = @($findings | Where-Object { -not $_.Suppressed })
$suppressedFindings = @($findings | Where-Object { $_.Suppressed })
if ($suppressionStateChanged) {
    Save-AlertDecisions -AlertDecisions $alertDecisions
}
@($findings) | ConvertTo-Json -Depth 8 | Out-File -LiteralPath (Join-Path $RunDir 'findings.json') -Encoding UTF8 -Width 240

$topGroups = @($records | Group-Object LogName, ProviderName, Id, LevelDisplayName | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
    $parts = $_.Name -split ', '
    [pscustomobject]@{
        Count = $_.Count
        LogName = $parts[0]
        ProviderName = $parts[1]
        Id = $parts[2]
        Level = $parts[3]
    }
})

$recentForCodex = @($records | Sort-Object TimeCreated -Descending | Select-Object -First 120)
$CanaryAccountNote = if (![string]::IsNullOrWhiteSpace($CanaryAccountName)) {
    "$CanaryAccountName is a configured canary account ($CanaryAccountDescription). Any successful login as $CanaryAccountName is critical; failed attempts are suspicious."
} else {
    'No canary account is configured.'
}
$codexInput = [ordered]@{
    computer = $ComputerLabel
    run_started_local = $runStart.ToString('yyyy-MM-dd HH:mm:ss zzz')
    window_start_local = $startLocal.ToString('yyyy-MM-dd HH:mm:ss zzz')
    window_end_local = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    local_context = [ordered]@{
        canary_account_note = $CanaryAccountNote
        security_product = $SecurityProductName
    }
    event_count = $records.Count
    top_groups = $topGroups
    preliminary_findings = @($activeFindings)
    suppressed_findings = @($suppressedFindings | Select-Object Fingerprint, SuppressionKey, Severity, Title, Detail, Suppression)
    recent_events = $recentForCodex
}
$inputJson = $codexInput | ConvertTo-Json -Depth 8
$inputJson | Out-File -LiteralPath (Join-Path $RunDir 'codex-input.json') -Encoding UTF8 -Width 240

$analysis = $null
$codexExit = $null
if (!$NoCodex) {
    $codexPath = Get-CodexPath
    if ($codexPath) {
        $prompt = @"
You are Codex running an hourly security and Windows event log review for this user's laptop.

You must not run commands or ask questions. Analyze only the JSON below.

Decide whether the user should be interrupted with a visible alert window. Alert only for actionable security or system-health concerns. A repeated low-grade issue can become alert-worthy if trend data suggests it may otherwise be missed.

Some findings may be listed as suppressed because the user previously marked matching alert fingerprints as ignored. Do not set alert=true solely because of a suppressed finding or its related events unless there is materially new evidence that is not covered by the suppression.

Hard rules:
- If a canary account is configured, any successful logon to it is critical and failed attempts are high severity.
- Security audit log clearing is critical unless clearly expected.
- Unexpected account creation, enabling, deletion, password reset, or Administrators membership change is high severity.
- Security product service stop/failure is high severity.
- New service installation, suspicious scheduled task creation/update, suspicious PowerShell, suspicious process command lines, WMI permanent event registration, audit/firewall policy tampering, and backup/log deletion commands are IOC signals.
- Repeated low-grade errors or firewall blocks can become alert-worthy when the trend state shows recurrence.
- Do not recommend disabling or modifying a configured canary account.

Return concise JSON matching the schema.

JSON to review:
$inputJson
"@
        $promptPath = Join-Path $RunDir 'codex-prompt.txt'
        $prompt | Out-File -LiteralPath $promptPath -Encoding UTF8 -Width 240
        $codexOutput = Join-Path $RunDir 'codex-analysis.json'
        $codexStdout = Join-Path $RunDir 'codex-stdout.txt'
        $codexStderr = Join-Path $RunDir 'codex-stderr.txt'
        $tmpPrompt = Get-Content -LiteralPath $promptPath -Raw
        $tmpPrompt | & $codexPath -a never exec --ephemeral --skip-git-repo-check -C $WorkRoot --sandbox read-only --output-schema $SchemaPath -o $codexOutput - 1> $codexStdout 2> $codexStderr
        $codexExit = $LASTEXITCODE
        if ($codexExit -eq 0 -and (Test-Path -LiteralPath $codexOutput)) {
            try {
                $analysis = Get-Content -LiteralPath $codexOutput -Raw | ConvertFrom-Json
            } catch {
                $analysis = $null
            }
        }
    }
}

if ($null -eq $analysis) {
    $reason = if ($NoCodex) { 'Codex analysis was disabled for this run; using deterministic findings.' } else { 'Codex analysis was unavailable or returned invalid output; using deterministic findings.' }
    $analysis = New-FallbackAnalysis -Findings @($activeFindings) -Reason $reason
}

$maxFindingRank = 0
foreach ($f in $activeFindings) { $maxFindingRank = [Math]::Max($maxFindingRank, (Get-SeverityRank $f.Severity)) }
if ($ForceAlert) { $analysis.alert = $true }
if ($maxFindingRank -ge 4 -and !$analysis.alert) {
    $analysis.alert = $true
    if ((Get-SeverityRank $analysis.severity) -lt $maxFindingRank) {
        $analysis.severity = if ($maxFindingRank -ge 5) { 'critical' } else { 'high' }
    }
}
if ([bool]$analysis.alert -and $activeFindings.Count -gt 0 -and $analysis.title -match '(?i)no\s+(visible\s+)?(actionable\s+)?alert|no alert needed') {
    $analysis.title = $activeFindings[0].Title
    $analysis.summary = "A deterministic alert rule fired: $($activeFindings[0].Detail) Codex assessment: $($analysis.summary)"
}

$alertFingerprint = Get-Hash -Text ((@($activeFindings | ForEach-Object { $_.Fingerprint }) | Sort-Object) -join '|')

$state.LastRunCompletedUtc = $nowUtc.ToString('o')
Save-State -State $state

$runSummary = [ordered]@{
    run_started_local = $runStart.ToString('yyyy-MM-dd HH:mm:ss zzz')
    run_completed_local = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    window_start_local = $startLocal.ToString('yyyy-MM-dd HH:mm:ss zzz')
    event_count = $records.Count
    preliminary_finding_count = $activeFindings.Count
    total_finding_count = $findings.Count
    suppressed_finding_count = $suppressedFindings.Count
    alert = [bool]$analysis.alert
    severity = $analysis.severity
    title = $analysis.title
    summary = $analysis.summary
    suggested_action = $analysis.suggested_action
    alert_fingerprint = $alertFingerprint
    alert_decisions_path = $AlertDecisionsPath
    run_folder = $RunDir
    codex_exit = $codexExit
}
$runSummary | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $RunDir 'run-summary.json') -Encoding UTF8 -Width 240

$alertPath = Join-Path $RunDir 'alert.md'
$reasons = @($analysis.reasons)
$trendNotes = @($analysis.trend_notes)
$watch = @($analysis.events_to_watch)
$falsePositive = @($analysis.false_positive_notes)

$entry = New-Object System.Collections.Generic.List[string]
$entry.Add("## $($runSummary.run_completed_local) - $($analysis.severity.ToString().ToUpper()) - Alert: $($analysis.alert)")
$entry.Add('')
$entry.Add("- Window: $($runSummary.window_start_local) to $($runSummary.run_completed_local)")
$entry.Add("- Events reviewed: $($records.Count)")
$entry.Add("- Active findings: $($activeFindings.Count)")
$entry.Add("- Suppressed findings: $($suppressedFindings.Count)")
$entry.Add("- Run folder: ``$RunDir``")
$entry.Add("- Alert fingerprint: ``$alertFingerprint``")
$entry.Add('')
$entry.Add("Summary: $($analysis.summary)")
$entry.Add('')
$entry.Add("Suggested action: $($analysis.suggested_action)")
$entry.Add('')
if ($reasons.Count -gt 0) {
    $entry.Add('Reasons:')
    foreach ($r in $reasons) { $entry.Add("- $r") }
    $entry.Add('')
}
if ($trendNotes.Count -gt 0) {
    $entry.Add('Trend notes:')
    foreach ($r in $trendNotes) { $entry.Add("- $r") }
    $entry.Add('')
}
if ($watch.Count -gt 0) {
    $entry.Add('Events to watch:')
    foreach ($r in $watch) { $entry.Add("- $r") }
    $entry.Add('')
}
if ($topGroups.Count -gt 0) {
    $entry.Add('Top event groups:')
    foreach ($g in @($topGroups | Select-Object -First 8)) {
        $entry.Add("- $($g.Count)x $($g.LogName) / $($g.ProviderName) / $($g.Id) / $($g.Level)")
    }
    $entry.Add('')
}

if (!(Test-Path -LiteralPath $DriveLog)) {
    "# $ComputerLabel Hourly Security Review Log`r`n`r`nThis log is generated by the scheduled Codex hourly security review. Each run appends a summary so recurring issues can be trended over time.`r`n" | Out-File -LiteralPath $DriveLog -Encoding UTF8 -Width 240
}
Add-Content -LiteralPath $DriveLog -Value ($entry -join "`r`n") -Encoding UTF8
Add-Content -LiteralPath $DriveLog -Value "`r`n---`r`n" -Encoding UTF8

$alertLines = New-Object System.Collections.Generic.List[string]
$alertLines.Add("# Codex Security Alert - $ComputerLabel")
$alertLines.Add('')
$alertLines.Add("**Time:** $($runSummary.run_completed_local)")
$alertLines.Add("**Severity:** $(([string]$analysis.severity).ToUpperInvariant())")
$alertLines.Add("**Title:** $($analysis.title)")
$alertLines.Add('')
$alertLines.Add("## Summary")
$alertLines.Add($analysis.summary)
$alertLines.Add('')
$alertLines.Add("## Suggested Action")
$alertLines.Add($analysis.suggested_action)
$alertLines.Add('')
if ($reasons.Count -gt 0) {
    $alertLines.Add("## Why It Fired")
    foreach ($r in $reasons) { $alertLines.Add("- $r") }
    $alertLines.Add('')
}
if ($falsePositive.Count -gt 0) {
    $alertLines.Add("## False-Positive Context")
    foreach ($r in $falsePositive) { $alertLines.Add("- $r") }
    $alertLines.Add('')
}
$alertLines.Add("## Alert Handling")
$alertLines.Add(('- Alert fingerprint: `{0}`' -f $alertFingerprint))
$alertLines.Add(('- Alert decisions file: `{0}`' -f $AlertDecisionsPath))
$alertLines.Add('')
if ($activeFindings.Count -gt 0) {
    $alertLines.Add('Active finding fingerprints:')
    foreach ($f in $activeFindings) {
        $alertLines.Add(('- `{0}` - {1} - {2}' -f $f.Fingerprint, $f.Severity, $f.Title))
        $alertLines.Add(('  Suppression key: `{0}`' -f $f.SuppressionKey))
    }
    $alertLines.Add('')
}
if ($suppressedFindings.Count -gt 0) {
    $alertLines.Add('Suppressed finding fingerprints:')
    foreach ($f in $suppressedFindings) {
        $reason = if ($f.Suppression -and $f.Suppression.Reason) { $f.Suppression.Reason } else { 'previously ignored' }
        $alertLines.Add(('- `{0}` - {1} - {2} ({3})' -f $f.Fingerprint, $f.Severity, $f.Title, $reason))
        $alertLines.Add(('  Suppression key: `{0}`' -f $f.SuppressionKey))
    }
    $alertLines.Add('')
}
$alertLines.Add("## Evidence")
$alertLines.Add(('- Run folder: `{0}`' -f $RunDir))
$alertLines.Add(('- Drive log: `{0}`' -f $DriveLog))
$alertLines.Add(('- Findings: `{0}`' -f (Join-Path $RunDir 'findings.json')))
$alertLines | Out-File -LiteralPath $alertPath -Encoding UTF8 -Width 240

if ([bool]$analysis.alert -and !$NoAlertWindow) {
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$AlertScript`"",'-AlertPath',"`"$alertPath`"","-ConfigPath","`"$ConfigPath`"") -WindowStyle Normal
}

Add-ActionLog "Hourly security review completed. Alert=$($analysis.alert); severity=$($analysis.severity); events=$($records.Count); active findings=$($activeFindings.Count); suppressed findings=$($suppressedFindings.Count); run folder=$RunDir."

Write-Output "Alert=$($analysis.alert); Severity=$($analysis.severity); Events=$($records.Count); ActiveFindings=$($activeFindings.Count); SuppressedFindings=$($suppressedFindings.Count); Run=$RunDir"
