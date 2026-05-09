param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [int]$LookbackDays = 0,
    [datetime]$EndTime = (Get-Date),
    [string]$OutputPath = '',
    [switch]$NoEmail
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

function Add-ActionLog {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    Add-Content -LiteralPath $ActionLog -Value "[$ts] $Message" -Encoding UTF8
}

function Escape-Html {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-SeverityRank {
    param([string]$Severity)
    switch -Regex ($Severity) {
        '(?i)^critical$' { return 5 }
        '(?i)^high$' { return 4 }
        '(?i)^medium$' { return 3 }
        '(?i)^low$' { return 2 }
        '(?i)^info$' { return 1 }
        default { return 0 }
    }
}

function Get-SeverityName {
    param([int]$Rank)
    switch ($Rank) {
        5 { 'critical' }
        4 { 'high' }
        3 { 'medium' }
        2 { 'low' }
        1 { 'info' }
        default { 'none' }
    }
}

function Get-ShortText {
    param([string]$Text, [int]$MaxLength = 220)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = (($Text -replace "`r?`n", ' ') -replace '\s+', ' ').Trim()
    if ($clean.Length -le $MaxLength) { return $clean }
    return $clean.Substring(0, $MaxLength - 3) + '...'
}

function Convert-PathToFileUri {
    param([string]$Path)
    try {
        return ([System.Uri](Resolve-Path -LiteralPath $Path -ErrorAction Stop | Select-Object -First 1).Path).AbsoluteUri
    } catch {
        return ''
    }
}

function Read-JsonFile {
    param([string]$Path)
    if (!(Test-Path -LiteralPath $Path)) { return $null }
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        Add-ActionLog "Weekly report could not parse JSON file '$Path'. $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-RunTime {
    param([object]$Summary, [string]$RunFolder)

    foreach ($name in @('run_completed_local','run_started_local')) {
        if ($Summary -and $Summary.PSObject.Properties.Name -contains $name -and ![string]::IsNullOrWhiteSpace([string]$Summary.$name)) {
            try {
                return ([DateTimeOffset]::Parse([string]$Summary.$name)).LocalDateTime
            } catch {
            }
        }
    }

    $leaf = Split-Path -Leaf $RunFolder
    try {
        return [datetime]::ParseExact($leaf, 'yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture)
    } catch {
        return $null
    }
}

function Get-RunRecords {
    param([string]$RunsRoot)

    if (!(Test-Path -LiteralPath $RunsRoot)) { return @() }

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($dir in @(Get-ChildItem -LiteralPath $RunsRoot -Directory -ErrorAction SilentlyContinue)) {
        $summaryPath = Join-Path $dir.FullName 'run-summary.json'
        $summary = Read-JsonFile -Path $summaryPath
        if ($null -eq $summary) { continue }

        $completed = ConvertTo-RunTime -Summary $summary -RunFolder $dir.FullName
        if ($null -eq $completed) { continue }

        $findings = @(Read-JsonFile -Path (Join-Path $dir.FullName 'findings.json'))
        $events = @(Read-JsonFile -Path (Join-Path $dir.FullName 'events.json'))
        [void]$records.Add([pscustomobject]@{
            RunFolder = $dir.FullName
            Completed = $completed
            Summary = $summary
            Findings = @($findings | Where-Object { $null -ne $_ })
            Events = @($events | Where-Object { $null -ne $_ })
        })
    }
    return @($records | Sort-Object Completed)
}

function Get-PeriodRuns {
    param([object[]]$Runs, [datetime]$Start, [datetime]$End)
    return @($Runs | Where-Object { $_.Completed -ge $Start -and $_.Completed -lt $End })
}

function Group-Count {
    param([object[]]$Items, [scriptblock]$KeyScript)

    $groups = @{}
    foreach ($item in @($Items)) {
        $key = [string](& $KeyScript $item)
        if ([string]::IsNullOrWhiteSpace($key)) { $key = '<blank>' }
        if (!$groups.ContainsKey($key)) { $groups[$key] = 0 }
        $groups[$key] += 1
    }
    return $groups
}

function Convert-GroupToRows {
    param([hashtable]$Groups, [int]$Limit = 15)

    return @($Groups.GetEnumerator() |
        Sort-Object @{Expression='Value';Descending=$true}, @{Expression='Name';Descending=$false} |
        Select-Object -First $Limit |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Value } })
}

function Get-FindingKey {
    param([object]$Finding)
    if ($Finding.Fingerprint) { return [string]$Finding.Fingerprint }
    if ($Finding.SuppressionKey) { return [string]$Finding.SuppressionKey }
    return "$($Finding.Severity)|$($Finding.Title)"
}

function New-PeriodStats {
    param(
        [object[]]$Runs,
        [datetime]$Start,
        [datetime]$End
    )

    $findings = @($Runs | ForEach-Object {
        foreach ($finding in @($_.Findings)) { $finding }
    })
    $activeFindings = @($findings | Where-Object { -not [bool]$_.Suppressed })
    $suppressedFindings = @($findings | Where-Object { [bool]$_.Suppressed })
    $events = @($Runs | ForEach-Object {
        foreach ($eventRecord in @($_.Events)) { $eventRecord }
    })

    $maxRank = 0
    foreach ($finding in $activeFindings) {
        $maxRank = [Math]::Max($maxRank, (Get-SeverityRank ([string]$finding.Severity)))
    }

    $severityCounts = @{
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        none = 0
    }
    foreach ($finding in $activeFindings) {
        $sev = ([string]$finding.Severity).ToLowerInvariant()
        if (!$severityCounts.ContainsKey($sev)) { $sev = 'none' }
        $severityCounts[$sev] += 1
    }

    $alertCount = @($Runs | Where-Object { [bool]$_.Summary.alert }).Count
    $telemetryGaps = @($activeFindings | Where-Object { ([string]$_.Title) -match '(?i)^Telemetry unavailable:' })
    $expectedRuns = [Math]::Max(1, [Math]::Ceiling(($End - $Start).TotalHours))

    $findingGroups = Group-Count -Items $activeFindings -KeyScript { param($f) "$($f.Severity)|$($f.Title)" }
    $eventGroups = Group-Count -Items $events -KeyScript { param($e) "$($e.LogName)|$($e.ProviderName)|$($e.Id)|$($e.LevelDisplayName)" }
    $fingerprints = @{}
    foreach ($finding in $activeFindings) {
        $key = Get-FindingKey -Finding $finding
        if (![string]::IsNullOrWhiteSpace($key) -and !$fingerprints.ContainsKey($key)) {
            $fingerprints[$key] = $finding
        }
    }

    $status = 'OK'
    if ($maxRank -ge 4 -or $telemetryGaps.Count -gt 0) {
        $status = 'Needs review'
    } elseif ($maxRank -eq 3 -or $alertCount -gt 0) {
        $status = 'Watch'
    }

    return [pscustomobject]@{
        Start = $Start
        End = $End
        Runs = @($Runs)
        RunCount = @($Runs).Count
        ExpectedRuns = $expectedRuns
        MissedRunEstimate = [Math]::Max(0, $expectedRuns - @($Runs).Count)
        AlertCount = $alertCount
        ActiveFindings = $activeFindings
        SuppressedFindings = $suppressedFindings
        ActiveFindingCount = $activeFindings.Count
        SuppressedFindingCount = $suppressedFindings.Count
        EventCount = $events.Count
        HighestSeverity = Get-SeverityName -Rank $maxRank
        HighestSeverityRank = $maxRank
        SeverityCounts = $severityCounts
        TelemetryGaps = $telemetryGaps
        TelemetryGapCount = $telemetryGaps.Count
        FindingGroups = $findingGroups
        EventGroups = $eventGroups
        Fingerprints = $fingerprints
        Status = $status
    }
}

function Get-DeltaText {
    param([int]$Current, [int]$Previous)
    $delta = $Current - $Previous
    if ($Previous -eq 0 -and $Current -gt 0) { return "new +$Current" }
    if ($Previous -eq 0) { return '0' }
    $pct = [Math]::Round(($delta / [double]$Previous) * 100, 1)
    if ($delta -gt 0) { return "+$delta (+$pct%)" }
    if ($delta -lt 0) { return "$delta ($pct%)" }
    return 'no change'
}

function New-MetricRows {
    param([object]$Current, [object]$Previous)
    return @(
        [pscustomobject]@{ Metric='Hourly runs observed'; Current=$Current.RunCount; Previous=$Previous.RunCount; Change=(Get-DeltaText $Current.RunCount $Previous.RunCount) },
        [pscustomobject]@{ Metric='Estimated missed runs'; Current=$Current.MissedRunEstimate; Previous=$Previous.MissedRunEstimate; Change=(Get-DeltaText $Current.MissedRunEstimate $Previous.MissedRunEstimate) },
        [pscustomobject]@{ Metric='Alerts'; Current=$Current.AlertCount; Previous=$Previous.AlertCount; Change=(Get-DeltaText $Current.AlertCount $Previous.AlertCount) },
        [pscustomobject]@{ Metric='Active findings'; Current=$Current.ActiveFindingCount; Previous=$Previous.ActiveFindingCount; Change=(Get-DeltaText $Current.ActiveFindingCount $Previous.ActiveFindingCount) },
        [pscustomobject]@{ Metric='Suppressed findings'; Current=$Current.SuppressedFindingCount; Previous=$Previous.SuppressedFindingCount; Change=(Get-DeltaText $Current.SuppressedFindingCount $Previous.SuppressedFindingCount) },
        [pscustomobject]@{ Metric='Telemetry gaps'; Current=$Current.TelemetryGapCount; Previous=$Previous.TelemetryGapCount; Change=(Get-DeltaText $Current.TelemetryGapCount $Previous.TelemetryGapCount) },
        [pscustomobject]@{ Metric='Events collected'; Current=$Current.EventCount; Previous=$Previous.EventCount; Change=(Get-DeltaText $Current.EventCount $Previous.EventCount) }
    )
}

function Add-Table {
    param(
        [System.Collections.Generic.List[string]]$Html,
        [object[]]$Rows,
        [string[]]$Columns,
        [string[]]$Headers
    )

    $Html.Add('<table>')
    $Html.Add('<thead><tr>')
    foreach ($header in $Headers) { $Html.Add("<th>$(Escape-Html $header)</th>") }
    $Html.Add('</tr></thead><tbody>')
    foreach ($row in @($Rows)) {
        $Html.Add('<tr>')
        foreach ($column in $Columns) {
            $Html.Add("<td>$(Escape-Html $row.$column)</td>")
        }
        $Html.Add('</tr>')
    }
    if (@($Rows).Count -eq 0) {
        $Html.Add("<tr><td colspan='$($Columns.Count)' class='muted'>No entries.</td></tr>")
    }
    $Html.Add('</tbody></table>')
}

function Get-NewFindingRows {
    param([object]$Current, [object]$Previous, [int]$Limit = 20)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($key in @($Current.Fingerprints.Keys | Sort-Object)) {
        if ($Previous.Fingerprints.ContainsKey($key)) { continue }
        $finding = $Current.Fingerprints[$key]
        [void]$rows.Add([pscustomobject]@{
            Severity = $finding.Severity
            Title = $finding.Title
            Detail = Get-ShortText -Text ([string]$finding.Detail) -MaxLength 260
            Key = $key
        })
        if ($rows.Count -ge $Limit) { break }
    }
    return @($rows.ToArray())
}

function Get-ResolvedFindingRows {
    param([object]$Current, [object]$Previous, [int]$Limit = 20)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($key in @($Previous.Fingerprints.Keys | Sort-Object)) {
        if ($Current.Fingerprints.ContainsKey($key)) { continue }
        $finding = $Previous.Fingerprints[$key]
        [void]$rows.Add([pscustomobject]@{
            Severity = $finding.Severity
            Title = $finding.Title
            Detail = Get-ShortText -Text ([string]$finding.Detail) -MaxLength 260
            Key = $key
        })
        if ($rows.Count -ge $Limit) { break }
    }
    return @($rows.ToArray())
}

function New-ReportHtml {
    param(
        [object]$Current,
        [object]$Previous,
        [string]$ComputerLabel,
        [string]$ReportPath
    )

    $metricRows = New-MetricRows -Current $Current -Previous $Previous
    $severityRows = foreach ($sev in @('critical','high','medium','low','info','none')) {
        [pscustomobject]@{
            Severity = $sev
            Current = [int]$Current.SeverityCounts[$sev]
            Previous = [int]$Previous.SeverityCounts[$sev]
            Change = Get-DeltaText ([int]$Current.SeverityCounts[$sev]) ([int]$Previous.SeverityCounts[$sev])
        }
    }
    $topFindingRows = Convert-GroupToRows -Groups $Current.FindingGroups -Limit 15 | ForEach-Object {
        $parts = $_.Name -split '\|', 2
        [pscustomobject]@{ Count=$_.Count; Severity=$parts[0]; Title=if ($parts.Count -gt 1) { $parts[1] } else { $_.Name } }
    }
    $topEventRows = Convert-GroupToRows -Groups $Current.EventGroups -Limit 15 | ForEach-Object {
        $parts = $_.Name -split '\|'
        [pscustomobject]@{
            Count = $_.Count
            LogName = if ($parts.Count -gt 0) { $parts[0] } else { '' }
            Provider = if ($parts.Count -gt 1) { $parts[1] } else { '' }
            EventId = if ($parts.Count -gt 2) { $parts[2] } else { '' }
            Level = if ($parts.Count -gt 3) { $parts[3] } else { '' }
        }
    }
    $telemetryRows = @($Current.TelemetryGaps | Select-Object -First 20 | ForEach-Object {
        [pscustomobject]@{
            Severity = $_.Severity
            Title = $_.Title
            Detail = Get-ShortText -Text ([string]$_.Detail) -MaxLength 260
        }
    })
    $runRows = @($Current.Runs | Sort-Object Completed -Descending | Select-Object -First 50 | ForEach-Object {
        [pscustomobject]@{
            Completed = $_.Completed.ToString('yyyy-MM-dd HH:mm:ss')
            Alert = [bool]$_.Summary.alert
            Severity = $_.Summary.severity
            ActiveFindings = $_.Summary.preliminary_finding_count
            Suppressed = $_.Summary.suppressed_finding_count
            RunFolder = $_.RunFolder
        }
    })
    $newRows = Get-NewFindingRows -Current $Current -Previous $Previous
    $resolvedRows = Get-ResolvedFindingRows -Current $Current -Previous $Previous
    $reportUri = Convert-PathToFileUri -Path $ReportPath

    $html = New-Object System.Collections.Generic.List[string]
    $html.Add('<!doctype html>')
    $html.Add('<html><head><meta charset="utf-8">')
    $html.Add("<title>$(Escape-Html $ComputerLabel) Weekly Security Review</title>")
    $html.Add('<style>')
    $html.Add('body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f6f7f9;color:#1f2933;}')
    $html.Add('header{background:#17202a;color:white;padding:24px 32px;}')
    $html.Add('main{padding:24px 32px;}')
    $html.Add('h1{margin:0 0 8px 0;font-size:28px;} h2{margin-top:30px;border-bottom:1px solid #d8dee6;padding-bottom:6px;}')
    $html.Add('.muted{color:#65758b;} .status{display:inline-block;padding:4px 10px;border-radius:4px;background:#e8edf3;color:#17202a;font-weight:600;}')
    $html.Add('.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0;}')
    $html.Add('.card{background:white;border:1px solid #d8dee6;border-radius:6px;padding:14px;} .card strong{display:block;font-size:24px;margin-top:6px;}')
    $html.Add('table{width:100%;border-collapse:collapse;background:white;border:1px solid #d8dee6;margin:12px 0;} th,td{padding:8px 10px;border-bottom:1px solid #edf0f3;text-align:left;vertical-align:top;} th{background:#eef2f6;}')
    $html.Add('code{background:#eef2f6;padding:2px 4px;border-radius:3px;} a{color:#0b5cad;}')
    $html.Add('</style></head><body>')
    $html.Add('<header>')
    $html.Add("<h1>$(Escape-Html $ComputerLabel) Weekly Security Review</h1>")
    $html.Add("<div>Period: $(Escape-Html $Current.Start.ToString('yyyy-MM-dd HH:mm')) to $(Escape-Html $Current.End.ToString('yyyy-MM-dd HH:mm'))</div>")
    $html.Add("<div>Generated: $(Escape-Html (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))</div>")
    if ($reportUri) { $html.Add("<div>Report file: <a href='$(Escape-Html $reportUri)'>$(Escape-Html $ReportPath)</a></div>") }
    $html.Add('</header><main>')
    $html.Add('<h2>Executive Summary</h2>')
    $html.Add("<p><span class='status'>$(Escape-Html $Current.Status)</span></p>")
    $html.Add('<div class="cards">')
    foreach ($card in @(
        @{ Label='Highest severity'; Value=$Current.HighestSeverity },
        @{ Label='Alerts'; Value=$Current.AlertCount },
        @{ Label='Active findings'; Value=$Current.ActiveFindingCount },
        @{ Label='Suppressed findings'; Value=$Current.SuppressedFindingCount },
        @{ Label='Telemetry gaps'; Value=$Current.TelemetryGapCount },
        @{ Label='Observed hourly runs'; Value="$($Current.RunCount) / $($Current.ExpectedRuns)" }
    )) {
        $html.Add("<div class='card'>$(Escape-Html $card.Label)<strong>$(Escape-Html $card.Value)</strong></div>")
    }
    $html.Add('</div>')

    $html.Add('<h2>Current Week vs Previous Week</h2>')
    Add-Table -Html $html -Rows $metricRows -Columns @('Metric','Current','Previous','Change') -Headers @('Metric','Current','Previous','Change')

    $html.Add('<h2>Severity Breakdown</h2>')
    Add-Table -Html $html -Rows $severityRows -Columns @('Severity','Current','Previous','Change') -Headers @('Severity','Current','Previous','Change')

    $html.Add('<h2>New Active Findings</h2>')
    Add-Table -Html $html -Rows $newRows -Columns @('Severity','Title','Detail','Key') -Headers @('Severity','Title','Detail','Fingerprint or key')

    $html.Add('<h2>Resolved or Absent This Week</h2>')
    Add-Table -Html $html -Rows $resolvedRows -Columns @('Severity','Title','Detail','Key') -Headers @('Severity','Title','Detail','Fingerprint or key')

    $html.Add('<h2>Top Active Finding Types</h2>')
    Add-Table -Html $html -Rows $topFindingRows -Columns @('Count','Severity','Title') -Headers @('Count','Severity','Title')

    $html.Add('<h2>Telemetry Health</h2>')
    $html.Add("<p>Estimated missed hourly runs: <strong>$(Escape-Html $Current.MissedRunEstimate)</strong>. A missed run estimate is based on expected hourly cadence for the report period.</p>")
    Add-Table -Html $html -Rows $telemetryRows -Columns @('Severity','Title','Detail') -Headers @('Severity','Title','Detail')

    $html.Add('<h2>Top Event Groups</h2>')
    Add-Table -Html $html -Rows $topEventRows -Columns @('Count','LogName','Provider','EventId','Level') -Headers @('Count','Log','Provider','Event ID','Level')

    $html.Add('<h2>Run Index</h2>')
    Add-Table -Html $html -Rows $runRows -Columns @('Completed','Alert','Severity','ActiveFindings','Suppressed','RunFolder') -Headers @('Completed','Alert','Severity','Active findings','Suppressed','Run folder')

    $html.Add('<h2>Privacy Note</h2>')
    $html.Add('<p>This local report may include hostnames, local paths, event IDs, finding titles, and summarized event metadata. The email digest, when enabled, is intentionally redacted and does not include raw commands, usernames, IP addresses, or event messages.</p>')
    $html.Add('</main></body></html>')
    return ($html -join "`r`n")
}

function Send-WeeklyDigest {
    param(
        [object]$Current,
        [object]$Previous,
        [string]$ComputerLabel,
        [string]$ReportPath
    )

    $enabled = [bool](Get-ConfigValue -Config $Config -Name 'EmailDigestEnabled' -Default $false)
    if (!$enabled -or $NoEmail) { return }

    $smtpServer = [string](Get-ConfigValue -Config $Config -Name 'EmailSmtpServer' -Default '')
    $from = [string](Get-ConfigValue -Config $Config -Name 'EmailFrom' -Default '')
    $toRaw = Get-ConfigValue -Config $Config -Name 'EmailTo' -Default ''
    if ([string]::IsNullOrWhiteSpace($smtpServer) -or [string]::IsNullOrWhiteSpace($from) -or [string]::IsNullOrWhiteSpace([string]$toRaw)) {
        Add-ActionLog 'Weekly email digest is enabled but EmailSmtpServer, EmailFrom, or EmailTo is missing.'
        Write-Warning 'EmailDigestEnabled is true, but EmailSmtpServer, EmailFrom, or EmailTo is missing.'
        return
    }

    $to = @($toRaw)
    if ($toRaw -is [array]) {
        $to = @($toRaw)
    } else {
        $to = @(([string]$toRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }))
    }
    $port = [int](Get-ConfigValue -Config $Config -Name 'EmailSmtpPort' -Default 25)
    $useSsl = [bool](Get-ConfigValue -Config $Config -Name 'EmailUseSsl' -Default $false)
    $subjectPrefix = [string](Get-ConfigValue -Config $Config -Name 'EmailSubjectPrefix' -Default '[Security Review]')
    $credentialPath = [string](Get-ConfigValue -Config $Config -Name 'EmailCredentialPath' -Default '')
    $credential = $null
    if (![string]::IsNullOrWhiteSpace($credentialPath) -and (Test-Path -LiteralPath $credentialPath)) {
        try {
            $credential = Import-Clixml -LiteralPath $credentialPath
        } catch {
            Add-ActionLog "Weekly email digest could not import EmailCredentialPath '$credentialPath'. $($_.Exception.Message)"
        }
    }

    $body = @(
        "$ComputerLabel weekly security review",
        "Period: $($Current.Start.ToString('yyyy-MM-dd HH:mm')) to $($Current.End.ToString('yyyy-MM-dd HH:mm'))",
        '',
        "Status: $($Current.Status)",
        "Highest severity: $($Current.HighestSeverity)",
        "Alerts: $($Current.AlertCount)",
        "Active findings: $($Current.ActiveFindingCount)",
        "Suppressed findings: $($Current.SuppressedFindingCount)",
        "Telemetry gaps: $($Current.TelemetryGapCount)",
        "Observed hourly runs: $($Current.RunCount) / $($Current.ExpectedRuns)",
        '',
        "Local report: $ReportPath",
        '',
        'This digest is redacted by design. Open the local report on the monitored machine for details.'
    ) -join "`r`n"

    $subject = "$subjectPrefix $ComputerLabel weekly security review - $($Current.Status)"
    $mailArgs = @{
        SmtpServer = $smtpServer
        Port = $port
        From = $from
        To = $to
        Subject = $subject
        Body = $body
    }
    if ($useSsl) { $mailArgs.UseSsl = $true }
    if ($credential) { $mailArgs.Credential = $credential }

    Send-MailMessage @mailArgs
    Add-ActionLog "Weekly email digest sent. To=$($to -join ','); Report=$ReportPath"
}

$Config = Get-ReviewConfig -Path $ConfigPath
$DocumentsRoot = [Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($DocumentsRoot)) {
    $DocumentsRoot = Join-Path $env:USERPROFILE 'Documents'
}
$DefaultOutputRoot = Join-Path $DocumentsRoot 'Codex Hourly Security Review'

$MonitorRoot = Get-ConfigValue -Config $Config -Name 'MonitorRoot' -Default $PSScriptRoot
$RunsRoot = Join-Path $MonitorRoot 'runs'
$ActionLog = Get-ConfigValue -Config $Config -Name 'ActionLogPath' -Default (Join-Path $MonitorRoot 'actions-taken.txt')
$ComputerLabel = Get-ConfigValue -Config $Config -Name 'ComputerLabel' -Default $env:COMPUTERNAME
$ReportRoot = Get-ConfigValue -Config $Config -Name 'WeeklyReportRoot' -Default (Join-Path $DefaultOutputRoot 'reports')
$RetentionWeeks = [int](Get-ConfigValue -Config $Config -Name 'WeeklyReportRetentionWeeks' -Default 26)

if ($LookbackDays -le 0) {
    $LookbackDays = [int](Get-ConfigValue -Config $Config -Name 'WeeklyReportLookbackDays' -Default 7)
}
if ($LookbackDays -le 0) { throw 'LookbackDays must be greater than zero.' }

$periodEnd = $EndTime
$periodStart = $periodEnd.AddDays(-1 * $LookbackDays)
$previousStart = $periodStart.AddDays(-1 * $LookbackDays)
$previousEnd = $periodStart

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null
    $weekStamp = $periodEnd.ToString('yyyy-MM-dd')
    $safeLabel = ([string]$ComputerLabel -replace '[^\w.-]+', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($safeLabel)) { $safeLabel = 'computer' }
    $OutputPath = Join-Path $ReportRoot "$safeLabel-weekly-security-report-$weekStamp.html"
}

$allRuns = Get-RunRecords -RunsRoot $RunsRoot
$currentRuns = Get-PeriodRuns -Runs $allRuns -Start $periodStart -End $periodEnd
$previousRuns = Get-PeriodRuns -Runs $allRuns -Start $previousStart -End $previousEnd
$currentStats = New-PeriodStats -Runs $currentRuns -Start $periodStart -End $periodEnd
$previousStats = New-PeriodStats -Runs $previousRuns -Start $previousStart -End $previousEnd

$html = New-ReportHtml -Current $currentStats -Previous $previousStats -ComputerLabel $ComputerLabel -ReportPath $OutputPath
$outputDir = Split-Path -Parent $OutputPath
if (![string]::IsNullOrWhiteSpace($outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
$html | Out-File -LiteralPath $OutputPath -Encoding UTF8 -Width 400

if ($RetentionWeeks -gt 0 -and (Test-Path -LiteralPath $ReportRoot)) {
    $cutoff = (Get-Date).AddDays(-7 * $RetentionWeeks)
    Get-ChildItem -LiteralPath $ReportRoot -Filter '*weekly-security-report-*.html' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force
}

Send-WeeklyDigest -Current $currentStats -Previous $previousStats -ComputerLabel $ComputerLabel -ReportPath $OutputPath
Add-ActionLog "Weekly security report generated. Report=$OutputPath; Status=$($currentStats.Status); Alerts=$($currentStats.AlertCount); ActiveFindings=$($currentStats.ActiveFindingCount)."
Write-Output "Weekly report generated: $OutputPath"
