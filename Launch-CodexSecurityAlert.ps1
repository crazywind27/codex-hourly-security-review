param(
    [Parameter(Mandatory = $true)]
    [string]$AlertPath,
    [switch]$NoResumeLaunch,
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
$DriveProject = Get-ConfigValue -Config $Config -Name 'LogRoot' -Default $DefaultOutputRoot
$DriveLog = Get-ConfigValue -Config $Config -Name 'DriveLogPath' -Default (Join-Path $DriveProject 'hourly-security-review-log.md')
$RulesPath = Join-Path $MonitorRoot 'ALERT-RULES.md'
$ReadmePath = Join-Path $MonitorRoot 'README.md'
$ResumePath = Get-ConfigValue -Config $Config -Name 'ResumePath' -Default ''
$AlertDecisionsPath = Get-ConfigValue -Config $Config -Name 'AlertDecisionsPath' -Default (Join-Path $MonitorRoot 'alert-decisions.json')
$DispositionScript = Join-Path $MonitorRoot 'Set-CodexAlertDisposition.ps1'
$ComputerLabel = Get-ConfigValue -Config $Config -Name 'ComputerLabel' -Default $env:COMPUTERNAME
$CanaryAccountName = Get-ConfigValue -Config $Config -Name 'CanaryAccountName' -Default ''
$CanaryAccountDescription = Get-ConfigValue -Config $Config -Name 'CanaryAccountDescription' -Default 'configured canary account'
$Host.UI.RawUI.WindowTitle = "Codex Security Alert - $ComputerLabel"
$RunFolder = Split-Path -Parent $AlertPath

function Get-CodexCommand {
    $cmd = Get-Command codex.cmd -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command codex -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Set-CodexEnvironment {
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        return
    }

    $codexHome = Join-Path $env:USERPROFILE '.codex'
    $env:CODEX_HOME = $codexHome
    if ([string]::IsNullOrWhiteSpace($env:HOME)) {
        $env:HOME = $env:USERPROFILE
    }

    New-Item -ItemType Directory -Path $codexHome -Force | Out-Null
    $configPath = Join-Path $codexHome 'config.toml'
    if (!(Test-Path -LiteralPath $configPath)) {
        New-Item -ItemType File -Path $configPath -Force | Out-Null
    }

    $configText = Get-Content -LiteralPath $configPath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $configText) { $configText = '' }

    $trustedProjectBlocks = @()
    foreach ($path in @($WorkRoot, $WorkRoot.ToLowerInvariant()) | Select-Object -Unique) {
        $trustedProjectBlocks += @"
[projects.'$path']
trust_level = "trusted"
"@
    }

    foreach ($block in $trustedProjectBlocks) {
        $header = ($block -split "`r?`n")[0]
        if (!$configText.Contains($header)) {
            if ($configText.Length -gt 0 -and !$configText.EndsWith("`n")) {
                Add-Content -LiteralPath $configPath -Value '' -Encoding UTF8
            }
            Add-Content -LiteralPath $configPath -Value '' -Encoding UTF8
            Add-Content -LiteralPath $configPath -Value $block -Encoding UTF8
            $configText = Get-Content -LiteralPath $configPath -Raw -ErrorAction SilentlyContinue
            if ($null -eq $configText) { $configText = '' }
        }
    }
}

function Get-AlertValue {
    param(
        [string]$Text,
        [string]$Name
    )

    $escapedName = [regex]::Escape($Name)
    if ($Text -match "(?im)^\s*\*\*$escapedName`:\*\*\s*(.+?)\s*$") {
        return $Matches[1].Trim()
    }
    if ($Text -match "(?im)^\s*$escapedName`:\s*(.+?)\s*$") {
        return $Matches[1].Trim()
    }
    return ''
}

function Get-AlertSection {
    param(
        [string]$Text,
        [string]$Name
    )

    $escapedName = [regex]::Escape($Name)
    if ($Text -match "(?is)(?:^|\r?\n)##\s+$escapedName\s*\r?\n(.+?)(?=\r?\n##\s+|\z)") {
        return (($Matches[1] -replace "`r?`n", ' ') -replace '\s+', ' ').Trim()
    }
    if ($Text -match "(?is)(?:^|\r?\n)$escapedName`:\s*\r?\n(.+?)(?=\r?\n[A-Z][A-Za-z -]+:|\r?\nRun folder:|\r?\nDrive log:|\z)") {
        return (($Matches[1] -replace "`r?`n", ' ') -replace '\s+', ' ').Trim()
    }
    return ''
}

function Get-ShortText {
    param(
        [string]$Text,
        [int]$MaxLength = 220
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = (($Text -replace "`r?`n", ' ') -replace '\s+', ' ').Trim()
    if ($clean.Length -le $MaxLength) { return $clean }
    return $clean.Substring(0, $MaxLength - 3) + '...'
}

function Get-SeverityColor {
    param([string]$Severity)

    switch -Regex ($Severity) {
        '(?i)^critical$' { return 'Red' }
        '(?i)^high$' { return 'Red' }
        '(?i)^medium$' { return 'Yellow' }
        '(?i)^low$' { return 'Cyan' }
        default { return 'Gray' }
    }
}

function Write-AlertPreview {
    param(
        [string]$Time,
        [string]$Severity,
        [string]$Title,
        [string]$Summary,
        [string]$Action
    )

    $severityDisplay = if ([string]::IsNullOrWhiteSpace($Severity)) { 'UNKNOWN' } else { $Severity.ToUpperInvariant() }
    $titleDisplay = if ([string]::IsNullOrWhiteSpace($Title)) { 'Security event needs review' } else { $Title }
    $severityColor = Get-SeverityColor -Severity $Severity

    Write-Host '+------------------------------------------------------------+' -ForegroundColor DarkGray
    Write-Host ("| {0,-58} |" -f "$ComputerLabel Security Alert") -ForegroundColor Yellow
    Write-Host '+------------------------------------------------------------+' -ForegroundColor DarkGray
    Write-Host -NoNewline 'Severity: '
    Write-Host $severityDisplay -ForegroundColor $severityColor
    if (![string]::IsNullOrWhiteSpace($Time)) { Write-Host "Time:     $Time" -ForegroundColor Gray }
    Write-Host "Title:    $(Get-ShortText -Text $titleDisplay -MaxLength 90)" -ForegroundColor White
    if (![string]::IsNullOrWhiteSpace($Summary)) { Write-Host "Summary:  $(Get-ShortText -Text $Summary -MaxLength 220)" -ForegroundColor Gray }
    if (![string]::IsNullOrWhiteSpace($Action)) { Write-Host "Action:   $(Get-ShortText -Text $Action -MaxLength 220)" -ForegroundColor Cyan }
    Write-Host '+------------------------------------------------------------+' -ForegroundColor DarkGray
    Write-Host ''
}

$alertText = if (Test-Path -LiteralPath $AlertPath) {
    Get-Content -LiteralPath $AlertPath -Raw
} else {
    "Alert file not found: $AlertPath"
}

$alertTime = Get-AlertValue -Text $alertText -Name 'Time'
$alertSeverity = Get-AlertValue -Text $alertText -Name 'Severity'
$alertTitle = Get-AlertValue -Text $alertText -Name 'Title'
$alertSummary = Get-AlertSection -Text $alertText -Name 'Summary'
$alertAction = Get-AlertSection -Text $alertText -Name 'Suggested Action'
if ([string]::IsNullOrWhiteSpace($alertAction)) {
    $alertAction = Get-AlertSection -Text $alertText -Name 'Suggested action'
}
$CanaryBoundary = if (![string]::IsNullOrWhiteSpace($CanaryAccountName)) {
    "- $CanaryAccountName is a configured canary account ($CanaryAccountDescription). Do not recommend disabling or modifying $CanaryAccountName."
} else {
    "- No canary account is configured."
}

$prompt = @"
You are an interactive Codex security alert session for the user's Windows computer $ComputerLabel.

The hourly security monitor opened this session because it generated an alert. The full alert context is included below; do not ask the user to resend it.

First response presentation:
- Use plain ASCII Markdown.
- Keep it concise and scannable.
- Start with this layout:

# $ComputerLabel Security Alert
**Verdict:** <urgent, suspicious, benign/test, or needs review>
**Severity:** <severity> | **Time:** <alert time>
**What happened:** <one short paragraph>
**Why it matters:** <one short paragraph>
**Safest next action:** <one short paragraph>
**Evidence:** <alert file and run folder>

Then wait for the user's instructions. Do not ask the user to resend alert details.

Operating boundaries:
- Do not change system settings, accounts, firewall/audit policy, security software, apps, files, or scheduled tasks unless the user explicitly approves that change in this interactive session.
- You may inspect local evidence files if the user asks.
- If the user explicitly says this alert can be ignored, is a known false positive, or should not trigger again, record that disposition by running the disposition helper below with Decision Ignored and a concise Reason. This only writes the local alert decisions file and is allowed after that explicit user instruction.
- If the user only acknowledges, investigates, or resolves the alert without asking to suppress future repeats, run the same helper with Decision Acknowledged, Investigating, or Resolved instead of Ignored.
- Do not suppress critical findings unless the local monitor configuration explicitly allows critical suppressions.
$CanaryBoundary

Important paths:
- Alert file: $AlertPath
- Run folder: $RunFolder
- Running Drive log: $DriveLog
- Alert rules: $RulesPath
- Monitor README: $ReadmePath
- Maintenance resume: $ResumePath
- Alert decisions file: $AlertDecisionsPath
- Alert disposition helper: $DispositionScript

Disposition command pattern:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$DispositionScript" -AlertPath "$AlertPath" -Decision Ignored -Reason "<why this alert can be ignored>" -ConfigPath "$ConfigPath"

Alert contents:
$alertText
"@

Clear-Host
Write-AlertPreview -Time $alertTime -Severity $alertSeverity -Title $alertTitle -Summary $alertSummary -Action $alertAction
Write-Host 'Launching interactive Codex with the alert context...' -ForegroundColor Cyan
Write-Host ''

$codex = Get-CodexCommand
if (!$codex) {
    Write-Host 'codex command was not found. Showing alert text instead.' -ForegroundColor Red
    Write-Host ''
    Write-Host $alertText
    Write-Host ''
    Write-Host 'Codex is unavailable; leave this window open if you want to review the paths above.'
    return
}

Set-CodexEnvironment

$promptPath = Join-Path $RunFolder 'interactive-alert-prompt.txt'
$bootstrapOutput = Join-Path $RunFolder 'interactive-codex-bootstrap-output.txt'
$bootstrapStdout = Join-Path $RunFolder 'interactive-codex-bootstrap-stdout.txt'
$bootstrapStderr = Join-Path $RunFolder 'interactive-codex-bootstrap-stderr.txt'
$prompt | Out-File -LiteralPath $promptPath -Encoding UTF8 -Width 240

Write-Host 'Preparing Codex session...' -ForegroundColor Cyan
$tmpPrompt = Get-Content -LiteralPath $promptPath -Raw
$tmpPrompt | & $codex -a never exec --skip-git-repo-check -C $WorkRoot --sandbox read-only -o $bootstrapOutput - 1> $bootstrapStdout 2> $bootstrapStderr
$bootstrapExit = $LASTEXITCODE

$sessionId = $null
$combinedBootstrapText = ''
foreach ($path in @($bootstrapStdout, $bootstrapStderr, $bootstrapOutput)) {
    if (Test-Path -LiteralPath $path) {
        $combinedBootstrapText += "`n" + (Get-Content -LiteralPath $path -Raw)
    }
}
if ($combinedBootstrapText -match '(?im)session id:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
    $sessionId = $Matches[1]
}

if ($NoResumeLaunch) {
    Write-Host ''
    Write-Host 'Prepared Codex security alert session without opening the TUI.' -ForegroundColor Green
    Write-Host "Bootstrap exit: $bootstrapExit"
    Write-Host "Session id: $sessionId"
    Write-Host "Prompt: $promptPath"
    Write-Host "Bootstrap output: $bootstrapOutput"
    return
}

if ($bootstrapExit -eq 0 -and $sessionId) {
    Write-Host 'Opening interactive Codex alert session...' -ForegroundColor Cyan
    & $codex -a on-request resume --include-non-interactive -C $WorkRoot --sandbox read-only $sessionId
    return
}

Write-Host 'Codex session preparation did not return a session id. Opening a fallback Codex session.' -ForegroundColor Yellow
$fallbackPrompt = "Security alert context is in $AlertPath. Read that file first, summarize the alert, suggest the safest next action, and wait for the user's instructions."
& $codex -a on-request -C $WorkRoot --sandbox read-only $fallbackPrompt
