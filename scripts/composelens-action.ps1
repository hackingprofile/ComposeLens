# ComposeLens composite-action wrapper: the PowerShell twin of scripts/composelens-action.sh,
# for Windows PowerShell or pwsh on any OS. Builds the CLI from THIS source tree (no release
# download). Secret-safe: does not echo env.
$ErrorActionPreference = "Stop"

function Test-Truthy([string]$Raw) {
    switch -Regex ($Raw.Trim().ToLowerInvariant()) {
        '^(true|yes|1)$' { return $true }
        default { return $false }
    }
}

function Split-InputList([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    # Regex escapes (\r \n), not PowerShell backtick escapes: inside a single-quoted
    # string `r and `n are literal characters, which would split on the letters r and n.
    return @($Raw -split '[,;\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$Root = $env:COMPOSELENS_ACTION_PATH
if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = $env:GITHUB_ACTION_PATH
}
if ([string]::IsNullOrWhiteSpace($Root)) {
    Write-Error "composelens action: missing COMPOSELENS_ACTION_PATH / GITHUB_ACTION_PATH"
}
if (-not (Test-Path -LiteralPath (Join-Path $Root "go.mod")) -or -not (Test-Path -LiteralPath (Join-Path (Join-Path $Root "cmd") "composelens"))) {
    Write-Error "composelens action: action path is not a ComposeLens source tree"
}

$FailOn = "error"
if (-not [string]::IsNullOrWhiteSpace($env:INPUT_FAIL_ON)) {
    $FailOn = $env:INPUT_FAIL_ON.Trim().ToLowerInvariant()
}
switch ($FailOn) {
    { $_ -in @("error", "warning", "info", "never") } { }
    default { Write-Error "composelens action: fail-on must be error, warning, info, or never" }
}

$OutDir = $env:RUNNER_TEMP
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = [System.IO.Path]::GetTempPath() }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Windows PowerShell has no $IsWindows; Windows_NT is set on every Windows host.
$ExeName = "composelens"
if ($env:OS -eq "Windows_NT") { $ExeName += ".exe" }
$Bin = Join-Path $OutDir $ExeName
Push-Location $Root
try {
    & go build -o $Bin ./cmd/composelens
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$Project = "."
if (-not [string]::IsNullOrWhiteSpace($env:INPUT_PROJECT_DIRECTORY)) {
    $Project = $env:INPUT_PROJECT_DIRECTORY
}

$JsonPath = ""
$SarifPath = ""
$SummaryPath = ""
if (Test-Truthy ($env:INPUT_EMIT_JSON)) {
    $JsonPath = Join-Path $OutDir "composelens-check.json"
    $env:COMPOSELENS_JSON_PATH = $JsonPath
} elseif ([string]::IsNullOrWhiteSpace($env:INPUT_EMIT_JSON)) {
    $JsonPath = Join-Path $OutDir "composelens-check.json"
    $env:COMPOSELENS_JSON_PATH = $JsonPath
} else {
    # A disabled output is cleared, so a path inherited from the job cannot reach the CLI.
    Remove-Item Env:\COMPOSELENS_JSON_PATH -ErrorAction SilentlyContinue
}
if (Test-Truthy ($env:INPUT_EMIT_SARIF)) {
    $SarifPath = Join-Path $OutDir "composelens-check.sarif"
    $env:COMPOSELENS_SARIF_PATH = $SarifPath
} elseif ([string]::IsNullOrWhiteSpace($env:INPUT_EMIT_SARIF)) {
    $SarifPath = Join-Path $OutDir "composelens-check.sarif"
    $env:COMPOSELENS_SARIF_PATH = $SarifPath
} else {
    Remove-Item Env:\COMPOSELENS_SARIF_PATH -ErrorAction SilentlyContinue
}
if (Test-Truthy ($env:INPUT_EMIT_SUMMARY)) {
    $SummaryPath = Join-Path $OutDir "composelens-check.md"
    $env:COMPOSELENS_GITHUB_SUMMARY = $SummaryPath
} elseif ([string]::IsNullOrWhiteSpace($env:INPUT_EMIT_SUMMARY)) {
    $SummaryPath = Join-Path $OutDir "composelens-check.md"
    $env:COMPOSELENS_GITHUB_SUMMARY = $SummaryPath
} else {
    # The CLI appends to GITHUB_STEP_SUMMARY whenever it is set (the direct `check --github`
    # behaviour), so emit-summary=false clears it as well, for this step's child only.
    Remove-Item Env:\COMPOSELENS_GITHUB_SUMMARY -ErrorAction SilentlyContinue
    Remove-Item Env:\GITHUB_STEP_SUMMARY -ErrorAction SilentlyContinue
}
$env:COMPOSELENS_FAIL_ON = $FailOn

$Cmd = @($Bin, "check", "--github", "--project-directory", $Project)
foreach ($f in (Split-InputList $env:INPUT_FILES)) { $Cmd += @("--file", $f) }
foreach ($p in (Split-InputList $env:INPUT_PROFILES)) { $Cmd += @("--profile", $p) }
if (-not [string]::IsNullOrWhiteSpace($env:INPUT_POLICY)) { $Cmd += @("--policy", $env:INPUT_POLICY) }
if (-not [string]::IsNullOrWhiteSpace($env:INPUT_REDACT)) { $Cmd += @("--redact", $env:INPUT_REDACT) }

$EmitAnn = $true
if (-not [string]::IsNullOrWhiteSpace($env:INPUT_EMIT_ANNOTATIONS)) {
    $EmitAnn = Test-Truthy $env:INPUT_EMIT_ANNOTATIONS
}

$Code = 0
if ($EmitAnn) {
    & $Cmd[0] @($Cmd[1..($Cmd.Length - 1)])
    $Code = $LASTEXITCODE
} else {
    $ann = Join-Path $OutDir "composelens-annotations.txt"
    & $Cmd[0] @($Cmd[1..($Cmd.Length - 1)]) | Out-File -FilePath $ann -Encoding utf8
    $Code = $LASTEXITCODE
}

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "json-path=$JsonPath"
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "sarif-path=$SarifPath"
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "summary-path=$SummaryPath"
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "exit-code=$Code"
}

exit $Code
