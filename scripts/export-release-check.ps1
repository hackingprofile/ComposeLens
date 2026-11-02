# Regression for export-release.ps1's destination guard. Runs the exporter from a disposable copy in
# the system temp folder (never the real tree): every unsafe destination, including aliases through a
# junction or link above it, must fail with the sentinel files still present; the default dist/
# destination and an external folder must still export. Exits 0 when every case holds.
# Runs under Windows PowerShell and under pwsh on Windows, Linux and macOS:
#   pwsh -NoProfile -File scripts/export-release-check.ps1
$ErrorActionPreference = "Stop"
$onWindows = $env:OS -eq "Windows_NT"
function J([string]$base) { $p = $base; foreach ($part in $args) { $p = Join-Path $p $part }; return $p }
$work = J ([System.IO.Path]::GetTempPath()) ("composelens-export-check-{0}" -f $PID)
$root = J $work "root"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path (J $root "scripts") | Out-Null
Copy-Item (J $PSScriptRoot "export-release.ps1") (J $root "scripts")
foreach ($f in ".editorconfig", ".gitattributes", ".gitignore", ".gitleaks.toml", ".golangci.yml", ".licenserc.yaml",
  "CHANGELOG.md", "CODEOWNERS", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "LICENSE", "MAINTAINERS.md", "NOTICE", "README.md",
  "SECURITY.md", "SUPPORT.md", "THIRD_PARTY_NOTICES.md", "action.yml", "go.mod", "go.sum") {
  Set-Content -Path (J $root $f) -Value "x"
}
foreach ($d in ".github", "cmd", "docs", "examples", "fixtures", "internal", "schemas", "testdata", "dist") {
  New-Item -ItemType Directory -Force -Path (J $root $d) | Out-Null
  Set-Content -Path (J $root $d "keep.txt") -Value "x"
}
$sentinels = @((J $root "internal" "keep.txt"), (J $root "scripts" "export-release.ps1"), (J $root "dist" "keep.txt"))
$export = J $root "scripts" "export-release.ps1"

# A directory alias: a junction on Windows (no privilege needed), a symbolic link elsewhere.
function New-DirLink([string]$path, [string]$target) {
  $type = "SymbolicLink"
  if ($onWindows) { $type = "Junction" }
  New-Item -ItemType $type -Path $path -Target $target | Out-Null
}
New-DirLink (J $root "dist" "junction") (J $root "internal")
New-DirLink (J $root "dist" "nest") (J $root "scripts")
New-DirLink (J $work "outside-link") $root
$links = @((J $root "dist" "junction"), (J $root "dist" "nest"), (J $work "outside-link"))

# The exporter runs in the same PowerShell that runs this check.
$shell = (Get-Process -Id $PID).Path
$shellArgs = @("-NoProfile")
if ($onWindows) { $shellArgs += @("-ExecutionPolicy", "Bypass") }
$fail = 0
function Run($dest) {
  $ErrorActionPreference = "Continue"   # the refused runs write to stderr by design
  $out = & $shell @shellArgs -File $export -Destination $dest 2>&1
  return @{ code = $LASTEXITCODE; out = ($out | Out-String) }
}
$unsafe = [ordered]@{
  "source root"            = $root
  "ancestor"               = $work
  "protected internal"     = (J $root "internal")
  "protected scripts"      = (J $root "scripts")
  "dist itself"            = (J $root "dist")
  "junction into internal" = (J $root "dist" "junction")
  "relative to root"       = (J $root "dist" ".." "internal")
  "outside link, internal" = (J $work "outside-link" "internal")
  "outside link, root"     = (J $work "outside-link")
  "nest below dist"        = (J $root "dist" "nest" "deeper")
}
# A short 8.3 name of the root, when the Windows volume keeps them.
if ($onWindows) {
  $short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($root).ShortPath
  if ($short -and -not $short.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
    $unsafe["short name, internal"] = (J $short "internal")
  }
}
foreach ($name in $unsafe.Keys) {
  $r = Run $unsafe[$name]
  $kept = @($sentinels | Where-Object { -not (Test-Path $_) }).Count -eq 0
  $ok = $r.code -ne 0 -and $kept -and $r.out -match "refusing\s+destination"
  "{0,-24} {1}" -f $name, $(if ($ok) { "refused, nothing removed" } else { "FAILED (exit $($r.code), sentinels kept: $kept)" })
  if (-not $ok) { $fail++ }
}
foreach ($case in @(@("default dist/ path", (J $root "dist" "composelens")), @("external folder", (J $work "out" "export")))) {
  $r = Run $case[1]
  $ok = $r.code -eq 0 -and (Test-Path (J $case[1] "internal" "keep.txt"))
  "{0,-24} {1}" -f $case[0], $(if ($ok) { "exported" } else { "FAILED (exit $($r.code)) $($r.out)" })
  if (-not $ok) { $fail++ }
}
# Remove the aliases themselves, never what they point at.
foreach ($link in $links) { [System.IO.Directory]::Delete($link) }
Remove-Item -Recurse -Force $work
if ($fail) { "export destination guard: $fail case(s) failed"; exit 1 }
"export destination guard: all cases hold"
