# Writes the public source tree of ComposeLens to a fresh folder, for example to start a new
# repository. Only the allowlisted entries are copied; toolchains, operator records, launchers and build
# outputs never are. The destination is refused before anything is removed when it is the source
# root, a folder containing it, or any folder inside it other than below dist/, or a junction or
# link at the destination or among its parents inside the root. The rules hold for the path as
# written AND for the real path the filesystem resolves it to, so an alias (a junction or link
# anywhere above the destination, a subst drive) cannot address a protected folder; a destination
# whose real path cannot be resolved is refused.
#
# Runs under Windows PowerShell and under pwsh on Windows, Linux and macOS. The regression is
# scripts/export-release-check.ps1 (a disposable copy in the system temp folder).
#
#   pwsh -NoProfile -File scripts/export-release.ps1 [-Destination dist/composelens]
Param(
  [string]$Destination = $(Join-Path (Join-Path (Join-Path $PSScriptRoot "..") "dist") "composelens")
)
$ErrorActionPreference = "Stop"
$onWindows = $env:OS -eq "Windows_NT"
$sep = [string][System.IO.Path]::DirectorySeparatorChar
$trim = [char[]]@('\', '/')
function TrimSep([string]$p) {
  $r = [System.IO.Path]::GetPathRoot($p)
  if ($r -and $p.TrimEnd($trim) -eq $r.TrimEnd($trim)) { return $r }
  return $p.TrimEnd($trim)
}
$Root = TrimSep (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Dest = TrimSep ([System.IO.Path]::GetFullPath($Destination))
$Allow = @(
  ".editorconfig", ".gitattributes", ".github", ".gitignore", ".gitleaks.toml", ".golangci.yml", ".licenserc.yaml",
  "CHANGELOG.md", "CODEOWNERS", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "LICENSE", "MAINTAINERS.md", "NOTICE",
  "README.md", "SECURITY.md", "SUPPORT.md", "THIRD_PARTY_NOTICES.md", "action.yml",
  "cmd", "docs", "examples", "fixtures", "go.mod", "go.sum", "internal", "schemas", "scripts", "testdata"
)

$cmp = [System.StringComparison]::OrdinalIgnoreCase
function Refuse($why) { Write-Error "refusing destination '$Dest': $why (nothing was removed)"; exit 1 }

# The real path of the deepest existing folder, following every junction, link and subst drive.
if ($onWindows) {
  Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class ComposeLensFinalPath {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
  public static string Get(string path) {
    using (SafeFileHandle handle = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
      if (handle.IsInvalid) throw new Win32Exception();
      StringBuilder buffer = new StringBuilder(32768);
      uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
      if (length == 0 || length >= buffer.Capacity) throw new Win32Exception();
      string real = buffer.ToString();
      if (real.StartsWith(@"\\?\UNC\")) return @"\\" + real.Substring(8);
      if (real.StartsWith(@"\\?\")) return real.Substring(4);
      return real;
    }
  }
}
"@
}
function Get-FinalFolder([string]$Folder) {
  if ($onWindows) { return [ComposeLensFinalPath]::Get($Folder) }
  # POSIX: the physical working directory resolves every symbolic link.
  Push-Location -LiteralPath $Folder
  try { $real = (& /bin/pwd -P) } finally { Pop-Location }
  if ($LASTEXITCODE -ne 0 -or -not $real) { throw "pwd -P failed" }
  return [string]$real
}
# The real path: the deepest existing folder as the filesystem resolves it, plus the part that does
# not exist yet (which cannot be an alias).
function Resolve-RealPath([string]$Path) {
  $existing = $Path
  $rest = @()
  while (-not (Test-Path -LiteralPath $existing)) {
    $parent = [System.IO.Path]::GetDirectoryName($existing)
    if (-not $parent) { throw "no existing parent folder" }
    $rest = @([System.IO.Path]::GetFileName($existing)) + $rest
    $existing = $parent
  }
  $real = Get-FinalFolder $existing
  foreach ($name in $rest) { $real = Join-Path $real $name }
  return TrimSep $real
}
try { $RootReal = Resolve-RealPath $Root; $DestReal = Resolve-RealPath $Dest }
catch { Refuse "its real path could not be resolved ($($_.Exception.Message))" }

$distPrefix = $sep + "dist" + $sep
foreach ($pair in @(@($Root, $Dest, ""), @($RootReal, $DestReal, " (its real path is '$DestReal')"))) {
  $rootP = $pair[0]; $destP = $pair[1]; $via = $pair[2]
  if ((TrimSep ([System.IO.Path]::GetPathRoot($destP))) -ieq $destP) { Refuse "a drive or file-system root$via" }
  if ($destP.Equals($rootP, $cmp)) { Refuse "it is the source root$via" }
  if (($rootP + $sep).StartsWith($destP.TrimEnd($trim) + $sep, $cmp)) { Refuse "it contains the source root$via" }
  if (($destP + $sep).StartsWith($rootP + $sep, $cmp) -and -not $destP.StartsWith($rootP + $distPrefix, $cmp)) {
    Refuse "inside the source root only folders below dist$sep may be replaced$via"
  }
}
# a junction or link at the destination, or among its existing parents inside the root
$p = $Dest
while ($true) {
  if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    Refuse "'$p' is a junction or link"
  }
  $parent = [System.IO.Path]::GetDirectoryName($p)
  if (-not $parent -or $parent.Equals($Root, $cmp) -or -not ($parent + $sep).StartsWith($Root + $sep, $cmp)) { break }
  $p = $parent
}

if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
foreach ($item in $Allow) {
  $from = Join-Path $Root $item
  if (-not (Test-Path -LiteralPath $from)) { Write-Error "allowlisted path missing: $item"; exit 1 }
  Copy-Item -LiteralPath $from -Destination (Join-Path $Dest $item) -Recurse -Force
}

# Nothing outside the allowlist, no binaries, no launchers.
$top = @(Get-ChildItem -LiteralPath $Dest -Force -Name)
foreach ($name in $top) { if ($Allow -notcontains $name) { Write-Error "export has an entry that is not allowlisted: $name"; exit 1 } }
$stray = @(Get-ChildItem -LiteralPath $Dest -Recurse -Force -File | Where-Object { $_.Extension -in '.exe', '.dll', '.bat', '.zip' })
if ($stray.Count) { Write-Error ("export carries build or launcher files: " + ($stray.FullName -join ', ')); exit 1 }
"exported $((Get-ChildItem -LiteralPath $Dest -Recurse -File).Count) files to $Dest"
