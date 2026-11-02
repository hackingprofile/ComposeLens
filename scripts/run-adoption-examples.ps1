# Local adoption-example runner (Windows PowerShell or pwsh on any OS).
# Executes the documented table via go test so exits match docs/examples.md.
# Modules come from the existing module cache (go's own default location).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$env:GOPROXY = "off"
go test ./internal/adoption -count=1
exit $LASTEXITCODE
