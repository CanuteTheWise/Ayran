# Ayran Windows host orchestrator. Staging and runtime remain WSL ext4.
param(
  [switch]$Layer,
  [switch]$Complete,
  [string]$Prime,
  [string]$Prefix,
  [string]$Source = ".",
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
if (-not $Layer -and -not $Complete) {
  throw "specify -Layer or -Complete"
}
if ($Layer -and -not $Prime) {
  throw "Layer install requires -Prime"
}

$kind = if ($Layer) { "--layer" } else { "--complete" }
$args = @("release", "install", $kind, "--source", $Source)
if ($Prefix) { $args += @("--prefix", $Prefix) }
if ($Prime) { $args += @("--prime", $Prime) }
if ($DryRun) { $args += "--dry-run" }

python -m ayran.cli @args
