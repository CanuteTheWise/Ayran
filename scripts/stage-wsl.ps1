[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Stage', 'Cleanup')]
    [string] $Action = 'Plan',

    [ValidateSet('Layer', 'Complete')]
    [string] $Distribution = 'Layer',

    [string] $Distro,

    [string] $SourceRoot,

    [string] $StageBase,

    [string] $StageRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $SourceRoot) {
    $SourceRoot = Split-Path -Parent $PSScriptRoot
}

function Get-WslDistributions {
    $values = @(& wsl.exe --list --quiet 2>$null) |
        ForEach-Object { ($_ -replace [char]0, '').Trim() } |
        Where-Object { $_ } |
        Sort-Object -Unique
    return @($values)
}

function Convert-ToWslPath([string] $WindowsPath, [string] $SelectedDistro) {
    $resolved = (Resolve-Path -LiteralPath $WindowsPath).Path
    $value = & wsl.exe -d $SelectedDistro --exec wslpath -a -u $resolved
    if ($LASTEXITCODE -ne 0 -or -not $value) {
        throw "Could not convert Windows path for WSL: $WindowsPath"
    }
    return ($value | Select-Object -First 1).Trim()
}

$available = @(Get-WslDistributions)
if ($available.Count -eq 0) {
    throw 'No WSL distribution is registered.'
}
if (-not $Distro) {
    if ($available.Count -ne 1) {
        throw "Multiple WSL distributions are available ($($available -join ', ')); pass -Distro explicitly."
    }
    $Distro = $available[0]
}
if ($Distro -notin $available) {
    throw "WSL distribution '$Distro' is not registered. Available: $($available -join ', ')"
}

$helper = Convert-ToWslPath (Join-Path $SourceRoot 'scripts/stage_wsl.py') $Distro
$arguments = @('-d', $Distro, '--exec', 'python3', $helper)
switch ($Action) {
    'Plan' {
        $source = Convert-ToWslPath $SourceRoot $Distro
        $arguments += @('plan', '--source', $source, '--distribution', $Distribution.ToLowerInvariant())
        if ($StageBase) { $arguments += @('--base', $StageBase) }
    }
    'Stage' {
        $source = Convert-ToWslPath $SourceRoot $Distro
        $arguments += @('stage', '--source', $source, '--distribution', $Distribution.ToLowerInvariant())
        if ($StageBase) { $arguments += @('--base', $StageBase) }
    }
    'Cleanup' {
        if (-not $StageRoot -or -not $StageBase) {
            throw 'Cleanup requires both the exact Linux -StageRoot and its exact Linux -StageBase.'
        }
        $arguments += @('cleanup', '--stage-root', $StageRoot, '--base', $StageBase)
    }
}

& wsl.exe @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Ayran M1 WSL $Action failed in distribution '$Distro'."
}
