# Bypass managed launcher. Invoked by bypass.cmd; does not change execution policy persistently.
$ErrorActionPreference = 'Stop'
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot '.bypass-launcher.json') -Raw | ConvertFrom-Json
$runtime = Join-Path $configuration.bundle 'plugin\runtime'
$env:Path = $runtime + ';' + $env:Path
# ProcessStartInfo avoids another command-shell interpretation of user arguments.
function ConvertTo-NativeArgument([string]$Value) {
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = Join-Path $runtime 'node.exe'
$values = @((Join-Path $runtime 'bin\bypass.mjs')) + @($args)
$info.Arguments = ($values | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' '
$info.UseShellExecute = $false
$info.WorkingDirectory = (Get-Location).ProviderPath
$process = [System.Diagnostics.Process]::Start($info)
$process.WaitForExit()
exit $process.ExitCode
