param([Parameter(Mandatory=$true)][string]$ReleaseId)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Assert-Bypass([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$originalUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$originalMachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$originalProcessPath = $env:Path
$sandbox = Join-Path $env:RUNNER_TEMP ('bypass ' + [char]0x03A9 + " '& " + [guid]::NewGuid().ToString('N').Substring(0, 8))
$env:BYPASS_INSTALL_DIR = Join-Path $sandbox 'install'
$env:BYPASS_BIN_DIR = Join-Path $sandbox 'bin'
$env:BYPASS_RELEASE = $ReleaseId
$env:BYPASS_NO_MODIFY_PATH = $null
$env:BYPASS_DOWNLOAD_BASE_URL = $null
$fixture = $null
try {
    # Exercise the customer's actual irm | iex flow, pinned to the unpromoted candidate.
    $installerUrl = "https://bypasslabs.ai/downloads/bypass/releases/$ReleaseId/install.ps1"
    $installer = irm $installerUrl
    $installer | iex
    $configuration = Join-Path $env:BYPASS_BIN_DIR '.bypass-launcher.json'
    $first = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
    $metadata = Get-Content -LiteralPath (Join-Path $first.bundle 'release.json') -Raw | ConvertFrom-Json
    Assert-Bypass (([string](bypass --version)).Trim() -ceq $metadata.version) 'Current PowerShell cannot resolve the installed Bypass.'
    Assert-Bypass ((Get-Command bypass).Source -ieq (Join-Path $env:BYPASS_BIN_DIR 'bypass.cmd')) 'PATH resolved a different command.'
    Assert-Bypass ([Environment]::GetEnvironmentVariable('Path', 'Machine') -ceq $originalMachinePath) 'The installer changed machine PATH.'
    $installer | iex
    $second = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
    Assert-Bypass ($second.bundle -ceq $first.bundle) 'Repeat installation did not reuse the immutable version.'
    foreach ($value in @($env:Path, [Environment]::GetEnvironmentVariable('Path', 'User'))) {
        Assert-Bypass (@($value -split ';' | Where-Object { $_.TrimEnd('\') -ieq $env:BYPASS_BIN_DIR }).Count -eq 1) 'Repeated installation duplicated PATH.'
    }
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $childVersion = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command 'bypass --version'
    Assert-Bypass (([string]$childVersion).Trim() -ceq $metadata.version) 'A fresh PowerShell cannot resolve Bypass from persisted PATH.'
    $app = Join-Path $sandbox 'customer app'
    New-Item -ItemType Directory -Path $app | Out-Null
    bypass init $app --non-interactive
    Assert-Bypass ($LASTEXITCODE -eq 0) 'Repository initialization failed.'
    $task = 'Add invoices & reports'
    $packet = bypass context --project $app --task $task --json | ConvertFrom-Json
    Assert-Bypass ($LASTEXITCODE -eq 0 -and $packet.kind -eq 'feature-security-context' -and $packet.task -ceq $task) 'Installed CLI did not preserve arguments or produce feature context.'
    $node = Join-Path $first.bundle 'plugin\runtime\node.exe'
    & $node (Join-Path $PSScriptRoot 'smoke-installed-windows.mjs') $first.bundle $app
    Assert-Bypass ($LASTEXITCODE -eq 0) 'Installed plugin/runtime verification failed.'
    # A corrupt download must not replace the active configuration.
    $portFile = Join-Path $env:RUNNER_TEMP ('bypass-port-' + [guid]::NewGuid().ToString('N'))
    $fixtureScript = Join-Path $PSScriptRoot 'windows-download-fixture.mjs'
    $fixture = Start-Process -FilePath $node -ArgumentList @(('"' + $fixtureScript + '"'), ('"' + $portFile + '"')) -PassThru -NoNewWindow
    for ($i=0; $i -lt 100 -and -not (Test-Path -LiteralPath $portFile); $i++) { Start-Sleep -Milliseconds 100 }
    $port = [IO.File]::ReadAllText($portFile).Trim()
    $env:BYPASS_DOWNLOAD_BASE_URL = "http://127.0.0.1:$port/downloads/bypass"
    $failed = $false
    try { $installer | iex } catch { $failed = $_.Exception.Message -match 'Checksum mismatch' }
    Assert-Bypass $failed 'A corrupt archive was not rejected.'
    Assert-Bypass ((Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json).bundle -ceq $first.bundle) 'A corrupt archive changed the active version.'
    Assert-Bypass (([string](bypass --version)).Trim() -ceq $metadata.version) 'Existing installation broke after a corrupt download.'
    $unrelated = Join-Path $sandbox 'unrelated'
    New-Item -ItemType Directory -Path $unrelated | Out-Null
    [IO.File]::WriteAllText((Join-Path $unrelated 'keep.txt'), 'preserve')
    $env:BYPASS_INSTALL_DIR = $unrelated
    $failed = $false
    try { $installer | iex } catch { $failed = $_.Exception.Message -match 'unrelated files' }
    Assert-Bypass $failed 'An unrelated installation directory was not protected.'
    Assert-Bypass ([IO.File]::ReadAllText((Join-Path $unrelated 'keep.txt')) -ceq 'preserve') 'Unrelated files were changed.'
    Write-Host "Windows PowerShell $($PSVersionTable.PSVersion): install, current/persistent PATH, repeat install, CLI, MCP, Muse launcher adapter, and failure preservation passed."
} finally {
    if ($fixture -and -not $fixture.HasExited) { Stop-Process -Id $fixture.Id -Force -ErrorAction SilentlyContinue }
    [Environment]::SetEnvironmentVariable('Path', $originalUserPath, 'User')
    $env:Path = $originalProcessPath
    $env:BYPASS_INSTALL_DIR = $null; $env:BYPASS_BIN_DIR = $null; $env:BYPASS_RELEASE = $null; $env:BYPASS_DOWNLOAD_BASE_URL = $null
}
