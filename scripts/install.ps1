# Bypass Windows installer: irm https://bypasslabs.ai/install.ps1 | iex
# A complete script block is parsed before installation begins. No administrator rights required.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion -lt [version]'5.1') {
        throw 'Use Windows PowerShell 5.1 or PowerShell 7 on Windows 10/11 or Windows Server 2016+.'
    }
    function Write-AtomicText([string]$File, [string]$Value, [bool]$Bom = $false) {
        $temporary = $File + '.new-' + [guid]::NewGuid().ToString('N')
        try {
            [IO.File]::WriteAllText($temporary, $Value, (New-Object Text.UTF8Encoding($Bom)))
            if ([IO.File]::Exists($File)) { [IO.File]::Replace($temporary, $File, $null) }
            else { [IO.File]::Move($temporary, $File) }
        } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    }
    function Contains-Path([string]$Value, [string]$Directory) {
        foreach ($entry in ($Value -split ';')) {
            $expanded = [Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"')).TrimEnd('\', '/')
            if ([string]::Equals($expanded, $Directory.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }
    function Download-Bypass([string]$Url, [string]$Destination) {
        # Fixed release URLs do not require redirects; reject redirects, including TLS downgrades.
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination -MaximumRedirection 0 -TimeoutSec 180 | Out-Null
    }
    $base = if ($env:BYPASS_DOWNLOAD_BASE_URL) { $env:BYPASS_DOWNLOAD_BASE_URL.TrimEnd('/') } else { 'https://bypasslabs.ai/downloads/bypass' }
    $uri = [uri]$base
    if (-not $uri.IsAbsoluteUri -or ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $uri.IsLoopback))) { throw 'The download URL must use HTTPS.' }
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    try { $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch { }
    $cpu = switch ($architecture.ToLowerInvariant()) { 'amd64' { 'x64' }; 'x64' { 'x64' }; 'arm64' { 'arm64' }; default { throw 'Bypass requires 64-bit x64 or arm64 Windows.' } }
    $installDir = if ($env:BYPASS_INSTALL_DIR) { $env:BYPASS_INSTALL_DIR } else { Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Bypass' }
    $binDir = if ($env:BYPASS_BIN_DIR) { $env:BYPASS_BIN_DIR } else { Join-Path $installDir 'bin' }
    foreach ($directory in @($installDir, $binDir)) {
        if (-not [IO.Path]::IsPathRooted($directory) -or $directory -match '[\r\n]') { throw 'Installation directories must be absolute paths without newlines.' }
    }
    $installDir = [IO.Path]::GetFullPath($installDir).TrimEnd('\', '/')
    $binDir = [IO.Path]::GetFullPath($binDir).TrimEnd('\', '/')
    if ($binDir.Contains(';')) { throw 'The executable directory cannot contain a semicolon, which separates PATH entries.' }
    $marker = Join-Path $installDir '.bypass-installer'
    if ((Test-Path -LiteralPath $installDir) -and @(Get-ChildItem -LiteralPath $installDir -Force).Count -and -not (Test-Path -LiteralPath $marker)) {
        throw "$installDir contains unrelated files. Choose an empty BYPASS_INSTALL_DIR."
    }
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    [IO.File]::WriteAllText($marker, 'bypass-windows-v1')
    $lock = $null
    $work = $null
    $tls = [Net.ServicePointManager]::SecurityProtocol
    try {
        try { $lock = [IO.File]::Open((Join-Path $installDir '.install-lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch { throw 'Another Bypass installation is running. Wait for it to finish and retry.' }
        $work = Join-Path $installDir ('.download-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $work | Out-Null
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $shim = Join-Path $binDir 'bypass.cmd'
        $launcher = Join-Path $binDir '.bypass-launcher.ps1'
        $configuration = Join-Path $binDir '.bypass-launcher.json'
        foreach ($other in @('bypass.exe', 'bypass.com', 'bypass.bat', 'bypass.ps1')) {
            if (Test-Path -LiteralPath (Join-Path $binDir $other)) { throw "$binDir\$other already exists. Choose another BYPASS_BIN_DIR." }
        }
        if ((Test-Path -LiteralPath $shim) -and -not ([IO.File]::ReadAllText($shim).StartsWith("@echo off`r`nrem Bypass managed launcher`r`n"))) { throw "$shim is not managed by this installer." }
        if ((Test-Path -LiteralPath $launcher) -and -not ([IO.File]::ReadAllText($launcher).StartsWith('# Bypass managed launcher.'))) { throw "$launcher is not managed by this installer." }
        if (Test-Path -LiteralPath $configuration) {
            $previous = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
            if ($previous.schema -ne 'bypass.windows.v1' -or $previous.installDir -ine $installDir) { throw "$configuration belongs to a different installation." }
        }
        $release = $env:BYPASS_RELEASE
        if (-not $release) { Download-Bypass "$base/channels/main.txt" (Join-Path $work 'channel'); $release = [IO.File]::ReadAllText((Join-Path $work 'channel')).Trim() }
        if ($release -cnotmatch '^main-[a-f0-9]{40}-[1-9][0-9]{0,15}-[1-9][0-9]{0,15}$') { throw 'Invalid release metadata; installation stopped.' }
        $asset = "bypass-win-$cpu.zip"
        Write-Host "Downloading Bypass for Windows $cpu..."
        $checksums = Join-Path $work 'SHASUMS256.txt'
        Download-Bypass "$base/releases/$release/SHASUMS256.txt" $checksums
        $hashes = @(foreach ($line in [IO.File]::ReadAllLines($checksums)) { if ($line -cmatch ('^([a-f0-9]{64})  ' + [regex]::Escape($asset) + '$')) { $Matches[1] } })
        if ($hashes.Count -ne 1) { throw 'Missing or invalid Windows artifact checksum.' }
        $expected = $hashes[0]
        $archive = Join-Path $work 'release.zip'
        Download-Bypass "$base/releases/$release/$asset" $archive
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { throw 'Checksum mismatch. Your existing installation was not changed.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $uncompressed = 0L
            if ($zip.Entries.Count -gt 10000) { throw 'Unexpected archive entry count.' }
            foreach ($entry in $zip.Entries) {
                $name = $entry.FullName.Replace('\', '/')
                $uncompressed += $entry.Length
                if ($name -cnotmatch '^bypass(/|$)' -or $name -match '(^|/)\.\.(/|$)|:' -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 -or $uncompressed -gt 500000000) { throw 'Unexpected archive paths or size.' }
            }
        } finally { $zip.Dispose() }
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $work)
        $stage = Join-Path $work 'bypass'
        foreach ($required in @('plugin\runtime\node.exe', 'plugin\runtime\bin\bypass.mjs', 'windows-launcher.ps1', 'release.json')) {
            if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw 'Incomplete Windows release archive.' }
        }
        $metadata = Get-Content -LiteralPath (Join-Path $stage 'release.json') -Raw | ConvertFrom-Json
        if ($metadata.releaseId -cne $release -or $metadata.platform -cne "win-$cpu") { throw 'Release identity or platform does not match the download.' }
        $node = Join-Path $stage 'plugin\runtime\node.exe'
        $version = & $node (Join-Path $stage 'plugin\runtime\bin\bypass.mjs') --version
        if ($LASTEXITCODE -ne 0 -or ([string]$version).Trim() -cne $metadata.version) { throw 'The downloaded runtime could not start Bypass.' }
        $releases = Join-Path $installDir 'releases'
        New-Item -ItemType Directory -Path $releases -Force | Out-Null
        $destination = Join-Path $releases ("$release-win-$cpu-" + $expected.Substring(0, 12))
        if (-not (Test-Path -LiteralPath $destination)) { Move-Item -LiteralPath $stage -Destination $destination }
        New-Item -ItemType Directory -Path $binDir -Force | Out-Null
        $shimContent = @('@echo off', 'rem Bypass managed launcher', 'setlocal DisableDelayedExpansion', '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0.bypass-launcher.ps1" %*', 'exit /b %ERRORLEVEL%') -join "`r`n"
        Write-AtomicText $shim ($shimContent + "`r`n")
        Write-AtomicText $launcher ([IO.File]::ReadAllText((Join-Path $destination 'windows-launcher.ps1'))) $true
        # Switch only after checksum verification and successful CLI execution. Keep old versions.
        $settings = @{ schema = 'bypass.windows.v1'; installDir = $installDir; bundle = $destination; releaseId = $release } | ConvertTo-Json
        Write-AtomicText $configuration $settings $true
        Write-Host "`nInstalled Bypass $version`nLocation: $destination"
        if ($env:BYPASS_NO_MODIFY_PATH -ne '1') {
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            if (-not (Contains-Path $userPath $binDir)) {
                $separator = if ($userPath -and -not $userPath.EndsWith(';')) { ';' } else { '' }
                try { [Environment]::SetEnvironmentVariable('Path', ($userPath + $separator + $binDir), 'User'); Write-Host 'Added Bypass to your user PATH for future terminals.' }
                catch { Write-Warning 'Could not save user PATH. Bypass is available in this session; add the bin directory to PATH for future terminals.' }
            } else { Write-Host 'Bypass is already in your user PATH.' }
            if (-not (Contains-Path $env:Path $binDir)) { $env:Path = $binDir + ';' + $env:Path }
            Write-Host 'Bypass is ready in this PowerShell session.'
            $commandName = 'bypass'
        } else { Write-Host 'Automatic PATH setup skipped (BYPASS_NO_MODIFY_PATH=1).'; $commandName = "& '" + $shim.Replace("'", "''") + "'" }
        Write-Host "`nMuse plugin:`n  $commandName integrate muse --scope user --replace`n  muse plugins inspect bypass`n  muse plugins approve bypass`n  Then open Muse and use /bypass:start."
        Write-Host "`nStandalone CLI:`n  $commandName onboard`n`nUpdate: rerun the same installer. Project settings and evidence stay in your app."
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $tls
        if ($work -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
        if ($lock) { $lock.Dispose() }
    }
}
