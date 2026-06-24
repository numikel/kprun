# kprun installer - https://github.com/numikel/kprun
# Usage: irm https://raw.githubusercontent.com/numikel/kprun/refs/heads/main/scripts/install.ps1 | iex

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$Repo = 'numikel/kprun'
$BinaryName = 'kprun'
$InstallDir = if ($env:KPRUN_INSTALL_DIR) { $env:KPRUN_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'kprun\bin' }

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Err([string]$Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

function Get-LatestVersion {
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 'Redirect') {
            $location = $_.Exception.Response.Headers['Location']
            if ($location -match '/tag/([^/?#]+)') {
                return $Matches[1]
            }
        }
    }

    Write-Warn 'Redirect lookup failed, falling back to GitHub API...'
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if (-not $release.tag_name) {
        Write-Err 'Failed to get latest version (GitHub API may be rate-limited; set KPRUN_VERSION=vX.Y.Z to pin)'
    }
    return $release.tag_name
}

function Get-TargetTriple {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        'X64' { return 'x86_64-pc-windows-msvc' }
        'Arm64' { Write-Err "Unsupported architecture: $arch" }
        default { Write-Err "Unsupported architecture: $arch" }
    }
}

function Test-ArchivePathsSafe([string[]]$EntryNames) {
    foreach ($entry in $EntryNames) {
        $normalized = $entry -replace '\\', '/'
        if ($normalized -match '^/' -or $normalized -match '(^|/)\.\.(/|$)') {
            Write-Err 'Archive contains unsafe paths (absolute or directory traversal) — refusing to extract'
        }
    }
}

function Verify-Checksum([string]$AssetName, [string]$ArchivePath, [string]$ChecksumsPath) {
    if ($env:KPRUN_SKIP_CHECKSUM -eq '1' -and $env:KPRUN_DEV -eq '1') {
        Write-Warn 'WARNING: checksum verification skipped (developer mode)'
        return
    }

    Write-Info 'Verifying SHA-256 checksum...'
    $expectedLine = Get-Content $ChecksumsPath | Where-Object { $_ -match "\s$([regex]::Escape($AssetName))$" } | Select-Object -First 1
    if (-not $expectedLine) {
        Write-Err "checksum for $AssetName not found in checksums.txt — refusing to install"
    }

    $expected = ($expectedLine -split '\s+', 2)[0]
    $actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Write-Err "checksum mismatch! expected=$expected actual=$actual — refusing to install"
    }

    Write-Info 'Checksum verified.'

  # Optional minisign verification (defense in depth on top of SHA-256).
  $KprunMinisignPubkey = 'RWS4FT610kpYiZVGSJF6QfIJEFHB1DKxvSQkISakpp4e86kABel6WVkr'
  $minisigPath = "$ChecksumsPath.minisig"
  if ($KprunMinisignPubkey -ne 'RWQ...' -and (Get-Command minisign -ErrorAction SilentlyContinue)) {
    if (Test-Path $minisigPath) {
      $pubFile = [System.IO.Path]::GetTempFileName()
      try {
        Set-Content -Path $pubFile -Value $KprunMinisignPubkey -NoNewline
        & minisign -V -p $pubFile -m $ChecksumsPath
        if ($LASTEXITCODE -ne 0) {
          Write-Err 'minisign signature verification failed'
        }
        Write-Info 'minisign signature verified'
      } finally {
        Remove-Item -Path $pubFile -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Update-UserPath {
    if ($env:KPRUN_NO_MODIFY_PATH -eq '1') {
        Write-Info 'KPRUN_NO_MODIFY_PATH=1 set — skipping PATH update'
        return
    }

    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $currentPath) {
        $currentPath = ''
    }

    $segments = $currentPath -split ';' | Where-Object { $_ -ne '' }
    if ($segments -contains $InstallDir) {
        Write-Info "PATH already contains $InstallDir"
        return
    }

    $newPath = if ($currentPath) { "$currentPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    $env:Path = "$env:Path;$InstallDir"
    Write-Info "Added $InstallDir to user PATH"
    Write-Warn 'Open a new terminal for PATH changes to take effect'
}

function Install-Kprun {
    param(
        [string]$Version,
        [string]$Target
    )

    $assetName = "$BinaryName-$Target.zip"
    $downloadUrl = "https://github.com/$Repo/releases/download/$Version/$assetName"
    $checksumsUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("kprun-install-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        $archivePath = Join-Path $tempDir $assetName
        $checksumsPath = Join-Path $tempDir 'checksums.txt'

        Write-Info "Detected: Windows $Target"
        Write-Info "Version: $Version"
        Write-Info "Downloading from: $downloadUrl"

        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing

        Write-Info 'Downloading checksums...'
        try {
            Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing
        } catch {
            if ($env:KPRUN_SKIP_CHECKSUM -eq '1' -and $env:KPRUN_DEV -eq '1') {
                Write-Warn 'Failed to download checksums.txt — continuing because developer skip is enabled'
            } else {
                Write-Err 'Failed to download checksums.txt — refusing to install unverified binary (set KPRUN_DEV=1 and KPRUN_SKIP_CHECKSUM=1 to bypass at your own risk)'
            }
        }

        if (Test-Path $checksumsPath) {
            $minisigUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt.minisig"
            $minisigPath = "$checksumsPath.minisig"
            try {
                Invoke-WebRequest -Uri $minisigUrl -OutFile $minisigPath -UseBasicParsing
            } catch {
                # Signature file is optional until signing is provisioned.
            }
            Verify-Checksum -AssetName $assetName -ArchivePath $archivePath -ChecksumsPath $checksumsPath
        }

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
        try {
            $entryNames = @($zip.Entries | ForEach-Object { $_.FullName })
            Test-ArchivePathsSafe -EntryNames $entryNames
        } finally {
            $zip.Dispose()
        }

        Write-Info 'Extracting...'
        $extractDir = Join-Path $tempDir 'extract'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $extractDir)

        $binaryPath = Join-Path $extractDir "$BinaryName.exe"
        if (-not (Test-Path $binaryPath)) {
            Write-Err "Expected $BinaryName.exe not found in archive"
        }

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        $installedBin = Join-Path $InstallDir "$BinaryName.exe"
        Move-Item -Path $binaryPath -Destination $installedBin -Force

        Write-Info "Successfully installed $BinaryName to $installedBin"
        return $installedBin
    } finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Verify-Installation([string]$InstalledBin) {
    if (-not (Test-Path $InstalledBin)) {
        Write-Err "Binary not found at expected location: $InstalledBin"
    }

    $versionOutput = & $InstalledBin --version
    Write-Info "Verification: $versionOutput"

    $command = Get-Command $BinaryName -ErrorAction SilentlyContinue
    if (-not $command) {
        Write-Warn 'Binary installed but not yet on PATH in this shell'
    }
}

Write-Info "Installing $BinaryName..."

$version = if ($env:KPRUN_VERSION) {
    Write-Info "Using pinned version from KPRUN_VERSION: $($env:KPRUN_VERSION)"
    $env:KPRUN_VERSION
} else {
    Get-LatestVersion
}

$target = Get-TargetTriple
$installedBin = Install-Kprun -Version $version -Target $target
Update-UserPath
Verify-Installation -InstalledBin $installedBin

Write-Host ''
Write-Info 'Installation complete!'
Write-Info "Binary: $installedBin"
Write-Info "Next step: open a new terminal, then run 'kprun init' to create your vault"
