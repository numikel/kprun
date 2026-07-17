# kprun installer - https://github.com/numikel/kprun
# Usage: irm https://raw.githubusercontent.com/numikel/kprun/refs/heads/main/scripts/install.ps1 | iex

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$Repo = 'numikel/kprun'
$BinaryName = 'kprun'
$InstallDir = if ($env:KPRUN_INSTALL_DIR) { $env:KPRUN_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'kprun\bin' }
# Optional minisign verification (defense in depth on top of SHA-256).
$KprunMinisignPubkey = 'RWS4FT610kpYiZVGSJF6QfIJEFHB1DKxvSQkISakpp4e86kABel6WVkr'

# --- Presentation layer ------------------------------------------------------
# Fancy mode: PowerShell 7+, Windows Terminal, or an IDE terminal (VS Code sets
# TERM_PROGRAM). Bare Windows PowerShell 5.1 in conhost gets the ASCII fallback.
$Fancy = ($PSVersionTable.PSVersion.Major -ge 7) -or [bool]$env:WT_SESSION -or [bool]$env:TERM_PROGRAM

# Glyphs are built from code points, not source literals: this file has no BOM,
# so Windows PowerShell 5.1 parses it as ANSI and would mangle a raw U+2713 at
# parse time. ASCII glyphs are pre-padded to a common width of 4 so the text
# column stays aligned in both glyph sets.
$Glyphs = if ($Fancy) {
    @{ Ok = [string][char]0x2713; Err = [string][char]0x2717; Warn = '!'; Sub = [string][char]0x2192 }
} else {
    @{ Ok = '[ok]'; Err = '[x] '; Warn = '[!] '; Sub = '... ' }
}

# Step labels are padded to the longest label ("Downloading", 11 chars) + 1.
$LabelWidth = 12

function Write-Step([string]$Label, [string]$Value) {
    Write-Host "  $($Glyphs.Ok) $($Label.PadRight($LabelWidth))" -ForegroundColor Green -NoNewline
    Write-Host " $Value"
}

function Write-Substep([string]$Label, [string]$Value) {
    Write-Host "  $($Glyphs.Sub) $($Label.PadRight($LabelWidth)) $Value" -ForegroundColor DarkGray
}

function Write-Warn([string]$Message) {
    Write-Host "  $($Glyphs.Warn) $Message" -ForegroundColor Yellow
}

function Write-Err([string]$Message) {
    Write-Host "  $($Glyphs.Err) $Message" -ForegroundColor Red
    exit 1
}

function Get-LatestVersion {
    # Invoke-WebRequest -MaximumRedirection 0 throws without a .Response under
    # Windows PowerShell 5.1, so read the redirect target via WebRequest instead.
    try {
        $request = [System.Net.WebRequest]::Create("https://github.com/$Repo/releases/latest")
        $request.Method = 'HEAD'
        $request.AllowAutoRedirect = $false
        $response = $request.GetResponse()
        try {
            $location = $response.Headers['Location']
        } finally {
            $response.Close()
        }
        if ($location -match '/tag/([^/?#]+)') {
            return $Matches[1]
        }
    } catch {
        # Fall through to the GitHub API lookup below.
    }

    Write-Warn 'Redirect lookup failed, falling back to GitHub API...'
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if (-not $release.tag_name) {
        Write-Err 'Failed to get latest version (GitHub API may be rate-limited; set KPRUN_VERSION=vX.Y.Z to pin)'
    }
    return $release.tag_name
}

function Get-TargetTriple {
    # RuntimeInformation::OSArchitecture silently evaluates to $null on hosts
    # without .NET Framework 4.7.1+; PROCESSOR_ARCHITECTURE is always set.
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        default { Write-Err "Unsupported architecture: '$arch' (only x86_64 Windows builds are published)" }
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

# Returns $true when minisign verification will actually run for the given
# signature path: pubkey configured (not the placeholder), the `minisign`
# binary is on PATH, and the signature file exists. Shared by the Checksums
# step label and Verify-Checksum so the two can't desync.
function Test-MinisignWillVerify([string]$MinisigPath) {
    return ($KprunMinisignPubkey -ne 'RWQ...') -and (Get-Command minisign -ErrorAction SilentlyContinue) -and (Test-Path $MinisigPath)
}

function Verify-Checksum([string]$AssetName, [string]$ArchivePath, [string]$ChecksumsPath) {
    if ($env:KPRUN_SKIP_CHECKSUM -eq '1' -and $env:KPRUN_DEV -eq '1') {
        Write-Warn 'WARNING: checksum verification skipped (developer mode)'
        return
    }

    $expectedLine = Get-Content $ChecksumsPath | Where-Object { $_ -match "\s$([regex]::Escape($AssetName))$" } | Select-Object -First 1
    if (-not $expectedLine) {
        Write-Err "checksum for $AssetName not found in checksums.txt — refusing to install"
    }

    $expected = ($expectedLine -split '\s+', 2)[0]
    $actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Write-Err "checksum mismatch! expected=$expected actual=$actual — refusing to install"
    }

    Write-Step 'Verified' 'SHA-256 checksum'

  $minisigPath = "$ChecksumsPath.minisig"
  if (Test-MinisignWillVerify $minisigPath) {
      # -P takes the raw base64 key; a key *file* would also need the
      # untrusted-comment header line, which a bare Set-Content omits.
      # Out-Null keeps minisign's stdout from polluting the caller's return
      # stream (Install-Kprun returns the installed binary path).
      & minisign -V -P $KprunMinisignPubkey -m $ChecksumsPath | Out-Null
      if ($LASTEXITCODE -ne 0) {
        Write-Err 'minisign signature verification failed'
      }
      Write-Step 'Verified' 'minisign signature'
  }
}

function Update-UserPath {
    if ($env:KPRUN_NO_MODIFY_PATH -eq '1') {
        Write-Step 'PATH' 'skipped (KPRUN_NO_MODIFY_PATH=1)'
        return
    }

    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $currentPath) {
        $currentPath = ''
    }

    $segments = $currentPath -split ';' | Where-Object { $_ -ne '' }
    if ($segments -contains $InstallDir) {
        Write-Step 'PATH' "already contains $InstallDir"
        return
    }

    $newPath = if ($currentPath) { "$currentPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    $env:Path = "$env:Path;$InstallDir"
    Write-Step 'PATH' "added $InstallDir to user PATH"
    Write-Warn 'Open a new terminal for PATH changes to take effect'
}

function Install-Kprun {
    param(
        [string]$Version,
        [string]$VersionNote,
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

        Write-Step 'Detected' "Windows $Target"
        Write-Step 'Version' "$Version ($VersionNote)"
        Write-Substep 'Downloading' $downloadUrl

        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
        Write-Step 'Downloaded' $assetName

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
            $checksumsValue = if (Test-MinisignWillVerify $minisigPath) { 'checksums.txt + checksums.txt.minisig' } else { 'checksums.txt' }
            Write-Step 'Checksums' $checksumsValue
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

        $extractDir = Join-Path $tempDir 'extract'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $extractDir)
        Write-Step 'Extracted' 'archive contents'

        $binaryPath = Join-Path $extractDir "$BinaryName.exe"
        if (-not (Test-Path $binaryPath)) {
            Write-Err "Expected $BinaryName.exe not found in archive"
        }

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        $installedBin = Join-Path $InstallDir "$BinaryName.exe"
        Move-Item -Path $binaryPath -Destination $installedBin -Force

        Write-Step 'Installed' $installedBin
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
    Write-Step 'Works' $versionOutput

    $command = Get-Command $BinaryName -ErrorAction SilentlyContinue
    if (-not $command) {
        Write-Warn 'Binary installed but not yet on PATH in this shell'
    } elseif ($command.Source -and ($command.Source -ne $InstalledBin)) {
        Write-Warn "Another version of $BinaryName is taking priority: $($command.Source)"
        if ($command.Source -match '\.cargo[/\\]bin') {
            Write-Substep 'Cleanup' 'Attempting to remove cargo-installed version...'
            Remove-Item -Path $command.Source -Force -ErrorAction SilentlyContinue
            if (Test-Path $command.Source) {
                Write-Warn "Could not remove $($command.Source) (it might be running). Please delete it manually."
            } else {
                Write-Step 'Cleanup' 'Removed cargo version to fix PATH conflict'
            }
        } else {
            Write-Warn "Please delete it manually so the newly installed version is used."
        }
    }
    return $versionOutput
}

Write-Host "$BinaryName installer"
Write-Host ''

if ($env:KPRUN_VERSION) {
    $version = $env:KPRUN_VERSION
    $versionNote = 'pinned via KPRUN_VERSION'
} else {
    $version = Get-LatestVersion
    $versionNote = 'latest'
}

$target = Get-TargetTriple
$installedBin = Install-Kprun -Version $version -VersionNote $versionNote -Target $target
Update-UserPath
$versionOutput = Verify-Installation -InstalledBin $installedBin

Write-Host ''
Write-Host "$versionOutput installed successfully!" -ForegroundColor Green
Write-Host ''
Write-Host "  Next: open a new terminal, then run 'kprun init' to create your vault"
