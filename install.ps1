<#
.SYNOPSIS
    Aperture installer for Windows.
.DESCRIPTION
    Installs -- or reinstalls/upgrades, if already present -- every
    dependency Aperture needs (Go, Node.js, ffuf, feroxbuster), then builds
    the frontend and the aperture binary from this checkout and installs
    everything into one directory on PATH. No admin rights required.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1
#>

$ErrorActionPreference = "Stop"

# Resolve the directory this script lives in (works regardless of the
# caller's cwd) and treat it as the repo root.
$RepoRoot = $PSScriptRoot
Set-Location $RepoRoot

$InstallDir = if ($env:APERTURE_INSTALL_DIR) { $env:APERTURE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Aperture\bin" }
$MinGoVersion = [version]"1.23"
$MinNodeMajor = 20

function Write-Info    ($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok      ($msg) { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warning2($msg) { Write-Host "!   $msg" -ForegroundColor Yellow }
function Write-Failure ($msg) { Write-Host "X   $msg" -ForegroundColor Red; exit 1 }

# Bail out early if this script has been copied somewhere other than the
# repo root -- everything below assumes it can build Aperture from source.
if (-not (Test-Path (Join-Path $RepoRoot "go.mod")) -or -not (Test-Path (Join-Path $RepoRoot "cmd\aperture"))) {
    Write-Failure "install.ps1 must be run from the root of the Aperture repo checkout."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Returns $true if a command is resolvable on PATH, without throwing.
function Test-CommandExists($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

# Refreshes $env:Path for the current process from the registry, so a
# package just installed by winget (which only updates the registry) is
# usable immediately without opening a new terminal.
function Sync-PathFromRegistry {
    $machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

# Installs a package via winget, if winget is available. Returns $false
# (rather than throwing) on any failure so callers can fall back to a
# manual-install message instead of crashing the whole script.
function Install-WithWinget($packageId) {
    if (-not (Test-CommandExists "winget")) { return $false }
    try {
        winget install --id $packageId -e --source winget `
            --accept-package-agreements --accept-source-agreements --scope user | Out-Null
        Sync-PathFromRegistry
        return $true
    } catch {
        return $false
    }
}

function Ensure-Go {
    Write-Info "Checking Go toolchain..."
    # Skip the (re)install entirely if a sufficiently new Go is already there.
    if (Test-CommandExists "go") {
        $verStr = ((go version) -split ' ')[2] -replace '^go', ''
        if ([version]$verStr -ge $MinGoVersion) {
            Write-Ok "Go $verStr already installed"
            return
        }
        Write-Warning2 "Go $verStr is older than required $MinGoVersion; attempting an upgrade"
    }
    if (-not (Install-WithWinget "GoLang.Go")) {
        Write-Failure "Go >= $MinGoVersion is required. Automatic install via winget did not succeed -- install it manually from https://go.dev/dl/ and re-run this script."
    }
    if (-not (Test-CommandExists "go")) { Write-Failure "Go installation appears to have failed." }
    Write-Ok "Go installed"
}

function Ensure-Node {
    Write-Info "Checking Node.js..."
    # Skip the (re)install entirely if a sufficiently new Node is already there.
    if (Test-CommandExists "node") {
        $major = [int]((node -v) -replace '^v(\d+)\..*', '$1')
        if ($major -ge $MinNodeMajor) {
            Write-Ok "Node $(node -v) already installed"
            return
        }
        Write-Warning2 "Node $(node -v) is older than required v$MinNodeMajor.x; attempting an upgrade"
    }
    if (-not (Install-WithWinget "OpenJS.NodeJS.LTS")) {
        Write-Failure "Node.js >= $MinNodeMajor is required. Automatic install via winget did not succeed -- install it manually from https://nodejs.org/ and re-run this script."
    }
    if (-not (Test-CommandExists "npm")) { Write-Failure "Node.js installation appears to have failed." }
    Write-Ok "Node $(node -v) installed"
}

function Install-Ffuf {
    Write-Info "Installing ffuf (latest) via go install..."
    # `go install ...@latest` always re-fetches and rebuilds, so this is
    # inherently an upgrade-or-fresh-install regardless of prior state.
    $env:GOBIN = $InstallDir
    go install github.com/ffuf/ffuf/v2@latest
    Remove-Item Env:\GOBIN
    Write-Ok "ffuf installed to $InstallDir\ffuf.exe"
}

function Install-Feroxbuster {
    Write-Info "Installing feroxbuster (latest release) for windows/x86_64..."
    $asset = "x86_64-windows-feroxbuster.exe.zip"
    $url = "https://github.com/epi052/feroxbuster/releases/latest/download/$asset"
    $tmp = Join-Path $env:TEMP ([System.Guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        $zipPath = Join-Path $tmp "ferox.zip"
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
        $exe = Get-ChildItem -Path $tmp -Filter "feroxbuster*.exe" -Recurse | Select-Object -First 1
        if (-not $exe) { Write-Failure "feroxbuster.exe not found inside the downloaded archive." }
        Copy-Item $exe.FullName (Join-Path $InstallDir "feroxbuster.exe") -Force
    } finally {
        # Always clean up the scratch directory, whether the above succeeded or failed.
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
    Write-Ok "feroxbuster installed to $InstallDir\feroxbuster.exe"
}

function Build-Frontend {
    Write-Info "Building frontend..."
    Push-Location (Join-Path $RepoRoot "web")
    try {
        npm install
        npm run build
    } finally {
        Pop-Location
    }
    Write-Ok "Frontend built into internal\webui\dist"
}

function Build-Aperture {
    Write-Info "Building aperture binary..."
    go build -o (Join-Path $InstallDir "aperture.exe") ./cmd/aperture
    Write-Ok "aperture installed to $InstallDir\aperture.exe"
}

function Ensure-Path {
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    # Only touch the persisted User PATH if InstallDir isn't already in it.
    if (($userPath -split ';') -contains $InstallDir) {
        Write-Ok "$InstallDir is already on PATH"
        return
    }
    [System.Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Warning2 "Added $InstallDir to your User PATH -- open a new terminal for it to apply everywhere."
}

Write-Info "Installing Aperture and its dependencies into $InstallDir"
Ensure-Go
Ensure-Node
Install-Ffuf
Install-Feroxbuster
Build-Frontend
Build-Aperture
Ensure-Path

$FfufExe = Join-Path $InstallDir "ffuf.exe"
$FeroxExe = Join-Path $InstallDir "feroxbuster.exe"
$ApertureExe = Join-Path $InstallDir "aperture.exe"

Write-Host ""
Write-Ok "Done. Installed:"
Write-Host "  go          $(go version)"
Write-Host "  node        $(node -v)"
Write-Host "  ffuf        $(& $FfufExe -V 2>&1 | Select-Object -First 1)"
Write-Host "  feroxbuster $(& $FeroxExe -V)"
Write-Host "  aperture    $ApertureExe"
Write-Host ""
Write-Info "Run 'aperture' to start (open a new terminal first if PATH was just updated)."
