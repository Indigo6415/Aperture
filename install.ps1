<#
.SYNOPSIS
    Aperture installer for Windows.
.DESCRIPTION
    Installs -- or reinstalls/upgrades, if already present -- every
    dependency Aperture needs (Go, Node.js, ffuf, feroxbuster, subfinder,
    amass, httpx, katana, retire.js), then builds the frontend and the aperture binary
    from this checkout and installs everything into one directory on PATH.
    No admin rights required. WhatWeb (Ruby-based, no Windows-friendly
    single-binary release) is not installed by this script -- see the
    summary printed at the end for how to add it manually.
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

function Install-Subfinder {
    Write-Info "Installing subfinder (latest) via go install..."
    $env:GOBIN = $InstallDir
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    Remove-Item Env:\GOBIN
    Write-Ok "subfinder installed to $InstallDir\subfinder.exe"
}

function Install-Amass {
    Write-Info "Installing amass (latest) via go install..."
    $env:GOBIN = $InstallDir
    go install github.com/owasp-amass/amass/v4/cmd/amass@latest
    Remove-Item Env:\GOBIN
    Write-Ok "amass installed to $InstallDir\amass.exe"
}

function Install-Httpx {
    Write-Info "Installing httpx (latest) via go install..."
    $env:GOBIN = $InstallDir
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    Remove-Item Env:\GOBIN
    Write-Ok "httpx installed to $InstallDir\httpx.exe"
}

function Install-Katana {
    Write-Info "Installing katana (latest) via go install..."
    $env:GOBIN = $InstallDir
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    Remove-Item Env:\GOBIN
    Write-Ok "katana installed to $InstallDir\katana.exe"
}

function Install-Retire {
    Write-Info "Installing retire.js (latest) via npm..."
    # retire.js powers the Domain Scan tab's first module (flags
    # known-vulnerable/outdated JS libraries). It's an npm package, not a
    # Go module, so this goes through npm's own global install rather than
    # GOBIN like the tools above -- best-effort, same posture as WhatWeb
    # below: Domain Scan still loads without it, it just reports retire's
    # module as unavailable.
    try {
        npm install -g retire | Out-Null
        Write-Ok "retire.js installed"
    } catch {
        Write-Warning2 "Failed to install retire.js via npm -- install it manually ('npm install -g retire') if you want Domain Scan's retire.js module to work; every other tool is unaffected."
    }
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
Install-Subfinder
Install-Amass
Install-Httpx
Install-Katana
Install-Retire
Build-Frontend
Build-Aperture
Ensure-Path

$FfufExe = Join-Path $InstallDir "ffuf.exe"
$FeroxExe = Join-Path $InstallDir "feroxbuster.exe"
$SubfinderExe = Join-Path $InstallDir "subfinder.exe"
$AmassExe = Join-Path $InstallDir "amass.exe"
$HttpxExe = Join-Path $InstallDir "httpx.exe"
$KatanaExe = Join-Path $InstallDir "katana.exe"
$ApertureExe = Join-Path $InstallDir "aperture.exe"

Write-Host ""
Write-Ok "Done. Installed:"
Write-Host "  go          $(go version)"
Write-Host "  node        $(node -v)"
Write-Host "  ffuf        $(& $FfufExe -V 2>&1 | Select-Object -First 1)"
Write-Host "  feroxbuster $(& $FeroxExe -V)"
Write-Host "  subfinder   $(& $SubfinderExe -version 2>&1 | Select-Object -First 1)"
Write-Host "  amass       $(& $AmassExe -version 2>&1 | Select-Object -First 1)"
Write-Host "  httpx       $(& $HttpxExe -version 2>&1 | Select-Object -First 1)"
Write-Host "  katana      $(& $KatanaExe -version 2>&1 | Select-Object -First 1)"
Write-Host "  retire.js   $(if (Get-Command retire -ErrorAction SilentlyContinue) { retire --version 2>&1 | Select-Object -First 1 } else { 'not installed -- Domain Scan retire.js module unavailable' })"
Write-Host "  aperture    $ApertureExe"
Write-Host ""
Write-Info "WhatWeb was not installed (Ruby-based, no Windows-friendly single-binary release) -- install it manually (e.g. via WSL, or 'gem install whatweb') if you want the WhatWeb tab to work; every other tool is unaffected."
Write-Info "Run 'aperture' to start (open a new terminal first if PATH was just updated)."
