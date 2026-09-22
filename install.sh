#!/usr/bin/env bash
#
# Aperture installer for macOS/Linux.
#
# Installs -- or reinstalls/upgrades, if already present -- every
# dependency Aperture needs (Go, Node.js, ffuf, feroxbuster, nuclei,
# subfinder, amass, httpx, katana, best-effort WhatWeb, and, best-effort, a
# headless-Chrome-compatible browser for screenshots/PDF report export),
# then builds the frontend and the aperture binary from this checkout and
# installs everything into one directory on PATH.
#
# Usage: ./install.sh
# Override the install location with: APERTURE_INSTALL_DIR=/some/dir ./install.sh

set -euo pipefail

# Resolve the directory this script lives in so it works regardless of the
# caller's cwd (e.g. `bash /path/to/install.sh`), and treat it as the repo root.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$SCRIPT_DIR"
cd "$REPO_ROOT"

INSTALL_DIR="${APERTURE_INSTALL_DIR:-$HOME/.local/bin}"
MIN_GO_VERSION="1.23"
MIN_NODE_MAJOR="20"

# --- output helpers ---------------------------------------------------------
BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
info() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$1"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$1" >&2; }
fail() { printf '%s✗ %s%s\n' "$RED" "$1" "$RESET" >&2; exit 1; }

# Bail out early if this script has been copied somewhere other than the
# repo root -- everything below assumes it can build Aperture from source.
if [[ ! -f "$REPO_ROOT/go.mod" || ! -d "$REPO_ROOT/cmd/aperture" ]]; then
  fail "install.sh must be run from the root of the Aperture repo checkout."
fi

mkdir -p "$INSTALL_DIR"

# --- OS / arch detection -----------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"

# Only macOS and Linux are supported here; Windows users run install.ps1.
case "$OS" in
  Darwin) PLATFORM="macos" ;;
  Linux)  PLATFORM="linux" ;;
  *) fail "Unsupported OS: $OS (this script supports macOS and Linux; use install.ps1 on Windows)" ;;
esac

# Map `uname -m` to feroxbuster's release-asset architecture naming.
case "$ARCH" in
  x86_64|amd64)  FEROX_ARCH="x86_64" ;;
  arm64|aarch64) FEROX_ARCH="aarch64" ;;
  armv7l|armv7)  FEROX_ARCH="armv7" ;;
  i386|i686)     FEROX_ARCH="x86" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

# --- package manager helper --------------------------------------------------
# Tries every package manager we know how to drive, in the order given
# below, and installs with whichever is found first. Each argument is the
# package name(s) to pass to that specific manager (names vary by distro).
# Returns 1 (without printing anything) if none of them are present, so
# callers can fall back to a manual-install message.
pkg_install() {
  local pkgs_brew="$1" pkgs_apt="$2" pkgs_dnf="$3" pkgs_pacman="$4" pkgs_apk="$5" pkgs_zypper="$6"
  if command -v brew &>/dev/null; then
    brew install $pkgs_brew
  elif command -v apt-get &>/dev/null; then
    sudo apt-get update -y && sudo apt-get install -y $pkgs_apt
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y $pkgs_dnf
  elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm $pkgs_pacman
  elif command -v apk &>/dev/null; then
    sudo apk add --no-cache $pkgs_apk
  elif command -v zypper &>/dev/null; then
    sudo zypper install -y $pkgs_zypper
  else
    return 1
  fi
}

# Returns success if version $1 >= version $2 (dotted numeric comparison).
version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# --- prerequisites: Go and Node ----------------------------------------------

ensure_go() {
  info "Checking Go toolchain..."
  # Skip the (re)install entirely if a sufficiently new Go is already there.
  if command -v go &>/dev/null; then
    local ver
    ver="$(go version | awk '{print $3}' | sed 's/^go//')"
    if version_ge "$ver" "$MIN_GO_VERSION"; then
      ok "Go $ver already installed"
      return
    fi
    warn "Go $ver is older than the required $MIN_GO_VERSION; attempting an upgrade"
  fi
  if ! pkg_install "go" "golang-go" "golang" "go" "go" "go"; then
    fail "Go >= $MIN_GO_VERSION is required. Automatic install did not succeed -- install it manually from https://go.dev/dl/ and re-run this script."
  fi
  command -v go &>/dev/null || fail "Go installation appears to have failed."
  ok "Go $(go version | awk '{print $3}') installed"
}

ensure_node() {
  info "Checking Node.js..."
  # Skip the (re)install entirely if a sufficiently new Node is already there.
  if command -v node &>/dev/null; then
    local major
    major="$(node -v | sed 's/^v//' | cut -d. -f1)"
    if [ "$major" -ge "$MIN_NODE_MAJOR" ]; then
      ok "Node $(node -v) already installed"
      return
    fi
    warn "Node $(node -v) is older than required v$MIN_NODE_MAJOR.x; attempting an upgrade"
  fi
  if ! pkg_install "node" "nodejs npm" "nodejs npm" "nodejs npm" "nodejs npm" "nodejs npm"; then
    fail "Node.js >= $MIN_NODE_MAJOR is required. Automatic install did not succeed -- install it manually from https://nodejs.org/ and re-run this script."
  fi
  command -v npm &>/dev/null || fail "Node.js installation appears to have failed."
  ok "Node $(node -v) installed"
}

# --- Aperture's own tool dependencies ----------------------------------------

install_ffuf() {
  info "Installing ffuf (latest) via go install..."
  # `go install ...@latest` always re-fetches and rebuilds, so this is
  # inherently an upgrade-or-fresh-install regardless of prior state.
  GOBIN="$INSTALL_DIR" go install github.com/ffuf/ffuf/v2@latest
  ok "ffuf $("$INSTALL_DIR/ffuf" -V 2>&1 | head -n1) installed to $INSTALL_DIR/ffuf"
}

install_feroxbuster() {
  info "Installing feroxbuster (latest release) for ${PLATFORM}/${FEROX_ARCH}..."
  local asset="${FEROX_ARCH}-${PLATFORM}-feroxbuster.zip"
  local url="https://github.com/epi052/feroxbuster/releases/latest/download/${asset}"
  local tmp
  tmp="$(mktemp -d)"
  # Always clean up the scratch directory, whether this function succeeds or fails.
  trap 'rm -rf "$tmp"' RETURN

  curl -fsSL "$url" -o "$tmp/ferox.zip" || fail "Failed to download feroxbuster from $url"

  # unzip ships with macOS by default but not all minimal Linux installs.
  if ! command -v unzip &>/dev/null; then
    pkg_install "unzip" "unzip" "unzip" "unzip" "unzip" "unzip" || fail "unzip is required to install feroxbuster and could not be installed automatically."
  fi
  unzip -oq "$tmp/ferox.zip" -d "$tmp" || fail "Failed to extract feroxbuster archive"

  mv "$tmp/feroxbuster" "$INSTALL_DIR/feroxbuster"
  chmod +x "$INSTALL_DIR/feroxbuster"
  ok "feroxbuster $("$INSTALL_DIR/feroxbuster" -V) installed to $INSTALL_DIR/feroxbuster"
}

install_nuclei() {
  info "Installing nuclei (latest) via go install..."
  # Same rationale as install_ffuf: `go install ...@latest` always re-fetches
  # and rebuilds, so this is inherently an upgrade-or-fresh-install.
  GOBIN="$INSTALL_DIR" go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ok "nuclei $("$INSTALL_DIR/nuclei" -version 2>&1 | head -n1) installed to $INSTALL_DIR/nuclei"
}

install_subfinder() {
  info "Installing subfinder (latest) via go install..."
  GOBIN="$INSTALL_DIR" go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ok "subfinder $("$INSTALL_DIR/subfinder" -version 2>&1 | head -n1) installed to $INSTALL_DIR/subfinder"
}

install_amass() {
  info "Installing amass (latest) via go install..."
  GOBIN="$INSTALL_DIR" go install github.com/owasp-amass/amass/v4/cmd/amass@latest
  ok "amass $("$INSTALL_DIR/amass" -version 2>&1 | head -n1) installed to $INSTALL_DIR/amass"
}

install_httpx() {
  info "Installing httpx (latest) via go install..."
  GOBIN="$INSTALL_DIR" go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  ok "httpx $("$INSTALL_DIR/httpx" -version 2>&1 | head -n1) installed to $INSTALL_DIR/httpx"
}

install_katana() {
  info "Installing katana (latest) via go install..."
  GOBIN="$INSTALL_DIR" go install github.com/projectdiscovery/katana/cmd/katana@latest
  ok "katana $("$INSTALL_DIR/katana" -version 2>&1 | head -n1) installed to $INSTALL_DIR/katana"
}

install_whatweb() {
  info "Checking for WhatWeb..."
  if command -v whatweb &>/dev/null; then
    ok "whatweb already installed"
    return
  fi
  # WhatWeb has no `go install`-style single-binary release and, unlike
  # every other pkg_install call in this script, no package-manager path
  # that actually works for it either: it isn't published as a rubygem at
  # all ("gem install whatweb" -- what this script used to suggest --
  # fails outright), and its old Homebrew formula was pulled from
  # homebrew-core, so `brew install whatweb` now fails on macOS too. The
  # one install path its own README still documents as reliable is a
  # straight git checkout run with `ruby` -- so that's what this does,
  # same as install_feroxbuster fetching a release archive directly
  # instead of going through a package manager.
  if ! command -v ruby &>/dev/null; then
    warn "Ruby not found -- WhatWeb needs it and there's no way to install Ruby itself here; install Ruby manually (e.g. 'brew install ruby') and re-run this script if you want the WhatWeb tab to work; every other tool is unaffected."
    return
  fi
  if ! command -v git &>/dev/null; then
    warn "git not found -- can't fetch WhatWeb's source; install git and re-run this script if you want the WhatWeb tab to work."
    return
  fi

  local src="$INSTALL_DIR/whatweb-src"
  if [[ -d "$src/.git" ]]; then
    git -C "$src" pull --ff-only -q || warn "Failed to update the existing WhatWeb checkout at $src -- using what's there."
  elif ! git clone --depth 1 -q https://github.com/urbanadventurer/WhatWeb.git "$src"; then
    warn "Failed to clone WhatWeb from GitHub -- install it manually (https://github.com/urbanadventurer/WhatWeb) if you want the WhatWeb tab to work."
    return
  fi

  # addressable is WhatWeb's one dependency that isn't already part of the
  # Ruby standard library (ipaddr/json ship with Ruby itself) -- installed
  # per-user so it doesn't need sudo/root. A plain install is tried first;
  # on a Ruby old enough that the current addressable/public_suffix won't
  # install (e.g. macOS's bundled Ruby 2.6), the last versions of each that
  # still support it are pinned instead.
  if ! ruby -e "require 'addressable'" &>/dev/null; then
    if ! gem install --user-install addressable &>/dev/null; then
      gem install --user-install public_suffix -v 5.1.1 &>/dev/null
      gem install --user-install addressable -v 2.8.7 &>/dev/null
    fi
  fi
  if ! ruby -e "require 'addressable'" &>/dev/null; then
    warn "Could not install WhatWeb's 'addressable' gem dependency automatically -- install it manually ('gem install addressable') and re-run this script if you want the WhatWeb tab to work."
    return
  fi

  cat >"$INSTALL_DIR/whatweb" <<WRAPPER
#!/usr/bin/env bash
exec ruby "$src/whatweb" "\$@"
WRAPPER
  chmod +x "$INSTALL_DIR/whatweb"
  command -v whatweb &>/dev/null && ok "whatweb installed to $INSTALL_DIR/whatweb" || warn "WhatWeb wrapper written to $INSTALL_DIR/whatweb but isn't resolving on PATH yet."
}

# chrome_binary_names lists the executable names install_headless_browser
# checks for -- kept in sync with adapters.chromeBinaries (internal/adapters
# /screenshot.go), since both are looking for the same thing.
CHROME_BINARY_NAMES=(google-chrome google-chrome-stable chromium chromium-browser chrome microsoft-edge)

install_headless_browser() {
  info "Checking for a headless-Chrome-compatible browser (used for screenshots and PDF report export)..."
  for name in "${CHROME_BINARY_NAMES[@]}"; do
    if command -v "$name" &>/dev/null; then
      ok "$name already installed"
      return
    fi
  done
  # Best-effort only: unlike the scanners above, Aperture runs fine without
  # this -- screenshots/PDF export just silently stay unavailable (see
  # adapters.CaptureScreenshot/report.RenderPDF), so a failure here warns
  # instead of aborting the whole install.
  if ! pkg_install "--cask google-chrome" "chromium" "chromium" "chromium" "chromium" "chromium"; then
    warn "No headless-Chrome-compatible browser found and automatic install did not succeed -- screenshots and PDF report export will be unavailable until one is installed (Chrome, Chromium, or Edge all work)."
    return
  fi
  for name in "${CHROME_BINARY_NAMES[@]}"; do
    if command -v "$name" &>/dev/null; then
      ok "$name installed"
      return
    fi
  done
  warn "Browser install command succeeded but no known binary was found on PATH afterward -- screenshots/PDF report export may be unavailable."
}

# --- build Aperture itself from this checkout --------------------------------

build_frontend() {
  info "Building frontend..."
  ( cd "$REPO_ROOT/web" && npm install && npm run build )
  ok "Frontend built into internal/webui/dist"
}

build_aperture() {
  info "Building aperture binary..."
  go build -o "$INSTALL_DIR/aperture" ./cmd/aperture
  chmod +x "$INSTALL_DIR/aperture"
  ok "aperture installed to $INSTALL_DIR/aperture"
}

# --- PATH setup ---------------------------------------------------------------

ensure_path() {
  # Only touch shell rc files if INSTALL_DIR isn't already resolvable.
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ok "$INSTALL_DIR is already on PATH"; return ;;
  esac

  local rc
  case "$(basename "${SHELL:-bash}")" in
    zsh)  rc="$HOME/.zshrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *)
      # Prefer .bash_profile on macOS (login shells), .bashrc on Linux.
      if [[ "$OS" == "Darwin" ]]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi
      ;;
  esac

  # Re-running install.sh within the same shell session (before the rc
  # file has been re-sourced) would otherwise append a duplicate line
  # every time, since $PATH itself hasn't picked up the earlier change yet.
  if [[ -f "$rc" ]] && grep -qF "$INSTALL_DIR" "$rc" 2>/dev/null; then
    export PATH="$INSTALL_DIR:$PATH"
    ok "$INSTALL_DIR is already configured in $rc (open a new shell if it's not on PATH yet)"
    return
  fi

  if [[ "$rc" == *fish* ]]; then
    printf '\nfish_add_path %s\n' "$INSTALL_DIR" >> "$rc"
  else
    printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
  fi
  export PATH="$INSTALL_DIR:$PATH"
  warn "Added $INSTALL_DIR to PATH in $rc -- open a new shell (or run: source $rc)"
}

# --- main ----------------------------------------------------------------------

info "Installing Aperture and its dependencies into $INSTALL_DIR"
ensure_go
ensure_node
install_ffuf
install_feroxbuster
install_nuclei
install_subfinder
install_amass
install_httpx
install_katana
install_whatweb
install_headless_browser
build_frontend
build_aperture
ensure_path

# Find whichever headless-Chrome-compatible binary ended up on PATH (if
# any) for the summary line below -- install_headless_browser only warns
# rather than failing, so this may come up empty.
FOUND_BROWSER=""
for name in "${CHROME_BINARY_NAMES[@]}"; do
  if command -v "$name" &>/dev/null; then
    FOUND_BROWSER="$name"
    break
  fi
done

echo
ok "Done. Installed:"
printf '  go          %s\n' "$(go version | awk '{print $3}')"
printf '  node        %s\n' "$(node -v)"
printf '  ffuf        %s\n' "$("$INSTALL_DIR/ffuf" -V 2>&1 | head -n1)"
printf '  feroxbuster %s\n' "$("$INSTALL_DIR/feroxbuster" -V)"
printf '  nuclei      %s\n' "$("$INSTALL_DIR/nuclei" -version 2>&1 | head -n1)"
printf '  subfinder   %s\n' "$("$INSTALL_DIR/subfinder" -version 2>&1 | head -n1)"
printf '  amass       %s\n' "$("$INSTALL_DIR/amass" -version 2>&1 | head -n1)"
printf '  httpx       %s\n' "$("$INSTALL_DIR/httpx" -version 2>&1 | head -n1)"
printf '  katana      %s\n' "$("$INSTALL_DIR/katana" -version 2>&1 | head -n1)"
printf '  whatweb     %s\n' "$(command -v whatweb &>/dev/null && echo "installed" || echo "not installed -- WhatWeb tab unavailable")"
printf '  browser     %s\n' "${FOUND_BROWSER:-none found -- screenshots/PDF report export unavailable}"
printf '  aperture    %s\n' "$INSTALL_DIR/aperture"
echo
info "Run 'aperture' to start (open a new shell first if PATH was just updated)."
