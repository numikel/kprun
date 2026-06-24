#!/usr/bin/env sh
# kprun installer - https://github.com/numikel/kprun
# Usage: curl -fsSL https://raw.githubusercontent.com/numikel/kprun/refs/heads/main/scripts/install.sh | sh

set -e

REPO="numikel/kprun"
BINARY_NAME="kprun"
INSTALL_DIR="${KPRUN_INSTALL_DIR:-$HOME/.local/bin}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
  printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

warn() {
  printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
  printf "${RED}[ERROR]${NC} %s\n" "$1"
  exit 1
}

detect_os() {
  case "$(uname -s)" in
    Linux*) OS="linux" ;;
    Darwin*) OS="darwin" ;;
    *) error "Unsupported operating system: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) error "Unsupported architecture: $(uname -m)" ;;
  esac
}

get_target() {
  case "$OS" in
    linux)
      case "$ARCH" in
        x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
        aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      esac
      ;;
    darwin)
      TARGET="${ARCH}-apple-darwin"
      ;;
  esac
}

get_latest_version() {
  VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" \
    | grep -i '^location:' \
    | sed -E 's|.*/tag/([^[:space:]]+).*|\1|' \
    | tr -d '\r')

  if [ -z "$VERSION" ]; then
    warn "Redirect lookup failed, falling back to GitHub API..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name":' \
      | sed -E 's/.*"([^"]+)".*/\1/')
  fi

  if [ -z "$VERSION" ]; then
    error "Failed to get latest version (GitHub API may be rate-limited; set KPRUN_VERSION=vX.Y.Z to pin)"
  fi
}

verify_checksum() {
  ASSET_NAME="$1"
  ARCHIVE="$2"
  CHECKSUMS="$3"

  if [ "${KPRUN_SKIP_CHECKSUM:-0}" = "1" ] && [ "${KPRUN_DEV:-0}" = "1" ]; then
    warn "WARNING: checksum verification skipped (developer mode)"
    return
  fi

  info "Verifying SHA-256 checksum..."
  EXPECTED=$(grep "[[:space:]]${ASSET_NAME}\$" "$CHECKSUMS" | awk '{print $1}')
  if [ -z "$EXPECTED" ]; then
    error "checksum for ${ASSET_NAME} not found in checksums.txt — refusing to install"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$ARCHIVE" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
  else
    error "Neither sha256sum nor shasum available — cannot verify checksum"
  fi

  if [ "$EXPECTED" != "$ACTUAL" ]; then
    error "checksum mismatch! expected=${EXPECTED} actual=${ACTUAL} — refusing to install"
  fi

  info "Checksum verified."

  # Optional minisign verification (defense in depth on top of SHA-256).
  KPRUN_MINISIGN_PUBKEY="RWQ..."   # published kprun release public key (replace during key ceremony)
  MINISIG="${CHECKSUMS}.minisig"
  if [ "$KPRUN_MINISIGN_PUBKEY" != "RWQ..." ] && command -v minisign >/dev/null 2>&1; then
    if [ -f "$MINISIG" ]; then
      PUBFILE="$(mktemp)"
      printf '%s\n' "$KPRUN_MINISIGN_PUBKEY" > "$PUBFILE"
      if ! minisign -V -p "$PUBFILE" -m "$CHECKSUMS"; then
        rm -f "$PUBFILE"
        error "minisign signature verification failed"
      fi
      rm -f "$PUBFILE"
      info "minisign signature verified"
    fi
  fi
}

verify_archive_paths() {
  ARCHIVE="$1"
  info "Verifying archive contents..."
  if tar -tzf "$ARCHIVE" | grep -qE '^/|(^|/)\.\.(/|$)'; then
    error "Archive contains unsafe paths (absolute or directory traversal) — refusing to extract"
  fi
}

update_path() {
  if [ "${KPRUN_NO_MODIFY_PATH:-0}" = "1" ]; then
    info "KPRUN_NO_MODIFY_PATH=1 set — skipping PATH update"
    return
  fi

  case ":$PATH:" in
    *:"$INSTALL_DIR":*) return ;;
  esac

  PATH_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
  for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$profile" ]; then
      if grep -qF "$INSTALL_DIR" "$profile" 2>/dev/null; then
        info "PATH already configured in $profile"
        return
      fi
      {
        echo ""
        echo "# kprun"
        echo "$PATH_LINE"
      } >> "$profile"
      info "Added $INSTALL_DIR to PATH in $profile"
      warn "Open a new terminal for PATH changes to take effect"
      return
    fi
  done

  warn "Could not find ~/.bashrc, ~/.zshrc, or ~/.profile to update PATH"
  warn "Add manually: export PATH=\"${INSTALL_DIR}:\$PATH\""
}

install() {
  info "Detected: $OS $ARCH"
  info "Target: $TARGET"
  info "Version: $VERSION"

  ASSET_NAME="${BINARY_NAME}-${TARGET}.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
  TEMP_DIR=$(mktemp -d)
  ARCHIVE="${TEMP_DIR}/${ASSET_NAME}"
  CHECKSUMS="${TEMP_DIR}/checksums.txt"

  info "Downloading from: $DOWNLOAD_URL"
  if ! curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE"; then
    error "Failed to download binary"
  fi

  info "Downloading checksums..."
  if ! curl -fsSL "$CHECKSUMS_URL" -o "$CHECKSUMS"; then
    if [ "${KPRUN_SKIP_CHECKSUM:-0}" = "1" ] && [ "${KPRUN_DEV:-0}" = "1" ]; then
      warn "Failed to download checksums.txt — continuing because developer skip is enabled"
    else
      error "Failed to download checksums.txt — refusing to install unverified binary (set KPRUN_DEV=1 and KPRUN_SKIP_CHECKSUM=1 to bypass at your own risk)"
    fi
  else
    MINISIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.minisig"
    MINISIG="${TEMP_DIR}/checksums.txt.minisig"
    curl -fsSL "$MINISIG_URL" -o "$MINISIG" 2>/dev/null || true
    verify_checksum "$ASSET_NAME" "$ARCHIVE" "$CHECKSUMS"
  fi

  verify_archive_paths "$ARCHIVE"

  info "Extracting..."
  tar -xzf "$ARCHIVE" -C "$TEMP_DIR"

  mkdir -p "$INSTALL_DIR"
  mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/"
  chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

  rm -rf "$TEMP_DIR"

  info "Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
}

verify() {
  INSTALLED_BIN="${INSTALL_DIR}/${BINARY_NAME}"
  if [ ! -x "$INSTALLED_BIN" ]; then
    error "Binary not found at expected location: $INSTALLED_BIN"
  fi

  info "Verification: $("$INSTALLED_BIN" --version)"

  if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
    warn "Binary installed but not yet on PATH in this shell"
  fi
}

main() {
  info "Installing $BINARY_NAME..."

  detect_os
  detect_arch
  get_target

  if [ -n "${KPRUN_VERSION:-}" ]; then
    VERSION="$KPRUN_VERSION"
    info "Using pinned version from KPRUN_VERSION: $VERSION"
  else
    get_latest_version
  fi

  install
  update_path
  verify

  echo ""
  info "Installation complete!"
  info "Binary: ${INSTALL_DIR}/${BINARY_NAME}"
  info "Next step: open a new terminal, then run 'kprun init' to create your vault"
}

main
