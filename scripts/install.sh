#!/usr/bin/env sh
# kprun installer - https://github.com/numikel/kprun
# Usage: curl -fsSL https://raw.githubusercontent.com/numikel/kprun/refs/heads/main/scripts/install.sh | sh

set -e

REPO="numikel/kprun"
BINARY_NAME="kprun"
INSTALL_DIR="${KPRUN_INSTALL_DIR:-$HOME/.local/bin}"
# Optional minisign verification (defense in depth on top of SHA-256).
KPRUN_MINISIGN_PUBKEY="RWS4FT610kpYiZVGSJF6QfIJEFHB1DKxvSQkISakpp4e86kABel6WVkr"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[90m'
NC='\033[0m'

# Plain text when stdout is not a terminal.
if [ ! -t 1 ]; then
  RED=''; GREEN=''; YELLOW=''; DIM=''; NC=''
fi

# Fancy glyphs only on a terminal with a UTF-8 locale; ASCII otherwise.
# ASCII glyphs are pre-padded to a common width of 4 so columns stay aligned.
FANCY=0
if [ -t 1 ]; then
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8*|*utf8*) FANCY=1 ;;
  esac
fi

if [ "$FANCY" = "1" ]; then
  GLYPH_OK='✓'
  GLYPH_ERR='✗'
  GLYPH_WARN='!'
  GLYPH_SUB='→'
else
  GLYPH_OK='[ok]'
  GLYPH_ERR='[x] '
  GLYPH_WARN='[!] '
  GLYPH_SUB='... '
fi

# Step labels are padded to the longest label ("Downloading", 11 chars) + 1.
LABEL_WIDTH=12

step() {
  printf "  ${GREEN}%s %-${LABEL_WIDTH}s${NC} %s\n" "$GLYPH_OK" "$1" "$2"
}

substep() {
  printf "  ${DIM}%s %-${LABEL_WIDTH}s %s${NC}\n" "$GLYPH_SUB" "$1" "$2"
}

warn() {
  printf "  ${YELLOW}%s %s${NC}\n" "$GLYPH_WARN" "$1"
}

error() {
  printf "  ${RED}%s %s${NC}\n" "$GLYPH_ERR" "$1"
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

# Returns success when minisign verification will actually run for the given
# signature path: pubkey configured (not the placeholder), the `minisign`
# binary is on PATH, and the signature file exists. Shared by the Checksums
# step label and verify_checksum() so the two can't desync.
minisign_will_verify() {
  MINISIG="$1"
  [ "$KPRUN_MINISIGN_PUBKEY" != "RWQ..." ] && command -v minisign >/dev/null 2>&1 && [ -f "$MINISIG" ]
}

verify_checksum() {
  ASSET_NAME="$1"
  ARCHIVE="$2"
  CHECKSUMS="$3"

  if [ "${KPRUN_SKIP_CHECKSUM:-0}" = "1" ] && [ "${KPRUN_DEV:-0}" = "1" ]; then
    warn "WARNING: checksum verification skipped (developer mode)"
    return
  fi

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

  step "Verified" "SHA-256 checksum"

  MINISIG="${CHECKSUMS}.minisig"
  if minisign_will_verify "$MINISIG"; then
    PUBFILE="$(mktemp)"
    printf '%s\n' "$KPRUN_MINISIGN_PUBKEY" > "$PUBFILE"
    if ! minisign -V -p "$PUBFILE" -m "$CHECKSUMS" >/dev/null; then
      rm -f "$PUBFILE"
      error "minisign signature verification failed"
    fi
    rm -f "$PUBFILE"
    step "Verified" "minisign signature"
  fi
}

verify_archive_paths() {
  ARCHIVE="$1"
  if tar -tzf "$ARCHIVE" | grep -qE '^/|(^|/)\.\.(/|$)'; then
    error "Archive contains unsafe paths (absolute or directory traversal) — refusing to extract"
  fi
}

update_path() {
  if [ "${KPRUN_NO_MODIFY_PATH:-0}" = "1" ]; then
    step "PATH" "skipped (KPRUN_NO_MODIFY_PATH=1)"
    return
  fi

  case ":$PATH:" in
    *:"$INSTALL_DIR":*)
      step "PATH" "already contains $INSTALL_DIR"
      return
      ;;
  esac

  PATH_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
  for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$profile" ]; then
      if grep -qF "$INSTALL_DIR" "$profile" 2>/dev/null; then
        step "PATH" "already configured in $profile"
        return
      fi
      {
        echo ""
        echo "# kprun"
        echo "$PATH_LINE"
      } >> "$profile"
      step "PATH" "added to $profile"
      warn "Open a new terminal for PATH changes to take effect"
      return
    fi
  done

  warn "Could not find ~/.bashrc, ~/.zshrc, or ~/.profile to update PATH"
  warn "Add manually: export PATH=\"${INSTALL_DIR}:\$PATH\""
}

install() {
  step "Detected" "$OS $ARCH"
  step "Target" "$TARGET"
  step "Version" "$VERSION ($VERSION_NOTE)"

  ASSET_NAME="${BINARY_NAME}-${TARGET}.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
  TEMP_DIR=$(mktemp -d)
  ARCHIVE="${TEMP_DIR}/${ASSET_NAME}"
  CHECKSUMS="${TEMP_DIR}/checksums.txt"

  substep "Downloading" "$DOWNLOAD_URL"
  if ! curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE"; then
    error "Failed to download binary"
  fi
  step "Downloaded" "$ASSET_NAME"

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
    if minisign_will_verify "$MINISIG"; then
      step "Checksums" "checksums.txt + checksums.txt.minisig"
    else
      step "Checksums" "checksums.txt"
    fi
    verify_checksum "$ASSET_NAME" "$ARCHIVE" "$CHECKSUMS"
  fi

  verify_archive_paths "$ARCHIVE"

  tar -xzf "$ARCHIVE" -C "$TEMP_DIR"
  step "Extracted" "archive contents"

  mkdir -p "$INSTALL_DIR"
  mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/"
  chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

  rm -rf "$TEMP_DIR"

  step "Installed" "${INSTALL_DIR}/${BINARY_NAME}"
}

verify() {
  INSTALLED_BIN="${INSTALL_DIR}/${BINARY_NAME}"
  if [ ! -x "$INSTALLED_BIN" ]; then
    error "Binary not found at expected location: $INSTALLED_BIN"
  fi

  INSTALLED_VERSION="$("$INSTALLED_BIN" --version)"
  step "Works" "$INSTALLED_VERSION"

  if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
    warn "Binary installed but not yet on PATH in this shell"
  fi
}

main() {
  printf '%s installer\n\n' "$BINARY_NAME"

  detect_os
  detect_arch
  get_target

  if [ -n "${KPRUN_VERSION:-}" ]; then
    VERSION="$KPRUN_VERSION"
    VERSION_NOTE="pinned via KPRUN_VERSION"
  else
    get_latest_version
    VERSION_NOTE="latest"
  fi

  install
  update_path
  verify

  echo ""
  printf "${GREEN}%s installed successfully!${NC}\n" "$INSTALLED_VERSION"
  echo ""
  printf "  Next: open a new terminal, then run 'kprun init' to create your vault\n"
}

main
