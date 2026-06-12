#!/usr/bin/env sh
# Install depx: download the latest release binary for this OS/arch, or build
# from source with go install when no matching release is available.
#
# One-liner:
#   curl -sfL https://raw.githubusercontent.com/projectdiscovery/depx/main/scripts/install.sh | sh
#
# Environment:
#   INSTALL_DIR   install destination (default: /usr/local/bin or ~/.local/bin)
#   DEPX_VERSION  pin a release tag (e.g. v0.1.0); default: latest GitHub release
#   DEPX_FORCE_BUILD  set to 1 to skip binary download and use go install
#   DEPX_NO_PATH_UPDATE  set to 1 to skip updating shell startup files for PATH

set -e

REPO="projectdiscovery/depx"
MODULE="github.com/projectdiscovery/depx/cmd/depx"
BINARY="depx"
GITHUB="https://github.com/${REPO}"

log() {
  printf '[depx] %s\n' "$*"
}

err() {
  printf '[depx] error: %s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

detect_os() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    darwin) echo "macOS" ;;
    linux) echo "linux" ;;
    mingw*|msys*|cygwin*|windows*) echo "windows" ;;
    *) echo "unsupported" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    i386|i686|x86) echo "386" ;;
    *) echo "unsupported" ;;
  esac
}

default_install_dir() {
  if [ -n "${INSTALL_DIR:-}" ]; then
    printf '%s' "$INSTALL_DIR"
    return
  fi
  if [ -w /usr/local/bin ] 2>/dev/null; then
    echo "/usr/local/bin"
  else
    echo "${HOME}/.local/bin"
  fi
}

latest_release_tag() {
  if [ -n "${DEPX_VERSION:-}" ]; then
    printf '%s' "$DEPX_VERSION"
    return
  fi
  if need_cmd curl; then
    curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" |
      sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
      head -n1
    return
  fi
  if need_cmd wget; then
    wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" |
      sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
      head -n1
    return
  fi
  echo ""
}

download_binary() {
  os_name="$1"
  arch="$2"
  tag="$3"
  asset_version="$4"
  dest="$5"

  asset="${BINARY}_${asset_version}_${os_name}_${arch}.zip"
  url="${GITHUB}/releases/download/${tag}/${asset}"

  tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t depx-install)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  log "Downloading ${asset}..."
  if need_cmd curl; then
    if ! curl -sfL "$url" -o "${tmpdir}/${asset}"; then
      return 1
    fi
  elif need_cmd wget; then
    if ! wget -q "$url" -O "${tmpdir}/${asset}"; then
      return 1
    fi
  else
    err "curl or wget is required to download release binaries"
    return 1
  fi

  if ! need_cmd unzip; then
    err "unzip is required to extract release archives"
    return 1
  fi

  unzip -oq "${tmpdir}/${asset}" -d "${tmpdir}/extract"
  bin_name="${BINARY}"
  if [ "$os_name" = "windows" ]; then
    bin_name="${BINARY}.exe"
  fi

  src="${tmpdir}/extract/${bin_name}"
  if [ ! -f "$src" ]; then
    src="$(find "${tmpdir}/extract" -maxdepth 2 -type f -name "${bin_name}" | head -n1)"
  fi
  if [ -z "$src" ] || [ ! -f "$src" ]; then
    err "binary not found inside ${asset}"
    return 1
  fi

  mkdir -p "$dest"
  install -m 755 "$src" "${dest}/${bin_name}"
  log "Installed ${dest}/${bin_name}"
}

install_from_source() {
  dest="$1"
  if ! need_cmd go; then
    err "Go is required to build from source (https://go.dev/dl/)"
    exit 1
  fi
  mkdir -p "$dest"
  log "Building ${BINARY} with go install..."
  GOBIN="$dest" go install -v "${MODULE}@latest"
  log "Installed ${dest}/${BINARY}"
}

installed_binary() {
  dest="$1"
  os_name="$2"
  if [ "$os_name" = "windows" ]; then
    echo "${dest}/${BINARY}.exe"
  else
    echo "${dest}/${BINARY}"
  fi
}

verify_install() {
  bin="$1"
  if [ ! -f "$bin" ]; then
    err "install verification failed: ${bin} not found"
    exit 1
  fi
  if [ ! -x "$bin" ]; then
    err "install verification failed: ${bin} is not executable"
    exit 1
  fi
  if ! "$bin" --disable-update-check --silent version >/dev/null 2>&1; then
    err "install verification failed: ${bin} could not run"
    exit 1
  fi
}

path_contains() {
  dir="$1"
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
  esac
  return 1
}

append_path_to_file() {
  file="$1"
  dest="$2"
  marker="# depx install script"
  export_line="export PATH=\"${dest}:\$PATH\"  ${marker}"

  if [ ! -f "$file" ]; then
    return 1
  fi
  if grep -Fq "$marker" "$file" 2>/dev/null; then
    return 0
  fi
  if grep -Fq "$dest" "$file" 2>/dev/null; then
    return 0
  fi

  {
    printf '\n%s\n' "$marker"
    printf '%s\n' "$export_line"
  } >>"$file"
  log "Updated ${file} — open a new terminal or run: source ${file}"
  return 0
}

ensure_path() {
  dest="$1"
  bin="$2"

  if path_contains "$dest"; then
    if need_cmd "$BINARY"; then
      log "${BINARY} is ready to run ($(command -v "${BINARY}"))"
    else
      log "${BINARY} is ready to run (${bin})"
    fi
    return 0
  fi

  if [ "${DEPX_NO_PATH_UPDATE:-0}" = "1" ]; then
    log "Add ${dest} to your PATH, then run: depx --help"
    log "  export PATH=\"${dest}:\$PATH\""
    return 0
  fi

  updated=0
  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh)
      append_path_to_file "${HOME}/.zshrc" "$dest" && updated=1
      ;;
    bash)
      append_path_to_file "${HOME}/.bashrc" "$dest" && updated=1
      append_path_to_file "${HOME}/.bash_profile" "$dest" && updated=1
      ;;
    fish)
      fish_rc="${HOME}/.config/fish/config.fish"
      if [ -f "$fish_rc" ] && ! grep -Fq "# depx install script" "$fish_rc" 2>/dev/null; then
        {
          printf '\n# depx install script\n'
          printf 'fish_add_path %s\n' "$dest"
        } >>"$fish_rc"
        log "Updated ${fish_rc} — open a new terminal or run: source ${fish_rc}"
        updated=1
      fi
      ;;
  esac

  # Login shells on macOS often read .profile instead of .bashrc.
  if [ "$updated" -eq 0 ]; then
    append_path_to_file "${HOME}/.profile" "$dest" && updated=1
  fi

  if [ "$updated" -eq 0 ]; then
    log "Add ${dest} to your PATH manually, then run: depx --help"
    log "  export PATH=\"${dest}:\$PATH\""
    return 0
  fi

  log "After reloading your shell, run: depx --help"
  log "Or run now with: ${bin} --help"
}

finish_install() {
  dest="$1"
  os_name="$2"
  bin="$(installed_binary "$dest" "$os_name")"
  verify_install "$bin"
  ensure_path "$dest" "$bin"
}

main() {
  dest="$(default_install_dir)"
  os_name="$(detect_os)"
  arch="$(detect_arch)"

  if [ "$os_name" = "unsupported" ] || [ "$arch" = "unsupported" ]; then
    log "No prebuilt binary for ${os_name:-unknown}/${arch:-unknown}; falling back to go install"
    install_from_source "$dest"
    finish_install "$dest" "$os_name"
    exit 0
  fi

  if [ "${DEPX_FORCE_BUILD:-0}" = "1" ]; then
    install_from_source "$dest"
    finish_install "$dest" "$os_name"
    exit 0
  fi

  version="$(latest_release_tag)"
  if [ -z "$version" ]; then
    log "Could not resolve latest release; falling back to go install"
    install_from_source "$dest"
    finish_install "$dest" "$os_name"
    exit 0
  fi

  asset_version="${version#v}"

  if download_binary "$os_name" "$arch" "$version" "$asset_version" "$dest"; then
    finish_install "$dest" "$os_name"
    exit 0
  fi

  log "Release download failed; falling back to go install"
  install_from_source "$dest"
  finish_install "$dest" "$os_name"
}

main "$@"
