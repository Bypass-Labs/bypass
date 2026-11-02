#!/usr/bin/env bash
# Bypass user-local installer. The main function prevents a truncated download
# from executing a partially received installation body.
bypass_install() {
  set -euo pipefail
  umask 022
  fail() { printf 'Bypass: %s\n' "$*" >&2; exit 1; }
  integration=cli
  bypass_accent='' bypass_dim='' bypass_reset=''
  if [ -t 1 ] && [ "${TERM:-}" != dumb ] && [ "${NO_COLOR+x}" != x ]; then
    bypass_accent=$'\033[1;31m'; bypass_dim=$'\033[37m'; bypass_reset=$'\033[0m'
    case "${COLORTERM:-}" in truecolor|24bit) bypass_accent=$'\033[1;38;2;255;74;44m' ;; *) case "${TERM:-}" in *256color*) bypass_accent=$'\033[1;38;5;202m' ;; esac ;; esac
  fi
  for argument in "$@"; do
    case "$argument" in --muse) integration=muse ;; --help|-h) printf 'Usage: install.sh [--muse]\nInstall Bypass, optionally register the full Muse plugin. Runtime approval stays in Muse.\n'; return ;; *) fail "Unknown option: $argument. Use --muse to install the Muse plugin." ;; esac
  done
  if [ "$integration" = muse ]; then
    command -v muse >/dev/null 2>&1 || fail 'Muse Code was not found on PATH. Install Muse from https://dev.meta.ai, open it and sign in, then retry. For the standalone CLI (no Muse Code required), run: curl -fsSL https://bypasslabs.ai/install | bash. No Bypass files were changed.'
  fi
  printf '\n%s▰╲▰  BYPASS LABS%s\n' "$bypass_accent" "$bypass_reset"
  if [ "$integration" = muse ]; then printf '%sInstalling Bypass for Muse Code%s\n' "$bypass_dim" "$bypass_reset"
  else printf '%sSecurity that stays with your code.%s\n' "$bypass_dim" "$bypass_reset"; fi
  case "$(uname -s)" in Darwin) platform=darwin ;; Linux) platform=linux ;; *) fail 'Supported platforms: macOS and glibc Linux (x64 or arm64).' ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=arm64 ;; *) fail 'Supported CPUs: x64 and arm64.' ;; esac
  if [ "$platform" = linux ] && command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then fail 'This download needs glibc Linux. Alpine/musl is not supported.'; fi
  for tool in curl tar mktemp; do command -v "$tool" >/dev/null 2>&1 || fail "$tool is required."; done
  if command -v sha256sum >/dev/null 2>&1; then checksum() { sha256sum "$1" | awk '{print $1}'; }
  elif command -v shasum >/dev/null 2>&1; then checksum() { shasum -a 256 "$1" | awk '{print $1}'; }
  else fail 'A SHA-256 verifier (sha256sum or shasum) is required.'; fi
  base=${BYPASS_DOWNLOAD_BASE_URL:-https://bypasslabs.ai/downloads/bypass}
  base=${base%/}
  protocol='=https'
  case "$base" in https://*) ;; http://127.0.0.1:*|http://localhost:*) protocol='=https,http' ;; *) fail 'The download URL must use HTTPS.' ;; esac
  download() { curl --proto "$protocol" --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 300 "$1" --output "$2"; }
  install_dir=${BYPASS_INSTALL_DIR:-"$HOME/.local/share/bypass"}
  bin_dir=${BYPASS_BIN_DIR:-"$HOME/.local/bin"}
  case "$install_dir:$bin_dir" in *$'\n'*|*$'\r'*) fail 'Installation paths cannot contain newlines.' ;; esac
  case "$install_dir" in /*) ;; *) fail 'BYPASS_INSTALL_DIR must be an absolute path.' ;; esac
  case "$bin_dir" in /*) ;; *) fail 'BYPASS_BIN_DIR must be an absolute path.' ;; esac
  case "$bin_dir" in *:*) fail 'BYPASS_BIN_DIR cannot contain a colon because PATH uses colons as separators.' ;; esac
  if [ -d "$install_dir" ] && [ -n "$(ls -A "$install_dir")" ] && [ ! -f "$install_dir/.bypass-installer" ]; then fail "$install_dir contains unrelated files. Set BYPASS_INSTALL_DIR to an empty directory."; fi
  mkdir -p "$install_dir" "$bin_dir"
  printf '1\n' > "$install_dir/.bypass-installer"
  lock="$install_dir/.install-lock"
  mkdir "$lock" 2>/dev/null || fail "Another install is running. If it was interrupted, remove $lock and retry."
  work=$(mktemp -d "$install_dir/.download.XXXXXX")
  trap 'rm -rf "$work"; rmdir "$lock" 2>/dev/null || true' EXIT
  if [ -e "$bin_dir/bypass" ] || [ -L "$bin_dir/bypass" ]; then
    [ -L "$bin_dir/bypass" ] && [ "$(readlink "$bin_dir/bypass")" = "$install_dir/current/launch-bypass" ] || fail "$bin_dir/bypass already exists and is not managed by this installer. Choose another BYPASS_BIN_DIR."
  fi
  release=${BYPASS_RELEASE:-}
  if [ -z "$release" ]; then download "$base/channels/main.txt" "$work/channel"; release=$(cat "$work/channel"); fi
  printf '%s' "$release" | grep -Eq '^main-[a-f0-9]{40}-[1-9][0-9]{0,15}-[1-9][0-9]{0,15}$' || fail 'Invalid release metadata; installation stopped.'
  asset="bypass-$platform-$arch.tar.gz"
  printf '\n%s01 / DOWNLOAD%s   Bypass for %s-%s…\n' "$bypass_accent" "$bypass_reset" "$platform" "$arch"
  download "$base/releases/$release/SHASUMS256.txt" "$work/checksums"
  expected=$(awk -v file="$asset" '$2==file {print $1}' "$work/checksums")
  printf '%s' "$expected" | grep -Eq '^[a-f0-9]{64}$' || fail 'Missing or invalid artifact checksum.'
  download "$base/releases/$release/$asset" "$work/release.tar.gz"
  [ "$(checksum "$work/release.tar.gz")" = "$expected" ] || fail 'Checksum mismatch. Your existing installation was not changed.'
  tar -tzf "$work/release.tar.gz" > "$work/contents"
  if grep -Ev '^bypass(/|$)' "$work/contents" >/dev/null || grep -E '(^|/)\.\.(/|$)' "$work/contents" >/dev/null; then fail 'Unexpected archive paths.'; fi
  tar -xzf "$work/release.tar.gz" -C "$work"
  stage="$work/bypass"
  [ -x "$stage/plugin/runtime/node" ] && [ -f "$stage/plugin/runtime/bin/bypass.mjs" ] && [ -x "$stage/launch-bypass" ] || fail 'Incomplete release archive.'
  "$stage/plugin/runtime/node" --version >/dev/null || fail 'The bundled runtime cannot run on this system. macOS 11+ or glibc 2.28+ Linux is required.'
  version=$("$stage/launch-bypass" --version)
  mkdir -p "$install_dir/releases"
  destination="$install_dir/releases/$release-$platform-$arch-${expected:0:12}"
  if [ ! -d "$destination" ]; then mv "$stage" "$destination"; fi
  # Node supplies atomic symlink replacement on both macOS and Linux. No sudo.
  "$destination/plugin/runtime/node" --input-type=module - "$install_dir" "$destination" "$bin_dir" <<'NODE'
import fs from 'node:fs';
import path from 'node:path';
const [install,destination,bin]=process.argv.slice(2);
for(const [link,target] of [[path.join(install,'current'),destination],[path.join(bin,'bypass'),path.join(install,'current/launch-bypass')]]){
  const temporary=link+'.new-'+process.pid;
  try{fs.symlinkSync(target,temporary);fs.renameSync(temporary,link);}finally{if(fs.existsSync(temporary))fs.unlinkSync(temporary);}
}
NODE
  if [ "$integration" = muse ]; then printf '✓ Downloaded Bypass %s\n' "$version"
  else printf '\nInstalled %s\nLocation: %s\n\n' "$version" "$install_dir/current"; fi
  if [ -f "$destination/configure-path.mjs" ]; then
    "$destination/plugin/runtime/node" "$destination/configure-path.mjs" "$bin_dir" "$integration" || printf 'PATH setup did not finish. Use the full executable path below.\n'
  else
    printf 'This older release has no automatic PATH setup. Add %s to your shell PATH.\n' "$bin_dir"
  fi
  case ":$PATH:" in *":$bin_dir:"*) command_name=bypass ;; *) printf -v command_name '%q' "$bin_dir/bypass" ;; esac
  printf '\n'
  if [ "$integration" = muse ]; then
    if [ -f "$destination/plugin/runtime/bin/muse-setup.mjs" ]; then
      # Release the download lock before the user enters an interactive Muse session.
      rm -rf "$work"; rmdir "$lock"; trap - EXIT
      MUSE_NO_AUTO_UPDATE=1 "$destination/plugin/runtime/node" "$destination/plugin/runtime/bin/muse-setup.mjs"
      return
    fi
    printf 'Connecting Bypass to Muse…\n'
    if ! MUSE_NO_AUTO_UPDATE=1 "$destination/launch-bypass" integrate muse --scope user --replace; then
      fail "The CLI is installed, but Muse setup did not finish. Fix the reason above and rerun this same installer. Your project settings and evidence are preserved."
    fi
  else
    printf 'Start onboarding (copy this command):\n  %s onboard\n\nRun it from your app folder, or enter the app folder when Bypass asks.\n\nMuse Code plugin (requires Muse Code installed, opened, and signed in first):\n  curl -fsSL https://bypasslabs.ai/install/muse | bash\n' "$command_name"
  fi
  printf '\nUpdate or repair: rerun this same installer. Project settings and evidence stay in your app.\n'
}
bypass_install "$@"
