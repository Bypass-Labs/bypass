#!/usr/bin/env bash
# Bypass user-local installer. The main function prevents a truncated download
# from executing a partially received installation body.
bypass_install() {
  set -euo pipefail
  umask 022
  fail() { printf 'Bypass: %s\n' "$*" >&2; exit 1; }
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
  printf 'Downloading Bypass for %s-%s…\n' "$platform" "$arch"
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
  printf '\nInstalled %s\nLocation: %s\n\n' "$version" "$install_dir/current"
  case ":$PATH:" in *":$bin_dir:"*) command_name=bypass ;; *) command_name="$bin_dir/bypass"; printf 'Add %s to PATH to use the short bypass command.\n\n' "$bin_dir" ;; esac
  printf 'Muse plugin:\n  %s integrate muse --scope user --replace\n  muse plugins inspect bypass\n  muse plugins approve bypass\n  Then open Muse and use /bypass:start.\n\n' "$command_name"
  printf 'Standalone CLI:\n  %s onboard\n\nUpdate: rerun the same installer. Project settings and evidence stay in your app.\n' "$command_name"
}
bypass_install "$@"
