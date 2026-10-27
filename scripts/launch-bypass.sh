#!/bin/sh
set -eu
source_path=$0
while [ -L "$source_path" ]; do
  source_dir=$(CDPATH= cd -P "$(dirname "$source_path")" && pwd)
  source_path=$(readlink "$source_path")
  case "$source_path" in /*) ;; *) source_path="$source_dir/$source_path" ;; esac
done
release_dir=$(CDPATH= cd -P "$(dirname "$source_path")" && pwd)
export PATH="$release_dir/plugin/runtime:$PATH"
exec "$release_dir/plugin/runtime/node" "$release_dir/plugin/runtime/bin/bypass.mjs" "$@"
