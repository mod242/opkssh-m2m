#!/usr/bin/env bash
# Collects the license and NOTICE files of every module linked into the
# release binaries (all release platforms) plus the Go standard library.
# Output: third_party_licenses/<module path>/{LICENSE*,NOTICE*,...}
# Fails if a linked module ships no license file and has no entry in
# scripts/license-overrides/<module path>/ (with a SOURCE.txt explaining it).
set -euo pipefail
cd "$(dirname "$0")/.."
out=third_party_licenses
rm -rf "$out"
mkdir -p "$out"

mods=$(
  for os in linux freebsd darwin; do
    for arch in amd64 arm64; do
      GOOS=$os GOARCH=$arch CGO_ENABLED=0 go list -deps \
        -f '{{if not .Standard}}{{with .Module}}{{if .Version}}{{.Path}}@{{.Version}}{{end}}{{end}}{{end}}' .
    done
  done | sort -u
)

missing=0
for mv in $mods; do
  path=${mv%@*}
  dir=$(go mod download -json "$mv" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')
  dest="$out/$path"
  mkdir -p "$dest"
  found=0
  for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/PATENTS*; do
    [ -f "$f" ] || continue
    cp "$f" "$dest/"
    found=1
  done
  if [ "$found" = 0 ] && [ -f "scripts/license-overrides/$path/SOURCE.txt" ]; then
    cp "scripts/license-overrides/$path/"* "$dest/"
    found=1
  fi
  if [ "$found" = 0 ]; then
    echo "no license file found for $mv" >&2
    missing=1
  fi
  echo "$mv" >>"$out/MODULES.txt"
done

mkdir -p "$out/go"
goroot=$(go env GOROOT)
golicense=""
for f in "$goroot/LICENSE" /usr/share/licenses/go/LICENSE; do
  if [ -f "$f" ]; then golicense=$f; break; fi
done
if [ -z "$golicense" ]; then
  echo "Go license file not found" >&2
  missing=1
else
  cp "$golicense" "$out/go/"
fi
if [ -f "$goroot/PATENTS" ]; then cp "$goroot/PATENTS" "$out/go/"; fi
echo "go $(go env GOVERSION)" >>"$out/MODULES.txt"

exit "$missing"
