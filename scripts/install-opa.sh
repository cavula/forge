#!/bin/sh
set -eu
version=1.21.3
case "$(uname -s)" in
 Linux) platform=linux ;;
 Darwin) platform=darwin ;;
 *) echo 'unsupported OPA platform' >&2; exit 1 ;;
esac
case "$(uname -m)" in
 x86_64) arch=amd64 ;;
 arm64|aarch64) arch=arm64 ;;
 *) echo 'unsupported OPA architecture' >&2; exit 1 ;;
esac
asset="opa_${platform}_${arch}"
if [ "$platform" = linux ]; then asset="${asset}_static"; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
base="https://github.com/open-policy-agent/opa/releases/download/v${version}/${asset}"
curl --fail --location --silent --show-error --retry 3 --max-time 120 "$base" -o "$work/opa"
curl --fail --location --silent --show-error --retry 3 --max-time 60 "$base.sha256" -o "$work/checksum"
expected=$(cut -d ' ' -f 1 "$work/checksum" | tr -d '\r\n')
actual=$(shasum -a 256 "$work/opa" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then echo 'OPA checksum mismatch' >&2; exit 1; fi
target=${1:?OPA destination required}
mkdir -p "$(dirname "$target")"
chmod 755 "$work/opa"
mv "$work/opa" "$target"
