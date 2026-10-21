#!/bin/sh
set -eu
# CI supplies the PR base or previous push SHA. The first repository commit has
# no prior API; compare to the committed M0 descriptor baseline instead.
base=${BUF_BREAKING_AGAINST:-}
if [ -n "$base" ] && git cat-file -e "$base:buf.yaml" 2>/dev/null; then
  buf breaking --against ".git#ref=$base"
else
  buf breaking --against docs/api/m0.binpb
fi
