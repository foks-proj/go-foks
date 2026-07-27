#!/bin/bash
# Regenerate client/libclient/assets/foks.icns from the FOKS logo SVG.
# Requires: rsvg-convert (brew install librsvg) and iconutil (macOS).
#
# The source SVG has a 583x665 viewBox; we recenter it on a square canvas
# with ~5% padding so the icon sits nicely in the macOS icon grid.

set -euo pipefail

cd "$(dirname "$0")/.."
assets=client/libclient/assets
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

sed 's/width="583" height="665" viewBox="0 0 583 665"/viewBox="-74.5 -33.5 732 732"/' \
    "$assets/foks.svg" > "$tmp/foks-square.svg"

mkdir -p "$tmp/foks.iconset"
for sz in 16 32 128 256 512; do
    rsvg-convert -w "$sz" -h "$sz" "$tmp/foks-square.svg" -o "$tmp/foks.iconset/icon_${sz}x${sz}.png"
    dbl=$((sz * 2))
    rsvg-convert -w "$dbl" -h "$dbl" "$tmp/foks-square.svg" -o "$tmp/foks.iconset/icon_${sz}x${sz}@2x.png"
done

iconutil -c icns "$tmp/foks.iconset" -o "$assets/foks.icns"
echo "wrote $assets/foks.icns"
