#!/bin/sh
# Builds the release zip: chaos-shield-<version>.zip with one chaos-shield/ folder inside.
# Usage: bin/build-zip.sh [output folder]   (default: dist/)
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(mkdir -p "${1:-$HERE/dist}" && cd "${1:-$HERE/dist}" && pwd)
VERSION=$(sed -n "s/^define( 'CSHIELD_VERSION', '\([^']*\)' );/\1/p" "$HERE/chaos-shield.php")
[ -n "$VERSION" ] || { echo "Could not read CSHIELD_VERSION" >&2; exit 1; }
STAGE=$(mktemp -d)
mkdir "$STAGE/chaos-shield"
# Everything except development files.
(cd "$HERE" && tar cf - --exclude=./.git --exclude=./.github --exclude=./tests --exclude=./bin \
	--exclude=./dist --exclude=./vendor --exclude=./node_modules --exclude=./composer.json \
	--exclude=./composer.lock --exclude=./phpcs.xml.dist --exclude=./.gitignore \
	--exclude=./.gitattributes --exclude=./CONTRIBUTING.md --exclude='*.zip' --exclude=.DS_Store .) | (cd "$STAGE/chaos-shield" && tar xf -)
rm -f "$OUT/chaos-shield-$VERSION.zip"
(cd "$STAGE" && zip -qr "$OUT/chaos-shield-$VERSION.zip" chaos-shield)
rm -rf "$STAGE"
echo "$OUT/chaos-shield-$VERSION.zip"
