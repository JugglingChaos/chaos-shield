#!/bin/sh
# Builds the release zip: chaos-shield-<version>.zip with one chaos-shield/ folder inside.
# With --wporg it builds the WordPress.org copy instead, wporg-chaos-shield-<version>.zip:
# the same plugin without the GitHub updater, since WordPress.org delivers its own updates.
# Usage: bin/build-zip.sh [--wporg] [output folder]   (default: dist/)
set -e
WPORG=
if [ "$1" = "--wporg" ]; then
	WPORG=1
	shift
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(mkdir -p "${1:-$HERE/dist}" && cd "${1:-$HERE/dist}" && pwd)
VERSION=$(sed -n "s/^define( 'CSHIELD_VERSION', '\([^']*\)' );/\1/p" "$HERE/chaos-shield.php")
[ -n "$VERSION" ] || { echo "Could not read CSHIELD_VERSION" >&2; exit 1; }
# The WordPress.org name never starts with chaos-shield, so the GitHub updater never picks it.
NAME="${WPORG:+wporg-}chaos-shield-$VERSION.zip"
STAGE=$(mktemp -d)
mkdir "$STAGE/chaos-shield"
# Everything except development files.
(cd "$HERE" && tar cf - --exclude=./.git --exclude=./.github --exclude=./tests --exclude=./bin \
	--exclude=./dist --exclude=./vendor --exclude=./node_modules --exclude=./composer.json \
	--exclude=./composer.lock --exclude=./phpcs.xml.dist --exclude=./.gitignore \
	--exclude=./.gitattributes --exclude=./CONTRIBUTING.md --exclude='*.zip' --exclude=.DS_Store .) | (cd "$STAGE/chaos-shield" && tar xf -)
if [ -n "$WPORG" ]; then
	rm "$STAGE/chaos-shield/includes/class-updater.php"
	sed -i.bak '/^ \* Update URI:/d' "$STAGE/chaos-shield/chaos-shield.php"
	rm "$STAGE/chaos-shield/chaos-shield.php.bak"
fi
rm -f "$OUT/$NAME"
(cd "$STAGE" && zip -qr "$OUT/$NAME" chaos-shield)
rm -rf "$STAGE"
echo "$OUT/$NAME"
