#!/bin/sh
# Runs the integration tests against a disposable WordPress test site.
# Usage: tests/run.sh /path/to/wordpress   (needs WP-CLI as `wp`, or WP=... to point at it)
set -e
SITE=${1:?Give the path of a TEST WordPress install}
WP=${WP:-wp}
HERE=$(cd "$(dirname "$0")" && pwd)
MU="$SITE/wp-content/mu-plugins"
mkdir -p "$MU"
if ! grep -rqs "sshield_client_ip" "$MU"; then
	cp "$HERE/fixtures/sshield-test-ip.php" "$MU/"
fi
cp "$HERE/fixtures/sshield-test-http.php" "$MU/"
$WP --path="$SITE" eval-file "$HERE/run.php"
if [ "$($WP --path="$SITE" eval 'echo is_multisite() ? 1 : 0;')" = "1" ]; then
	$WP --path="$SITE" eval-file "$HERE/multisite.php"
fi
