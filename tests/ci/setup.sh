#!/bin/sh
# Builds two disposable WordPress test sites for the integration tests:
# a single site on http://localhost:8080 and a subdirectory multisite with two
# extra sites on http://localhost:8081 (ports can be changed), both with Chaos Shield and the test mocks.
#
# Usage: tests/ci/setup.sh
# Environment: WP (WP-CLI command), ROOT (where the sites go), DB_HOST, DB_USER,
# DB_PASS, WP_VERSION (default latest), PORT and MS_PORT (default 8080 and 8081),
# WP_SRC (copy WordPress from this folder instead of downloading it).
set -e
WP=${WP:-wp}
ROOT=${ROOT:-/tmp/cshield-sites}
DB_HOST=${DB_HOST:-127.0.0.1}
DB_USER=${DB_USER:-root}
DB_PASS=${DB_PASS:-root}
WP_VERSION=${WP_VERSION:-latest}
PORT=${PORT:-8080}
MS_PORT=${MS_PORT:-8081}
HERE=$(cd "$(dirname "$0")/.." && pwd)
PLUGIN=$(cd "$HERE/.." && pwd)

mkdir -p "$ROOT"
SRC="$ROOT/wordpress"
if [ -n "$WP_SRC" ]; then
	rm -rf "$SRC" && cp -r "$WP_SRC" "$SRC"
elif [ ! -f "$SRC/wp-load.php" ]; then
	$WP core download --path="$SRC" --version="$WP_VERSION"
fi

# What the mocks serve as "the original files": checksums of the untouched download,
# and pristine copies of a bundled plugin, a theme and one core file.
DATA="$ROOT/data"
rm -rf "$DATA" && mkdir -p "$DATA/pristine/plugins" "$DATA/pristine/themes"
php -r '
$root = $argv[1];
$sums = array();
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	$sums[ substr( $f->getPathname(), strlen( $root ) + 1 ) ] = md5_file( $f->getPathname() );
}
file_put_contents( $argv[2], json_encode( $sums ) );
' "$SRC" "$DATA/sums.json"
cp -r "$SRC/wp-content/plugins/akismet" "$DATA/pristine/plugins/"
cp -r "$SRC/wp-content/themes/twentytwentyfour" "$DATA/pristine/themes/"
cp "$SRC/wp-includes/class-wp-embed.php" "$DATA/embed.bak"
cp "$HERE/fixtures/wpvuln.json" "$DATA/wpvuln.json"

site() {
	dir=$1 port=$2 db=$3
	rm -rf "$dir" && cp -r "$SRC" "$dir"
	mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "DROP DATABASE IF EXISTS $db; CREATE DATABASE $db;"
	$WP config create --path="$dir" --dbname="$db" --dbuser="$DB_USER" --dbpass="$DB_PASS" --dbhost="$DB_HOST" --skip-check --extra-php <<PHP
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
define( 'WP_ENVIRONMENT_TYPE', 'local' );
define( 'CSHIELD_TEST_DATA', '$DATA' );
PHP
	mkdir -p "$dir/wp-content/mu-plugins"
	cp "$HERE"/fixtures/mocks/*.php "$dir/wp-content/mu-plugins/"
	ln -s "$PLUGIN" "$dir/wp-content/plugins/chaos-shield"
}

# Single site.
site "$ROOT/single" $PORT cshield_single
$WP core install --path="$ROOT/single" --url=http://localhost:$PORT --title=Test --admin_user=admin --admin_password=admin-pass-123 --admin_email=admin@example.com --skip-email
$WP plugin activate chaos-shield --path="$ROOT/single"

# Multisite with two more sites.
site "$ROOT/multi" $MS_PORT cshield_multi
$WP core multisite-install --path="$ROOT/multi" --url=http://localhost:$MS_PORT --title=Network --admin_user=admin --admin_password=admin-pass-123 --admin_email=admin@example.com --skip-email --skip-config
$WP config set --path="$ROOT/multi" WP_ALLOW_MULTISITE true --raw
$WP config set --path="$ROOT/multi" MULTISITE true --raw
$WP config set --path="$ROOT/multi" SUBDOMAIN_INSTALL false --raw
$WP config set --path="$ROOT/multi" DOMAIN_CURRENT_SITE localhost:$MS_PORT
$WP config set --path="$ROOT/multi" PATH_CURRENT_SITE /
$WP config set --path="$ROOT/multi" SITE_ID_CURRENT_SITE 1 --raw
$WP config set --path="$ROOT/multi" BLOG_ID_CURRENT_SITE 1 --raw
cp "$HERE/ci/router.php" "$ROOT/multi/router.php"
$WP site create --path="$ROOT/multi" --url=http://localhost:$MS_PORT --slug=shop --title=Shop
$WP site create --path="$ROOT/multi" --url=http://localhost:$MS_PORT --slug=news --title=News
$WP plugin activate chaos-shield --network --path="$ROOT/multi" --url=http://localhost:$MS_PORT

# Start both with PHP's built-in server, four workers each so a page can call back into its own site.
cd "$ROOT/single" && PHP_CLI_SERVER_WORKERS=4 nohup php -S 127.0.0.1:$PORT > "$ROOT/single.log" 2>&1 &
cd "$ROOT/multi" && PHP_CLI_SERVER_WORKERS=4 nohup php -S 127.0.0.1:$MS_PORT router.php > "$ROOT/multi.log" 2>&1 &
sleep 2
curl -s -o /dev/null -w "single site %{http_code}\n" http://localhost:$PORT/
curl -s -o /dev/null -w "multisite %{http_code}\n" http://localhost:$MS_PORT/
