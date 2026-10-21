<?php
// Built-in server router for a subdirectory multisite.
$uri  = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
$root = __DIR__;
if ( preg_match( '#^/[_0-9a-zA-Z-]+(/wp-(content|admin|includes)/.*)$#', $uri, $m ) || preg_match( '#^/[_0-9a-zA-Z-]+(/[^/]+\.php)$#', $uri, $m ) ) {
	if ( file_exists( $root . $m[1] ) ) { $uri = $m[1]; }
}
$file = $root . $uri;
if ( is_dir( $file ) ) { $file = rtrim( $file, '/' ) . '/index.php'; }
if ( is_file( $file ) ) {
	if ( substr( $file, -4 ) !== '.php' ) {
		if ( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) === $uri ) { return false; }
		$types = array( 'css' => 'text/css', 'js' => 'application/javascript', 'svg' => 'image/svg+xml', 'png' => 'image/png', 'json' => 'application/json', 'woff2' => 'font/woff2' );
		$ext   = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );
		header( 'Content-Type: ' . ( isset( $types[ $ext ] ) ? $types[ $ext ] : 'application/octet-stream' ) );
		readfile( $file );
		return true;
	}
	$_SERVER['SCRIPT_NAME'] = substr( $file, strlen( $root ) );
	$_SERVER['SCRIPT_FILENAME'] = $file;
	$_SERVER['PHP_SELF'] = $_SERVER['SCRIPT_NAME'];
	chdir( dirname( $file ) );
	require $file;
	return true;
}
$_SERVER['SCRIPT_NAME'] = '/index.php';
require $root . '/index.php';
