<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: serve plugin checksums, theme zips and plugin/theme svn files from pristine copies.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	$ok = function ( $body, $code = 200 ) { return array( 'headers' => array(), 'body' => $body, 'response' => array( 'code' => $code, 'message' => 'X' ), 'cookies' => array(), 'filename' => null ); };
	$pristine = CSHIELD_TEST_DATA . '/pristine';
	if ( preg_match( '#^https://downloads\.wordpress\.org/plugin-checksums/([^/]+)/([^/]+)\.json$#', $url, $m ) ) {
		@file_put_contents( CSHIELD_TEST_DATA . '/orgfiles.log', $url . "\n", FILE_APPEND );
		$dir = "$pristine/plugins/{$m[1]}";
		if ( ! is_dir( $dir ) ) return $ok( '{"error":"not found"}', 404 );
		$files = array();
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) { $rel = substr( $f->getPathname(), strlen( $dir ) + 1 ); $files[ $rel ] = array( 'md5' => md5_file( $f->getPathname() ), 'sha256' => hash_file( 'sha256', $f->getPathname() ) ); }
		return $ok( wp_json_encode( array( 'plugin' => $m[1], 'version' => $m[2], 'files' => $files ) ) );
	}
	if ( preg_match( '#^https://downloads\.wordpress\.org/theme/([a-z0-9-]+)\.([0-9.]+)\.zip$#', $url, $m ) ) {
		@file_put_contents( CSHIELD_TEST_DATA . '/orgfiles.log', $url . "\n", FILE_APPEND );
		$dir = "$pristine/themes/{$m[1]}";
		if ( ! is_dir( $dir ) ) return $ok( 'nope', 404 );
		$zip = new ZipArchive(); $zip->open( $args['filename'], ZipArchive::CREATE | ZipArchive::OVERWRITE );
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) { $zip->addFile( $f->getPathname(), $m[1] . '/' . substr( $f->getPathname(), strlen( $dir ) + 1 ) ); }
		$zip->close();
		return array( 'headers' => array(), 'body' => '', 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => $args['filename'] );
	}
	if ( preg_match( '#^https://plugins\.svn\.wordpress\.org/([^/]+)/(?:tags/[^/]+|trunk)/(.+)$#', $url, $m ) || preg_match( '#^https://themes\.svn\.wordpress\.org/([^/]+)/[^/]+/(.+)$#', $url, $t ) ) {
		@file_put_contents( CSHIELD_TEST_DATA . '/orgfiles.log', $url . "\n", FILE_APPEND );
		$kind = strpos( $url, 'plugins.svn' ) ? 'plugins' : 'themes';
		$mm = $kind === 'plugins' ? $m : $t;
		$f = "$pristine/$kind/{$mm[1]}/" . rawurldecode( $mm[2] );
		return is_file( $f ) ? $ok( file_get_contents( $f ) ) : $ok( 'Not Found', 404 );
	}
	return $pre;
}, 10, 3 );
