<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: serve original core files as if from core.svn.wordpress.org.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( false === strpos( $url, 'core.svn.wordpress.org/tags/' ) ) return $pre;
	$file = preg_replace( '#^.*/tags/[^/]+/#', '', $url );
	$src  = 'wp-includes/class-wp-embed.php' === $file ? CSHIELD_TEST_DATA . '/embed.bak' : ABSPATH . $file;
	$body = (string) @file_get_contents( $src );
	if ( ! empty( $GLOBALS['cshield_svn_tamper'] ) ) $body .= ' ';
	return array( 'headers' => array(), 'body' => $body, 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
}, 10, 3 );
