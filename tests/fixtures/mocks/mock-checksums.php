<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: serve checksums of the local core files as if from api.wordpress.org.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( false === strpos( $url, 'api.wordpress.org/core/checksums' ) ) return $pre;
	$sums = json_decode( (string) @file_get_contents( CSHIELD_TEST_DATA . '/sums.json' ), true );
	return array( 'headers' => array(), 'body' => wp_json_encode( array( 'checksums' => $sums ) ), 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
}, 10, 3 );
