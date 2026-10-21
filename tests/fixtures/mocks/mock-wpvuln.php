<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: answer WPVulnerability API calls from fixtures.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( 0 !== strpos( $url, 'https://www.wpvulnerability.net/' ) ) return $pre;
	@file_put_contents( CSHIELD_TEST_DATA . '/wpvuln.log', $url . ' UA=' . $args['user-agent'] . "\n", FILE_APPEND );
	if ( file_exists( CSHIELD_TEST_DATA . '/wpvuln-down' ) ) return new WP_Error( 'http_request_failed', 'cURL error 28: timed out' );
	$path = trim( substr( $url, strlen( 'https://www.wpvulnerability.net/' ) ), '/' );
	$fx = json_decode( file_get_contents( CSHIELD_TEST_DATA . '/wpvuln.json' ), true );
	$body = isset( $fx[ $path ] ) ? $fx[ $path ] : array( 'error' => 1, 'message' => 'Not found', 'data' => null );
	return array( 'headers' => array(), 'body' => wp_json_encode( $body ), 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
}, 10, 3 );
