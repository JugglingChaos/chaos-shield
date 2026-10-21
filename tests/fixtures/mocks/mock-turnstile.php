<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: answer Turnstile siteverify locally. Token "pass" succeeds; "down" simulates an outage.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( false === strpos( $url, 'challenges.cloudflare.com/turnstile' ) ) return $pre;
	$t = $args['body']['response'] ?? '';
	if ( 'down' === $t ) return new WP_Error( 'http_request_failed', 'timeout' );
	$ok = 'pass' === $t && 'test-secret' === ( $args['body']['secret'] ?? '' );
	return array( 'headers' => array(), 'body' => wp_json_encode( array( 'success' => $ok ) ), 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
}, 10, 3 );
