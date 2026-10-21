<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: answer the Pwned Passwords range API locally. "password123" is breached.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( false === strpos( $url, 'api.pwnedpasswords.com/range/' ) ) return $pre;
	$GLOBALS['cshield_hibp_calls'][] = $url;
	$hash = strtoupper( sha1( 'password123' ) );
	$body = "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n";
	if ( substr( $url, -5 ) === substr( $hash, 0, 5 ) ) $body .= substr( $hash, 5 ) . ":251682\r\n";
	return array( 'headers' => array(), 'body' => $body, 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
}, 10, 3 );
