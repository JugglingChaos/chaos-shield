<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: capture outgoing mail and let a test header pick the client IP.
add_filter( 'pre_wp_mail', function ( $null, $atts ) {
	file_put_contents( CSHIELD_TEST_DATA . '/mail.log', "TO: {$atts['to']}\nSUBJECT: {$atts['subject']}\n{$atts['message']}\n=====\n", FILE_APPEND );
	return true;
}, 10, 2 );
add_filter( 'cshield_client_ip', function ( $ip ) {
	return isset( $_SERVER['HTTP_X_TEST_IP'] ) ? $_SERVER['HTTP_X_TEST_IP'] : $ip;
} );
