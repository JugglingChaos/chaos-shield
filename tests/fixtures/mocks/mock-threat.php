<?php
defined( 'CSHIELD_TEST_DATA' ) || define( 'CSHIELD_TEST_DATA', __DIR__ . '/cshield-test-data' );
// Test only: serve Spamhaus DROP and Tor exit lists.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	$lists = array(
		'https://www.spamhaus.org/drop/drop_v4.json' => "{\"cidr\":\"203.0.113.0/24\",\"sblid\":\"SBL1\",\"rir\":\"arin\"}\n{\"cidr\":\"198.51.100.128/25\",\"sblid\":\"SBL2\",\"rir\":\"ripencc\"}\n{\"cidr\":\"198.51.100.0/24\",\"sblid\":\"SBL3\",\"rir\":\"ripencc\"}\n{\"cidr\":\"10.0.0.0/4\",\"sblid\":\"SBL4\",\"rir\":\"x\"}\n{\"type\":\"metadata\",\"timestamp\":1760000000,\"size\":3,\"records\":4}\n",
		'https://www.spamhaus.org/drop/drop_v6.json' => "{\"cidr\":\"2001:db8:bad::/48\",\"sblid\":\"SBL5\",\"rir\":\"arin\"}\n{\"type\":\"metadata\",\"timestamp\":1760000000}\n",
		'https://check.torproject.org/torbulkexitlist' => "192.0.2.77\n192.0.2.78\n",
	);
	if ( ! isset( $lists[ $url ] ) ) return $pre;
	if ( file_exists( CSHIELD_TEST_DATA . '/threat-down' ) ) return array( 'headers' => array(), 'body' => 'err', 'response' => array( 'code' => 503, 'message' => 'X' ), 'cookies' => array(), 'filename' => null );
	return array( 'headers' => array(), 'body' => $lists[ $url ], 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
}, 10, 3 );
