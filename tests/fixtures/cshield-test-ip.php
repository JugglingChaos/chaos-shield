<?php
/**
 * Plugin Name: Chaos Shield test IP helper
 * Description: TEST SITES ONLY. Lets the integration tests pick the client IP with an X-Test-IP header.
 *
 * @package ChaosShield
 */

// Never install this on a real site: anyone could pick their own IP.
add_filter(
	'cshield_client_ip',
	static function ( $ip ) {
		return isset( $_SERVER['HTTP_X_TEST_IP'] ) && filter_var( wp_unslash( $_SERVER['HTTP_X_TEST_IP'] ), FILTER_VALIDATE_IP ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_TEST_IP'] ) ) : $ip;
	}
);
