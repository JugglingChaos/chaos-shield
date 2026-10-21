<?php
/**
 * Plugin Name: Chaos Shield test HTTP stand-in
 * Description: TEST SITES ONLY. Answers outgoing requests to chosen hosts from a site option, so the tests never reach real services.
 *
 * @package ChaosShield
 */

// Each entry of the sst_http_mock site option: host => code, body, and optionally
// match + else, where else is the body used when the request body lacks match.
// An entry with routes answers by "METHOD /path?query" prefix instead, longest first,
// each route being code + body; anything unmatched gets a 404.
// Runs late, so a test's own answer wins over other mocks on the site.
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) {
		$mock = get_site_option( 'sst_http_mock' );
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		if ( ! is_array( $mock ) || ! isset( $mock[ $host ] ) ) {
			return $pre;
		}
		$entry = $mock[ $host ];
		$body  = is_array( $args['body'] ) ? http_build_query( $args['body'] ) : (string) $args['body'];
		$log   = (array) get_site_option( 'sst_http_log', array() );
		$log[] = array(
			'url'    => $url,
			'body'   => $body,
			'method' => isset( $args['method'] ) ? strtoupper( $args['method'] ) : 'GET',
			'auth'   => ! empty( $args['headers']['Authorization'] ),
		);
		update_site_option( 'sst_http_log', $log );
		if ( ! empty( $entry['error'] ) ) {
			return new WP_Error( 'http_request_failed', $entry['error'] );
		}
		if ( isset( $entry['routes'] ) ) {
			$path   = (string) wp_parse_url( $url, PHP_URL_PATH ) . ( wp_parse_url( $url, PHP_URL_QUERY ) ? '?' . wp_parse_url( $url, PHP_URL_QUERY ) : '' );
			$key    = strtoupper( isset( $args['method'] ) ? $args['method'] : 'GET' ) . ' ' . $path;
			$routes = $entry['routes'];
			uksort(
				$routes,
				static function ( $a, $b ) {
					return strlen( $b ) - strlen( $a );
				}
			);
			$entry = array(
				'code' => 404,
				'body' => '{"success":false,"errors":[{"message":"No route"}]}',
			);
			foreach ( $routes as $prefix => $route ) {
				if ( 0 === strpos( $key, $prefix ) ) {
					$entry = $route;
					break;
				}
			}
		}
		$answer = isset( $entry['match'] ) && false === strpos( $body, $entry['match'] ) ? $entry['else'] : $entry['body'];
		if ( ! empty( $args['stream'] ) && ! empty( $args['filename'] ) ) {
			file_put_contents( $args['filename'], $answer ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Test fixture.
		}
		return array(
			'headers'  => isset( $entry['headers'] ) ? $entry['headers'] : array(),
			'body'     => $answer,
			'response' => array(
				'code'    => isset( $entry['code'] ) ? (int) $entry['code'] : 200,
				'message' => '',
			),
			'cookies'  => array(),
			'filename' => ! empty( $args['stream'] ) ? $args['filename'] : null,
		);
	},
	99,
	3
);

// Prints the sst_inject site option at the foot of every front-end page, to plant scripts and keys.
add_action(
	'wp_footer',
	static function () {
		echo (string) get_site_option( 'sst_inject', '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Test markup.
	}
);
