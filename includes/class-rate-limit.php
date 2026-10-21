<?php
/**
 * Per-IP rate limits for the routes bots hammer.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Counts requests per IP and route group per minute and answers 429 above the limit.
 *
 * Login, API, AJAX and search requests are always counted. Every page view is
 * counted too, but only when a persistent object cache is present, so ordinary
 * hosting never pays a database write for each visit.
 */
final class Rate_Limit {

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( Settings::enabled( 'rate_limit' ) ) {
			// After the firewall (0) and the custom login address router (1).
			add_action( 'plugins_loaded', array( $this, 'check' ), 2 );
		}
	}

	/**
	 * Route groups and their per-minute limits.
	 *
	 * @return array Group => limit.
	 */
	public static function limits() {
		return array(
			'login'  => (int) Settings::get( 'rate_login' ),
			'api'    => (int) Settings::get( 'rate_api' ),
			'search' => (int) Settings::get( 'rate_search' ),
			'pages'  => (int) Settings::get( 'rate_pages' ),
		);
	}

	/**
	 * Counts this request and stops it when its group is over the limit.
	 */
	public function check() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || Firewall::allowlisted() || Page_Check::is_self() || current_user_can( Network::cap() ) ) {
			return;
		}
		$ip = Request::ip();
		if ( ! $ip ) {
			return;
		}
		$limits = self::limits();
		$group  = self::group();
		if ( 'pages' === $group && ! wp_using_ext_object_cache() ) {
			return;
		}
		$limit = $group ? $limits[ $group ] : 0;
		if ( $limit <= 0 ) {
			return;
		}
		if ( self::hit( $ip, $group ) <= $limit ) {
			return;
		}

		Login_Guard::bump_stat( 'rate_limited' );
		$throttle = 'sshield_rl_log_' . md5( $ip . $group );
		if ( ! self::get( $throttle ) ) {
			self::set( $throttle, 1, 10 * MINUTE_IN_SECONDS );
			// Plain English: this runs before translations may be loaded.
			Events::add( 'blocked', sprintf( 'Rate limit hit (%1$s, over %2$d requests a minute).', $group, $limit ), $ip, array( 'action' => 'fw.rate' ) );
			Bans::strike( $ip, 'ratelimit' );
		}

		Attack_Mode::note();
		Help::block_page( 429, 'rate' );
	}

	/**
	 * Which group this request belongs to, or ''.
	 *
	 * @return string
	 */
	public static function group() {
		global $pagenow;
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';

		if ( ( 'wp-login.php' === $pagenow && 'POST' === $method ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || Passkeys::is_login_request() ) {
			return 'login';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only classifies the request.
		if ( isset( $_GET['rest_route'] ) || false !== strpos( $uri, '/' . rest_get_url_prefix() . '/' ) || wp_doing_ajax() ) {
			return 'api';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only classifies the request.
		if ( isset( $_GET['s'] ) ) {
			return 'search';
		}
		if ( is_admin() ) {
			return '';
		}
		return 'pages';
	}

	/**
	 * Adds one to an IP's counter for the current minute.
	 *
	 * @param string $ip    IP address.
	 * @param string $group Group.
	 * @return int Requests in this minute so far.
	 */
	private static function hit( $ip, $group ) {
		$key   = 'sshield_rl_' . $group . '_' . md5( $ip );
		$data  = self::get( $key );
		$now   = time();
		$fresh = ! is_array( $data ) || $now - (int) $data[0] >= MINUTE_IN_SECONDS;
		$data  = $fresh ? array( $now, 1 ) : array( (int) $data[0], (int) $data[1] + 1 );
		self::set( $key, $data, MINUTE_IN_SECONDS );
		return $data[1];
	}

	/**
	 * Reads a counter from the object cache when there is one, otherwise a transient.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	private static function get( $key ) {
		return wp_using_ext_object_cache() ? wp_cache_get( $key, 'sshield' ) : Network::get_transient( $key );
	}

	/**
	 * Writes a counter.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl   Seconds.
	 */
	private static function set( $key, $value, $ttl ) {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $value, 'sshield', $ttl );
		} else {
			Network::set_transient( $key, $value, $ttl );
		}
	}
}
