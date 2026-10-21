<?php
/**
 * The daily look at the site from outside: page scripts, HTTPS, exposed files and keys.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Loads a few public pages the way a visitor's browser would, once, and hands
 * them to the script monitor, the HTTPS check and the exposure check.
 */
final class Page_Check {

	const OPTION = 'sshield_page_check';
	const HOOK   = 'sshield_page_check';
	const HEADER = 'X-Sshield-Check';
	const BUDGET = 45;

	/**
	 * When this run started, to stay inside the time budget.
	 *
	 * @var float
	 */
	private static $started = 0.0;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
	}

	/**
	 * The last run: checked, took, pages (url => status code), error.
	 *
	 * @return array
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION, array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Proof that a request is this check, so the browser check and the firewall let it through.
	 *
	 * @param int $time Issue time.
	 * @return string
	 */
	private static function token( $time ) {
		return (int) $time . '.' . substr( hash_hmac( 'sha256', 'pagecheck|' . (int) $time, wp_salt( 'nonce' ) ), 0, 32 );
	}

	/**
	 * Whether the current request is this check.
	 *
	 * @return bool
	 */
	public static function is_self() {
		$value = Request::server( 'HTTP_X_SSHIELD_CHECK' );
		$parts = explode( '.', $value, 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || abs( time() - (int) $parts[0] ) > 5 * MINUTE_IN_SECONDS || ! function_exists( 'wp_salt' ) ) {
			return false;
		}
		return hash_equals( self::token( (int) $parts[0] ), $value );
	}

	/**
	 * The pages worth looking at: home, the newest post and page, and a shop's cart and checkout.
	 *
	 * @return string[]
	 */
	public static function pages() {
		$urls = array( home_url( '/' ) );
		foreach ( array( 'post', 'page' ) as $type ) {
			$ids = get_posts(
				array(
					'post_type'      => $type,
					'post_status'    => 'publish',
					'posts_per_page' => 1,
					'fields'         => 'ids',
					'has_password'   => false,
				)
			);
			if ( $ids ) {
				$urls[] = get_permalink( $ids[0] );
			}
		}
		if ( function_exists( 'wc_get_page_permalink' ) ) {
			foreach ( array( 'cart', 'checkout', 'myaccount' ) as $page ) {
				$urls[] = wc_get_page_permalink( $page );
			}
		}
		/**
		 * Filters the pages the daily check loads to look at scripts, mixed content and keys.
		 *
		 * @param string[] $urls Full addresses on this site.
		 */
		$urls = (array) apply_filters( 'sshield_check_pages', $urls );
		return array_slice( array_values( array_unique( array_filter( array_map( 'strval', $urls ) ) ) ), 0, 8 );
	}

	/**
	 * Fetches an address, as this check.
	 *
	 * @param string $url  Address.
	 * @param array  $args Extra wp_remote_request() arguments.
	 * @return array|\WP_Error
	 */
	public static function fetch( $url, array $args = array() ) {
		if ( self::$started && microtime( true ) - self::$started > self::BUDGET ) {
			return new \WP_Error( 'sshield_budget', 'Out of time' );
		}
		$own     = (string) wp_parse_url( $url, PHP_URL_HOST ) === (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$headers = array(
			'User-Agent' => 'Mozilla/5.0 (compatible; SentinelShield/' . SSHIELD_VERSION . '; page check)',
			'Accept'     => 'text/html,application/xhtml+xml,*/*;q=0.8',
		);
		if ( $own ) {
			$headers[ self::HEADER ] = self::token( time() );
		}
		return wp_remote_request(
			$url,
			array_merge(
				array(
					'method'              => 'GET',
					'timeout'             => 10,
					'redirection'         => 3,
					// The certificate is checked on its own; a bad one must not hide what the pages load.
					'sslverify'           => false,
					'limit_response_size' => 2 * MB_IN_BYTES,
					'headers'             => $headers,
				),
				$args,
				isset( $args['headers'] ) ? array( 'headers' => array_merge( $headers, $args['headers'] ) ) : array()
			)
		);
	}

	/**
	 * Loads the pages and runs every check on them.
	 *
	 * @return array State.
	 */
	public static function run() {
		self::$started = microtime( true );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Not allowed on every host.
		}
		$pages = array();
		$codes = array();
		foreach ( self::pages() as $url ) {
			$res = self::fetch( $url );
			if ( is_wp_error( $res ) ) {
				$codes[ $url ] = 0;
				continue;
			}
			$codes[ $url ] = (int) wp_remote_retrieve_response_code( $res );
			if ( $codes[ $url ] >= 200 && $codes[ $url ] < 400 ) {
				$pages[ $url ] = (string) wp_remote_retrieve_body( $res );
			}
		}
		$scripts = Settings::enabled( 'script_watch' ) ? Scripts::analyze( $pages ) : array();
		Https::check( $pages );
		if ( Settings::enabled( 'exposure_check' ) ) {
			Exposure::check( $pages, $scripts );
		}
		$state = array(
			'checked' => time(),
			'took'    => round( microtime( true ) - self::$started, 1 ),
			'pages'   => $codes,
			'error'   => $pages ? '' : 'none',
		);
		Network::update_option( self::OPTION, $state, false );
		self::$started = 0.0;
		return $state;
	}

	/**
	 * Queues a run in its own request, from the daily job.
	 */
	public static function schedule() {
		if ( ! Network::next_scheduled( self::HOOK ) ) {
			Network::schedule_single( time() + 90, self::HOOK );
		}
	}

	/**
	 * Address with the site part cut off, for display.
	 *
	 * @param string $url Address.
	 * @return string
	 */
	public static function short( $url ) {
		$home = untrailingslashit( home_url() );
		return 0 === strpos( $url, $home ) ? ( '' === substr( $url, strlen( $home ) ) ? '/' : substr( $url, strlen( $home ) ) ) : $url;
	}
}
