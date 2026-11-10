<?php
/**
 * The daily look at the site from outside: page scripts, HTTPS, exposed files and keys.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Loads a few public pages the way a visitor's browser would, once, and hands
 * them to the script monitor, the HTTPS check and the exposure check.
 */
final class Page_Check {

	const OPTION = 'cshield_page_check';
	const HOOK   = 'cshield_page_check';
	const HEADER = 'X-Cshield-Check';
	const BUDGET = 45;
	const RUN    = 'cshield_page_check_run';

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
	 * It is tied to the run in progress, so a token that leaks stops working when the run ends.
	 *
	 * @param int $time Issue time.
	 * @return string
	 */
	private static function token( $time ) {
		$run = (string) Network::get_transient( self::RUN );
		return (int) $time . '.' . substr( hash_hmac( 'sha256', 'pagecheck|' . (int) $time . '|' . $run, wp_salt( 'nonce' ) ), 0, 32 );
	}

	/**
	 * Whether the current request is this check.
	 *
	 * @return bool
	 */
	public static function is_self() {
		$value = Request::server( 'HTTP_X_CSHIELD_CHECK' );
		$parts = explode( '.', $value, 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || abs( time() - (int) $parts[0] ) > 2 * MINUTE_IN_SECONDS || ! function_exists( 'wp_salt' ) ) {
			return false;
		}
		if ( ! Network::get_transient( self::RUN ) ) {
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
		$urls = (array) apply_filters( 'cshield_check_pages', $urls );
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
			return new \WP_Error( 'cshield_budget', 'Out of time' );
		}
		$home    = home_url();
		$own     = (string) wp_parse_url( $url, PHP_URL_HOST ) === (string) wp_parse_url( $home, PHP_URL_HOST );
		$headers = array(
			'User-Agent' => 'Mozilla/5.0 (compatible; ChaosShield/' . CSHIELD_VERSION . '; page check)',
			'Accept'     => 'text/html,application/xhtml+xml,*/*;q=0.8',
		);
		// The token only goes to this site, and never over plain http when the site has HTTPS.
		$token = $own && Network::get_transient( self::RUN ) && ( 0 === strpos( $url, 'https://' ) || 0 === strpos( $home, 'http://' ) );
		if ( $token ) {
			$headers[ self::HEADER ] = self::token( time() );
		}
		$hops = isset( $args['redirection'] ) ? (int) $args['redirection'] : 3;
		$args = array_merge(
			array(
				'method'              => 'GET',
				'timeout'             => 10,
				// The certificate is checked on its own; a bad one must not hide what the pages load.
				'sslverify'           => false,
				'limit_response_size' => 2 * MB_IN_BYTES,
			),
			$args,
			array(
				// Redirects are followed here, so the token never travels to another host.
				'redirection' => 0,
				'headers'     => isset( $args['headers'] ) ? array_merge( $headers, $args['headers'] ) : $headers,
			)
		);
		// Other hosts are fetched the safe way, so a planted script address cannot reach private networks.
		$res = $own ? wp_remote_request( $url, $args ) : wp_safe_remote_request( $url, $args );
		if ( $hops > 0 && ! is_wp_error( $res ) && in_array( (int) wp_remote_retrieve_response_code( $res ), array( 301, 302, 303, 307, 308 ), true ) ) {
			$to = (string) wp_remote_retrieve_header( $res, 'location' );
			if ( '' !== $to ) {
				$next                = $args;
				$next['redirection'] = $hops - 1;
				unset( $next['headers'][ self::HEADER ] );
				return self::fetch( Scripts::absolute( $to, $url ), $next );
			}
		}
		return $res;
	}


	/**
	 * Loads the pages and runs every check on them.
	 *
	 * @return array State.
	 */
	public static function run() {
		self::$started = microtime( true );
		Network::set_transient( self::RUN, bin2hex( random_bytes( 16 ) ), self::BUDGET + 2 * MINUTE_IN_SECONDS );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, Squiz.PHP.DiscouragedFunctions.Discouraged -- Several page loads can outlast the default limit; not allowed on every host.
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
		if ( Settings::enabled( 'reputation_check' ) ) {
			Reputation::check();
		}
		$state = array(
			'checked' => time(),
			'took'    => round( microtime( true ) - self::$started, 1 ),
			'pages'   => $codes,
			'error'   => $pages ? '' : 'none',
		);
		Network::update_option( self::OPTION, $state, false );
		Network::delete_transient( self::RUN );
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
