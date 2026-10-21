<?php
/**
 * Custom login address.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Moves the login page to a secret address and answers 404 on wp-login.php,
 * so bots that hammer the default address never reach a login form.
 *
 * Emergency switch: define( 'CSHIELD_DISABLE_LOGIN_SLUG', true ) in wp-config.php.
 */
final class Login_Url {

	/**
	 * Words that cannot be used, because WordPress or common plugins use them.
	 *
	 * @var string[]
	 */
	private static $reserved = array( 'wp-admin', 'wp-login', 'wp-login-php', 'admin', 'login', 'dashboard', 'wp-json', 'feed', 'xmlrpc', 'wp-content', 'wp-includes', 'register', 'signup' );

	/**
	 * Whether this request is serving the login page at the custom address.
	 *
	 * @var bool
	 */
	private $serving = false;

	/**
	 * Current slug, or '' when the feature is off.
	 *
	 * @return string
	 */
	public static function slug() {
		if ( defined( 'CSHIELD_DISABLE_LOGIN_SLUG' ) && CSHIELD_DISABLE_LOGIN_SLUG ) {
			return '';
		}
		return (string) Settings::get( 'login_slug' );
	}

	/**
	 * The custom login address, or the default one.
	 *
	 * @return string
	 */
	public static function url() {
		$slug = self::slug();
		return $slug ? home_url( '/' . $slug ) : site_url( 'wp-login.php' );
	}

	/**
	 * Validates a slug.
	 *
	 * @param string $slug Raw input.
	 * @return string|\WP_Error Clean slug, '' to turn off.
	 */
	public static function validate( $slug ) {
		$slug = sanitize_title( (string) $slug );
		if ( '' === $slug ) {
			return '';
		}
		if ( strlen( $slug ) < 6 ) {
			return new \WP_Error( 'cshield_slug_short', __( 'Use at least 6 letters, numbers or dashes for the login address.', 'chaos-shield' ) );
		}
		if ( in_array( $slug, self::$reserved, true ) || get_page_by_path( $slug ) || term_exists( $slug ) ) {
			return new \WP_Error( 'cshield_slug_taken', __( 'That login address is already used by WordPress or by a page on your site. Pick another one.', 'chaos-shield' ) );
		}
		return $slug;
	}

	/**
	 * Registers hooks. Runs while the plugin loads.
	 */
	public function register() {
		if ( '' === self::slug() ) {
			return;
		}
		add_action( 'plugins_loaded', array( $this, 'route' ), 1 );
		add_action( 'wp_loaded', array( $this, 'serve' ) );
		add_filter( 'site_url', array( $this, 'filter_url' ), 10, 1 );
		add_filter( 'network_site_url', array( $this, 'filter_url' ), 10, 1 );
		add_filter( 'wp_redirect', array( $this, 'filter_url' ), 10, 1 );
		add_filter( 'register_url', array( $this, 'filter_url' ), 10, 1 );
		// Core sends /login and /admin to the login page, which would give the secret away.
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Decides what this request is: the secret address, the old address or a logged-out admin page.
	 */
	public function route() {
		global $pagenow;
		$path = $this->request_path();
		$slug = self::slug();

		if ( $path === $slug ) {
			$this->serving = true;
			$pagenow       = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php is about to run in this request.
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only routes the request.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( 'wp-login.php' === $pagenow || preg_match( '#(^|/)wp-login\.php$#', $path ) ) {
			// Password protected posts submit their form to wp-login.php.
			if ( 'postpass' === $action ) {
				return;
			}
			$this->not_found();
		}

		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() && ! wp_doing_cron() && 'admin-post.php' !== $pagenow && 'async-upload.php' !== $pagenow ) {
			$this->not_found();
		}
	}

	/**
	 * Runs wp-login.php at the secret address.
	 */
	public function serve() {
		if ( ! $this->serving ) {
			return;
		}
		// wp-login.php reads these as globals.
		global $error, $interim_login, $action, $user_login, $user, $redirect_to;
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Swaps wp-login.php for the secret address in URLs that WordPress builds.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public function filter_url( $url ) {
		$url = (string) $url;
		$pos = strpos( $url, 'wp-login.php' );
		if ( false === $pos || false !== strpos( $url, 'action=postpass' ) ) {
			return $url;
		}
		$query = substr( $url, $pos + strlen( 'wp-login.php' ) );
		$base  = home_url( '/' . self::slug(), wp_parse_url( $url, PHP_URL_SCHEME ) );
		return $base . $query;
	}

	/**
	 * Request path relative to the site home, without slashes at either end.
	 *
	 * @return string
	 */
	private function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$home = (string) wp_parse_url( home_url(), PHP_URL_PATH );
		if ( $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		return trim( $path, '/' );
	}

	/**
	 * Answers like any missing page.
	 */
	private function not_found() {
		if ( ! headers_sent() ) {
			status_header( 404 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
		}
		// Plain text: this runs before translations may be loaded.
		echo '404 Not Found';
		exit;
	}
}
