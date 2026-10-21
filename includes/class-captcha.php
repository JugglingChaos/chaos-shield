<?php
/**
 * Cloudflare Turnstile or hCaptcha on the login, lost password and registration forms.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a CAPTCHA challenge to the core forms and checks it on submit.
 */
final class Captcha {

	const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
	const SECRET     = 'sshield_turnstile_secret';

	/**
	 * The supported services.
	 *
	 * @return array Provider => script, verify address, widget class, response field, site key setting, secret option.
	 */
	public static function providers() {
		return array(
			'turnstile' => array(
				'name'     => 'Cloudflare Turnstile',
				'script'   => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
				'verify'   => self::VERIFY_URL,
				'class'    => 'cf-turnstile',
				'field'    => 'cf-turnstile-response',
				'key'      => 'turnstile_site_key',
				'secret'   => self::SECRET,
				'key_test' => '/^[0-9]x[A-Za-z0-9_-]{16,}$/',
			),
			'hcaptcha'  => array(
				'name'     => 'hCaptcha',
				'script'   => 'https://js.hcaptcha.com/1/api.js',
				'verify'   => 'https://api.hcaptcha.com/siteverify',
				'class'    => 'h-captcha',
				'field'    => 'h-captcha-response',
				'key'      => 'hcaptcha_site_key',
				'secret'   => 'sshield_hcaptcha_secret',
				'key_test' => '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
			),
		);
	}

	/**
	 * The chosen provider's key.
	 *
	 * @return string
	 */
	public static function provider() {
		$provider = (string) Settings::get( 'captcha_provider' );
		return array_key_exists( $provider, self::providers() ) ? $provider : 'turnstile';
	}

	/**
	 * One provider's details.
	 *
	 * @param string $provider Provider, or '' for the chosen one.
	 * @return array
	 */
	public static function details( $provider = '' ) {
		$all = self::providers();
		return $all[ isset( $all[ $provider ] ) ? $provider : self::provider() ];
	}

	/**
	 * Whether a provider has both keys saved.
	 *
	 * @param string $provider Provider, or '' for the chosen one.
	 * @return bool
	 */
	public static function configured( $provider = '' ) {
		$d = self::details( $provider );
		return '' !== (string) Settings::get( $d['key'] ) && (bool) Network::get_option( $d['secret'] );
	}

	/**
	 * Whether the CAPTCHA is switched on and has both keys.
	 *
	 * @return bool
	 */
	public static function active() {
		return Settings::enabled( 'captcha' ) && self::configured();
	}

	/**
	 * Stores a secret key, encrypted.
	 *
	 * @param string $secret   Secret, or '' to keep the current one.
	 * @param string $provider Provider, or '' for Turnstile.
	 */
	public static function save_secret( $secret, $provider = 'turnstile' ) {
		$secret = trim( (string) $secret );
		if ( '' !== $secret ) {
			$d = self::details( $provider ? $provider : 'turnstile' );
			Network::update_option( $d['secret'], Totp::seal( $secret ), false );
		}
	}

	/**
	 * Asks the provider whether a secret key, and optionally a solved challenge, are good.
	 *
	 * Without a token this still tells a wrong secret apart from a right one,
	 * because both services name the bad part in their error codes.
	 *
	 * @param string $provider Provider.
	 * @param string $site_key Site key.
	 * @param string $secret   Secret key.
	 * @param string $token    Token from a solved challenge, or ''.
	 * @return array{success:bool,codes:string[]}|\WP_Error
	 */
	public static function siteverify( $provider, $site_key, $secret, $token = '' ) {
		$d    = self::details( $provider );
		$body = array(
			'secret'   => (string) $secret,
			'response' => '' !== $token ? (string) $token : 'sshield-connection-test',
		);
		if ( 'hcaptcha' === $provider ) {
			$body['sitekey'] = (string) $site_key;
		}
		if ( '' !== $token ) {
			$body['remoteip'] = Request::ip();
		}
		$response = wp_remote_post(
			$d['verify'],
			array(
				'timeout' => 8,
				'body'    => $body,
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			/* translators: %d: HTTP status code. */
			return new \WP_Error( 'sshield_captcha_http', sprintf( __( 'The service answered HTTP %d.', 'sentinel-shield' ), (int) wp_remote_retrieve_response_code( $response ) ) );
		}
		return array(
			'success' => ! empty( $data['success'] ),
			'codes'   => isset( $data['error-codes'] ) ? array_map( 'strval', (array) $data['error-codes'] ) : array(),
		);
	}

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! self::active() ) {
			return;
		}
		add_action( 'login_enqueue_scripts', array( $this, 'script' ) );
		add_action( 'login_form', array( $this, 'widget' ) );
		add_action( 'lostpassword_form', array( $this, 'widget' ) );
		add_action( 'register_form', array( $this, 'widget' ) );
		// After core's password check (20) and before the generic error and lockout filters (98, 99).
		add_filter( 'authenticate', array( $this, 'check_login' ), 30 );
		add_action( 'lostpassword_post', array( $this, 'check_lostpassword' ), 5 );
		add_filter( 'registration_errors', array( $this, 'check_registration' ) );
	}

	/**
	 * Loads the provider's script on the login screen.
	 */
	public function script() {
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- The provider serves the current version at this address.
		wp_enqueue_script( 'sshield-captcha', self::details()['script'], array(), null, array( 'strategy' => 'defer' ) );
	}

	/**
	 * Prints the challenge.
	 */
	public function widget() {
		$d = self::details();
		printf(
			'<div class="%s" data-sitekey="%s" data-theme="light" style="margin:0 0 16px"></div>',
			esc_attr( $d['class'] ),
			esc_attr( Settings::get( $d['key'] ) )
		);
	}

	/**
	 * Checks the challenge on the login form. Other sign-in paths, such as the REST API, are left alone.
	 *
	 * @param \WP_User|\WP_Error|null $user Authentication result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function check_login( $user ) {
		global $pagenow;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core's login form has no nonce.
		if ( 'wp-login.php' !== $pagenow || empty( $_POST['log'] ) ) {
			return $user;
		}
		$error = $this->verify();
		return $error ? $error : $user;
	}

	/**
	 * Checks the challenge on the lost password form.
	 *
	 * @param \WP_Error $errors Errors.
	 */
	public function check_lostpassword( $errors ) {
		if ( ! did_action( 'login_init' ) ) {
			return;
		}
		$error = $this->verify();
		if ( $error ) {
			$errors->add( $error->get_error_code(), $error->get_error_message() );
		}
	}

	/**
	 * Checks the challenge on the registration form.
	 *
	 * @param \WP_Error $errors Errors.
	 * @return \WP_Error
	 */
	public function check_registration( $errors ) {
		$error = $this->verify();
		if ( $error ) {
			$errors->add( $error->get_error_code(), $error->get_error_message() );
		}
		return $errors;
	}

	/**
	 * Verifies the posted token with the provider.
	 *
	 * @return \WP_Error|null Error when the check failed.
	 */
	private function verify() {
		$d = self::details();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The challenge token is the proof here.
		$token  = isset( $_POST[ $d['field'] ] ) ? sanitize_text_field( wp_unslash( $_POST[ $d['field'] ] ) ) : '';
		$failed = new \WP_Error( 'sshield_captcha', __( '<strong>Error:</strong> Please complete the security check and try again.', 'sentinel-shield' ) );
		if ( '' === $token ) {
			return $failed;
		}
		$result = self::siteverify( self::provider(), (string) Settings::get( $d['key'] ), (string) Totp::open( Network::get_option( $d['secret'] ) ), $token );
		if ( is_wp_error( $result ) ) {
			// Fail open: a provider outage must not lock every administrator out. Login limits still apply.
			$throttle = 'sshield_captcha_down';
			if ( ! Network::get_transient( $throttle ) ) {
				Network::set_transient( $throttle, 1, HOUR_IN_SECONDS );
				/* translators: %s: service name, such as hCaptcha. */
				Events::add( 'system', sprintf( __( '%s could not be reached, so logins were allowed without the security check.', 'sentinel-shield' ), $d['name'] ), '', array( 'severity' => Events::NOTICE ) );
			}
			return null;
		}
		return $result['success'] ? null : $failed;
	}
}
