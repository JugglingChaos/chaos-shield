<?php
/**
 * Cloudflare Turnstile or hCaptcha on the login, lost password and registration forms.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a CAPTCHA challenge to the core forms and checks it on submit.
 */
final class Captcha {

	const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'; // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- The server-side token check of the Turnstile service, not an asset.
	const SECRET     = 'cshield_turnstile_secret';

	/**
	 * The supported services.
	 *
	 * @return array Provider => script, verify address, widget class, response field, site key setting, secret option.
	 */
	public static function providers() {
		return array(
			'turnstile' => array(
				'name'     => 'Cloudflare Turnstile',
				'script'   => 'https://challenges.cloudflare.com/turnstile/v0/api.js', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- The Turnstile widget must load from Cloudflare; listed under External services.
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
				'secret'   => 'cshield_hcaptcha_secret',
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
			'response' => '' !== $token ? (string) $token : 'cshield-connection-test',
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
			$code = (int) wp_remote_retrieve_response_code( $response );
			/* translators: %d: HTTP status code. */
			return new \WP_Error( 'cshield_captcha_http', sprintf( __( 'The service answered HTTP %d.', 'chaos-shield' ), $code ), array( 'status' => $code ) );
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

		if ( Settings::enabled( 'captcha_comments' ) ) {
			add_filter( 'comment_form_submit_field', array( $this, 'comment_widget' ) );
			add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 2 );
		}
		if ( Settings::enabled( 'captcha_woo' ) ) {
			add_action( 'woocommerce_login_form', array( $this, 'widget' ) );
			add_action( 'woocommerce_register_form', array( $this, 'widget' ) );
			add_action( 'woocommerce_lostpassword_form', array( $this, 'widget' ) );
			add_filter( 'woocommerce_process_login_errors', array( $this, 'check_errors' ) );
			add_filter( 'woocommerce_process_registration_errors', array( $this, 'check_errors' ) );
		}
		if ( Settings::enabled( 'captcha_cf7' ) ) {
			add_filter( 'wpcf7_form_elements', array( $this, 'cf7_widget' ) );
			add_filter( 'wpcf7_spam', array( $this, 'cf7_check' ), 20 );
		}
		if ( Settings::enabled( 'captcha_wpforms' ) ) {
			add_action( 'wpforms_display_submit_before', array( $this, 'widget' ) );
			add_action( 'wpforms_process_before', array( $this, 'wpforms_check' ), 10, 2 );
		}
	}

	/**
	 * Which outside forms the CAPTCHA can cover: setting => label.
	 *
	 * @return array
	 */
	public static function form_options() {
		return array(
			'captcha_comments' => __( 'Comments from visitors who are not logged in', 'chaos-shield' ),
			'captcha_woo'      => __( 'WooCommerce login, sign-up and lost password forms', 'chaos-shield' ),
			'captcha_cf7'      => __( 'Contact Form 7 forms', 'chaos-shield' ),
			'captcha_wpforms'  => __( 'WPForms forms', 'chaos-shield' ),
		);
	}

	/**
	 * Loads the provider's script on the login screen.
	 */
	public function script() {
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- The provider serves the current version at this address.
		wp_enqueue_script( 'cshield-captcha', self::details()['script'], array(), null, array( 'strategy' => 'defer' ) );
	}

	/**
	 * Prints the challenge.
	 */
	public function widget() {
		echo $this->markup(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in markup().
	}

	/**
	 * The challenge, with its script queued when the form is not on the login screen.
	 *
	 * Forms in themes and other plugins share the login screen's widget, so they
	 * also share the light theme: the provider draws it in its own frame.
	 *
	 * @return string
	 */
	private function markup() {
		if ( ! did_action( 'login_enqueue_scripts' ) ) {
			$this->script();
			if ( ! wp_script_is( 'cshield-captcha-reset' ) ) {
				// Forms sent without a page load need a fresh challenge for the next try.
				wp_register_script( 'cshield-captcha-reset', '', array(), CSHIELD_VERSION, true );
				wp_enqueue_script( 'cshield-captcha-reset' );
				wp_add_inline_script( 'cshield-captcha-reset', "(function(){function r(){try{window.turnstile&&turnstile.reset();window.hcaptcha&&hcaptcha.reset();}catch(e){}}document.addEventListener('wpcf7submit',r);if(window.jQuery){jQuery(document).on('wpformsAjaxSubmitFailed wpformsAjaxSubmitSuccess',r);}})();" );
			}
		}
		$d = self::details();
		return sprintf(
			'<div class="%s" data-sitekey="%s" data-theme="light" style="margin:0 0 16px"></div>',
			esc_attr( $d['class'] ),
			esc_attr( Settings::get( $d['key'] ) )
		);
	}

	/**
	 * Adds the challenge above the comment button for visitors who are not logged in.
	 *
	 * @param string $field Submit field markup.
	 * @return string
	 */
	public function comment_widget( $field ) {
		return is_user_logged_in() ? $field : $this->markup() . $field;
	}

	/**
	 * Checks the challenge on a comment from a visitor who is not logged in.
	 *
	 * @param array $data Comment data.
	 * @return array
	 */
	public function check_comment( $data ) {
		$type = isset( $data['comment_type'] ) ? (string) $data['comment_type'] : '';
		if ( is_user_logged_in() || ! did_action( 'pre_comment_on_post' ) || ! in_array( $type, array( '', 'comment' ), true ) ) {
			return $data;
		}
		$error = $this->verify();
		if ( $error ) {
			wp_die(
				wp_kses_post( $error->get_error_message() ),
				esc_html__( 'Comment not sent', 'chaos-shield' ),
				array(
					'response'  => 403,
					'back_link' => true,
				)
			);
		}
		return $data;
	}

	/**
	 * Checks the challenge on WooCommerce's login and sign-up forms.
	 *
	 * @param \WP_Error $errors Errors so far.
	 * @return \WP_Error
	 */
	public function check_errors( $errors ) {
		$error = $this->verify();
		if ( $error && $errors instanceof \WP_Error ) {
			$errors->add( $error->get_error_code(), $error->get_error_message() );
		}
		return $errors;
	}

	/**
	 * Adds the challenge before a Contact Form 7 send button.
	 *
	 * @param string $html Form elements.
	 * @return string
	 */
	public function cf7_widget( $html ) {
		$widget = $this->markup();
		$count  = 0;
		$html   = preg_replace( '/<(input|button)[^>]*\bwpcf7-submit\b/', $widget . '$0', (string) $html, 1, $count );
		return $count ? $html : $html . $widget;
	}

	/**
	 * Counts a Contact Form 7 message without a passed challenge as spam, so it is not sent.
	 *
	 * @param bool $spam Spam so far.
	 * @return bool
	 */
	public function cf7_check( $spam ) {
		return $spam || null !== $this->verify();
	}

	/**
	 * Stops a WPForms entry without a passed challenge.
	 *
	 * @param array $entry     Entry.
	 * @param array $form_data Form settings.
	 */
	public function wpforms_check( $entry, $form_data ) {
		$error = $this->verify();
		if ( $error && function_exists( 'wpforms' ) && isset( $form_data['id'] ) ) {
			wpforms()->process->errors[ $form_data['id'] ]['header'] = wp_strip_all_tags( $error->get_error_message() );
		}
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
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WooCommerce checks its own nonce; this only reads which form was sent.
		$woo = Settings::enabled( 'captcha_woo' ) && isset( $_POST['wc_reset_password'] );
		if ( ! did_action( 'login_init' ) && ! $woo ) {
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
		$failed = new \WP_Error( 'cshield_captcha', __( '<strong>Error:</strong> Please complete the security check and try again.', 'chaos-shield' ) );
		// Real tokens are a few hundred characters; an oversized one only tries to make the service answer with an error.
		if ( '' === $token || strlen( $token ) > 2048 ) {
			return $failed;
		}
		$result = self::siteverify( self::provider(), (string) Settings::get( $d['key'] ), (string) Totp::open( Network::get_option( $d['secret'] ) ), $token );
		$status = is_wp_error( $result ) ? $result->get_error_data() : null;
		if ( is_wp_error( $result ) && ( ! isset( $status['status'] ) || (int) $status['status'] >= 500 ) ) {
			// Fail open: a provider outage must not lock every administrator out. Login limits still apply.
			$throttle = 'cshield_captcha_down';
			if ( ! Network::get_transient( $throttle ) ) {
				Network::set_transient( $throttle, 1, HOUR_IN_SECONDS );
				/* translators: %s: service name, such as hCaptcha. */
				Events::add( 'system', sprintf( __( '%s could not be reached, so logins were allowed without the security check.', 'chaos-shield' ), $d['name'] ), '', array( 'severity' => Events::NOTICE ) );
			}
			return null;
		}
		return ! is_wp_error( $result ) && $result['success'] ? null : $failed;
	}
}
