<?php
/**
 * Passkey login (WebAuthn).
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Lets users register passkeys on their profile and sign in with them.
 *
 * A passkey login needs the device's fingerprint, face or PIN check, so it
 * counts as two factors and skips the authenticator code step.
 */
final class Passkeys {

	const META        = '_cshield_passkeys';
	const INDEX       = 'cshield_passkey_index';
	const TTL         = 300;
	const MAX_PER_USR = 20;
	const ALG_ES256   = -7;
	const ALG_RS256   = -257;

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! self::active() ) {
			return;
		}
		add_action( 'wp_ajax_cshield_pk_reg_options', array( $this, 'ajax_reg_options' ) );
		add_action( 'wp_ajax_cshield_pk_register', array( $this, 'ajax_register' ) );
		add_action( 'wp_ajax_cshield_pk_delete', array( $this, 'ajax_delete' ) );
		add_action( 'wp_ajax_nopriv_cshield_pk_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_nopriv_cshield_pk_login', array( $this, 'ajax_login' ) );
		add_action( 'login_form', array( $this, 'login_button' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'login_assets' ) );
		add_action( 'show_user_profile', array( $this, 'profile_section' ), 5 );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ), 5 );
		add_action( 'admin_enqueue_scripts', array( $this, 'profile_assets' ) );
		add_action( 'deleted_user', array( $this, 'forget_user' ) );
	}

	/**
	 * Whether passkeys can be used on this site.
	 *
	 * @return bool
	 */
	public static function active() {
		return Settings::enabled( 'passkeys' ) && function_exists( 'openssl_verify' ) && function_exists( 'openssl_pkey_get_public' );
	}

	/**
	 * Whether this request is one of the passkey AJAX calls, for the login rate limit and country rules.
	 *
	 * @return bool
	 */
	public static function is_login_request() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only classifies the request.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		return wp_doing_ajax() && in_array( $action, array( 'cshield_pk_login_options', 'cshield_pk_login' ), true );
	}

	/**
	 * Passkeys of a user.
	 *
	 * @param int $user_id User ID.
	 * @return array Credential ID (base64url) => data.
	 */
	public static function for_user( $user_id ) {
		$keys = get_user_meta( (int) $user_id, self::META, true );
		return is_array( $keys ) ? $keys : array();
	}

	/**
	 * Number of users with at least one passkey.
	 *
	 * @return int
	 */
	public static function user_count() {
		return count( array_unique( array_values( (array) Network::get_option( self::INDEX, array() ) ) ) );
	}

	// Relying party.

	/**
	 * Relying party ID: the host the login page lives on.
	 *
	 * @return string
	 */
	public static function rp_id() {
		return (string) wp_parse_url( site_url(), PHP_URL_HOST );
	}

	/**
	 * Origins a browser may report.
	 *
	 * @return string[]
	 */
	private static function origins() {
		$origins = array();
		foreach ( array( site_url(), home_url() ) as $url ) {
			$parts = wp_parse_url( $url );
			if ( empty( $parts['host'] ) ) {
				continue;
			}
			$origin = ( isset( $parts['scheme'] ) ? $parts['scheme'] : 'https' ) . '://' . $parts['host'];
			if ( ! empty( $parts['port'] ) ) {
				$origin .= ':' . $parts['port'];
			}
			$origins[] = strtolower( $origin );
			// Sites behind a proxy that ends TLS often report http in their own address.
			$origins[] = strtolower( preg_replace( '#^http://#', 'https://', $origin ) );
		}
		return array_values( array_unique( $origins ) );
	}

	/**
	 * Whether the browser will allow passkeys here (HTTPS or localhost).
	 *
	 * @return bool
	 */
	public static function secure_context() {
		$host = self::rp_id();
		return is_ssl() || 0 === strpos( site_url(), 'https://' ) || 'localhost' === $host || '127.0.0.1' === $host || '.localhost' === substr( $host, -10 );
	}

	// Registration.

	/**
	 * Sends the options for creating a passkey.
	 */
	public function ajax_reg_options() {
		check_ajax_referer( 'cshield_passkeys', 'nonce' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( array( 'message' => __( 'Please sign in again.', 'chaos-shield' ) ), 403 );
		}
		if ( count( self::for_user( $user->ID ) ) >= self::MAX_PER_USR ) {
			wp_send_json_error( array( 'message' => __( 'You have reached the limit of 20 passkeys. Remove one first.', 'chaos-shield' ) ) );
		}
		// A passkey is a way in, so a stolen session alone must not be enough to add one.
		$tries_key = 'cshield_pk_reauth_' . $user->ID;
		$tries     = (int) Network::get_transient( $tries_key );
		if ( $tries >= 5 ) {
			wp_send_json_error( array( 'message' => __( 'Too many wrong passwords. Try again in 15 minutes.', 'chaos-shield' ) ), 429 );
		}
		$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passwords are compared, never stored or printed.
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			Network::set_transient( $tries_key, $tries + 1, 15 * MINUTE_IN_SECONDS );
			Events::add(
				'login',
				/* translators: %s: username. */
				sprintf( __( 'Wrong password when %s tried to add a passkey.', 'chaos-shield' ), $user->user_login ),
				Request::ip(),
				array(
					'user_id'  => $user->ID,
					'severity' => 'medium',
					'action'   => 'auth.passkey_reauth_failed',
				)
			);
			wp_send_json_error( array( 'message' => __( 'Enter your current password to add a passkey.', 'chaos-shield' ) ), 403 );
		}
		Network::delete_transient( $tries_key );
		$challenge = random_bytes( 32 );
		Network::set_transient( 'cshield_pk_reg_' . $user->ID, self::b64u_encode( $challenge ), self::TTL );

		$exclude = array();
		foreach ( array_keys( self::for_user( $user->ID ) ) as $id ) {
			$exclude[] = array(
				'type' => 'public-key',
				'id'   => $id,
			);
		}
		wp_send_json_success(
			array(
				'challenge'              => self::b64u_encode( $challenge ),
				'rp'                     => array(
					'id'   => self::rp_id(),
					'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				),
				'user'                   => array(
					'id'          => self::b64u_encode( self::user_handle( $user->ID ) ),
					'name'        => $user->user_login,
					'displayName' => $user->display_name ? $user->display_name : $user->user_login,
				),
				'pubKeyCredParams'       => array(
					array(
						'type' => 'public-key',
						'alg'  => self::ALG_ES256,
					),
					array(
						'type' => 'public-key',
						'alg'  => self::ALG_RS256,
					),
				),
				'timeout'                => self::TTL * 1000,
				'attestation'            => 'none',
				'excludeCredentials'     => $exclude,
				'authenticatorSelection' => array(
					'residentKey'        => 'required',
					'requireResidentKey' => true,
					'userVerification'   => 'required',
				),
			)
		);
	}

	/**
	 * Checks and saves a new passkey.
	 */
	public function ajax_register() {
		check_ajax_referer( 'cshield_passkeys', 'nonce' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( array( 'message' => __( 'Please sign in again.', 'chaos-shield' ) ), 403 );
		}
		$expected = Network::get_transient( 'cshield_pk_reg_' . $user->ID );
		Network::delete_transient( 'cshield_pk_reg_' . $user->ID );

		$client = self::b64u_decode( self::post( 'clientDataJSON' ) );
		$att    = self::b64u_decode( self::post( 'attestationObject' ) );
		$name   = sanitize_text_field( self::post( 'name' ) );
		$result = self::verify_registration( $client, $att, (string) $expected );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		$index = (array) Network::get_option( self::INDEX, array() );
		if ( isset( $index[ $result['id'] ] ) ) {
			wp_send_json_error( array( 'message' => __( 'This passkey is already registered.', 'chaos-shield' ) ) );
		}
		$keys                  = self::for_user( $user->ID );
		$keys[ $result['id'] ] = array(
			'name'       => '' !== $name ? mb_substr( $name, 0, 60 ) : __( 'Passkey', 'chaos-shield' ),
			'key'        => $result['pem'],
			'alg'        => $result['alg'],
			'sign_count' => $result['sign_count'],
			'created'    => time(),
			'last_used'  => 0,
		);
		update_user_meta( $user->ID, self::META, $keys );
		$index[ $result['id'] ] = $user->ID;
		Network::update_option( self::INDEX, $index, false );

		/* translators: 1: passkey name, 2: username. */
		Events::add( 'login', sprintf( __( 'Passkey "%1$s" added for %2$s.', 'chaos-shield' ), $keys[ $result['id'] ]['name'], $user->user_login ), Request::ip(), array( 'user_id' => $user->ID ) );
		wp_send_json_success( array( 'message' => __( 'Passkey added. You can now sign in with it.', 'chaos-shield' ) ) );
	}

	/**
	 * Removes a passkey.
	 */
	public function ajax_delete() {
		check_ajax_referer( 'cshield_passkeys', 'nonce' );
		$user_id = absint( self::post( 'user' ) );
		$id      = self::post( 'id' );
		if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to change this user.', 'chaos-shield' ) ), 403 );
		}
		$keys = self::for_user( $user_id );
		if ( ! isset( $keys[ $id ] ) ) {
			wp_send_json_error( array( 'message' => __( 'That passkey no longer exists.', 'chaos-shield' ) ) );
		}
		$name = $keys[ $id ]['name'];
		unset( $keys[ $id ] );
		if ( $keys ) {
			update_user_meta( $user_id, self::META, $keys );
		} else {
			delete_user_meta( $user_id, self::META );
		}
		$index = (array) Network::get_option( self::INDEX, array() );
		unset( $index[ $id ] );
		Network::update_option( self::INDEX, $index, false );

		$owner = get_userdata( $user_id );
		/* translators: 1: passkey name, 2: username. */
		Events::add( 'login', sprintf( __( 'Passkey "%1$s" removed from %2$s.', 'chaos-shield' ), $name, $owner ? $owner->user_login : $user_id ), Request::ip() );
		wp_send_json_success();
	}

	/**
	 * Verifies a registration response.
	 *
	 * @param string $client_json Raw clientDataJSON.
	 * @param string $att_object  Raw attestationObject.
	 * @param string $expected    Expected challenge (base64url).
	 * @return array|\WP_Error id, pem, alg, sign_count.
	 */
	public static function verify_registration( $client_json, $att_object, $expected ) {
		$fail   = new \WP_Error( 'cshield_pk', __( 'The passkey could not be verified. Please try again.', 'chaos-shield' ) );
		$client = self::check_client( $client_json, 'webauthn.create', $expected );
		if ( is_wp_error( $client ) ) {
			return $client;
		}
		try {
			$offset = 0;
			$att    = Cbor::decode( $att_object, $offset );
		} catch ( \Exception $e ) {
			return $fail;
		}
		if ( ! is_array( $att ) || ! isset( $att['authData'] ) || ! is_string( $att['authData'] ) ) {
			return $fail;
		}
		$auth = self::parse_auth_data( $att['authData'], true );
		if ( is_wp_error( $auth ) ) {
			return $auth;
		}
		$pem = self::cose_to_pem( $auth['cose'] );
		if ( ! $pem ) {
			return new \WP_Error( 'cshield_pk', __( 'This passkey uses a key type the site does not support.', 'chaos-shield' ) );
		}
		return array(
			'id'         => self::b64u_encode( $auth['cred_id'] ),
			'pem'        => $pem,
			'alg'        => (int) $auth['cose'][3],
			'sign_count' => $auth['sign_count'],
		);
	}

	// Login.

	/**
	 * Sends the options for signing in with a passkey.
	 */
	public function ajax_login_options() {
		$ip = Request::ip();
		if ( $ip && ! Firewall::allowlisted() && Login_Guard::locked_until( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Too many failed login attempts. Try again later.', 'chaos-shield' ) ), 403 );
		}
		$challenge = random_bytes( 32 );
		$ticket    = wp_generate_password( 32, false );
		Network::set_transient( 'cshield_pk_ch_' . $ticket, self::b64u_encode( $challenge ), self::TTL );
		wp_send_json_success(
			array(
				'ticket'    => $ticket,
				'publicKey' => array(
					'challenge'        => self::b64u_encode( $challenge ),
					'rpId'             => self::rp_id(),
					'timeout'          => self::TTL * 1000,
					'userVerification' => 'required',
					'allowCredentials' => array(),
				),
			)
		);
	}

	/**
	 * Checks a passkey assertion and signs the user in.
	 */
	public function ajax_login() {
		$ip = Request::ip();
		if ( $ip && ! Firewall::allowlisted() && Login_Guard::locked_until( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Too many failed login attempts. Try again later.', 'chaos-shield' ) ), 403 );
		}
		$ticket = preg_replace( '/[^A-Za-z0-9]/', '', self::post( 'ticket' ) );
		$key    = 'cshield_pk_ch_' . $ticket;
		$expect = $ticket ? (string) Network::get_transient( $key ) : '';
		if ( $ticket ) {
			Network::delete_transient( $key );
		}

		$id     = self::post( 'id' );
		$index  = (array) Network::get_option( self::INDEX, array() );
		$userid = isset( $index[ $id ] ) ? (int) $index[ $id ] : 0;
		$user   = $userid ? get_userdata( $userid ) : false;
		$keys   = $user ? self::for_user( $user->ID ) : array();

		$result = ( $user && isset( $keys[ $id ] ) )
			? self::verify_assertion(
				$keys[ $id ],
				self::b64u_decode( self::post( 'clientDataJSON' ) ),
				self::b64u_decode( self::post( 'authenticatorData' ) ),
				self::b64u_decode( self::post( 'signature' ) ),
				$expect
			)
			: new \WP_Error( 'cshield_pk', __( 'This passkey is not registered on this site.', 'chaos-shield' ) );

		if ( is_wp_error( $result ) ) {
			do_action( 'wp_login_failed', $user ? $user->user_login : '', $result ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress's own hook, fired so other plugins see this sign-in.
			if ( 'cshield_pk_clone' === $result->get_error_code() && $user ) {
				Events::add(
					'blocked',
					/* translators: %s: username. */
					sprintf( __( 'Refused a passkey for %s: its signature counter went backwards, which can mean a copied key.', 'chaos-shield' ), $user->user_login ),
					$ip,
					array(
						'user_id'  => $user->ID,
						'severity' => Events::NOTICE,
						'action'   => 'auth.passkey_clone',
					)
				);
			}
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		if ( Password_Policy::forced( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'An administrator asked you to choose a new password. Sign in with your password once to set it.', 'chaos-shield' ) ) );
		}

		$keys[ $id ]['sign_count'] = $result['sign_count'];
		$keys[ $id ]['last_used']  = time();
		update_user_meta( $user->ID, self::META, $keys );

		// The device already checked a fingerprint, face or PIN, so no authenticator code is asked.
		Two_Factor::$passkey_login = true;
		wp_set_auth_cookie( $user->ID, true, is_ssl() );
		wp_set_current_user( $user->ID );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress's own hook, fired so other plugins see this sign-in.

		$redirect = wp_validate_redirect( esc_url_raw( self::post( 'redirect_to' ) ), admin_url() );
		/** This filter is documented in wp-login.php. */
		$redirect = apply_filters( 'login_redirect', $redirect, self::post( 'redirect_to' ), $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress's own filter, so the usual redirect rules apply.
		wp_send_json_success( array( 'redirect' => $redirect ? $redirect : admin_url() ) );
	}

	/**
	 * Verifies a sign-in response against a stored passkey.
	 *
	 * @param array  $stored      Stored passkey.
	 * @param string $client_json Raw clientDataJSON.
	 * @param string $auth_data   Raw authenticatorData.
	 * @param string $signature   Raw signature.
	 * @param string $expected    Expected challenge (base64url).
	 * @return array|\WP_Error sign_count.
	 */
	public static function verify_assertion( array $stored, $client_json, $auth_data, $signature, $expected ) {
		$client = self::check_client( $client_json, 'webauthn.get', $expected );
		if ( is_wp_error( $client ) ) {
			return $client;
		}
		$auth = self::parse_auth_data( $auth_data, false );
		if ( is_wp_error( $auth ) ) {
			return $auth;
		}
		$key = openssl_pkey_get_public( (string) $stored['key'] );
		if ( ! $key || 1 !== openssl_verify( $auth_data . hash( 'sha256', $client_json, true ), $signature, $key, OPENSSL_ALGO_SHA256 ) ) {
			return new \WP_Error( 'cshield_pk', __( 'The passkey signature is not valid.', 'chaos-shield' ) );
		}
		$old = (int) $stored['sign_count'];
		if ( ( $old || $auth['sign_count'] ) && $auth['sign_count'] <= $old ) {
			return new \WP_Error( 'cshield_pk_clone', __( 'This passkey was refused because it may have been copied. Remove it and add it again.', 'chaos-shield' ) );
		}
		return array( 'sign_count' => $auth['sign_count'] );
	}

	// Shared checks.

	/**
	 * Checks clientDataJSON type, challenge and origin.
	 *
	 * @param string $json     Raw clientDataJSON.
	 * @param string $type     Expected type.
	 * @param string $expected Expected challenge (base64url).
	 * @return true|\WP_Error
	 */
	private static function check_client( $json, $type, $expected ) {
		$data = json_decode( (string) $json, true );
		if ( ! is_array( $data ) || ! isset( $data['type'], $data['challenge'], $data['origin'] ) || $type !== $data['type'] ) {
			return new \WP_Error( 'cshield_pk', __( 'The passkey response was not understood.', 'chaos-shield' ) );
		}
		if ( '' === $expected || ! hash_equals( $expected, rtrim( (string) $data['challenge'], '=' ) ) ) {
			return new \WP_Error( 'cshield_pk', __( 'The passkey request expired. Please try again.', 'chaos-shield' ) );
		}
		if ( ! in_array( strtolower( (string) $data['origin'] ), self::origins(), true ) ) {
			return new \WP_Error( 'cshield_pk', __( 'The passkey response came from a different site address.', 'chaos-shield' ) );
		}
		return true;
	}

	/**
	 * Parses authenticator data and checks the site hash and flags.
	 *
	 * @param string $data         Raw authenticator data.
	 * @param bool   $registration Whether credential data must be present.
	 * @return array|\WP_Error sign_count, and cred_id and cose when registering.
	 */
	private static function parse_auth_data( $data, $registration ) {
		$fail = new \WP_Error( 'cshield_pk', __( 'The passkey could not be verified. Please try again.', 'chaos-shield' ) );
		if ( strlen( $data ) < 37 ) {
			return $fail;
		}
		if ( ! hash_equals( hash( 'sha256', self::rp_id(), true ), substr( $data, 0, 32 ) ) ) {
			return new \WP_Error( 'cshield_pk', __( 'The passkey belongs to a different site.', 'chaos-shield' ) );
		}
		$flags = ord( $data[32] );
		if ( ! ( $flags & 0x01 ) || ! ( $flags & 0x04 ) ) {
			return new \WP_Error( 'cshield_pk', __( 'The device did not confirm it was you. Use your fingerprint, face or PIN when asked.', 'chaos-shield' ) );
		}
		$out = array( 'sign_count' => unpack( 'N', substr( $data, 33, 4 ) )[1] );
		if ( ! $registration ) {
			return $out;
		}
		if ( ! ( $flags & 0x40 ) || strlen( $data ) < 55 ) {
			return $fail;
		}
		$len = unpack( 'n', substr( $data, 53, 2 ) )[1];
		if ( $len < 16 || $len > 1023 || strlen( $data ) < 55 + $len ) {
			return $fail;
		}
		$out['cred_id'] = substr( $data, 55, $len );
		try {
			$offset      = 55 + $len;
			$out['cose'] = Cbor::decode( $data, $offset );
		} catch ( \Exception $e ) {
			return $fail;
		}
		return is_array( $out['cose'] ) && isset( $out['cose'][1], $out['cose'][3] ) ? $out : $fail;
	}

	/**
	 * Converts a COSE public key to PEM.
	 *
	 * @param array $cose COSE key map.
	 * @return string PEM, or '' when unsupported.
	 */
	public static function cose_to_pem( array $cose ) {
		$kty = isset( $cose[1] ) ? (int) $cose[1] : 0;
		$alg = isset( $cose[3] ) ? (int) $cose[3] : 0;
		if ( 2 === $kty && self::ALG_ES256 === $alg && isset( $cose[-1], $cose[-2], $cose[-3] ) && 1 === (int) $cose[-1] ) {
			$x = (string) $cose[-2];
			$y = (string) $cose[-3];
			if ( 32 !== strlen( $x ) || 32 !== strlen( $y ) ) {
				return '';
			}
			// SubjectPublicKeyInfo header for a P-256 key, then the uncompressed point.
			$der = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $x . $y;
		} elseif ( 3 === $kty && self::ALG_RS256 === $alg && isset( $cose[-1], $cose[-2] ) ) {
			$rsa = self::der( 0x30, self::der_int( (string) $cose[-1] ) . self::der_int( (string) $cose[-2] ) );
			$der = self::der( 0x30, self::der( 0x30, hex2bin( '06092a864886f70d0101010500' ) ) . self::der( 0x03, "\x00" . $rsa ) );
		} else {
			return '';
		}
		$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- PEM encoding.
		return openssl_pkey_get_public( $pem ) ? $pem : '';
	}

	/**
	 * DER element.
	 *
	 * @param int    $tag   Tag.
	 * @param string $value Contents.
	 * @return string
	 */
	private static function der( $tag, $value ) {
		$len = strlen( $value );
		if ( $len < 128 ) {
			$head = chr( $len );
		} else {
			$bytes = ltrim( pack( 'N', $len ), "\x00" );
			$head  = chr( 0x80 | strlen( $bytes ) ) . $bytes;
		}
		return chr( $tag ) . $head . $value;
	}

	/**
	 * DER unsigned integer.
	 *
	 * @param string $bytes Big-endian bytes.
	 * @return string
	 */
	private static function der_int( $bytes ) {
		$bytes = ltrim( $bytes, "\x00" );
		if ( '' === $bytes || ord( $bytes[0] ) > 0x7f ) {
			$bytes = "\x00" . $bytes;
		}
		return self::der( 0x02, $bytes );
	}

	/**
	 * Stable opaque user handle, so the username never leaves the site.
	 *
	 * @param int $user_id User ID.
	 * @return string 32 bytes.
	 */
	private static function user_handle( $user_id ) {
		return hash_hmac( 'sha256', 'cshield-passkey-' . (int) $user_id, wp_salt( 'auth' ), true );
	}

	/**
	 * Drops the passkeys of a deleted user from the index.
	 *
	 * @param int $user_id User ID.
	 */
	public function forget_user( $user_id ) {
		$index = (array) Network::get_option( self::INDEX, array() );
		$left  = array_filter(
			$index,
			static function ( $owner ) use ( $user_id ) {
				return (int) $owner !== (int) $user_id;
			}
		);
		if ( count( $left ) !== count( $index ) ) {
			Network::update_option( self::INDEX, $left, false );
		}
	}

	// Screens.

	/**
	 * Adds the passkey button to the login form.
	 */
	public function login_button() {
		if ( ! self::secure_context() || ! self::user_count() ) {
			return;
		}
		?>
		<div class="cshield-pk-login" hidden>
			<p class="cshield-pk-login__or"><span><?php esc_html_e( 'or', 'chaos-shield' ); ?></span></p>
			<button type="button" class="button button-large cshield-pk-login__btn"><?php esc_html_e( 'Sign in with a passkey', 'chaos-shield' ); ?></button>
			<p class="cshield-pk-login__msg" role="alert" aria-live="assertive"></p>
		</div>
		<?php
	}

	/**
	 * Loads the login page script.
	 */
	public function login_assets() {
		if ( ! self::secure_context() || ! self::user_count() ) {
			return;
		}
		wp_enqueue_script( 'cshield-passkey-login', CSHIELD_URL . 'assets/js/passkey-login.js', array(), CSHIELD_VERSION, true );
		wp_localize_script(
			'cshield-passkey-login',
			'cshieldPasskey',
			array(
				'ajax'    => admin_url( 'admin-ajax.php' ),
				'working' => __( 'Waiting for your passkey…', 'chaos-shield' ),
				'failed'  => __( 'Passkey sign-in did not work. Try again or use your password.', 'chaos-shield' ),
			)
		);
		wp_enqueue_style( 'cshield-passkey-login', CSHIELD_URL . 'assets/css/passkey-login.css', array(), CSHIELD_VERSION );
	}

	/**
	 * Loads the profile script.
	 *
	 * @param string $hook Admin page hook.
	 */
	public function profile_assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_script( 'cshield-passkey-profile', CSHIELD_URL . 'assets/js/passkey-profile.js', array(), CSHIELD_VERSION, true );
		wp_localize_script(
			'cshield-passkey-profile',
			'cshieldPasskey',
			array(
				'ajax'        => admin_url( 'admin-ajax.php' ),
				'nonce'       => wp_create_nonce( 'cshield_passkeys' ),
				'working'     => __( 'Follow the steps on your device…', 'chaos-shield' ),
				'password'    => __( 'Enter your current password to add a passkey.', 'chaos-shield' ),
				'failed'      => __( 'The passkey was not added.', 'chaos-shield' ),
				'exists'      => __( 'This device already has a passkey for your account.', 'chaos-shield' ),
				'cancelled'   => __( 'Cancelled. No passkey was added.', 'chaos-shield' ),
				'unsupported' => __( 'This browser cannot create passkeys.', 'chaos-shield' ),
				'confirm'     => __( 'Remove this passkey? It will no longer sign in to this site.', 'chaos-shield' ),
			)
		);
		wp_enqueue_style( 'cshield-profile', CSHIELD_URL . 'assets/css/profile.css', array(), CSHIELD_VERSION );
	}

	/**
	 * Prints the passkeys section of a profile.
	 *
	 * @param \WP_User $user User being edited.
	 */
	public function profile_section( $user ) {
		$own  = get_current_user_id() === $user->ID;
		$keys = self::for_user( $user->ID );
		if ( ! $own && ! $keys ) {
			return;
		}
		?>
		<div class="cshield-2fa cshield-pk" id="cshield-passkeys" data-user="<?php echo esc_attr( $user->ID ); ?>">
			<h2><?php esc_html_e( 'Passkeys', 'chaos-shield' ); ?></h2>
			<p class="description">
				<?php
				echo $own
					? esc_html__( 'Sign in with your fingerprint, face or device PIN instead of a password. A passkey cannot be phished or reused on another site, and it counts as two-factor, so no code is asked.', 'chaos-shield' )
					: esc_html__( 'Passkeys this user can sign in with. Remove one if the device is lost.', 'chaos-shield' );
				?>
			</p>
			<?php if ( $keys ) : ?>
				<table class="widefat striped cshield-pk__list">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Name', 'chaos-shield' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Added', 'chaos-shield' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last used', 'chaos-shield' ); ?></th>
							<td></td>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $keys as $id => $key ) : ?>
							<tr>
								<td><?php echo esc_html( $key['name'] ); ?></td>
								<td><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $key['created'] ) ); ?></td>
								<td><?php echo $key['last_used'] ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $key['last_used'] ) ) : esc_html__( 'Never', 'chaos-shield' ); ?></td>
								<td class="cshield-pk__actions"><button type="button" class="button-link button-link-delete cshield-pk__remove" data-id="<?php echo esc_attr( $id ); ?>"><?php esc_html_e( 'Remove', 'chaos-shield' ); ?></button></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
			<?php if ( $own ) : ?>
				<?php if ( ! self::secure_context() ) : ?>
					<p><?php esc_html_e( 'Passkeys need the site to run on HTTPS.', 'chaos-shield' ); ?></p>
				<?php else : ?>
					<p class="cshield-pk__add">
						<label for="cshield-pk-name" class="screen-reader-text"><?php esc_html_e( 'Passkey name', 'chaos-shield' ); ?></label>
						<input type="text" id="cshield-pk-name" class="regular-text" maxlength="60" placeholder="<?php esc_attr_e( 'Name, such as Work laptop', 'chaos-shield' ); ?>">
						<label for="cshield-pk-password" class="screen-reader-text"><?php esc_html_e( 'Current password', 'chaos-shield' ); ?></label>
						<input type="password" id="cshield-pk-password" class="regular-text" autocomplete="current-password" placeholder="<?php esc_attr_e( 'Current password', 'chaos-shield' ); ?>">
						<button type="button" class="button cshield-pk__create"><?php esc_html_e( 'Add a passkey', 'chaos-shield' ); ?></button>
					</p>
				<?php endif; ?>
			<?php endif; ?>
			<p class="cshield-pk__msg" role="status" aria-live="polite"></p>
		</div>
		<?php
	}

	// Helpers.

	/**
	 * Reads a posted string.
	 *
	 * @param string $key Field.
	 * @return string
	 */
	private static function post( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Callers check a nonce, or a one-time challenge on the login page.
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? trim( sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) ) : '';
	}

	/**
	 * Base64url encoding without padding.
	 *
	 * @param string $bin Bytes.
	 * @return string
	 */
	public static function b64u_encode( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WebAuthn wire format.
	}

	/**
	 * Base64url decoding.
	 *
	 * @param string $text Encoded text.
	 * @return string Bytes, or '' when invalid.
	 */
	public static function b64u_decode( $text ) {
		$bin = base64_decode( strtr( (string) $text, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- WebAuthn wire format.
		return false === $bin ? '' : $bin;
	}
}
