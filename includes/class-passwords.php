<?php
/**
 * Breached password checks through the Have I Been Pwned range API.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Refuses breached passwords and warns administrators who still use one.
 *
 * Only the first five characters of the password's SHA-1 hash leave the site
 * (k-anonymity), and the comparison happens locally.
 */
final class Passwords {

	const API           = 'https://api.pwnedpasswords.com/range/';
	const BREACHED_META = '_cshield_pw_breached';
	const CHECKED_META  = '_cshield_pw_checked';

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! Settings::enabled( 'breached_passwords' ) ) {
			return;
		}
		add_action( 'user_profile_update_errors', array( $this, 'check_profile' ), 10, 3 );
		add_action( 'validate_password_reset', array( $this, 'check_reset' ), 10, 2 );
		add_filter( 'wp_authenticate_user', array( $this, 'check_login' ), 100, 2 );
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	/**
	 * Checks a new password set from a profile or the Add User screen.
	 *
	 * @param \WP_Error $errors Errors.
	 * @param bool      $update Whether an existing user is updated.
	 * @param \stdClass $user   User data, with the plain password when one was entered.
	 */
	public function check_profile( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) || $errors->has_errors() ) {
			return;
		}
		$this->refuse_if_breached( $errors, (string) $user->user_pass, 'pass' );
		if ( ! $errors->has_errors() && ! empty( $user->ID ) ) {
			delete_user_meta( (int) $user->ID, self::BREACHED_META );
		}
	}

	/**
	 * Checks a password chosen on the reset screen.
	 *
	 * @param \WP_Error          $errors Errors.
	 * @param \WP_User|\WP_Error $user   User.
	 */
	public function check_reset( $errors, $user ) {
		// Core verifies the reset key before this runs. Passwords are not sanitized; it is only hashed.
		$pass = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( '' === $pass || $errors->has_errors() ) {
			return;
		}
		$this->refuse_if_breached( $errors, $pass, 'pass' );
		if ( ! $errors->has_errors() && $user instanceof \WP_User ) {
			delete_user_meta( $user->ID, self::BREACHED_META );
		}
	}

	/**
	 * Checks an administrator's password at login, at most once a week, and flags it when breached.
	 *
	 * @param \WP_User|\WP_Error $user     User after the password check.
	 * @param string             $password Plain password.
	 * @return \WP_User|\WP_Error
	 */
	public function check_login( $user, $password ) {
		if ( ! $user instanceof \WP_User || ! user_can( $user, 'manage_options' ) ) {
			return $user;
		}
		// Note: wp_authenticate_user runs before the password check, so verify it first.
		if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return $user;
		}
		$checked = (int) get_user_meta( $user->ID, self::CHECKED_META, true );
		if ( $checked > time() - WEEK_IN_SECONDS ) {
			return $user;
		}
		$count = self::breach_count( $password );
		if ( false === $count ) {
			return $user;
		}
		update_user_meta( $user->ID, self::CHECKED_META, time() );
		if ( $count > 0 ) {
			update_user_meta( $user->ID, self::BREACHED_META, $count );
			Events::add(
				'password',
				/* translators: %s: username. */
				sprintf( __( 'Administrator %s logged in with a password found in public data breaches.', 'chaos-shield' ), $user->user_login ),
				Request::ip(),
				array(
					'severity' => Events::CRITICAL,
					'user_id'  => $user->ID,
					'action'   => 'auth.breached_password',
					'subject'  => $user->user_login,
				)
			);
		} else {
			delete_user_meta( $user->ID, self::BREACHED_META );
		}
		return $user;
	}

	/**
	 * Warns a user whose password was found in a breach.
	 */
	public function notice() {
		$count = (int) get_user_meta( get_current_user_id(), self::BREACHED_META, true );
		if ( ! $count ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
			esc_html__( 'Chaos Shield:', 'chaos-shield' ),
			esc_html(
				sprintf(
					/* translators: %s: number of breaches. */
					_n( 'Your password has appeared in %s known data breach, so attackers will try it.', 'Your password has appeared in %s known data breaches, so attackers will try it.', $count, 'chaos-shield' ),
					number_format_i18n( $count )
				)
			),
			esc_url( admin_url( 'profile.php#password' ) ),
			esc_html__( 'Change it now', 'chaos-shield' )
		);
	}

	/**
	 * Adds an error when the password is breached.
	 *
	 * @param \WP_Error $errors   Errors.
	 * @param string    $password Plain password.
	 * @param string    $field    Field the error belongs to.
	 */
	private function refuse_if_breached( $errors, $password, $field ) {
		$count = self::breach_count( $password );
		if ( $count ) {
			$errors->add(
				'cshield_breached_password',
				sprintf(
					/* translators: %s: number of breaches. */
					_n(
						'<strong>Error:</strong> This password has appeared in %s known data breach, so attackers will try it. Please choose a different one.',
						'<strong>Error:</strong> This password has appeared in %s known data breaches, so attackers will try it. Please choose a different one.',
						$count,
						'chaos-shield'
					),
					number_format_i18n( $count )
				),
				array( 'form-field' => $field )
			);
		}
	}

	/**
	 * How often a password appears in known breaches.
	 *
	 * @param string $password Plain password.
	 * @return int|false Count, or false when the service could not be reached.
	 */
	public static function breach_count( $password ) {
		$hash   = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );

		$response = wp_remote_get(
			self::API . $prefix,
			array(
				'timeout'    => 4,
				'headers'    => array( 'Add-Padding' => 'true' ),
				'user-agent' => 'ChaosShield/' . CSHIELD_VERSION,
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}
		foreach ( preg_split( '/\r?\n/', (string) wp_remote_retrieve_body( $response ) ) as $line ) {
			$parts = explode( ':', trim( $line ) );
			if ( 2 === count( $parts ) && hash_equals( $suffix, strtoupper( $parts[0] ) ) ) {
				return (int) $parts[1];
			}
		}
		return 0;
	}
}
