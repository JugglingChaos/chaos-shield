<?php
/**
 * Login attempt limiting and generic login errors.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Counts failed logins per IP and locks out repeat offenders.
 */
final class Login_Guard {

	const LOCKOUTS_OPTION = 'cshield_lockouts';
	const STATS_OPTION    = 'cshield_stats';

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( Settings::enabled( 'generic_login_errors' ) ) {
			add_filter( 'authenticate', array( $this, 'generic_errors' ), 98 );
			add_action( 'lostpassword_post', array( $this, 'hide_unknown_reset' ), 10, 2 );
		}
		if ( Settings::enabled( 'limit_login' ) ) {
			// Runs after core's username and password checks (priority 20) so a lockout always wins.
			add_filter( 'authenticate', array( $this, 'enforce_lockout' ), 99 );
			add_action( 'wp_login_failed', array( $this, 'record_failure' ), 10, 2 );
			add_action( 'wp_login', array( $this, 'clear_attempts' ) );
		}
	}

	/**
	 * Replaces errors that reveal whether a username exists.
	 *
	 * @param \WP_User|\WP_Error|null $user Authentication result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function generic_errors( $user ) {
		if ( ! is_wp_error( $user ) ) {
			return $user;
		}
		$revealing = array( 'invalid_username', 'invalid_email', 'incorrect_password' );
		if ( array_intersect( $revealing, $user->get_error_codes() ) ) {
			return new \WP_Error(
				'cshield_invalid_login',
				__( '<strong>Error:</strong> The login details you entered are incorrect.', 'chaos-shield' )
			);
		}
		return $user;
	}

	/**
	 * Answers a password reset for an unknown account exactly like a real one,
	 * so the reset form cannot be used to test which usernames exist.
	 *
	 * @param \WP_Error      $errors    Errors so far.
	 * @param \WP_User|false $user_data Matched user, or false.
	 */
	public function hide_unknown_reset( $errors, $user_data ) {
		if ( $user_data || ! did_action( 'login_init' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core's reset form has no nonce; this only reads whether a value was sent.
		if ( empty( $_POST['user_login'] ) || array_diff( $errors->get_error_codes(), array( 'invalid_email' ) ) ) {
			return;
		}
		wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', wp_login_url() ) );
		exit;
	}

	/**
	 * Blocks authentication while the client IP is locked out.
	 *
	 * @param \WP_User|\WP_Error|null $user Authentication result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function enforce_lockout( $user ) {
		$ip    = Request::ip();
		$until = $ip && ! Firewall::allowlisted() ? self::locked_until( $ip ) : 0;
		if ( ! $until ) {
			return $user;
		}
		$minutes = max( 1, (int) ceil( ( $until - time() ) / MINUTE_IN_SECONDS ) );
		return new \WP_Error(
			'cshield_locked_out',
			sprintf(
				/* translators: %d: minutes until the lockout ends. */
				_n(
					'<strong>Error:</strong> Too many failed login attempts. Try again in %d minute.',
					'<strong>Error:</strong> Too many failed login attempts. Try again in %d minutes.',
					$minutes,
					'chaos-shield'
				),
				$minutes
			)
		);
	}

	/**
	 * Counts a failed login and starts a lockout once the limit is reached.
	 *
	 * @param string         $username Attempted username.
	 * @param \WP_Error|null $error    Why the login failed.
	 */
	public function record_failure( $username, $error = null ) {
		if ( $error instanceof \WP_Error && 'cshield_reset_required' === $error->get_error_code() ) {
			return; // Right password, but a new one is due: not a failure.
		}
		$ip = Request::ip();
		if ( ! $ip || Firewall::allowlisted() || self::locked_until( $ip ) ) {
			return;
		}

		self::bump_stat( 'failed_logins' );

		$window = (int) Settings::get( 'login_window' ) * MINUTE_IN_SECONDS;
		$key    = self::attempts_key( $ip );
		$count  = (int) Network::get_transient( $key ) + 1;

		if ( $count < (int) Settings::get( 'login_max_attempts' ) ) {
			Network::set_transient( $key, $count, $window );
			return;
		}

		Network::delete_transient( $key );
		$minutes         = (int) Settings::get( 'login_lockout' );
		$lockouts        = self::lockouts();
		$lockouts[ $ip ] = time() + $minutes * MINUTE_IN_SECONDS;
		self::save_lockouts( $lockouts );
		self::bump_stat( 'lockouts' );

		Events::add(
			'lockout',
			sprintf(
				/* translators: 1: number of attempts, 2: attempted username, 3: lockout minutes. */
				__( 'Locked out after %1$d failed logins (last username tried: %2$s) for %3$d minutes.', 'chaos-shield' ),
				$count,
				sanitize_user( $username ),
				$minutes
			),
			$ip,
			array(
				'severity' => Events::NOTICE,
				'action'   => 'auth.lockout',
				'subject'  => sanitize_user( $username ),
			)
		);
		Alerts::send(
			'alert_lockouts',
			/* translators: %s: IP address. */
			sprintf( __( 'IP %s locked out', 'chaos-shield' ), $ip ),
			sprintf(
				/* translators: 1: IP address, 2: attempts, 3: username, 4: minutes. */
				__( '%1$s was locked out after %2$d failed logins. The last username tried was "%3$s". The lockout lasts %4$d minutes.', 'chaos-shield' ),
				$ip,
				$count,
				sanitize_user( $username ),
				$minutes
			),
			$ip
		);
		Bans::strike( $ip, 'lockout' );
	}

	/**
	 * Resets the counter after a successful login.
	 */
	public function clear_attempts() {
		$ip = Request::ip();
		if ( $ip ) {
			Network::delete_transient( self::attempts_key( $ip ) );
		}
	}

	/**
	 * Active lockouts as IP => expiry timestamp. Expired entries are pruned.
	 *
	 * @return array
	 */
	public static function lockouts() {
		$lockouts = Network::get_option( self::LOCKOUTS_OPTION, array() );
		$lockouts = is_array( $lockouts ) ? $lockouts : array();
		$now      = time();
		$active   = array_filter(
			$lockouts,
			static function ( $until ) use ( $now ) {
				return (int) $until > $now;
			}
		);
		if ( count( $active ) !== count( $lockouts ) ) {
			self::save_lockouts( $active );
		}
		return $active;
	}

	/**
	 * Lockout expiry for an IP, or 0 when it is not locked out.
	 *
	 * @param string $ip IP address.
	 * @return int
	 */
	public static function locked_until( $ip ) {
		$lockouts = self::lockouts();
		return isset( $lockouts[ $ip ] ) ? (int) $lockouts[ $ip ] : 0;
	}

	/**
	 * Removes one lockout, or all of them when no IP is given.
	 *
	 * @param string $ip Optional IP address.
	 */
	public static function release( $ip = '' ) {
		if ( '' === $ip ) {
			self::save_lockouts( array() );
			return;
		}
		$lockouts = self::lockouts();
		unset( $lockouts[ $ip ] );
		self::save_lockouts( $lockouts );
	}

	/**
	 * Daily counters for the dashboard.
	 *
	 * @return array Counter name => count for the last 24 hours.
	 */
	public static function stats() {
		$stats = Network::get_option( self::STATS_OPTION, array() );
		$stats = is_array( $stats ) ? $stats : array();
		$today = gmdate( 'Y-m-d' );
		$prev  = gmdate( 'Y-m-d', time() - DAY_IN_SECONDS );
		$out   = array(
			'failed_logins'   => 0,
			'lockouts'        => 0,
			'firewall_blocks' => 0,
			'threat_blocks'   => 0,
		);
		foreach ( array( $today, $prev ) as $day ) {
			foreach ( $out as $name => $value ) {
				if ( isset( $stats[ $day ][ $name ] ) ) {
					$out[ $name ] = $value + (int) $stats[ $day ][ $name ];
				}
			}
		}
		return $out;
	}

	/**
	 * Increments today's counter, keeping two days of history.
	 *
	 * @param string $name Counter name.
	 */
	public static function bump_stat( $name ) {
		$stats = Network::get_option( self::STATS_OPTION, array() );
		$stats = is_array( $stats ) ? $stats : array();
		$today = gmdate( 'Y-m-d' );
		if ( ! isset( $stats[ $today ][ $name ] ) ) {
			$stats[ $today ][ $name ] = 0;
		}
		++$stats[ $today ][ $name ];
		krsort( $stats );
		$stats = array_slice( $stats, 0, 2, true );
		Network::update_option( self::STATS_OPTION, $stats, false );
	}

	/**
	 * Saves lockouts without autoloading them.
	 *
	 * @param array $lockouts IP => expiry.
	 */
	private static function save_lockouts( array $lockouts ) {
		Network::update_option( self::LOCKOUTS_OPTION, $lockouts, false );
	}

	/**
	 * Transient key for an IP's failure counter.
	 *
	 * @param string $ip IP address.
	 * @return string
	 */
	private static function attempts_key( $ip ) {
		return 'cshield_att_' . md5( $ip );
	}
}
