<?php
/**
 * Administrator sessions overview with remote sign out.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Reads and ends the login sessions WordPress keeps in user meta.
 */
final class Sessions {

	/**
	 * Active sessions of users who can manage the site, newest first.
	 *
	 * @return array Each: user_id, login, verifier, ip, agent, login_time, expiration, current.
	 */
	public static function admins() {
		$current = function_exists( 'wp_get_session_token' ) ? hash( 'sha256', wp_get_session_token() ) : '';
		$users   = get_users(
			array(
				'role__in' => array( 'administrator' ),
				'number'   => 100,
			)
		);
		$rows    = array();
		foreach ( $users as $user ) {
			$tokens = get_user_meta( $user->ID, 'session_tokens', true );
			if ( ! is_array( $tokens ) ) {
				continue;
			}
			foreach ( $tokens as $verifier => $session ) {
				if ( ! is_array( $session ) || (int) $session['expiration'] < time() ) {
					continue;
				}
				$rows[] = array(
					'user_id'    => $user->ID,
					'login'      => $user->user_login,
					'verifier'   => (string) $verifier,
					'ip'         => isset( $session['ip'] ) ? (string) $session['ip'] : '',
					'agent'      => self::browser( isset( $session['ua'] ) ? (string) $session['ua'] : '' ),
					'login_time' => isset( $session['login'] ) ? (int) $session['login'] : 0,
					'expiration' => (int) $session['expiration'],
					'current'    => get_current_user_id() === $user->ID && hash_equals( (string) $verifier, $current ),
				);
			}
		}
		usort(
			$rows,
			static function ( $a, $b ) {
				return $b['login_time'] <=> $a['login_time'];
			}
		);
		return $rows;
	}

	/**
	 * Ends one session.
	 *
	 * @param int    $user_id  User ID.
	 * @param string $verifier Session verifier (hashed token).
	 * @return bool
	 */
	public static function end( $user_id, $verifier ) {
		$tokens = get_user_meta( (int) $user_id, 'session_tokens', true );
		if ( ! is_array( $tokens ) || ! isset( $tokens[ $verifier ] ) ) {
			return false;
		}
		unset( $tokens[ $verifier ] );
		if ( $tokens ) {
			update_user_meta( (int) $user_id, 'session_tokens', $tokens );
		} else {
			delete_user_meta( (int) $user_id, 'session_tokens' );
		}
		return true;
	}

	/**
	 * Short browser and system name from a user agent.
	 *
	 * @param string $ua User agent.
	 * @return string
	 */
	private static function browser( $ua ) {
		if ( '' === $ua ) {
			return '';
		}
		$browser = 'Other';
		foreach ( array(
			'Edg/'     => 'Edge',
			'OPR/'     => 'Opera',
			'Firefox/' => 'Firefox',
			'Chrome/'  => 'Chrome',
			'Safari/'  => 'Safari',
			'curl/'    => 'curl',
		) as $needle => $name ) {
			if ( false !== strpos( $ua, $needle ) ) {
				$browser = $name;
				break;
			}
		}
		$os = '';
		foreach ( array(
			'iPhone'   => 'iPhone',
			'iPad'     => 'iPad',
			'Android'  => 'Android',
			'Windows'  => 'Windows',
			'Mac OS X' => 'macOS',
			'Linux'    => 'Linux',
		) as $needle => $name ) {
			if ( false !== strpos( $ua, $needle ) ) {
				$os = $name;
				break;
			}
		}
		return $os ? $browser . ', ' . $os : $browser;
	}
}
