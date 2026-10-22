<?php
/**
 * Shared helpers for the integration tests.
 *
 * @package ChaosShield
 */

// phpcs:disable WordPress.Security.EscapeOutput -- Command line output.

namespace ChaosShield\Tests;

use ChaosShield\Api;
use ChaosShield\Bans;
use ChaosShield\Events;
use ChaosShield\Firewall;
use ChaosShield\Geo_Db;
use ChaosShield\Incidents;
use ChaosShield\Login_Guard;
use ChaosShield\Password_Policy;
use ChaosShield\Request;
use ChaosShield\Scanner;
use ChaosShield\Settings;
use ChaosShield\Siem;
use ChaosShield\Threat_Feed;
use ChaosShield\Totp;
use ChaosShield\Two_Factor;

$GLOBALS['sst'] = array(
	'pass'  => 0,
	'fail'  => array(),
	'users' => array(),
	'ips'   => array(),
	'files' => array(),
);

/**
 * Records one assertion.
 *
 * @param string $name What is checked.
 * @param bool   $ok   Result.
 * @param string $info Detail on failure.
 */
function check( $name, $ok, $info = '' ) {
	if ( $ok ) {
		++$GLOBALS['sst']['pass'];
		echo "  ok    {$name}\n";
	} else {
		$GLOBALS['sst']['fail'][] = $name;
		echo "  FAIL  {$name}" . ( $info ? " ({$info})" : '' ) . "\n";
	}
}

/**
 * A fresh public-looking IP for one test, released at the end.
 *
 * @return string
 */
function ip() {
	static $n = 0;
	++$n;
	$ip                      = '45.33.' . wp_rand( 1, 254 ) . '.' . ( ( $n % 250 ) + 1 );
	$GLOBALS['sst']['ips'][] = $ip;
	return $ip;
}

/**
 * HTTP request to the site from a given IP.
 *
 * @param string $method  GET or POST.
 * @param string $path    Path and query, or a full URL.
 * @param string $from    Client IP ('' sends none).
 * @param array  $args    body, headers, cookies.
 * @return array status, body, headers, cookies (name => value), location.
 */
function http( $method, $path, $from, array $args = array() ) {
	$url     = 0 === strpos( $path, 'http' ) ? $path : home_url( $path );
	$headers = isset( $args['headers'] ) ? $args['headers'] : array();
	if ( $from ) {
		$headers['X-Test-IP'] = $from;
	}
	$res = wp_remote_request(
		$url,
		array(
			'method'      => $method,
			'body'        => isset( $args['body'] ) ? $args['body'] : null,
			'headers'     => $headers + array( 'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0' ),
			'cookies'     => isset( $args['cookies'] ) ? $args['cookies'] : array(),
			'redirection' => 0,
			'timeout'     => 60,
			'sslverify'   => false,
		)
	);
	if ( is_wp_error( $res ) ) {
		return array(
			'status'   => 0,
			'body'     => $res->get_error_message(),
			'headers'  => array(),
			'cookies'  => array(),
			'location' => '',
		);
	}
	// The site changed options and user meta in its own process: read them fresh here.
	wp_cache_flush();
	$cookies = array();
	foreach ( wp_remote_retrieve_cookies( $res ) as $c ) {
		// Logging out or a cancelled login sends the cookie again, emptied.
		if ( '' !== trim( $c->value ) && 'deleted' !== $c->value ) {
			$cookies[ $c->name ] = $c->value;
		}
	}
	return array(
		'status'   => (int) wp_remote_retrieve_response_code( $res ),
		'body'     => (string) wp_remote_retrieve_body( $res ),
		'headers'  => wp_remote_retrieve_headers( $res ),
		'cookies'  => $cookies,
		'location' => (string) wp_remote_retrieve_header( $res, 'location' ),
	);
}

/**
 * Whether a response logged someone in.
 *
 * @param array $res Response from http().
 * @return bool
 */
function logged_in( array $res ) {
	foreach ( array_keys( $res['cookies'] ) as $name ) {
		if ( 0 === strpos( $name, 'wordpress_logged_in_' ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Posts the login form.
 *
 * @param string $user Username.
 * @param string $pass Password.
 * @param string $from Client IP.
 * @param array  $extra More form fields.
 * @return array
 */
function login( $user, $pass, $from, array $extra = array() ) {
	return http(
		'POST',
		'/wp-login.php',
		$from,
		array(
			'body' => $extra + array(
				'log'       => $user,
				'pwd'       => $pass,
				'wp-submit' => 'Log In',
			),
		)
	);
}

/**
 * Creates a throwaway user, deleted at the end.
 *
 * @param string $role Role.
 * @return \WP_User
 */
function user( $role = 'administrator' ) {
	$login                     = 'sst_' . strtolower( wp_generate_password( 8, false ) );
	$id                        = wp_insert_user(
		array(
			'user_login' => $login,
			'user_pass'  => 'Sst-' . wp_generate_password( 20, false ) . '-9x',
			'user_email' => $login . '@example.invalid',
			'role'       => $role,
		)
	);
	$GLOBALS['sst']['users'][] = $id;
	return get_userdata( $id );
}

/**
 * Sets a user's password and returns it.
 *
 * @param \WP_User $user User.
 * @return string
 */
function password( $user ) {
	$pass = 'Sst-' . wp_generate_password( 20, false ) . '-9x';
	wp_set_password( $pass, $user->ID );
	return $pass;
}

/**
 * Auth cookies for a user, to load admin pages.
 *
 * @param int $user_id User ID.
 * @return array
 */
function admin_cookies( $user_id ) {
	$expire = time() + HOUR_IN_SECONDS;
	$token  = \WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
}

/**
 * Runs one group of checks, reporting a crash as a failure instead of stopping.
 *
 * @param string   $title Group.
 * @param callable $checks    Checks.
 */
function group( $title, callable $checks ) {
	echo "\n{$title}\n";
	try {
		$checks();
	} catch ( \Throwable $e ) {
		check( $title . ' ran without errors', false, $e->getMessage() . ' at ' . basename( $e->getFile() ) . ':' . $e->getLine() );
	}
}
