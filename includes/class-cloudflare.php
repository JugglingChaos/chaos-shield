<?php
/**
 * Cloudflare: blocks at the edge for what a plugin cannot stop on the server.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Talks to the Cloudflare API with a token the owner creates.
 *
 * Bans and blocked IPs become Cloudflare IP Access rules, so those visitors
 * are refused before they reach the server. Under attack mode switches on
 * Cloudflare's own Under Attack mode at the same time. Also reads the zone's
 * SSL settings, and purges the cache. Cloudflare's free plan covers all of it.
 */
final class Cloudflare {

	const API    = 'https://api.cloudflare.com/client/v4';
	const TOKEN  = 'sshield_cf_token';
	const ZONE   = 'sshield_cf_zone';
	const RULES  = 'sshield_cf_rules';
	const STATUS = 'sshield_cf_status';
	const HOOK   = 'sshield_cf_sync';
	const NOTE   = 'Sentinel Shield';
	const BATCH  = 50;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'sync' ) );
		add_action( 'sshield_attack_mode', array( __CLASS__, 'attack' ) );
		add_action( 'sshield_ip_banned', array( __CLASS__, 'soon' ) );
		add_action( 'sshield_ip_released', array( __CLASS__, 'soon' ) );
		add_action( 'init', array( __CLASS__, 'schedule' ) );
		// Block list changes reach Cloudflare too.
		add_action( 'update_option_' . Settings::OPTION, array( __CLASS__, 'soon' ) );
		add_action( 'update_site_option_' . Settings::OPTION, array( __CLASS__, 'soon' ) );
	}

	/**
	 * Whether a token and zone are saved.
	 *
	 * @return bool
	 */
	public static function connected() {
		$zone = self::zone();
		return ! empty( $zone['id'] ) && '' !== self::token();
	}

	/**
	 * The saved zone: id, name, plan, status, can (permissions found).
	 *
	 * @return array
	 */
	public static function zone() {
		$zone = Network::get_option( self::ZONE, array() );
		return is_array( $zone ) ? $zone : array();
	}

	/**
	 * The last sync and settings read: synced, rules, error, ssl, always_https, security_level.
	 *
	 * @return array
	 */
	public static function status() {
		$status = Network::get_option( self::STATUS, array() );
		return wp_parse_args(
			is_array( $status ) ? $status : array(),
			array(
				'synced'         => 0,
				'error'          => '',
				'ssl'            => '',
				'always_https'   => '',
				'security_level' => '',
				'previous_level' => '',
				'read'           => 0,
			)
		);
	}

	/**
	 * Saves part of the status.
	 *
	 * @param array $changes Changes.
	 */
	private static function set_status( array $changes ) {
		Network::update_option( self::STATUS, array_merge( self::status(), $changes ), false );
	}

	/**
	 * The API token.
	 *
	 * @return string
	 */
	private static function token() {
		$sealed = Network::get_option( self::TOKEN );
		return $sealed ? (string) Totp::open( $sealed ) : '';
	}

	/**
	 * Calls the API.
	 *
	 * @param string $method GET, POST, PATCH or DELETE.
	 * @param string $path   Path after /client/v4.
	 * @param array  $body   JSON body.
	 * @param string $token  Token, when not the saved one.
	 * @return array|\WP_Error The result, or why it failed.
	 */
	public static function call( $method, $path, array $body = array(), $token = '' ) {
		$token = '' !== $token ? $token : self::token();
		$res   = wp_remote_request(
			self::API . $path,
			array(
				'method'  => $method,
				'timeout' => 15,
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'body'    => $body ? wp_json_encode( $body ) : null,
			)
		);
		if ( is_wp_error( $res ) ) {
			/* translators: %s: error. */
			return new \WP_Error( 'sshield_unreachable', sprintf( __( 'Cloudflare could not be reached: %s', 'sentinel-shield' ), $res->get_error_message() ) );
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $data ) || empty( $data['success'] ) ) {
			$code    = (int) wp_remote_retrieve_response_code( $res );
			$message = isset( $data['errors'][0]['message'] ) ? (string) $data['errors'][0]['message'] : 'HTTP ' . $code;
			return new \WP_Error( 403 === $code || 401 === $code ? 'sshield_cf_denied' : 'sshield_cf_error', sanitize_text_field( $message ), array( 'code' => $code ) );
		}
		return $data;
	}

	/**
	 * Checks a token, finds this site's zone and saves both.
	 *
	 * @param string $token API token.
	 * @param bool   $force Save even when Cloudflare could not be reached.
	 * @return string|\WP_Error Message, or why not.
	 */
	public static function connect( $token, $force = false ) {
		$token = trim( $token );
		if ( '' === $token && self::token() ) {
			$token = self::token();
		}
		if ( ! preg_match( '/^[A-Za-z0-9_-]{30,80}$/', $token ) ) {
			return new \WP_Error( 'sshield_connect', __( 'That does not look like a Cloudflare API token. Copy the token itself, not the Global API Key.', 'sentinel-shield' ) );
		}
		$verify = self::call( 'GET', '/user/tokens/verify', array(), $token );
		if ( is_wp_error( $verify ) ) {
			if ( 'sshield_unreachable' === $verify->get_error_code() && ! $force ) {
				return $verify;
			}
			if ( 'sshield_unreachable' !== $verify->get_error_code() ) {
				return new \WP_Error( 'sshield_connect', __( 'Cloudflare does not accept this token. Copy it again, or create a new one.', 'sentinel-shield' ) );
			}
		} elseif ( isset( $verify['result']['status'] ) && 'active' !== $verify['result']['status'] ) {
			return new \WP_Error( 'sshield_connect', __( 'This token is not active. Check its start and end dates in Cloudflare.', 'sentinel-shield' ) );
		}
		$zone = self::find_zone( $token );
		if ( is_wp_error( $zone ) ) {
			return $zone;
		}
		$zone['can'] = self::permissions( $zone['id'], $token );
		Network::update_option( self::TOKEN, Totp::seal( $token ), false );
		Network::update_option( self::ZONE, $zone, false );
		Network::delete_option( self::STATUS );
		self::read_settings();
		if ( Settings::get( 'cf_sync_bans' ) && $zone['can']['firewall'] ) {
			Network::schedule_single( time() + 5, self::HOOK );
		}
		$missing = array_keys( array_filter( $zone['can'], array( __CLASS__, 'is_false' ) ) );
		if ( $missing ) {
			return sprintf(
				/* translators: 1: zone name, 2: missing permissions. */
				__( 'Connected to %1$s. The token is missing some permissions (%2$s), so those parts stay off. You can edit the token in Cloudflare and connect again.', 'sentinel-shield' ),
				$zone['name'],
				implode( ', ', array_map( array( __CLASS__, 'permission_name' ), $missing ) )
			);
		}
		/* translators: %s: zone name. */
		return sprintf( __( 'Connected to %s. Bans now reach Cloudflare, and under attack mode switches on Cloudflare\'s as well.', 'sentinel-shield' ), $zone['name'] );
	}

	/**
	 * For array_filter.
	 *
	 * @param mixed $value Value.
	 * @return bool
	 */
	public static function is_false( $value ) {
		return ! $value;
	}

	/**
	 * A permission's name as Cloudflare shows it.
	 *
	 * @param string $key settings, firewall or purge.
	 * @return string
	 */
	public static function permission_name( $key ) {
		$names = array(
			'settings' => 'Zone Settings: Edit',
			'firewall' => 'Firewall Services: Edit',
			'purge'    => 'Cache Purge: Purge',
		);
		return isset( $names[ $key ] ) ? $names[ $key ] : $key;
	}

	/**
	 * Finds the zone for this site's domain, trying the host and its parents.
	 *
	 * @param string $token Token.
	 * @return array|\WP_Error id, name, plan, status.
	 */
	private static function find_zone( $token ) {
		$host  = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$parts = explode( '.', $host );
		$names = array( $host );
		// Then each parent down to the registrable domain.
		for ( $i = 1, $n = count( $parts ); $i <= $n - 2; $i++ ) {
			$names[] = implode( '.', array_slice( $parts, $i ) );
		}
		foreach ( $names as $name ) {
			$zones = self::call( 'GET', '/zones?name=' . rawurlencode( $name ) . '&per_page=1', array(), $token );
			if ( is_wp_error( $zones ) ) {
				return 'sshield_unreachable' === $zones->get_error_code() ? $zones : new \WP_Error( 'sshield_connect', __( 'The token cannot list zones. Give it the permission Zone: Read for this site\'s zone.', 'sentinel-shield' ) );
			}
			if ( ! empty( $zones['result'][0]['id'] ) ) {
				$z = $zones['result'][0];
				return array(
					'id'     => sanitize_key( $z['id'] ),
					'name'   => sanitize_text_field( $z['name'] ),
					'plan'   => isset( $z['plan']['name'] ) ? sanitize_text_field( $z['plan']['name'] ) : '',
					'status' => isset( $z['status'] ) ? sanitize_key( $z['status'] ) : '',
				);
			}
		}
		return new \WP_Error(
			'sshield_connect',
			/* translators: %s: host name. */
			sprintf( __( 'This token cannot see a Cloudflare zone for %s. Add the site to Cloudflare first, or include its zone under Zone Resources when you create the token.', 'sentinel-shield' ), $host )
		);
	}

	/**
	 * What the token may do, found by reading.
	 *
	 * @param string $zone  Zone ID.
	 * @param string $token Token.
	 * @return array settings, firewall, purge.
	 */
	private static function permissions( $zone, $token ) {
		$settings = self::call( 'GET', '/zones/' . $zone . '/settings/security_level', array(), $token );
		$firewall = self::call( 'GET', '/zones/' . $zone . '/firewall/access_rules/rules?per_page=1', array(), $token );
		return array(
			'settings' => ! is_wp_error( $settings ),
			'firewall' => ! is_wp_error( $firewall ),
			// Purging cannot be tried without purging; assume the template's permissions.
			'purge'    => true,
		);
	}

	/**
	 * Removes the token, and the rules this plugin made when it can.
	 *
	 * @param bool $clean Also delete the IP Access rules from Cloudflare.
	 */
	public static function disconnect( $clean = true ) {
		if ( $clean ) {
			self::release_edge();
		}
		foreach ( array( self::TOKEN, self::ZONE, self::RULES, self::STATUS ) as $option ) {
			Network::delete_option( $option );
		}
		Network::clear_scheduled( self::HOOK );
	}

	/**
	 * Takes this plugin's IP Access rules off Cloudflare and puts the security level back.
	 */
	public static function release_edge() {
		if ( ! self::connected() ) {
			return;
		}
		$zone  = self::zone();
		$rules = self::rules();
		foreach ( array_slice( $rules, 0, 200, true ) as $ip => $rule ) {
			$res = self::call( 'DELETE', '/zones/' . $zone['id'] . '/firewall/access_rules/rules/' . rawurlencode( $rule['id'] ) );
			if ( ! is_wp_error( $res ) ) {
				unset( $rules[ $ip ] );
			}
		}
		Network::update_option( self::RULES, $rules, false );
		$status = self::status();
		if ( $status['previous_level'] && 'under_attack' === $status['security_level'] ) {
			self::call( 'PATCH', '/zones/' . $zone['id'] . '/settings/security_level', array( 'value' => $status['previous_level'] ) );
			self::set_status(
				array(
					'previous_level' => '',
					'security_level' => $status['previous_level'],
				)
			);
		}
	}

	/**
	 * Rules this plugin made: IP => id, until.
	 *
	 * @return array
	 */
	public static function rules() {
		$rules = Network::get_option( self::RULES, array() );
		return is_array( $rules ) ? $rules : array();
	}

	/**
	 * Keeps an hourly sync scheduled while connected, so expired bans leave Cloudflare too.
	 */
	public static function schedule() {
		$want = self::connected() && Settings::get( 'cf_sync_bans' );
		$next = Network::next_scheduled( self::HOOK );
		if ( $want && ! $next ) {
			Network::schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::HOOK );
		} elseif ( ! $want && $next && ! self::rules() ) {
			Network::clear_scheduled( self::HOOK );
		}
	}

	/**
	 * Syncs shortly after a ban changes, once for a burst of changes.
	 */
	public static function soon() {
		if ( ! self::connected() || ! Settings::get( 'cf_sync_bans' ) ) {
			return;
		}
		if ( ! Network::next_scheduled( self::HOOK, array( 'soon' ) ) ) {
			Network::schedule_single( time() + 30, self::HOOK, array( 'soon' ) );
		}
	}

	/**
	 * The IPs that should be blocked at Cloudflare: active bans and single blocked IPs.
	 *
	 * @return array IP or range => until (0 for the block list).
	 */
	public static function wanted() {
		$out = array();
		foreach ( Bans::bans() as $ip => $ban ) {
			$out[ $ip ] = (int) $ban['until'];
		}
		foreach ( (array) Settings::get( 'ip_blocklist' ) as $entry ) {
			$entry = trim( (string) $entry );
			// Cloudflare takes single IPs, and IPv4 /16 and /24 or IPv6 /32, /48 and /64 ranges.
			if ( filter_var( $entry, FILTER_VALIDATE_IP ) || preg_match( '#^[0-9.]+/(16|24)$#', $entry ) || preg_match( '#^[0-9a-f:]+/(32|48|64)$#i', $entry ) ) {
				$out[ $entry ] = 0;
			}
		}
		foreach ( (array) Settings::get( 'ip_allowlist' ) as $entry ) {
			unset( $out[ trim( (string) $entry ) ] );
		}
		return $out;
	}

	/**
	 * Brings Cloudflare's IP Access rules in line with the bans and block list.
	 *
	 * @return array|\WP_Error added, removed.
	 */
	public static function sync() {
		if ( ! self::connected() ) {
			return new \WP_Error( 'sshield_cf_none', __( 'Cloudflare is not connected.', 'sentinel-shield' ) );
		}
		$zone   = self::zone();
		$rules  = self::rules();
		$want   = Settings::get( 'cf_sync_bans' ) ? self::wanted() : array();
		$added  = 0;
		$gone   = 0;
		$errors = array();
		foreach ( $rules as $ip => $rule ) {
			if ( isset( $want[ $ip ] ) || $gone >= self::BATCH ) {
				continue;
			}
			$res = self::call( 'DELETE', '/zones/' . $zone['id'] . '/firewall/access_rules/rules/' . rawurlencode( $rule['id'] ) );
			$why = is_wp_error( $res ) ? (array) $res->get_error_data() : array();
			if ( is_wp_error( $res ) && ( ! isset( $why['code'] ) || 404 !== (int) $why['code'] ) ) {
				$errors[] = $res->get_error_message();
				continue;
			}
			unset( $rules[ $ip ] );
			++$gone;
		}
		foreach ( $want as $ip => $until ) {
			if ( isset( $rules[ $ip ] ) || $added >= self::BATCH ) {
				continue;
			}
			$target = false !== strpos( $ip, '/' ) ? 'ip_range' : ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 'ip6' : 'ip' );
			$res    = self::call(
				'POST',
				'/zones/' . $zone['id'] . '/firewall/access_rules/rules',
				array(
					'mode'          => 'block',
					'configuration' => array(
						'target' => $target,
						'value'  => $ip,
					),
					'notes'         => self::NOTE . ( $until ? ': banned until ' . gmdate( 'Y-m-d H:i', $until ) . ' UTC' : ': block list' ),
				)
			);
			if ( is_wp_error( $res ) ) {
				$errors[] = $res->get_error_message();
				if ( 'sshield_cf_denied' === $res->get_error_code() || 'sshield_unreachable' === $res->get_error_code() ) {
					break;
				}
				continue;
			}
			$rules[ $ip ] = array(
				'id'    => sanitize_key( $res['result']['id'] ),
				'until' => $until,
			);
			++$added;
		}
		Network::update_option( self::RULES, $rules, false );
		self::set_status(
			array(
				'synced' => time(),
				'error'  => $errors ? implode( '; ', array_unique( array_slice( $errors, 0, 3 ) ) ) : '',
			)
		);
		if ( $added + $gone >= self::BATCH && ! Network::next_scheduled( self::HOOK, array( 'more' ) ) ) {
			Network::schedule_single( time() + 60, self::HOOK, array( 'more' ) );
		}
		return array(
			'added'   => $added,
			'removed' => $gone,
		);
	}

	/**
	 * Reads the zone's SSL, Always Use HTTPS and security level.
	 *
	 * @return array Status.
	 */
	public static function read_settings() {
		$zone = self::zone();
		if ( empty( $zone['id'] ) ) {
			return self::status();
		}
		$values = array( 'read' => time() );
		foreach ( array(
			'ssl'            => 'ssl',
			'always_https'   => 'always_use_https',
			'security_level' => 'security_level',
		) as $key => $setting ) {
			$res            = self::call( 'GET', '/zones/' . $zone['id'] . '/settings/' . $setting );
			$values[ $key ] = is_wp_error( $res ) || ! isset( $res['result']['value'] ) ? '' : sanitize_key( (string) $res['result']['value'] );
		}
		self::set_status( $values );
		return self::status();
	}

	/**
	 * Changes a zone setting.
	 *
	 * @param string $setting always_use_https or security_level.
	 * @param string $value   Value.
	 * @return true|\WP_Error
	 */
	public static function set( $setting, $value ) {
		$zone = self::zone();
		$res  = self::call( 'PATCH', '/zones/' . $zone['id'] . '/settings/' . $setting, array( 'value' => $value ) );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		self::read_settings();
		return true;
	}

	/**
	 * Switches Cloudflare's Under Attack mode with the plugin's, and back to what it was.
	 *
	 * @param bool $on Whether the plugin's mode is on now.
	 */
	public static function attack( $on ) {
		if ( ! self::connected() || ! Settings::get( 'cf_attack_sync' ) || empty( self::zone()['can']['settings'] ) ) {
			return;
		}
		$status = self::read_settings();
		if ( $on && 'under_attack' !== $status['security_level'] ) {
			self::set_status( array( 'previous_level' => $status['security_level'] ? $status['security_level'] : 'medium' ) );
			$res = self::set( 'security_level', 'under_attack' );
		} elseif ( ! $on && 'under_attack' === $status['security_level'] && $status['previous_level'] ) {
			$res = self::set( 'security_level', $status['previous_level'] );
			self::set_status( array( 'previous_level' => '' ) );
		} else {
			return;
		}
		Events::add(
			'system',
			is_wp_error( $res )
				/* translators: %s: error. */
				? sprintf( __( 'Could not change Cloudflare\'s security level: %s', 'sentinel-shield' ), $res->get_error_message() )
				: ( $on ? __( 'Switched on Cloudflare\'s Under Attack mode.', 'sentinel-shield' ) : __( 'Switched Cloudflare\'s security level back.', 'sentinel-shield' ) ),
			'',
			array(
				'severity' => is_wp_error( $res ) ? Events::NOTICE : Events::INFO,
				'action'   => 'cloudflare.level',
			)
		);
	}

	/**
	 * Clears Cloudflare's cache for the zone.
	 *
	 * @return true|\WP_Error
	 */
	public static function purge() {
		$zone = self::zone();
		$res  = self::call( 'POST', '/zones/' . $zone['id'] . '/purge_cache', array( 'purge_everything' => true ) );
		return is_wp_error( $res ) ? $res : true;
	}

	/**
	 * Whether this request came through Cloudflare.
	 *
	 * @return bool
	 */
	public static function in_front() {
		return '' !== Request::server( 'HTTP_CF_RAY' ) || '' !== Request::server( 'HTTP_CF_CONNECTING_IP' );
	}
}
