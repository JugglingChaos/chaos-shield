<?php
/**
 * Hub: watch the security status of other sites running Chaos Shield.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Stores connected sites and fetches their status through the API.
 */
final class Hub {

	const SITES_OPTION = 'cshield_hub_sites';
	const CACHE_TTL    = 600;

	/**
	 * Connected sites.
	 *
	 * @return array ID => [ url, name, key (sealed), added ].
	 */
	public static function sites() {
		$sites = Network::get_option( self::SITES_OPTION, array() );
		return is_array( $sites ) ? $sites : array();
	}

	/**
	 * Connects a site after checking that its key works.
	 *
	 * @param string $url  Site address.
	 * @param string $key  Hub key from that site.
	 * @param string $name Optional label.
	 * @return array|\WP_Error The status on success.
	 */
	public static function add( $url, $key, $name = '' ) {
		$url = esc_url_raw( trim( $url ) );
		$key = trim( $key );
		if ( ! $url || ! in_array( wp_parse_url( $url, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) ) {
			return new \WP_Error( 'cshield_hub_url', __( 'Enter the full site address, starting with https://.', 'chaos-shield' ) );
		}
		if ( ! self::secure_url( $url ) ) {
			return new \WP_Error( 'cshield_hub_url', __( 'Connect sites over https:// so the hub key cannot be read on the way.', 'chaos-shield' ) );
		}
		if ( 0 !== strpos( $key, 'ssk_' ) ) {
			return new \WP_Error( 'cshield_hub_key', __( 'That does not look like a Chaos Shield hub key. Keys start with ssk_.', 'chaos-shield' ) );
		}
		$url    = trailingslashit( $url );
		$status = self::request( $url, $key );
		if ( is_wp_error( $status ) ) {
			return $status;
		}
		$id           = md5( $url );
		$sites        = self::sites();
		$sites[ $id ] = array(
			'url'   => $url,
			'name'  => sanitize_text_field( '' !== $name ? $name : $status['site']['name'] ),
			'key'   => Totp::seal( $key ),
			'added' => time(),
		);
		Network::update_option( self::SITES_OPTION, $sites, false );
		Network::set_transient( 'cshield_hub_' . $id, $status, self::CACHE_TTL );
		return $status;
	}

	/**
	 * Disconnects a site.
	 *
	 * @param string $id Site ID.
	 */
	public static function remove( $id ) {
		$sites = self::sites();
		unset( $sites[ $id ] );
		Network::update_option( self::SITES_OPTION, $sites, false );
		Network::delete_transient( 'cshield_hub_' . $id );
	}

	/**
	 * Status of a connected site, cached for ten minutes.
	 *
	 * @param string $id    Site ID.
	 * @param bool   $fresh Skip the cache.
	 * @return array|\WP_Error
	 */
	public static function status( $id, $fresh = false ) {
		$sites = self::sites();
		if ( ! isset( $sites[ $id ] ) ) {
			return new \WP_Error( 'cshield_hub_missing', __( 'Unknown site.', 'chaos-shield' ) );
		}
		$cache = 'cshield_hub_' . $id;
		if ( ! $fresh ) {
			$cached = Network::get_transient( $cache );
			if ( false !== $cached ) {
				return is_array( $cached ) ? $cached : new \WP_Error( 'cshield_hub_down', (string) $cached );
			}
		}
		$key = Totp::open( $sites[ $id ]['key'] );
		if ( false === $key ) {
			return new \WP_Error( 'cshield_hub_key', __( 'The stored key can no longer be read. Remove the site and add it again.', 'chaos-shield' ) );
		}
		$status = self::request( $sites[ $id ]['url'], $key );
		// Errors are cached too, as a string, so a dead site does not slow every page load.
		Network::set_transient( $cache, is_wp_error( $status ) ? $status->get_error_message() : $status, is_wp_error( $status ) ? 2 * MINUTE_IN_SECONDS : self::CACHE_TTL );
		return $status;
	}

	/**
	 * Calls a site's status route, with or without pretty permalinks.
	 *
	 * @param string $url Site address with trailing slash.
	 * @param string $key Hub key.
	 * @return array|\WP_Error
	 */
	private static function request( $url, $key ) {
		$route   = '/' . Api::NS . '/status';
		$targets = array(
			$url . 'wp-json' . $route,
			add_query_arg( 'rest_route', $route, $url ),
		);
		$last    = null;
		$legacy  = false;
		$i       = 0;
		$total   = count( $targets );
		while ( $i < $total ) {
			$target = $targets[ $i ];
			// Sign with the key's hash: the site stores only that, and the key never travels.
			$time     = time();
			$nonce    = wp_generate_password( 32, false );
			$headers  = $legacy
				? array( Api::KEY_HEADER => $key )
				: array(
					Api::TIME_HDR  => (string) $time,
					Api::NONCE_HDR => $nonce,
					Api::SIG_HDR   => Api::sign( hash( 'sha256', $key ), $time, $nonce, 'GET', $route, '' ),
				);
			$response = wp_remote_get(
				$target,
				array(
					'timeout'     => 10,
					'redirection' => 0,
					'headers'     => $headers + array( 'Accept' => 'application/json' ),
					'user-agent'  => 'ChaosShieldHub/' . CSHIELD_VERSION . '; ' . home_url( '/' ),
				)
			);
			if ( is_wp_error( $response ) ) {
				/* translators: %s: error message. */
				return new \WP_Error( 'cshield_hub_down', sprintf( __( 'Could not reach the site: %s', 'chaos-shield' ), $response->get_error_message() ) );
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( 200 === $code && is_array( $body ) && isset( $body['score'] ) ) {
				return self::clean_status( $body );
			}
			if ( 401 === $code && ! $legacy && self::secure_url( $url ) ) {
				// Sites before 1.6.2 only know the plain key header; send it only over https.
				$legacy = true;
				continue; // Same address again, the old way.
			}
			if ( in_array( $code, array( 401, 403 ), true ) ) {
				return new \WP_Error( 'cshield_hub_denied', __( 'The site refused the key. Check that you copied the current hub key from that site.', 'chaos-shield' ) );
			}
			if ( 429 === $code ) {
				return new \WP_Error( 'cshield_hub_locked', __( 'The site has locked this server out after failed attempts. Release the lockout there, or wait.', 'chaos-shield' ) );
			}
			$last = $code;
			++$i;
		}
		/* translators: %d: HTTP status code. */
		return new \WP_Error( 'cshield_hub_missing', sprintf( __( 'Chaos Shield did not answer on that site (HTTP %d). Make sure version 1.0 or later is active there.', 'chaos-shield' ), (int) $last ) );
	}

	/**
	 * Whether a site address is safe to send hub credentials to: https, or a local test address.
	 *
	 * @param string $url Site address.
	 * @return bool
	 */
	public static function secure_url( $url ) {
		if ( 'https' === wp_parse_url( $url, PHP_URL_SCHEME ) ) {
			return true;
		}
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$host = trim( $host, '[]' );
		return in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true ) || (bool) preg_match( '/\.(localhost|test)$/', $host ) || ( filter_var( $host, FILTER_VALIDATE_IP ) && ! filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) );
	}

	/**
	 * Forces a connected site's status into the shape the hub screen expects.
	 *
	 * Another site can be compromised, so nothing it sends may break this one.
	 *
	 * @param array $s Decoded status.
	 * @return array
	 */
	private static function clean_status( array $s ) {
		$str         = static function ( $v ) {
			return is_scalar( $v ) ? sanitize_text_field( (string) $v ) : '';
		};
		$site        = isset( $s['site'] ) && is_array( $s['site'] ) ? $s['site'] : array();
		$scan        = isset( $s['scan'] ) && is_array( $s['scan'] ) ? $s['scan'] : array();
		$out         = array(
			'site'      => array(
				'name' => $str( isset( $site['name'] ) ? $site['name'] : '' ),
				'url'  => esc_url_raw( isset( $site['url'] ) && is_string( $site['url'] ) ? $site['url'] : '' ),
			),
			'plugin'    => $str( isset( $s['plugin'] ) ? $s['plugin'] : '' ),
			'wordpress' => $str( isset( $s['wordpress'] ) ? $s['wordpress'] : '' ),
			'php'       => $str( isset( $s['php'] ) ? $s['php'] : '' ),
			'score'     => max( 0, min( 100, (int) $s['score'] ) ),
			'issues'    => array(),
			'modules'   => array(),
			'stats'     => array(),
			'lockouts'  => isset( $s['lockouts'] ) ? absint( $s['lockouts'] ) : 0,
			'bans'      => isset( $s['bans'] ) ? absint( $s['bans'] ) : 0,
			'vulns'     => isset( $s['vulns'] ) ? absint( $s['vulns'] ) : 0,
			'scan'      => array(
				'running'  => ! empty( $scan['running'] ),
				'finished' => isset( $scan['finished'] ) ? absint( $scan['finished'] ) : null,
				'files'    => isset( $scan['files'] ) ? absint( $scan['files'] ) : 0,
				'findings' => isset( $scan['findings'] ) ? absint( $scan['findings'] ) : 0,
				'high'     => isset( $scan['high'] ) ? absint( $scan['high'] ) : 0,
			),
			'actions'   => ! empty( $s['actions'] ),
			'generated' => isset( $s['generated'] ) ? absint( $s['generated'] ) : 0,
		);
		$out['band'] = Admin::band( $out['score'] );
		foreach ( isset( $s['issues'] ) && is_array( $s['issues'] ) ? array_slice( $s['issues'], 0, 50 ) : array() as $issue ) {
			if ( is_array( $issue ) ) {
				$out['issues'][] = array(
					'id'     => sanitize_key( isset( $issue['id'] ) && is_string( $issue['id'] ) ? $issue['id'] : '' ),
					'label'  => $str( isset( $issue['label'] ) ? $issue['label'] : '' ),
					'status' => sanitize_key( isset( $issue['status'] ) && is_string( $issue['status'] ) ? $issue['status'] : '' ),
					'detail' => $str( isset( $issue['detail'] ) ? $issue['detail'] : '' ),
				);
			}
		}
		foreach ( isset( $s['modules'] ) && is_array( $s['modules'] ) ? $s['modules'] : array() as $k => $v ) {
			$out['modules'][ sanitize_key( (string) $k ) ] = (bool) $v;
		}
		foreach ( isset( $s['stats'] ) && is_array( $s['stats'] ) ? $s['stats'] : array() as $k => $v ) {
			$out['stats'][ sanitize_key( (string) $k ) ] = is_numeric( $v ) ? (int) $v : 0;
		}
		if ( isset( $s['incidents'] ) && is_array( $s['incidents'] ) ) {
			$inc              = $s['incidents'];
			$by               = isset( $inc['by_severity'] ) && is_array( $inc['by_severity'] ) ? $inc['by_severity'] : array();
			$out['incidents'] = array(
				'open'        => isset( $inc['open'] ) ? absint( $inc['open'] ) : 0,
				'by_severity' => array(),
				'latest'      => array(),
			);
			foreach ( array( 1, 2, 3, 4 ) as $sev ) {
				$out['incidents']['by_severity'][ $sev ] = isset( $by[ $sev ] ) ? absint( $by[ $sev ] ) : 0;
			}
			foreach ( isset( $inc['latest'] ) && is_array( $inc['latest'] ) ? array_slice( $inc['latest'], 0, 10 ) : array() as $i ) {
				if ( is_array( $i ) ) {
					$out['incidents']['latest'][] = array(
						'id'        => isset( $i['id'] ) ? absint( $i['id'] ) : 0,
						'title'     => $str( isset( $i['title'] ) ? $i['title'] : '' ),
						'severity'  => isset( $i['severity'] ) ? max( 1, min( 4, (int) $i['severity'] ) ) : 1,
						'status'    => sanitize_key( isset( $i['status'] ) && is_string( $i['status'] ) ? $i['status'] : '' ),
						'updated'   => isset( $i['updated'] ) ? absint( $i['updated'] ) : 0,
						'technique' => $str( isset( $i['technique'] ) ? $i['technique'] : '' ),
					);
				}
			}
		}
		return $out;
	}

	/**
	 * Hub actions and their labels.
	 *
	 * @return array Action => label.
	 */
	public static function actions() {
		return array(
			'scan'     => __( 'Start a scan', 'chaos-shield' ),
			'release'  => __( 'Release all lockouts and bans', 'chaos-shield' ),
			'settings' => __( 'Push this site\'s hardening settings', 'chaos-shield' ),
		);
	}

	/**
	 * Whether a connected site accepts actions, going by its last status.
	 *
	 * @param string $id Site ID.
	 * @return bool
	 */
	public static function can_act( $id ) {
		$status = self::status( $id );
		return is_array( $status ) && ! empty( $status['actions'] );
	}

	/**
	 * Runs an action on a connected site.
	 *
	 * @param string $id     Site ID.
	 * @param string $action scan, release or settings.
	 * @return array|\WP_Error Response body.
	 */
	public static function act( $id, $action ) {
		$sites = self::sites();
		if ( ! isset( $sites[ $id ] ) || ! isset( self::actions()[ $action ] ) ) {
			return new \WP_Error( 'cshield_hub_missing', __( 'Unknown site or action.', 'chaos-shield' ) );
		}
		$key = Totp::open( $sites[ $id ]['key'] );
		if ( false === $key ) {
			return new \WP_Error( 'cshield_hub_key', __( 'The stored key can no longer be read. Remove the site and add it again.', 'chaos-shield' ) );
		}
		$body = array();
		if ( 'settings' === $action ) {
			$all              = Settings::all();
			$body['settings'] = array_intersect_key( $all, array_flip( Api::pushable() ) );
		}
		$body  = wp_json_encode( (object) $body );
		$route = '/' . Api::NS . '/hub/' . $action;
		$url   = $sites[ $id ]['url'];

		$targets = array( $url . 'wp-json' . $route, add_query_arg( 'rest_route', $route, $url ) );
		$result  = null;
		foreach ( $targets as $target ) {
			$time     = time();
			$nonce    = wp_generate_password( 32, false );
			$response = wp_remote_post(
				$target,
				array(
					'timeout'     => 15,
					'redirection' => 0,
					'headers'     => array(
						'Content-Type' => 'application/json',
						'Accept'       => 'application/json',
						Api::TIME_HDR  => (string) $time,
						Api::NONCE_HDR => $nonce,
						Api::SIG_HDR   => Api::sign( $key, $time, $nonce, 'POST', $route, $body ),
					),
					'body'        => $body,
					'user-agent'  => 'ChaosShieldHub/' . CSHIELD_VERSION . '; ' . home_url( '/' ),
				)
			);
			if ( is_wp_error( $response ) ) {
				/* translators: %s: error message. */
				$result = new \WP_Error( 'cshield_hub_down', sprintf( __( 'Could not reach the site: %s', 'chaos-shield' ), $response->get_error_message() ) );
				break;
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( 200 === $code && is_array( $data ) ) {
				$result = $data;
				break;
			}
			if ( 404 === $code || ( 200 === $code && ! is_array( $data ) ) ) {
				// Without pretty permalinks /wp-json/ serves the home page; try the next form.
				$result = new \WP_Error( 'cshield_hub_old', __( 'That site runs a Chaos Shield version without hub actions. Update it to 1.4 or later.', 'chaos-shield' ) );
				continue;
			}
			$message = is_array( $data ) && isset( $data['message'] ) ? sanitize_text_field( $data['message'] ) : '';
			/* translators: %d: HTTP status code. */
			$result = new \WP_Error( 'cshield_hub_refused', $message ? $message : sprintf( __( 'The site refused the action (HTTP %d).', 'chaos-shield' ), $code ) );
			break;
		}
		Network::delete_transient( 'cshield_hub_' . $id );

		$labels = self::actions();
		Events::add(
			'settings',
			is_wp_error( $result )
				/* translators: 1: action, 2: site name, 3: error. */
				? sprintf( __( 'Hub action "%1$s" failed on %2$s: %3$s', 'chaos-shield' ), $labels[ $action ], $sites[ $id ]['name'], $result->get_error_message() )
				/* translators: 1: action, 2: site name. */
				: sprintf( __( 'Hub action "%1$s" done on %2$s.', 'chaos-shield' ), $labels[ $action ], $sites[ $id ]['name'] ),
			Request::ip(),
			array( 'severity' => is_wp_error( $result ) ? Events::NOTICE : Events::INFO )
		);
		return $result;
	}

	/**
	 * Runs an action on every site that accepts actions.
	 *
	 * @param string $action Action.
	 * @return array ok => count, failed => [ name => message ], skipped => count.
	 */
	public static function act_all( $action ) {
		$out = array(
			'ok'      => 0,
			'failed'  => array(),
			'skipped' => 0,
		);
		foreach ( self::sites() as $id => $site ) {
			if ( ! self::can_act( $id ) ) {
				++$out['skipped'];
				continue;
			}
			$result = self::act( $id, $action );
			if ( is_wp_error( $result ) ) {
				$out['failed'][ $site['name'] ] = $result->get_error_message();
			} else {
				++$out['ok'];
			}
		}
		return $out;
	}
}
