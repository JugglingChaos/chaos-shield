<?php
/**
 * SIEM search, timelines and charts.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Read side of the SIEM: the search language, entity timelines, the activity
 * chart, and the response actions taken from an incident.
 */
final class Siem {

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'admin_post_sshield_incident', array( __CLASS__, 'handle' ) );
		add_action( 'admin_post_sshield_rules', array( __CLASS__, 'handle_rules' ) );
	}

	/**
	 * Parses a search such as: action:auth.* ip:203.0.113.7 user:admin sev:3 type:login site:shop since:24h "wrong password".
	 *
	 * Words without a field search the message, IP and subject.
	 *
	 * @param string $q Query.
	 * @return array Arguments for Events::query().
	 */
	public static function parse( $q ) {
		$args  = array();
		$words = array();
		preg_match_all( '/(\w+):("[^"]*"|\S+)|"([^"]*)"|(\S+)/u', (string) $q, $m, PREG_SET_ORDER );
		foreach ( $m as $part ) {
			if ( ! empty( $part[1] ) ) {
				$field = strtolower( $part[1] );
				$value = trim( $part[2], '"' );
				switch ( $field ) {
					case 'ip':
						$args['ip'] = $value;
						break;
					case 'user':
						$user = get_user_by( 'login', $value );
						if ( $user ) {
							$args['user_id'] = $user->ID;
						} else {
							$args['subject'] = $value;
						}
						break;
					case 'subject':
						$args['subject'] = $value;
						break;
					case 'site':
						// A network site by ID, path (shop) or address. Unknown sites match nothing.
						$site            = Network::site_id( $value );
						$args['blog_id'] = $site ? $site : -1;
						break;
					case 'action':
						$args['action'] = $value;
						break;
					case 'type':
						$args['type'] = sanitize_key( $value );
						break;
					case 'sev':
					case 'severity':
						$args['min_severity'] = max( 1, min( 3, (int) ltrim( $value, '>=' ) ) );
						break;
					case 'since':
					case 'last':
						$args['since'] = time() - self::duration( $value );
						break;
					default:
						$words[] = $part[0];
				}
			} elseif ( isset( $part[3] ) && '' !== $part[3] ) {
				$words[] = $part[3];
			} elseif ( ! empty( $part[4] ) ) {
				$words[] = $part[4];
			}
		}
		if ( $words ) {
			$args['search'] = implode( ' ', $words );
		}
		return $args;
	}

	/**
	 * Seconds in a duration such as 30m, 24h, 7d or 2w.
	 *
	 * @param string $value Duration.
	 * @return int
	 */
	public static function duration( $value ) {
		if ( ! preg_match( '/^(\d+)\s*([mhdw]?)$/i', trim( (string) $value ), $m ) ) {
			return DAY_IN_SECONDS;
		}
		$units = array(
			'm' => MINUTE_IN_SECONDS,
			'h' => HOUR_IN_SECONDS,
			'd' => DAY_IN_SECONDS,
			'w' => WEEK_IN_SECONDS,
			''  => HOUR_IN_SECONDS,
		);
		return (int) $m[1] * $units[ strtolower( $m[2] ) ];
	}

	/**
	 * Everything known about an IP or a user, newest first.
	 *
	 * @param string $kind ip or user.
	 * @param string $id   IP address or user ID.
	 * @return array Items: time, source (event, traffic, incident), severity, text, plus the row.
	 */
	public static function timeline( $kind, $id ) {
		$items = array();
		$args  = 'ip' === $kind ? array( 'ip' => $id ) : array( 'user_id' => (int) $id );
		foreach ( Events::query( $args + array( 'limit' => 300 ) ) as $e ) {
			if ( 'siem.incident' === $e['action'] ) {
				continue; // The incident itself is listed below.
			}
			$items[] = array(
				'time'     => (int) $e['time'],
				'source'   => 'event',
				'severity' => (int) $e['severity'],
				'text'     => $e['message'],
				'meta'     => $e['action'] ? $e['action'] : $e['type'],
				'ip'       => $e['ip'],
			);
		}
		if ( 'ip' === $kind && Settings::enabled( 'live_traffic' ) ) {
			global $wpdb;
			$table = Traffic::table();
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE ip = %s ORDER BY id DESC LIMIT 200", $id ), ARRAY_A );
			foreach ( (array) $rows as $r ) {
				$items[] = array(
					'time'     => (int) $r['created'],
					'source'   => 'traffic',
					'severity' => 'blocked' === $r['kind'] ? 2 : 1,
					'text'     => $r['method'] . ' ' . $r['uri'] . ' → ' . $r['status'],
					'meta'     => $r['kind'],
					'ip'       => $r['ip'],
				);
			}
		}
		foreach ( Incidents::query( $args + array( 'status' => 'all' ) ) as $i ) {
			$items[] = array(
				'time'     => $i['created'],
				'source'   => 'incident',
				'severity' => min( 3, $i['severity'] ),
				'text'     => $i['title'],
				'meta'     => $i['technique'],
				'ip'       => $i['ip'],
				'id'       => $i['id'],
			);
		}
		usort(
			$items,
			static function ( $a, $b ) {
				// Within one second, the incident comes before its evidence, and the log before raw traffic.
				$rank = array(
					'incident' => 0,
					'event'    => 1,
					'traffic'  => 2,
				);
				return array( $b['time'], $rank[ $a['source'] ] ) <=> array( $a['time'], $rank[ $b['source'] ] );
			}
		);
		return array_slice( $items, 0, 400 );
	}

	/**
	 * Events per hour for the last 24 hours, split by severity.
	 *
	 * @return array List of [ start, 1 => n, 2 => n, 3 => n ], oldest first.
	 */
	public static function hourly() {
		global $wpdb;
		$table = Events::table();
		$start = (int) ( floor( time() / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS ) - 23 * HOUR_IN_SECONDS;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$rows    = $wpdb->get_results( $wpdb->prepare( "SELECT FLOOR((created - %d) / 3600) AS h, severity, COUNT(*) AS n FROM {$table} WHERE created >= %d GROUP BY h, severity", $start, $start ), ARRAY_A );
		$buckets = array();
		for ( $h = 0; $h < 24; $h++ ) {
			$buckets[ $h ] = array(
				'start' => $start + $h * HOUR_IN_SECONDS,
				1       => 0,
				2       => 0,
				3       => 0,
			);
		}
		foreach ( (array) $rows as $row ) {
			$h   = (int) $row['h'];
			$sev = max( 1, min( 3, (int) $row['severity'] ) );
			if ( isset( $buckets[ $h ] ) ) {
				$buckets[ $h ][ $sev ] += (int) $row['n'];
			}
		}
		return array_values( $buckets );
	}

	/**
	 * Incident updates and response actions.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'sentinel-shield' ), 403 );
		}
		check_admin_referer( 'sshield_incident' );
		$id       = isset( $_POST['incident'] ) ? absint( $_POST['incident'] ) : 0;
		$op       = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$incident = Incidents::get( $id );
		if ( ! $incident ) {
			wp_safe_redirect( Admin::url( 'siem' ) );
			exit;
		}
		$notice = 'incident_saved';
		$done   = false;
		$ip     = $incident['ip'];
		$self   = Request::ip() === $ip;
		switch ( $op ) {
			case 'update':
				Incidents::update(
					$id,
					isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '',
					isset( $_POST['assignee'] ) ? (int) $_POST['assignee'] : -1,
					isset( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : ''
				);
				break;
			case 'ban':
				if ( $ip && ! $self && Bans::ban( $ip, 'incident #' . $id ) ) {
					/* translators: %s: IP address. */
					Incidents::note_action( $id, sprintf( __( 'Banned %s.', 'sentinel-shield' ), $ip ) );
					$done = true;
				}
				$notice = $done ? 'incident_acted' : 'incident_skipped';
				break;
			case 'block':
				if ( $ip && ! $self && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					Settings::block_ip( $ip );
					Events::add(
						'settings',
						/* translators: %s: IP address. */
						sprintf( __( '%s added to the block list.', 'sentinel-shield' ), $ip ),
						Request::ip(),
						array(
							'action'  => 'fw.blocklist',
							'subject' => $ip,
						)
					);
					/* translators: %s: IP address. */
					Incidents::note_action( $id, sprintf( __( 'Added %s to the block list.', 'sentinel-shield' ), $ip ) );
					$done = true;
				}
				$notice = $done ? 'incident_acted' : 'incident_skipped';
				break;
			case 'sessions':
			case 'reset':
				$user = $incident['user_id'] ? get_userdata( $incident['user_id'] ) : get_user_by( 'login', $incident['subject'] );
				if ( $user && get_current_user_id() !== $user->ID ) {
					if ( 'reset' === $op ) {
						Password_Policy::force( $user->ID );
						/* translators: %s: username. */
						Incidents::note_action( $id, sprintf( __( 'Forced a password reset for %s and ended their sessions.', 'sentinel-shield' ), $user->user_login ) );
					} else {
						\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
						Events::add(
							'user',
							/* translators: %s: username. */
							sprintf( __( 'All sessions of %s were ended from an incident.', 'sentinel-shield' ), $user->user_login ),
							Request::ip(),
							array(
								'user_id' => $user->ID,
								'action'  => 'user.sessions_ended',
							)
						);
						/* translators: %s: username. */
						Incidents::note_action( $id, sprintf( __( 'Ended all sessions of %s.', 'sentinel-shield' ), $user->user_login ) );
					}
				}
				$notice = 'incident_acted';
				break;
		}
		wp_safe_redirect(
			Admin::url(
				'siem',
				array(
					'incident'       => $id,
					'sshield_notice' => $notice,
				)
			)
		);
		exit;
	}

	/**
	 * Saves which rules are on and the alert threshold.
	 */
	public static function handle_rules() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'sentinel-shield' ), 403 );
		}
		check_admin_referer( 'sshield_rules' );
		$on  = isset( $_POST['rules'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['rules'] ) ) : array();
		$off = array_values( array_diff( array_keys( Detect::rules() ), $on ) );
		$min = isset( $_POST['alert_min'] ) ? (int) $_POST['alert_min'] : 3;
		Settings::save_siem( $off, $min );
		if ( $off ) {
			Events::add(
				'settings',
				/* translators: %s: rule keys. */
				sprintf( __( 'SIEM rules switched off: %s.', 'sentinel-shield' ), implode( ', ', $off ) ),
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => 'settings.weakened',
				)
			);
		}
		wp_safe_redirect( Admin::url( 'siem', array( 'sshield_notice' => 'saved' ) ) );
		exit;
	}
}
