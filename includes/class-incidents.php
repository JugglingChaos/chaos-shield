<?php
/**
 * SIEM incidents.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Stores incidents raised by detection rules, with status, assignee and notes.
 *
 * Repeat hits of one rule on the same IP or user fold into the open incident
 * instead of opening new ones, so an attack reads as one case, not a flood.
 */
final class Incidents {

	const DB_VERSION        = '1';
	const DB_VERSION_OPTION = 'sshield_incidents_db';
	const MAX_EVENTS        = 200;
	const MERGE_WINDOW      = DAY_IN_SECONDS;

	const LOW      = 1;
	const MEDIUM   = 2;
	const HIGH     = 3;
	const CRITICAL = 4;

	/**
	 * Full table name.
	 *
	 * @return string
	 */
	public static function table() {
		return Network::table( 'sshield_incidents' );
	}

	/**
	 * Creates the table when needed.
	 */
	public static function maybe_install() {
		if ( Network::get_option( self::DB_VERSION_OPTION ) === self::DB_VERSION ) {
			return;
		}
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created int(10) unsigned NOT NULL,
				updated int(10) unsigned NOT NULL,
				rule varchar(48) NOT NULL DEFAULT '',
				technique varchar(16) NOT NULL DEFAULT '',
				severity tinyint(3) unsigned NOT NULL DEFAULT 2,
				status varchar(16) NOT NULL DEFAULT 'open',
				title varchar(255) NOT NULL DEFAULT '',
				summary text NOT NULL,
				ip varchar(45) NOT NULL DEFAULT '',
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				subject varchar(191) NOT NULL DEFAULT '',
				dedupe char(32) NOT NULL DEFAULT '',
				hits int(10) unsigned NOT NULL DEFAULT 1,
				events longtext NOT NULL,
				notes longtext NOT NULL,
				assignee bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				KEY status (status),
				KEY dedupe (dedupe),
				KEY updated (updated)
			) {$charset};"
		);
		Network::update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
		Network::add_option( 'sshield_detect_queue', array(), true );
	}

	/**
	 * Statuses and their labels.
	 *
	 * @return array
	 */
	public static function statuses() {
		return array(
			'open'           => __( 'Open', 'sentinel-shield' ),
			'investigating'  => __( 'Investigating', 'sentinel-shield' ),
			'resolved'       => __( 'Resolved', 'sentinel-shield' ),
			'false_positive' => __( 'False positive', 'sentinel-shield' ),
		);
	}

	/**
	 * Severity labels.
	 *
	 * @return array
	 */
	public static function severities() {
		return array(
			self::LOW      => __( 'Low', 'sentinel-shield' ),
			self::MEDIUM   => __( 'Medium', 'sentinel-shield' ),
			self::HIGH     => __( 'High', 'sentinel-shield' ),
			self::CRITICAL => __( 'Critical', 'sentinel-shield' ),
		);
	}

	/**
	 * Opens an incident, or adds the hit to a matching open one.
	 *
	 * @param array $data rule, technique, severity, title, summary, ip, user_id, subject, key, events (IDs).
	 * @return int Incident ID.
	 */
	public static function raise( array $data ) {
		global $wpdb;
		self::maybe_install();
		$table  = self::table();
		$dedupe = md5( $data['rule'] . '|' . ( isset( $data['key'] ) ? $data['key'] : '' ) );
		$events = array_values( array_unique( array_map( 'absint', isset( $data['events'] ) ? (array) $data['events'] : array() ) ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$open = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE dedupe = %s AND status IN ('open','investigating') AND updated >= %d ORDER BY id DESC LIMIT 1", $dedupe, time() - self::MERGE_WINDOW ), ARRAY_A );
		if ( $open ) {
			$merged = array_slice( array_values( array_unique( array_merge( (array) json_decode( $open['events'], true ), $events ) ) ), -self::MAX_EVENTS );
			$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Own table.
				$table,
				array(
					'updated'  => time(),
					'hits'     => (int) $open['hits'] + 1,
					'events'   => wp_json_encode( $merged ),
					'severity' => max( (int) $open['severity'], (int) $data['severity'] ),
					'summary'  => (string) $data['summary'],
					'title'    => substr( (string) $data['title'], 0, 255 ),
				),
				array( 'id' => (int) $open['id'] ),
				array( '%d', '%d', '%s', '%d', '%s', '%s' ),
				array( '%d' )
			);
			// An incident that got worse is worth a second email.
			if ( (int) $data['severity'] > (int) $open['severity'] ) {
				self::notify( (int) $open['id'], $data );
			}
			return (int) $open['id'];
		}

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Own table.
			$table,
			array(
				'created'   => time(),
				'updated'   => time(),
				'rule'      => (string) $data['rule'],
				'technique' => isset( $data['technique'] ) ? (string) $data['technique'] : '',
				'severity'  => (int) $data['severity'],
				'status'    => 'open',
				'title'     => substr( (string) $data['title'], 0, 255 ),
				'summary'   => (string) $data['summary'],
				'ip'        => isset( $data['ip'] ) ? (string) $data['ip'] : '',
				'user_id'   => isset( $data['user_id'] ) ? (int) $data['user_id'] : 0,
				'subject'   => isset( $data['subject'] ) ? substr( (string) $data['subject'], 0, 191 ) : '',
				'dedupe'    => $dedupe,
				'hits'      => 1,
				'events'    => wp_json_encode( $events ),
				'notes'     => '[]',
				'assignee'  => 0,
			),
			array( '%d', '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%d', '%s', '%s', '%d' )
		);
		$id = (int) $wpdb->insert_id;
		if ( $id ) {
			self::notify( $id, $data );
		}
		return $id;
	}

	/**
	 * Logs and emails a new or escalated incident.
	 *
	 * @param int   $id   Incident ID.
	 * @param array $data Incident data.
	 */
	private static function notify( $id, array $data ) {
		$labels = self::severities();
		$sev    = (int) $data['severity'];
		Events::add(
			'incident',
			/* translators: 1: severity, 2: incident title. */
			sprintf( __( '%1$s incident: %2$s', 'sentinel-shield' ), $labels[ $sev ], $data['title'] ),
			isset( $data['ip'] ) ? (string) $data['ip'] : '',
			array(
				'severity' => $sev >= self::HIGH ? Events::CRITICAL : Events::NOTICE,
				'action'   => 'siem.incident',
				'subject'  => (string) $id,
				'user_id'  => isset( $data['user_id'] ) ? (int) $data['user_id'] : 0,
			)
		);
		if ( $sev < (int) Settings::get( 'siem_alert_min' ) ) {
			return;
		}
		$link = Network::admin_url( 'admin.php?page=' . Admin::SLUG . '&tab=siem&incident=' . $id );
		Alerts::send(
			'alert_incidents',
			/* translators: 1: severity, 2: incident title. */
			sprintf( __( '%1$s incident: %2$s', 'sentinel-shield' ), $labels[ $sev ], $data['title'] ),
			$data['summary'] . "\n\n" . ( ! empty( $data['technique'] ) ? 'MITRE ATT&CK ' . $data['technique'] . "\n\n" : '' ) . __( 'Investigate and respond:', 'sentinel-shield' ) . "\n" . $link,
			'incident-' . $id . '-' . $sev
		);
	}

	/**
	 * One incident.
	 *
	 * @param int $id ID.
	 * @return array|null
	 */
	public static function get( $id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", (int) $id ), ARRAY_A );
		return $row ? self::decode( $row ) : null;
	}

	/**
	 * Incidents, newest activity first.
	 *
	 * @param array $args status (a status, 'active' or 'all'), ip, user_id, since, limit, offset.
	 * @return array
	 */
	public static function query( array $args = array() ) {
		global $wpdb;
		$args  = wp_parse_args(
			$args,
			array(
				'status' => 'active',
				'limit'  => 50,
				'offset' => 0,
			)
		);
		$table = self::table();
		$where = self::where( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; $where is prepared.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where} ORDER BY updated DESC, id DESC LIMIT %d OFFSET %d", max( 1, min( 500, (int) $args['limit'] ) ), max( 0, (int) $args['offset'] ) ), ARRAY_A );
		return array_map( array( __CLASS__, 'decode' ), is_array( $rows ) ? $rows : array() );
	}

	/**
	 * Number of incidents matching filters.
	 *
	 * @param array $args As for query().
	 * @return int
	 */
	public static function count( array $args = array() ) {
		global $wpdb;
		$table = self::table();
		$where = self::where( wp_parse_args( $args, array( 'status' => 'active' ) ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Own table; $where is prepared.
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );
	}

	/**
	 * WHERE clause.
	 *
	 * @param array $args Filters.
	 * @return string Prepared SQL.
	 */
	private static function where( array $args ) {
		global $wpdb;
		$parts  = array( '1=1' );
		$status = isset( $args['status'] ) ? (string) $args['status'] : 'active';
		if ( 'active' === $status ) {
			$parts[] = "status IN ('open','investigating')";
		} elseif ( isset( self::statuses()[ $status ] ) ) {
			$parts[] = $wpdb->prepare( 'status = %s', $status );
		}
		if ( ! empty( $args['ip'] ) ) {
			$parts[] = $wpdb->prepare( 'ip = %s', (string) $args['ip'] );
		}
		if ( ! empty( $args['user_id'] ) ) {
			$parts[] = $wpdb->prepare( 'user_id = %d', (int) $args['user_id'] );
		}
		if ( ! empty( $args['rule'] ) ) {
			$parts[] = $wpdb->prepare( 'rule = %s', (string) $args['rule'] );
		}
		if ( ! empty( $args['since'] ) ) {
			$parts[] = $wpdb->prepare( 'updated >= %d', (int) $args['since'] );
		}
		if ( ! empty( $args['min_severity'] ) ) {
			$parts[] = $wpdb->prepare( 'severity >= %d', (int) $args['min_severity'] );
		}
		return implode( ' AND ', $parts );
	}

	/**
	 * Decodes JSON columns.
	 *
	 * @param array $row Row.
	 * @return array
	 */
	private static function decode( array $row ) {
		$row['events'] = array_map( 'absint', (array) json_decode( (string) $row['events'], true ) );
		$notes         = json_decode( (string) $row['notes'], true );
		$row['notes']  = is_array( $notes ) ? $notes : array();
		foreach ( array( 'id', 'created', 'updated', 'severity', 'user_id', 'hits', 'assignee' ) as $int ) {
			$row[ $int ] = (int) $row[ $int ];
		}
		return $row;
	}

	/**
	 * Changes status or assignee, and adds a note. Every change is noted on the incident.
	 *
	 * @param int    $id       Incident ID.
	 * @param string $status   New status, or '' to keep.
	 * @param int    $assignee User ID, or -1 to keep.
	 * @param string $note     Note text.
	 * @return bool
	 */
	public static function update( $id, $status, $assignee, $note ) {
		global $wpdb;
		$incident = self::get( $id );
		if ( ! $incident ) {
			return false;
		}
		$me      = wp_get_current_user();
		$notes   = $incident['notes'];
		$changes = array();
		$data    = array( 'updated' => time() );
		$labels  = self::statuses();
		if ( '' !== $status && isset( $labels[ $status ] ) && $status !== $incident['status'] ) {
			$data['status'] = $status;
			/* translators: 1: old status, 2: new status. */
			$changes[] = sprintf( __( 'Status changed from %1$s to %2$s.', 'sentinel-shield' ), $labels[ $incident['status'] ], $labels[ $status ] );
		}
		if ( $assignee >= 0 && $assignee !== $incident['assignee'] ) {
			$data['assignee'] = $assignee;
			$who              = $assignee ? get_userdata( $assignee ) : null;
			$changes[]        = $who
				/* translators: %s: username. */
				? sprintf( __( 'Assigned to %s.', 'sentinel-shield' ), $who->user_login )
				: __( 'Unassigned.', 'sentinel-shield' );
		}
		$note = trim( sanitize_textarea_field( (string) $note ) );
		if ( $changes || '' !== $note ) {
			$notes[]       = array(
				'time'   => time(),
				'user'   => (int) $me->ID,
				'text'   => mb_substr( $note, 0, 4000 ),
				'change' => implode( ' ', $changes ),
			);
			$data['notes'] = wp_json_encode( $notes );
		}
		if ( 1 === count( $data ) ) {
			return true;
		}
		$wpdb->update( self::table(), $data, array( 'id' => (int) $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Own table.
		if ( isset( $data['status'] ) ) {
			Events::add(
				'incident',
				/* translators: 1: incident ID, 2: incident title, 3: status. */
				sprintf( __( 'Incident #%1$d (%2$s) marked %3$s.', 'sentinel-shield' ), $id, $incident['title'], $labels[ $status ] ),
				Request::ip(),
				array(
					'action'  => 'siem.status',
					'subject' => (string) $id,
				)
			);
		}
		return true;
	}

	/**
	 * Records a response action on the incident's notes.
	 *
	 * @param int    $id   Incident ID.
	 * @param string $text What was done.
	 */
	public static function note_action( $id, $text ) {
		global $wpdb;
		$incident = self::get( $id );
		if ( ! $incident ) {
			return;
		}
		$notes   = $incident['notes'];
		$notes[] = array(
			'time'   => time(),
			'user'   => get_current_user_id(),
			'text'   => '',
			'change' => (string) $text,
		);
		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Own table.
			self::table(),
			array(
				'notes'   => wp_json_encode( $notes ),
				'updated' => time(),
			),
			array( 'id' => (int) $id )
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Own table.
	}

	/**
	 * Open incidents per severity, and the newest few, for the overview and the hub.
	 *
	 * @return array open, by_severity, latest.
	 */
	public static function summary() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$rows = $wpdb->get_results( "SELECT severity, COUNT(*) AS n FROM {$table} WHERE status IN ('open','investigating') GROUP BY severity", ARRAY_A );
		$by   = array_fill_keys( array( self::LOW, self::MEDIUM, self::HIGH, self::CRITICAL ), 0 );
		foreach ( (array) $rows as $row ) {
			$by[ (int) $row['severity'] ] = (int) $row['n'];
		}
		$latest = array();
		foreach ( self::query( array( 'limit' => 10 ) ) as $i ) {
			$latest[] = array(
				'id'        => $i['id'],
				'title'     => $i['title'],
				'severity'  => $i['severity'],
				'status'    => $i['status'],
				'updated'   => $i['updated'],
				'technique' => $i['technique'],
			);
		}
		return array(
			'open'        => array_sum( $by ),
			'by_severity' => $by,
			'latest'      => $latest,
		);
	}

	/**
	 * Deletes closed incidents older than a year.
	 */
	public static function prune() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE status IN ('resolved','false_positive') AND updated < %d", time() - YEAR_IN_SECONDS ) );
	}
}
