<?php
/**
 * Security activity log, stored in its own table.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Writes and reads the activity log.
 */
final class Events {

	const DB_VERSION        = '3';
	const DB_VERSION_OPTION = 'cshield_db_version';
	const LEGACY_OPTION     = 'cshield_events';

	const INFO     = 1;
	const NOTICE   = 2;
	const CRITICAL = 3;

	/**
	 * Full table name.
	 *
	 * @return string
	 */
	public static function table() {
		return Network::table( 'cshield_log' );
	}

	/**
	 * Creates or upgrades the table when the stored schema version is old.
	 */
	public static function maybe_install() {
		if ( Network::get_option( self::DB_VERSION_OPTION ) === self::DB_VERSION ) {
			return;
		}
		self::install();
	}

	/**
	 * Creates the table and moves events from the 0.1 and 0.2 option store.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created int(10) unsigned NOT NULL,
				type varchar(32) NOT NULL,
				severity tinyint(3) unsigned NOT NULL DEFAULT 1,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				ip varchar(45) NOT NULL DEFAULT '',
				message text NOT NULL,
				action varchar(48) NOT NULL DEFAULT '',
				subject varchar(191) NOT NULL DEFAULT '',
				blog_id bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				KEY created (created),
				KEY type (type),
				KEY action (action),
				KEY ip (ip),
				KEY blog_id (blog_id)
			) {$charset};"
		);

		$legacy = Network::get_option( self::LEGACY_OPTION );
		if ( is_array( $legacy ) ) {
			foreach ( array_reverse( $legacy ) as $event ) {
				self::insert(
					array(
						'created' => (int) $event['time'],
						'type'    => sanitize_key( $event['type'] ),
						'ip'      => (string) $event['ip'],
						'message' => (string) $event['message'],
						'legacy'  => true,
					)
				);
			}
			Network::delete_option( self::LEGACY_OPTION );
		}

		self::merge_site_logs();
		Network::update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Network activated before 1.7, each site kept its own log table. Moves those
	 * events into the network log, marked with their site, and drops the old tables.
	 */
	private static function merge_site_logs() {
		global $wpdb;
		if ( ! Network::active() ) {
			return;
		}
		$table = self::table();
		// The main site's events were already in this table.
		$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET blog_id = %d WHERE blog_id = 0", Network::main_site() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom log table.
		foreach ( get_sites(
			array(
				'number' => 0,
				'fields' => 'ids',
			)
		) as $blog_id ) {
			$old = $wpdb->get_blog_prefix( $blog_id ) . 'cshield_log';
			if ( $old === $table || $old !== $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $old ) ) ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- One-off migration.
				continue;
			}
			$columns = $wpdb->get_col( "SHOW COLUMNS FROM `{$old}`" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name built from the blog prefix.
			$extra   = in_array( 'action', $columns, true ) ? 'action, subject' : "'', ''";
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names built from the blog prefixes.
			$moved = $wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (created, type, severity, user_id, ip, message, action, subject, blog_id) SELECT created, type, severity, user_id, ip, message, {$extra}, %d FROM `{$old}`", (int) $blog_id ) );
			if ( false !== $moved ) {
				$wpdb->query( "DROP TABLE IF EXISTS `{$old}`" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Data moved above.
			}
		}
	}

	/**
	 * Records an event.
	 *
	 * @param string $type    Event type, such as login, lockout, blocked, settings, user, plugin, scan.
	 * @param string $message Human readable message.
	 * @param string $ip      Optional IP address.
	 * @param array  $args    Optional: severity (INFO, NOTICE, CRITICAL), user_id, action (a code
	 *                        such as auth.failed that detection rules match on) and subject
	 *                        (the username, plugin or setting the event is about).
	 */
	public static function add( $type, $message, $ip = '', array $args = array() ) {
		$user_id = isset( $args['user_id'] ) ? (int) $args['user_id'] : 0;
		if ( ! $user_id && did_action( 'init' ) ) {
			$user_id = get_current_user_id();
		}
		self::insert(
			array(
				'created'  => time(),
				'type'     => sanitize_key( $type ),
				'severity' => isset( $args['severity'] ) ? (int) $args['severity'] : self::INFO,
				'user_id'  => $user_id,
				'ip'       => (string) $ip,
				'message'  => sanitize_text_field( $message ),
				'action'   => isset( $args['action'] ) ? substr( preg_replace( '/[^a-z0-9._-]/', '', strtolower( (string) $args['action'] ) ), 0, 48 ) : '',
				'subject'  => isset( $args['subject'] ) ? substr( sanitize_text_field( (string) $args['subject'] ), 0, 191 ) : '',
			)
		);
	}

	/**
	 * Hands a stored row to listeners such as log forwarding.
	 *
	 * @param array $data Row.
	 */
	private static function announce( array $data ) {
		/**
		 * Fires after an event is stored.
		 *
		 * @param array $event id, created, type, severity, user_id, ip, message, action, subject, blog_id.
		 */
		do_action( 'cshield_event', $data );
	}

	/**
	 * Inserts a row, ignoring failures so logging can never break a request.
	 *
	 * @param array $row Column values.
	 */
	private static function insert( array $row ) {
		global $wpdb;
		$data     = array(
			'created'  => (int) $row['created'],
			'type'     => (string) $row['type'],
			'severity' => isset( $row['severity'] ) ? (int) $row['severity'] : self::INFO,
			'user_id'  => isset( $row['user_id'] ) ? (int) $row['user_id'] : 0,
			'ip'       => isset( $row['ip'] ) ? substr( (string) $row['ip'], 0, 45 ) : '',
			'message'  => (string) $row['message'],
			'action'   => isset( $row['action'] ) ? (string) $row['action'] : '',
			'subject'  => isset( $row['subject'] ) ? (string) $row['subject'] : '',
			'blog_id'  => get_current_blog_id(),
		);
		$suppress = $wpdb->suppress_errors( true );
		$ok       = $wpdb->insert( self::table(), $data, array( '%d', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom log table.
		if ( false === $ok ) {
			// The table may predate the newer columns on a site that has not upgraded it yet.
			unset( $data['action'], $data['subject'], $data['blog_id'] );
			$wpdb->insert( self::table(), $data, array( '%d', '%s', '%d', '%d', '%s', '%s' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom log table.
			if ( $wpdb->insert_id ) {
				// The old columns worked, so the schema is older than the stored version says: rebuild it next request.
				Network::delete_option( self::DB_VERSION_OPTION );
			}
			$data['action']  = isset( $row['action'] ) ? (string) $row['action'] : '';
			$data['subject'] = isset( $row['subject'] ) ? (string) $row['subject'] : '';
			$data['blog_id'] = get_current_blog_id();
		}
		$data['id'] = (int) $wpdb->insert_id;
		$wpdb->suppress_errors( $suppress );
		if ( empty( $row['legacy'] ) ) {
			self::announce( $data );
		}
	}

	/**
	 * Newest events.
	 *
	 * @param int $limit Maximum number to return.
	 * @return array
	 */
	public static function all( $limit = 50 ) {
		return self::query( array( 'limit' => $limit ) );
	}

	/**
	 * Builds the WHERE clause for the filters.
	 *
	 * @param array $args type, user_id, search, since, until.
	 * @return string SQL, already prepared.
	 */
	private static function where( array $args ) {
		global $wpdb;
		$parts = array( '1=1' );
		if ( ! empty( $args['type'] ) ) {
			$parts[] = $wpdb->prepare( 'type = %s', $args['type'] );
		}
		if ( isset( $args['user_id'] ) && '' !== $args['user_id'] && null !== $args['user_id'] ) {
			$parts[] = $wpdb->prepare( 'user_id = %d', (int) $args['user_id'] );
		}
		if ( ! empty( $args['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$parts[] = $wpdb->prepare( '(message LIKE %s OR ip LIKE %s)', $like, $like );
		}
		if ( ! empty( $args['since'] ) ) {
			$parts[] = $wpdb->prepare( 'created >= %d', (int) $args['since'] );
		}
		if ( ! empty( $args['until'] ) ) {
			$parts[] = $wpdb->prepare( 'created <= %d', (int) $args['until'] );
		}
		if ( ! empty( $args['min_severity'] ) ) {
			$parts[] = $wpdb->prepare( 'severity >= %d', (int) $args['min_severity'] );
		}
		if ( ! empty( $args['ip'] ) ) {
			$parts[] = $wpdb->prepare( 'ip = %s', (string) $args['ip'] );
		}
		if ( ! empty( $args['subject'] ) ) {
			$parts[] = $wpdb->prepare( 'subject = %s', (string) $args['subject'] );
		}
		if ( ! empty( $args['action'] ) ) {
			// A trailing * matches a family of actions, such as auth.*.
			$action  = (string) $args['action'];
			$parts[] = '*' === substr( $action, -1 )
				? $wpdb->prepare( 'action LIKE %s', $wpdb->esc_like( substr( $action, 0, -1 ) ) . '%' )
				: $wpdb->prepare( 'action = %s', $action );
		}
		if ( ! empty( $args['blog_id'] ) ) {
			$parts[] = $wpdb->prepare( 'blog_id = %d', (int) $args['blog_id'] );
		}
		if ( ! empty( $args['ids'] ) ) {
			$parts[] = 'id IN (' . implode( ',', array_map( 'absint', (array) $args['ids'] ) ) . ')';
		}
		return implode( ' AND ', $parts );
	}

	/**
	 * Reads events, newest first.
	 *
	 * @param array $args Optional: type, user_id, search, since, until, min_severity, ip, action, subject, blog_id, ids, limit, offset.
	 * @return array Rows with id, time, type, severity, user_id, ip, message, action, subject, blog_id.
	 */
	public static function query( array $args = array() ) {
		global $wpdb;
		$args  = wp_parse_args(
			$args,
			array(
				'limit'  => 50,
				'offset' => 0,
			)
		);
		$table = self::table();
		$limit = max( 1, min( 5000, (int) $args['limit'] ) );
		$off   = max( 0, (int) $args['offset'] );
		$where = self::where( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom log table; the WHERE clause is prepared above.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, created AS time, type, severity, user_id, ip, message, action, subject, blog_id FROM {$table} WHERE {$where} ORDER BY created DESC, id DESC LIMIT %d OFFSET %d", $limit, $off ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Number of events matching the filters. A string is read as a type, for older callers.
	 *
	 * @param array|string $args Filters as for query(), or a type.
	 * @return int
	 */
	public static function count( $args = array() ) {
		global $wpdb;
		$args  = is_array( $args ) ? $args : array( 'type' => (string) $args );
		$table = self::table();
		$where = self::where( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Custom log table; the WHERE clause is prepared above.
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );
	}

	/**
	 * Number of events per type since a time.
	 *
	 * @param int $since Unix timestamp.
	 * @return array Type => count.
	 */
	public static function counts_since( $since ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom log table.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT type, COUNT(*) AS n FROM {$table} WHERE created >= %d GROUP BY type", (int) $since ), ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$out[ $row['type'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Types that appear in the log.
	 *
	 * @return string[]
	 */
	public static function types() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom log table.
		$types = $wpdb->get_col( "SELECT DISTINCT type FROM {$table} ORDER BY type" );
		return is_array( $types ) ? $types : array();
	}

	/**
	 * Deletes events older than the retention period.
	 *
	 * @param int $days Days to keep.
	 */
	public static function prune( $days ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom log table.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created < %d", time() - max( 1, (int) $days ) * DAY_IN_SECONDS ) );
	}

	/**
	 * Drops the table. Used on uninstall.
	 */
	public static function drop() {
		global $wpdb;
		$table = self::table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup.
	}
}
