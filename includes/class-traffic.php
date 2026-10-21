<?php
/**
 * Live traffic.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Records requests in a small table that keeps the last 24 hours.
 *
 * In security mode only requests worth a look are kept: blocks, missing pages,
 * logins and XML-RPC calls. In full mode every visit is kept, except cron,
 * heartbeat and this dashboard's own polling.
 */
final class Traffic {

	const DB_VERSION        = '1';
	const DB_VERSION_OPTION = 'sshield_traffic_db';
	const KEEP              = DAY_IN_SECONDS;
	const MAX_ROWS          = 20000;

	/**
	 * Why this request was blocked, when it was.
	 *
	 * @var string
	 */
	private static $blocked = '';

	/**
	 * Whether the current request is recorded.
	 *
	 * @var bool
	 */
	private static $armed = false;

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! Settings::enabled( 'live_traffic' ) || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		self::maybe_install();
		self::$armed = true;
		// Registered while the plugin loads, so requests the firewall stops early are recorded too.
		register_shutdown_function( array( __CLASS__, 'record' ) );
		add_action( 'wp_ajax_sshield_traffic', array( __CLASS__, 'ajax' ) );
	}

	/**
	 * Full table name.
	 *
	 * @return string
	 */
	public static function table() {
		return Network::table( 'sshield_traffic' );
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
				ip varchar(45) NOT NULL DEFAULT '',
				country char(2) NOT NULL DEFAULT '',
				method varchar(8) NOT NULL DEFAULT '',
				uri varchar(255) NOT NULL DEFAULT '',
				status smallint(5) unsigned NOT NULL DEFAULT 0,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				kind varchar(16) NOT NULL DEFAULT '',
				agent varchar(255) NOT NULL DEFAULT '',
				referer varchar(255) NOT NULL DEFAULT '',
				PRIMARY KEY  (id),
				KEY created (created),
				KEY kind (kind)
			) {$charset};"
		);
		Network::update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Marks the current request as blocked, before the firewall stops it.
	 *
	 * @param string $why firewall, ban, threat, country or rate.
	 */
	public static function note_block( $why ) {
		if ( '' === self::$blocked ) {
			self::$blocked = (string) $why;
		}
	}

	/**
	 * Writes the current request to the table at shutdown.
	 */
	public static function record() {
		if ( ! self::$armed ) {
			return;
		}
		self::$armed = false;
		$row         = self::current();
		if ( ! $row ) {
			return;
		}
		global $wpdb;
		$wpdb->insert( self::table(), $row, array( '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Own table.
		self::maybe_prune();
	}

	/**
	 * The current request as a row, or null when it is not worth keeping.
	 *
	 * @return array|null
	 */
	private static function current() {
		$uri    = substr( Request::server( 'REQUEST_URI' ), 0, 255 );
		$method = strtoupper( substr( Request::server( 'REQUEST_METHOD' ), 0, 8 ) );
		$status = (int) http_response_code();
		$path   = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$file   = basename( $path );

		// Noise nobody needs to watch.
		if ( 'wp-cron.php' === $file || ( 'admin-ajax.php' === $file && in_array( self::ajax_action(), array( 'heartbeat', 'sshield_traffic', 'sshield_scan' ), true ) ) ) {
			return null;
		}

		$user  = function_exists( 'wp_get_current_user' ) ? get_current_user_id() : 0;
		$agent = substr( Request::server( 'HTTP_USER_AGENT' ), 0, 255 );
		$kind  = self::kind( $status, $file, $method, $agent );
		if ( in_array( $kind, array( 'human', 'bot' ), true ) ) {
			// Administrators clicking around their own dashboard are not worth watching.
			if ( 'security' === Settings::get( 'traffic_mode' ) || ( $user && current_user_can( Network::cap() ) ) ) {
				return null;
			}
		}
		return array(
			'created' => time(),
			'ip'      => Request::ip(),
			'country' => self::country(),
			'method'  => $method,
			'uri'     => $uri,
			'status'  => $status,
			'user_id' => $user,
			'kind'    => $kind,
			'agent'   => $agent,
			'referer' => substr( Request::server( 'HTTP_REFERER' ), 0, 255 ),
		);
	}

	/**
	 * The admin-ajax action of the current request.
	 *
	 * @return string
	 */
	private static function ajax_action() {
		// phpcs:ignore WordPress.Security.NonceVerification -- Only read to skip logging.
		return isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
	}

	/**
	 * Sorts a request into a kind.
	 *
	 * @param int    $status HTTP status.
	 * @param string $file   Last path part.
	 * @param string $method HTTP method.
	 * @param string $agent  User agent.
	 * @return string blocked, login, notfound, bot or human.
	 */
	public static function kind( $status, $file, $method, $agent ) {
		if ( '' !== self::$blocked || 403 === $status || 429 === $status ) {
			return 'blocked';
		}
		$slug = Login_Url::slug();
		if ( 'xmlrpc.php' === $file || ( 'POST' === $method && ( 'wp-login.php' === $file || ( $slug && $slug === $file ) ) ) ) {
			return 'login';
		}
		if ( 404 === $status ) {
			return 'notfound';
		}
		return self::is_bot( $agent ) ? 'bot' : 'human';
	}

	/**
	 * Whether a user agent belongs to a crawler or script.
	 *
	 * @param string $agent User agent.
	 * @return bool
	 */
	public static function is_bot( $agent ) {
		return '' === trim( $agent ) || (bool) preg_match( '/bot\b|bot\/|crawl|spider|slurp|scan|curl|wget|python|go-http|java\/|okhttp|libwww|httpclient|headless|phantom|axios|node-fetch|feedfetcher|monitor|uptime|preview/i', $agent );
	}

	/**
	 * Country code from the configured source, if any.
	 *
	 * @return string
	 */
	private static function country() {
		$code = Geo::country();
		if ( '' === $code ) {
			// No header from a proxy or host: use the built-in database.
			$code = Geo_Db::lookup( Request::ip() );
		}
		return is_string( $code ) && 2 === strlen( $code ) ? strtoupper( $code ) : '';
	}

	/**
	 * Drops old rows every ten minutes at most.
	 */
	private static function maybe_prune() {
		if ( Network::get_transient( 'sshield_traffic_pruned' ) ) {
			return;
		}
		Network::set_transient( 'sshield_traffic_pruned', 1, 10 * MINUTE_IN_SECONDS );
		global $wpdb;
		$table = self::table();
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created < %d", time() - self::KEEP ) );
		$cut = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", self::MAX_ROWS ) );
		if ( $cut ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", $cut ) );
		}
		// phpcs:enable
	}

	/**
	 * Recent rows.
	 *
	 * @param string $kind  Filter: all, human, bot, blocked, login, notfound.
	 * @param int    $after Only rows with a higher ID.
	 * @param int    $limit   Rows.
	 * @param string $country Optional two-letter country filter.
	 * @return array
	 */
	public static function rows( $kind = 'all', $after = 0, $limit = 100, $country = '' ) {
		global $wpdb;
		$table = self::table();
		$where = $wpdb->prepare( 'id > %d', (int) $after );
		if ( in_array( $kind, self::kinds(), true ) ) {
			$where .= $wpdb->prepare( ' AND kind = %s', $kind );
		}
		if ( preg_match( '/^[A-Z]{2}$/', (string) $country ) ) {
			$where .= $wpdb->prepare( ' AND country = %s', $country );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; $where is prepared above.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT %d", max( 1, min( 500, (int) $limit ) ) ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Row counts per kind in the last 24 hours.
	 *
	 * @return array Kind => count.
	 */
	public static function counts() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT kind, COUNT(*) AS n FROM {$table} WHERE created >= %d GROUP BY kind", time() - self::KEEP ), ARRAY_A );
		$out  = array_fill_keys( self::kinds(), 0 );
		foreach ( (array) $rows as $row ) {
			$out[ $row['kind'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Requests per country in the last 24 hours, for the map.
	 *
	 * @return array Code => [ all, blocked, login, ips ], busiest first.
	 */
	public static function by_country() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT country, COUNT(*) AS n, SUM(kind = 'blocked') AS blocked, SUM(kind = 'login') AS login, COUNT(DISTINCT ip) AS ips FROM {$table} WHERE created >= %d AND country <> '' GROUP BY country ORDER BY n DESC", time() - self::KEEP ), ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$out[ $row['country'] ] = array(
				'all'     => (int) $row['n'],
				'blocked' => (int) $row['blocked'],
				'login'   => (int) $row['login'],
				'ips'     => (int) $row['ips'],
			);
		}
		return $out;
	}

	/**
	 * Requests with no country, in the last 24 hours.
	 *
	 * @return int
	 */
	public static function unlocated() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created >= %d AND country = ''", time() - self::KEEP ) );
	}

	/**
	 * Country shapes for the map: Natural Earth, public domain.
	 *
	 * @return array w, h, shapes (code => [ n, d ]), dots (code => [ n, x, y ]).
	 */
	public static function world() {
		static $world = null;
		if ( null === $world ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			$json  = file_get_contents( SSHIELD_DIR . 'assets/data/world.json' );
			$world = $json ? json_decode( $json, true ) : null;
			$world = is_array( $world ) ? $world : array(
				'w'      => 1000,
				'h'      => 435,
				'shapes' => array(),
				'dots'   => array(),
			);
		}
		return $world;
	}

	/**
	 * Shade step for a count: 0 for none, then 1 to 5 on a log scale up to the busiest country.
	 *
	 * @param int $n   Count.
	 * @param int $max Busiest country's count.
	 * @return int
	 */
	public static function shade( $n, $max ) {
		if ( $n <= 0 || $max <= 0 ) {
			return 0;
		}
		return max( 1, min( 5, (int) ceil( 5 * log( 1 + $n ) / log( 1 + $max ) ) ) );
	}

	/**
	 * Kinds of request.
	 *
	 * @return string[]
	 */
	public static function kinds() {
		return array( 'human', 'bot', 'blocked', 'login', 'notfound' );
	}

	/**
	 * Labels for the kinds.
	 *
	 * @return array
	 */
	public static function labels() {
		return array(
			'human'    => __( 'Visitor', 'sentinel-shield' ),
			'bot'      => __( 'Bot', 'sentinel-shield' ),
			'blocked'  => __( 'Blocked', 'sentinel-shield' ),
			'login'    => __( 'Login', 'sentinel-shield' ),
			'notfound' => __( 'Not found', 'sentinel-shield' ),
		);
	}

	/**
	 * New rows for the live view.
	 */
	public static function ajax() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_send_json_error( null, 403 );
		}
		check_ajax_referer( 'sshield_traffic' );
		$kind    = isset( $_POST['kind'] ) ? sanitize_key( wp_unslash( $_POST['kind'] ) ) : 'all';
		$after   = isset( $_POST['after'] ) ? absint( $_POST['after'] ) : 0;
		$country = isset( $_POST['country'] ) ? strtoupper( sanitize_key( wp_unslash( $_POST['country'] ) ) ) : '';
		$rows    = self::rows( $kind, $after, 100, $country );
		$html    = '';
		foreach ( $rows as $row ) {
			$html .= self::row_html( $row );
		}
		wp_send_json_success(
			array(
				'html'   => $html,
				'last'   => $rows ? (int) $rows[0]['id'] : $after,
				'counts' => self::counts(),
			)
		);
	}

	/**
	 * One table row.
	 *
	 * @param array $row Row.
	 * @return string
	 */
	public static function row_html( array $row ) {
		$labels = self::labels();
		$user   = $row['user_id'] ? get_userdata( (int) $row['user_id'] ) : null;
		$self   = Request::ip() === $row['ip'];
		$block  = '';
		if ( $row['ip'] && ! $self ) {
			$block = '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="sshield-inline-form">'
				. '<input type="hidden" name="action" value="sshield_block">'
				. '<input type="hidden" name="back" value="traffic">'
				. '<input type="hidden" name="ip" value="' . esc_attr( $row['ip'] ) . '">'
				. wp_nonce_field( 'sshield_block', '_wpnonce', true, false )
				. '<button type="submit" class="sshield-link sshield-link--danger">' . esc_html__( 'Block IP', 'sentinel-shield' ) . '</button></form>';
		}
		return '<tr data-id="' . esc_attr( $row['id'] ) . '" class="sshield-traffic--' . esc_attr( $row['kind'] ) . '">'
			. '<td><span class="sshield-pill sshield-pill--' . esc_attr( $row['kind'] ) . '">' . esc_html( isset( $labels[ $row['kind'] ] ) ? $labels[ $row['kind'] ] : $row['kind'] ) . '</span></td>'
			. '<td title="' . esc_attr( wp_date( 'Y-m-d H:i:s', (int) $row['created'] ) ) . '">' . esc_html( wp_date( get_option( 'time_format' ), (int) $row['created'] ) ) . '</td>'
			. '<td><code>' . esc_html( $row['ip'] ) . '</code>' . ( $row['country'] ? ' <span class="sshield-small">' . esc_html( $row['country'] ) . '</span>' : '' ) . ( $user ? '<br><span class="sshield-small">' . esc_html( $user->user_login ) . '</span>' : '' ) . '</td>'
			. '<td class="sshield-traffic__req"><code>' . esc_html( $row['method'] . ' ' . $row['uri'] ) . '</code><br><span class="sshield-small" title="' . esc_attr( $row['agent'] ) . '">' . esc_html( wp_html_excerpt( $row['agent'], 80, '…' ) ) . '</span></td>'
			. '<td>' . esc_html( $row['status'] ) . '</td>'
			. '<td class="sshield-right">' . $block . '</td>'
			. '</tr>';
	}

	/**
	 * Drops the table.
	 */
	public static function drop() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Own table.
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		Network::delete_option( self::DB_VERSION_OPTION );
	}
}
