<?php
/**
 * Activity log CSV export and the printable compliance report.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Admin downloads built from the activity log and the current settings.
 */
final class Export {

	const MAX_ROWS = 200000;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'admin_post_cshield_export', array( $this, 'csv' ) );
		add_action( 'admin_post_cshield_compliance', array( $this, 'compliance' ) );
	}

	/**
	 * Log filters from the request, shared by the Activity tab and the export.
	 *
	 * @param array $source Request values, usually $_GET.
	 * @return array type, user_id, search, since, until, and the raw form values.
	 */
	public static function filters( array $source ) {
		$type   = isset( $source['type'] ) ? sanitize_key( wp_unslash( $source['type'] ) ) : '';
		$search = isset( $source['s'] ) ? sanitize_text_field( wp_unslash( $source['s'] ) ) : '';
		$login  = isset( $source['user'] ) ? sanitize_user( wp_unslash( $source['user'] ) ) : '';
		$from   = isset( $source['from'] ) ? sanitize_text_field( wp_unslash( $source['from'] ) ) : '';
		$to     = isset( $source['to'] ) ? sanitize_text_field( wp_unslash( $source['to'] ) ) : '';
		$site   = isset( $source['site'] ) ? absint( $source['site'] ) : 0;
		$site   = $site && Network::active() && get_site( $site ) ? $site : 0;

		$user_id = '';
		if ( '' !== $login ) {
			$user    = get_user_by( 'login', $login );
			$user_id = $user ? $user->ID : -1;
		}
		return array(
			'type'    => $type,
			'search'  => $search,
			'user_id' => $user_id,
			'since'   => self::day( $from, false ),
			'until'   => self::day( $to, true ),
			'blog_id' => $site,
			'form'    => array_filter(
				array(
					'type' => $type,
					's'    => $search,
					'user' => $login,
					'from' => self::day( $from, false ) ? $from : '',
					'to'   => self::day( $to, true ) ? $to : '',
					'site' => $site,
				)
			),
		);
	}

	/**
	 * Start or end of a YYYY-MM-DD day in the site's timezone.
	 *
	 * @param string $date Date.
	 * @param bool   $end  End of the day instead of the start.
	 * @return int Timestamp, or 0.
	 */
	private static function day( $date, $end ) {
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
			return 0;
		}
		$time = date_create_immutable( $date . ( $end ? ' 23:59:59' : ' 00:00:00' ), wp_timezone() );
		return $time ? $time->getTimestamp() : 0;
	}

	/**
	 * Streams the filtered log as CSV.
	 */
	public function csv() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( 'cshield_export' );
		$filters = self::filters( $_GET ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checked above.
		$args    = array_intersect_key( $filters, array_flip( array( 'type', 'search', 'user_id', 'since', 'until', 'blog_id' ) ) );

		Events::add(
			'settings',
			__( 'Activity log exported to CSV.', 'chaos-shield' ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'data.export',
			)
		);

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="chaos-shield-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
		header( 'X-Content-Type-Options: nosniff' );

		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming a download.
		fwrite( $out, "\xEF\xBB\xBF" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- UTF-8 mark so spreadsheet apps read accents.
		fputcsv( $out, array( 'id', 'time_utc', 'time_local', 'site', 'type', 'severity', 'user', 'ip', 'message' ), ',', '"', '\\' );

		$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		$users  = array();
		$offset = 0;
		while ( $offset < self::MAX_ROWS ) {
			$rows = Events::query(
				array_merge(
					$args,
					array(
						'limit'  => 1000,
						'offset' => $offset,
					)
				)
			);
			if ( ! $rows ) {
				break;
			}
			foreach ( $rows as $row ) {
				$uid = (int) $row['user_id'];
				if ( $uid && ! isset( $users[ $uid ] ) ) {
					$user          = get_userdata( $uid );
					$users[ $uid ] = $user ? $user->user_login : '#' . $uid;
				}
				fputcsv(
					$out,
					array(
						(int) $row['id'],
						gmdate( 'c', (int) $row['time'] ),
						wp_date( $format, (int) $row['time'] ),
						self::cell( ! empty( $row['blog_id'] ) && is_multisite() ? Network::site_name( $row['blog_id'] ) : '' ),
						$row['type'],
						Forwarder::severity_name( (int) $row['severity'] ),
						self::cell( $uid ? $users[ $uid ] : '' ),
						$row['ip'],
						self::cell( $row['message'] ),
					),
					',',
					'"',
					'\\'
				);
			}
			$offset += 1000;
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming a download.
		exit;
	}

	/**
	 * Stops spreadsheet apps from running a cell as a formula.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	public static function cell( $value ) {
		$value = (string) $value;
		return '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ? "'" . $value : $value;
	}

	// Compliance report.

	/**
	 * Controls with their status and evidence.
	 *
	 * @return array Each: area, label, ok (bool|null for info), evidence, refs.
	 */
	public static function controls() {
		$admins   = self::admins();
		$covered  = count(
			array_filter(
				$admins,
				static function ( $a ) {
					return $a['twofactor'] || $a['passkeys'];
				}
			)
		);
		$days     = (int) Settings::get( 'log_retention' );
		$forward  = Forwarder::webhook() || Forwarder::syslog_target();
		$results  = Scanner::results();
		$open     = Scanner::open_findings( $results );
		$vulns    = Vulns::open();
		$updates  = self::pending_updates();
		$policy   = Settings::enabled( 'password_policy' );
		$controls = array();

		$controls[] = array(
			'area'     => __( 'Access control', 'chaos-shield' ),
			'label'    => __( 'Multi-factor authentication for administrators', 'chaos-shield' ),
			'ok'       => $admins && count( $admins ) === $covered,
			/* translators: 1: covered admins, 2: all admins. */
			'evidence' => sprintf( __( '%1$d of %2$d administrators use two-factor login or a passkey.', 'chaos-shield' ), $covered, count( $admins ) ),
			'refs'     => 'SOC 2 CC6.1 · ISO 27001 A.8.5',
		);
		$controls[] = array(
			'area'     => __( 'Access control', 'chaos-shield' ),
			'label'    => __( 'Password policy', 'chaos-shield' ),
			'ok'       => $policy && (int) Settings::get( 'pw_min_length' ) >= 12,
			'evidence' => $policy
				? Password_Policy::describe() . ' ' . ( (int) Settings::get( 'pw_max_age' ) ? sprintf( /* translators: %d: days. */ __( 'Passwords expire after %d days.', 'chaos-shield' ), (int) Settings::get( 'pw_max_age' ) ) : __( 'Passwords do not expire.', 'chaos-shield' ) )
				: __( 'No password policy is enforced.', 'chaos-shield' ),
			'refs'     => 'SOC 2 CC6.1 · ISO 27001 A.5.17',
		);
		$controls[] = array(
			'area'     => __( 'Access control', 'chaos-shield' ),
			'label'    => __( 'Breached password screening', 'chaos-shield' ),
			'ok'       => Settings::enabled( 'breached_passwords' ),
			'evidence' => Settings::enabled( 'breached_passwords' ) ? __( 'New passwords are checked against known data breaches.', 'chaos-shield' ) : __( 'Off.', 'chaos-shield' ),
			'refs'     => 'ISO 27001 A.5.17',
		);
		$controls[] = array(
			'area'     => __( 'Access control', 'chaos-shield' ),
			'label'    => __( 'Brute force protection', 'chaos-shield' ),
			'ok'       => Settings::enabled( 'limit_login' ),
			/* translators: 1: attempts, 2: minutes, 3: minutes. */
			'evidence' => Settings::enabled( 'limit_login' ) ? sprintf( __( 'Lockout after %1$d failed logins in %2$d minutes, for %3$d minutes; repeat offenders are banned.', 'chaos-shield' ), (int) Settings::get( 'login_max_attempts' ), (int) Settings::get( 'login_window' ), (int) Settings::get( 'login_lockout' ) ) : __( 'Off.', 'chaos-shield' ),
			'refs'     => 'SOC 2 CC6.1 · ISO 27001 A.8.5',
		);
		$controls[] = array(
			'area'     => __( 'Network protection', 'chaos-shield' ),
			'label'    => __( 'Web application firewall and rate limiting', 'chaos-shield' ),
			'ok'       => Settings::enabled( 'firewall' ) && Settings::enabled( 'rate_limit' ),
			'evidence' => implode(
				' ',
				array(
					Settings::enabled( 'firewall' ) ? __( 'Firewall on.', 'chaos-shield' ) : __( 'Firewall off.', 'chaos-shield' ),
					Settings::enabled( 'rate_limit' ) ? __( 'Rate limits on.', 'chaos-shield' ) : __( 'Rate limits off.', 'chaos-shield' ),
				)
			),
			'refs'     => 'SOC 2 CC6.6 · ISO 27001 A.8.20',
		);
		$controls[] = array(
			'area'     => __( 'Network protection', 'chaos-shield' ),
			'label'    => __( 'Encryption in transit (HTTPS)', 'chaos-shield' ),
			'ok'       => 0 === strpos( home_url(), 'https://' ) && 0 === strpos( site_url(), 'https://' ),
			'evidence' => home_url( '/' ),
			'refs'     => 'SOC 2 CC6.7 · ISO 27001 A.8.24',
		);
		$controls[] = array(
			'area'     => __( 'Logging and monitoring', 'chaos-shield' ),
			'label'    => __( 'Audit trail', 'chaos-shield' ),
			'ok'       => Settings::enabled( 'audit_trail' ),
			/* translators: %d: days. */
			'evidence' => ( Settings::enabled( 'audit_trail' ) ? __( 'Security, user, content and setting changes are logged.', 'chaos-shield' ) : __( 'Only security events are logged.', 'chaos-shield' ) ) . ' ' . sprintf( __( 'Kept for %d days.', 'chaos-shield' ), $days ),
			'refs'     => 'SOC 2 CC7.2 · ISO 27001 A.8.15',
		);
		$controls[] = array(
			'area'     => __( 'Logging and monitoring', 'chaos-shield' ),
			'label'    => __( 'Log retention of at least one year', 'chaos-shield' ),
			'ok'       => $days >= 365 || $forward,
			'evidence' => $forward ? __( 'Events are forwarded to an external log store, which holds them independently of this site.', 'chaos-shield' ) : sprintf( /* translators: %d: days. */ __( 'Kept on this site for %d days, with no external copy.', 'chaos-shield' ), $days ),
			'refs'     => 'ISO 27001 A.8.15',
		);
		$controls[] = array(
			'area'     => __( 'Logging and monitoring', 'chaos-shield' ),
			'label'    => __( 'Security alerts', 'chaos-shield' ),
			'ok'       => Settings::enabled( 'alert_new_admin' ) && Settings::enabled( 'alert_scan' ),
			/* translators: %s: email address. */
			'evidence' => sprintf( __( 'Alerts go to %s.', 'chaos-shield' ), Settings::alert_email() ),
			'refs'     => 'SOC 2 CC7.2 · ISO 27001 A.8.16',
		);
		$controls[] = array(
			'area'     => __( 'Vulnerability management', 'chaos-shield' ),
			'label'    => __( 'Known vulnerability monitoring', 'chaos-shield' ),
			'ok'       => Vulns::enabled() && ! $vulns,
			'evidence' => Vulns::enabled()
				/* translators: %d: number of vulnerabilities. */
				? sprintf( _n( 'Checked daily against the WPVulnerability database. %d open vulnerability.', 'Checked daily against the WPVulnerability database. %d open vulnerabilities.', count( $vulns ), 'chaos-shield' ), count( $vulns ) )
				: __( 'Vulnerability alerts are switched off.', 'chaos-shield' ),
			'refs'     => 'SOC 2 CC7.1 · ISO 27001 A.8.8',
		);
		$controls[] = array(
			'area'     => __( 'Vulnerability management', 'chaos-shield' ),
			'label'    => __( 'Software kept up to date', 'chaos-shield' ),
			'ok'       => 0 === $updates,
			/* translators: %d: number of updates. */
			'evidence' => sprintf( _n( '%d update waiting for WordPress, plugins or themes.', '%d updates waiting for WordPress, plugins or themes.', $updates, 'chaos-shield' ), $updates ),
			'refs'     => 'SOC 2 CC7.1 · ISO 27001 A.8.8',
		);
		$controls[] = array(
			'area'     => __( 'Integrity', 'chaos-shield' ),
			'label'    => __( 'Malware and file integrity scanning', 'chaos-shield' ),
			'ok'       => $results && (int) $results['finished'] > time() - 8 * DAY_IN_SECONDS && ! $open,
			'evidence' => $results
				/* translators: 1: date, 2: number of findings. */
				? sprintf( __( 'Last scan %1$s, %2$d open findings.', 'chaos-shield' ), wp_date( get_option( 'date_format' ), (int) $results['finished'] ), count( $open ) )
				: __( 'No scan has run yet.', 'chaos-shield' ),
			'refs'     => 'SOC 2 CC6.8 · ISO 27001 A.8.7',
		);
		return $controls;
	}

	/**
	 * Administrators and their sign-in protections.
	 *
	 * @return array Each: login, email, twofactor, passkeys, last_login, pw_changed, reset_pending.
	 */
	public static function admins() {
		$out = array();
		foreach ( get_users(
			array(
				'role__in' => array( 'administrator' ),
				'number'   => 200,
			)
		) as $user ) {
			$last  = Events::query(
				array(
					'type'    => 'login',
					'user_id' => $user->ID,
					'search'  => ' logged in',
					'limit'   => 1,
				)
			);
			$out[] = array(
				'login'         => $user->user_login,
				'email'         => $user->user_email,
				'twofactor'     => Two_Factor::is_enabled( $user->ID ),
				'passkeys'      => count( Passkeys::for_user( $user->ID ) ),
				'last_login'    => $last ? (int) $last[0]['time'] : 0,
				'pw_changed'    => (int) get_user_meta( $user->ID, Password_Policy::CHANGED_META, true ),
				'reset_pending' => Password_Policy::forced( $user->ID ),
			);
		}
		return $out;
	}

	/**
	 * Number of pending core, plugin and theme updates.
	 *
	 * @return int
	 */
	private static function pending_updates() {
		$n = 0;
		foreach ( array( 'update_plugins', 'update_themes' ) as $key ) {
			$transient = get_site_transient( $key );
			$n        += ( is_object( $transient ) && ! empty( $transient->response ) ) ? count( (array) $transient->response ) : 0;
		}
		$core = get_site_transient( 'update_core' );
		if ( is_object( $core ) && ! empty( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( isset( $update->response ) && 'upgrade' === $update->response ) {
					++$n;
					break;
				}
			}
		}
		return $n;
	}

	/**
	 * Prints the compliance report as a standalone page.
	 */
	public function compliance() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( 'cshield_compliance' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checked above.
		$days = isset( $_GET['days'] ) ? absint( $_GET['days'] ) : 30;
		$days = in_array( $days, array( 7, 30, 90, 365 ), true ) ? $days : 30;

		Events::add( 'settings', __( 'Compliance report generated.', 'chaos-shield' ), Request::ip() );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Frame-Options: SAMEORIGIN' );

		$report            = array(
			'days'     => $days,
			'since'    => time() - $days * DAY_IN_SECONDS,
			'checks'   => Posture::checks(),
			'controls' => self::controls(),
			'admins'   => self::admins(),
		);
		$report['score']   = Posture::score( $report['checks'] );
		$report['counts']  = Events::counts_since( $report['since'] );
		$report['notable'] = Events::query(
			array(
				'since'        => $report['since'],
				'min_severity' => Events::NOTICE,
				'limit'        => 300,
			)
		);
		include CSHIELD_DIR . 'includes/views/report-compliance.php';
		exit;
	}
}
