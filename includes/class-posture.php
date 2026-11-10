<?php
/**
 * Security posture checks and score.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Inspects the site configuration and produces a weighted score.
 */
final class Posture {

	const PASS = 'pass';
	const WARN = 'warn';
	const FAIL = 'fail';

	/**
	 * Runs every check.
	 *
	 * @return array[] Each: id, label, status, detail, weight.
	 */
	public static function checks() {
		$checks = array();

		$https    = is_ssl() || 0 === strpos( home_url(), 'https://' );
		$checks[] = self::check(
			'https',
			__( 'HTTPS', 'chaos-shield' ),
			$https ? self::PASS : self::FAIL,
			$https ? __( 'The site is served over HTTPS.', 'chaos-shield' ) : __( 'Logins and cookies travel unencrypted. Install a TLS certificate and switch the site URL to https.', 'chaos-shield' ),
			3
		);

		$checks[] = self::core_updates_check();
		$checks[] = self::extension_updates_check();

		$debug   = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display = $debug && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		if ( $display ) {
			$status = self::FAIL;
			$detail = __( 'Errors are printed to visitors and can leak file paths. Set WP_DEBUG_DISPLAY to false.', 'chaos-shield' );
		} elseif ( $debug ) {
			$status = self::WARN;
			$detail = __( 'Debug mode is on but hidden from visitors. Turn it off on production.', 'chaos-shield' );
		} else {
			$status = self::PASS;
			$detail = __( 'Debug mode is off.', 'chaos-shield' );
		}
		$checks[] = self::check( 'debug', __( 'Debug output', 'chaos-shield' ), $status, $detail, 2 );

		$admin    = username_exists( 'admin' );
		$checks[] = self::check(
			'admin_user',
			__( 'Default "admin" username', 'chaos-shield' ),
			$admin ? self::WARN : self::PASS,
			$admin ? __( 'An account named "admin" exists and is the first name attackers try. Create a new administrator and delete it.', 'chaos-shield' ) : __( 'No account uses the name "admin".', 'chaos-shield' ),
			2
		);

		$public   = Accounts::public_logins();
		$checks[] = self::check(
			'public_logins',
			__( 'Public names', 'chaos-shield' ),
			$public ? self::WARN : self::PASS,
			$public
				/* translators: 1: number of accounts, 2: usernames. */
				? sprintf( _n( '%1$d account that can write posts shows its username as its public name (%2$s), which gives attackers half of the login. Pick another "Display name publicly as" on its profile.', '%1$d accounts that can write posts show their username as their public name (%2$s), which gives attackers half of the login. Pick another "Display name publicly as" on each profile.', count( $public ), 'chaos-shield' ), count( $public ), implode( ', ', array_slice( $public, 0, 5 ) ) . ( count( $public ) > 5 ? ', …' : '' ) )
				: __( 'No author publishes under their username.', 'chaos-shield' ),
			1
		);

		$file_edit = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$checks[]  = self::check(
			'file_edit',
			__( 'Code editor', 'chaos-shield' ),
			$file_edit ? self::PASS : self::FAIL,
			$file_edit ? __( 'The theme and plugin editors are disabled.', 'chaos-shield' ) : __( 'Anyone with an admin login can edit PHP from the dashboard. Turn on "Disable file editor", or remove a DISALLOW_FILE_EDIT false line from wp-config.php.', 'chaos-shield' ),
			2
		);

		$php_ok   = version_compare( PHP_VERSION, '8.1', '>=' );
		$checks[] = self::check(
			'php',
			__( 'PHP version', 'chaos-shield' ),
			$php_ok ? self::PASS : self::WARN,
			sprintf(
				/* translators: %s: PHP version. */
				$php_ok ? __( 'PHP %s is supported.', 'chaos-shield' ) : __( 'PHP %s no longer receives security fixes. Ask your host to upgrade to 8.1 or newer.', 'chaos-shield' ),
				PHP_VERSION
			),
			2
		);

		global $wpdb;
		$default_prefix = 'wp_' === $wpdb->prefix;
		$checks[]       = self::check(
			'db_prefix',
			__( 'Database prefix', 'chaos-shield' ),
			$default_prefix ? self::WARN : self::PASS,
			$default_prefix ? __( 'The default wp_ table prefix makes automated SQL injection slightly easier. Change it under Hardening, after a database backup.', 'chaos-shield' ) : __( 'A custom table prefix is in use.', 'chaos-shield' ),
			1
		);

		$loose    = array_filter(
			Server::permissions(),
			static function ( $row ) {
				return self::PASS !== $row['status'];
			}
		);
		$open     = array_filter(
			$loose,
			static function ( $row ) {
				return self::FAIL === $row['status'];
			}
		);
		$checks[] = self::check(
			'file_permissions',
			__( 'File permissions', 'chaos-shield' ),
			$open ? self::FAIL : ( $loose ? self::WARN : self::PASS ),
			$loose
				/* translators: %s: list of files and folders. */
				? sprintf( __( 'Looser than needed: %s. Tighten them in one click under Hardening.', 'chaos-shield' ), implode( ', ', wp_list_pluck( $loose, 'label' ) ) )
				: __( 'wp-config.php, .htaccess and the main folders are not writable by others.', 'chaos-shield' ),
			$open ? 3 : 1
		);

		$checks[] = self::two_factor_check();
		foreach ( self::reputation_checks() as $rep ) {
			$checks[] = $rep;
		}
		$checks[] = self::scan_check();
		$checks[] = self::vuln_check();

		$proxy_hint = Request::detected_proxy_headers() && ! Settings::get( 'proxy_header' );
		$checks[]   = self::check(
			'proxy',
			__( 'Visitor IP detection', 'chaos-shield' ),
			$proxy_hint ? self::WARN : self::PASS,
			$proxy_hint ? __( 'Requests arrive through a proxy but no proxy is set, so lockouts may hit the proxy instead of the attacker. Set it under Access.', 'chaos-shield' ) : __( 'Visitor IPs are read correctly.', 'chaos-shield' ),
			2
		);

		foreach ( Edge::checks() as $edge ) {
			$checks[] = self::check( $edge[0], $edge[1], $edge[2], $edge[3], $edge[4] );
		}

		foreach ( Settings::modules() as $key => $module ) {
			if ( in_array( $key, array( 'disable_file_edit', 'disable_app_passwords', 'two_factor', 'country_block', 'captcha', 'approve_signups', 'block_blank_ua', 'rest_private', 'disable_feeds', 'block_hotlinks' ), true ) ) {
				continue; // Covered by its own check, or optional.
			}
			$on       = Settings::enabled( $key );
			$checks[] = self::check(
				'module_' . $key,
				$module['label'],
				$on ? self::PASS : self::WARN,
				$on ? __( 'Enabled.', 'chaos-shield' ) : __( 'Off. Turn it on under Hardening.', 'chaos-shield' ),
				in_array( $key, array( 'limit_login', 'firewall' ), true ) ? 3 : 1
			);
		}

		return $checks;
	}

	/**
	 * Blocklist and domain expiry results from the last daily check.
	 *
	 * @return array[]
	 */
	private static function reputation_checks() {
		$state = Reputation::state();
		if ( ! Settings::enabled( 'reputation_check' ) || ! $state['checked'] ) {
			return array();
		}
		$out    = array();
		$listed = array();
		foreach ( $state['lists'] as $row ) {
			if ( 'listed' === $row['status'] ) {
				$listed[] = $row['label'];
			}
		}
		$out[] = self::check(
			'blocklists',
			__( 'Blocklists', 'chaos-shield' ),
			$listed ? self::FAIL : self::PASS,
			$listed
				/* translators: %s: list of blocklists. */
				? sprintf( __( 'The site is listed on %s. Scan for malware, clean up, then ask each list for a review from the Edge tab.', 'chaos-shield' ), implode( ', ', $listed ) )
				: __( 'No blocklist that was asked lists the site.', 'chaos-shield' ),
			3
		);
		$expires = isset( $state['expiry']['expires'] ) ? (int) $state['expiry']['expires'] : 0;
		if ( $expires ) {
			$days  = Uptime::days_left( $expires );
			$out[] = self::check(
				'domain_expiry',
				__( 'Domain registration', 'chaos-shield' ),
				$days < 0 ? self::FAIL : ( $days <= Reputation::EXPIRY_WARN ? self::WARN : self::PASS ),
				sprintf(
					/* translators: 1: domain, 2: date, 3: days. */
					_n( '%1$s is registered until %2$s, %3$d day from now.', '%1$s is registered until %2$s, %3$d days from now.', max( 0, $days ), 'chaos-shield' ),
					$state['expiry']['domain'],
					wp_date( get_option( 'date_format' ), $expires ),
					max( 0, $days )
				) . ( $days <= Reputation::EXPIRY_WARN ? ' ' . __( 'Renew it with your registrar.', 'chaos-shield' ) : '' ),
				2
			);
		}
		return $out;
	}

	/**
	 * Score from 0 to 100. A warning earns half of its weight.
	 *
	 * @param array|null $checks Optional precomputed checks.
	 * @return int
	 */
	public static function score( $checks = null ) {
		$checks = null === $checks ? self::checks() : $checks;
		$total  = 0;
		$earned = 0;
		foreach ( $checks as $check ) {
			$total += $check['weight'];
			if ( self::PASS === $check['status'] ) {
				$earned += $check['weight'];
			} elseif ( self::WARN === $check['status'] ) {
				$earned += $check['weight'] / 2;
			}
		}
		return $total ? (int) round( $earned / $total * 100 ) : 0;
	}

	/**
	 * Builds a check row.
	 *
	 * @param string $id     Identifier.
	 * @param string $label  Label.
	 * @param string $status pass, warn or fail.
	 * @param string $detail Explanation.
	 * @param int    $weight Weight in the score.
	 * @return array
	 */
	private static function check( $id, $label, $status, $detail, $weight ) {
		return array(
			'id'     => $id,
			'label'  => $label,
			'status' => $status,
			'detail' => $detail,
			'weight' => $weight,
		);
	}

	/**
	 * Result of the latest file scan.
	 *
	 * @return array
	 */
	private static function scan_check() {
		$label   = __( 'File scan', 'chaos-shield' );
		$results = Scanner::results();
		if ( ! $results ) {
			return self::check( 'scan', $label, self::WARN, __( 'No scan has run yet. Start one on the Scan tab.', 'chaos-shield' ), 3 );
		}
		$open = Scanner::open_findings( $results );
		$high = array_filter(
			$open,
			static function ( $f ) {
				return 'high' === $f['severity'];
			}
		);
		if ( $high ) {
			/* translators: %d: number of findings. */
			return self::check( 'scan', $label, self::FAIL, sprintf( _n( '%d high risk finding needs review on the Scan tab.', '%d high risk findings need review on the Scan tab.', count( $high ), 'chaos-shield' ), count( $high ) ), 3 );
		}
		if ( $open ) {
			/* translators: %d: number of findings. */
			return self::check( 'scan', $label, self::WARN, sprintf( _n( '%d finding needs review on the Scan tab.', '%d findings need review on the Scan tab.', count( $open ), 'chaos-shield' ), count( $open ) ), 3 );
		}
		if ( time() - (int) $results['finished'] > 8 * DAY_IN_SECONDS ) {
			return self::check( 'scan', $label, self::WARN, __( 'The last clean scan is more than a week old.', 'chaos-shield' ), 3 );
		}
		return self::check( 'scan', $label, self::PASS, __( 'The latest scan found nothing suspicious.', 'chaos-shield' ), 3 );
	}

	/**
	 * Known vulnerabilities in installed software.
	 *
	 * @return array
	 */
	private static function vuln_check() {
		$label = __( 'Known vulnerabilities', 'chaos-shield' );
		if ( ! Vulns::enabled() ) {
			return self::check( 'vulns', $label, self::WARN, __( 'Vulnerability alerts are off. Switch them on under Hardening.', 'chaos-shield' ), 4 );
		}
		$open = Vulns::open();
		if ( $open ) {
			/* translators: %d: number of vulnerabilities. */
			return self::check( 'vulns', $label, self::FAIL, sprintf( _n( '%d installed item has a known vulnerability. Update it from the Scan tab.', '%d installed items have known vulnerabilities. Update them from the Scan tab.', count( $open ), 'chaos-shield' ), count( $open ) ), 4 );
		}
		$result = Vulns::result();
		if ( ! $result || ! $result['checked'] ) {
			return self::check( 'vulns', $label, self::WARN, __( 'The first vulnerability check has not finished yet.', 'chaos-shield' ), 4 );
		}
		return self::check( 'vulns', $label, self::PASS, __( 'No installed version has a known vulnerability.', 'chaos-shield' ), 4 );
	}

	/**
	 * How many administrators use two-factor.
	 *
	 * @return array
	 */
	private static function two_factor_check() {
		$label = __( 'Administrators with two-factor', 'chaos-shield' );
		if ( ! Settings::enabled( 'two_factor' ) ) {
			return self::check( 'two_factor', $label, self::FAIL, __( 'Two-factor login is switched off. A stolen password is enough to take over the site.', 'chaos-shield' ), 3 );
		}
		$cover = Two_Factor::admin_coverage();
		if ( $cover['total'] && $cover['enabled'] === $cover['total'] ) {
			return self::check( 'two_factor', $label, self::PASS, __( 'Every administrator has a second login step: an authenticator app or a passkey.', 'chaos-shield' ), 3 );
		}
		return self::check(
			'two_factor',
			$label,
			$cover['enabled'] ? self::WARN : self::FAIL,
			sprintf(
				/* translators: 1: admins with two-factor, 2: all admins. */
				__( '%1$d of %2$d administrators have two-factor or a passkey. Each admin can add one under Users > Profile, or you can require it under Hardening.', 'chaos-shield' ),
				$cover['enabled'],
				$cover['total']
			),
			3
		);
	}

	/**
	 * WordPress core update status, from the cached update check.
	 *
	 * @return array
	 */
	private static function core_updates_check() {
		$label   = __( 'WordPress core', 'chaos-shield' );
		$updates = get_site_transient( 'update_core' );
		if ( empty( $updates->updates ) ) {
			return self::check( 'core', $label, self::WARN, __( 'No update check has run yet. Visit Dashboard > Updates.', 'chaos-shield' ), 3 );
		}
		foreach ( $updates->updates as $update ) {
			if ( isset( $update->response ) && 'upgrade' === $update->response ) {
				return self::check(
					'core',
					$label,
					self::FAIL,
					sprintf(
						/* translators: %s: new WordPress version. */
						__( 'WordPress %s is available. Update to get the latest security fixes.', 'chaos-shield' ),
						$update->current
					),
					3
				);
			}
		}
		return self::check( 'core', $label, self::PASS, __( 'WordPress is up to date.', 'chaos-shield' ), 3 );
	}

	/**
	 * Plugin and theme update status.
	 *
	 * @return array
	 */
	private static function extension_updates_check() {
		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );
		$count   = ( empty( $plugins->response ) ? 0 : count( $plugins->response ) ) + ( empty( $themes->response ) ? 0 : count( $themes->response ) );
		$label   = __( 'Plugins and themes', 'chaos-shield' );
		if ( ! $count ) {
			return self::check( 'extensions', $label, self::PASS, __( 'All plugins and themes are up to date.', 'chaos-shield' ), 3 );
		}
		return self::check(
			'extensions',
			$label,
			$count > 2 ? self::FAIL : self::WARN,
			sprintf(
				/* translators: %d: number of pending updates. */
				_n( '%d plugin or theme has an update waiting. Outdated extensions are the most common way sites get hacked.', '%d plugins or themes have updates waiting. Outdated extensions are the most common way sites get hacked.', $count, 'chaos-shield' ),
				$count
			),
			3
		);
	}
}
