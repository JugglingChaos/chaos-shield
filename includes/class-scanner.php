<?php
/**
 * Core file integrity check and malware scan.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Scans files in small batches so it works on cheap hosting with short time limits.
 */
final class Scanner {

	const STATE_OPTION   = 'sshield_scan_state';
	const RESULTS_OPTION = 'sshield_scan_results';
	const IGNORE_OPTION  = 'sshield_scan_ignored';
	const CRON_STEP      = 'sshield_scan_continue';
	const BASELINE       = 'sshield_file_baseline';
	const EXPECTED       = 'sshield_expected_changes';
	const MAX_FILES      = 60000;
	const MAX_BYTES      = 2097152;

	/**
	 * Extensions that can run as PHP.
	 *
	 * @var string[]
	 */
	private static $php_ext = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'inc', 'pht' );

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::CRON_STEP, array( __CLASS__, 'cron_step' ) );
	}

	/**
	 * Whether a scan is in progress.
	 *
	 * @return bool
	 */
	public static function running() {
		$state = Network::get_option( self::STATE_OPTION );
		return is_array( $state ) && 'running' === $state['status'];
	}

	/**
	 * Last finished scan.
	 *
	 * @return array|null
	 */
	public static function results() {
		$results = Network::get_option( self::RESULTS_OPTION );
		return is_array( $results ) ? $results : null;
	}

	/**
	 * Progress of the running scan.
	 *
	 * @return array status, done, total, percent.
	 */
	public static function progress() {
		$state = Network::get_option( self::STATE_OPTION );
		if ( ! is_array( $state ) ) {
			return array(
				'status'  => 'idle',
				'done'    => 0,
				'total'   => 0,
				'percent' => 100,
			);
		}
		$total = count( $state['queue'] );
		return array(
			'status'  => $state['status'],
			'done'    => (int) $state['pos'],
			'total'   => $total,
			'percent' => $total ? (int) floor( $state['pos'] / $total * 100 ) : 100,
		);
	}

	/**
	 * Builds the file list and starts a scan.
	 *
	 * @param string $trigger manual or scheduled.
	 */
	public static function start( $trigger = 'manual' ) {
		$checksums = self::core_checksums();
		$queue     = array();
		$core      = array();

		if ( is_array( $checksums ) ) {
			foreach ( $checksums as $file => $hash ) {
				// wp-content ships default themes and plugins that sites delete or update; skip them.
				if ( 0 === strpos( $file, 'wp-content/' ) ) {
					continue;
				}
				$core[ $file ] = true;
				$queue[]       = 'c|' . $file . '|' . $hash;
			}
		}

		// PHP files in core folders and the root that WordPress did not ship.
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( self::walk( ABSPATH . $dir, true ) as $file ) {
				if ( ! isset( $core[ $file ] ) ) {
					$queue[] = ( $checksums ? 'u|' : 'm|' ) . $file;
				}
			}
		}
		foreach ( self::walk( ABSPATH, false ) as $file ) {
			if ( ! isset( $core[ $file ] ) && 'wp-config.php' !== $file ) {
				$queue[] = ( $checksums ? 'u|' : 'm|' ) . $file;
			}
		}

		// Everything that can run as PHP inside wp-content, except this plugin.
		$self = '@content/' . trim( substr( wp_normalize_path( WP_PLUGIN_DIR ), strlen( wp_normalize_path( WP_CONTENT_DIR ) ) ), '/' ) . '/' . dirname( plugin_basename( SSHIELD_FILE ) ) . '/';
		foreach ( self::walk( WP_CONTENT_DIR, true ) as $file ) {
			if ( 0 !== strpos( $file, $self ) ) {
				$queue[] = 'm|' . $file;
			}
		}

		$queue = array_slice( array_values( array_unique( $queue ) ), 0, self::MAX_FILES );

		foreach ( self::exposed_files() as $file ) {
			$queue[] = 'x|' . $file;
		}

		// Plugins and themes from WordPress.org are compared with their official release.
		$org = array();
		foreach ( Vulns::installed() as $key => $sw ) {
			if ( 0 !== strpos( $key, 'core:' ) && '' !== $sw['version'] && ( 0 === strpos( $key, 'theme:' ) || false !== strpos( $sw['file'], '/' ) ) ) {
				$org[ $key ] = $sw['version'];
			}
		}

		Network::update_option(
			self::STATE_OPTION,
			array(
				'status'   => 'running',
				'trigger'  => $trigger,
				'started'  => time(),
				'queue'    => $queue,
				'pos'      => 0,
				'core'     => is_array( $checksums ),
				'findings' => array(),
				'scanned'  => 0,
				'org'      => $org,
				'org_done' => array(),
			),
			false
		);

		if ( 'manual' !== $trigger ) {
			Network::schedule_single( time() + 5, self::CRON_STEP );
		}
	}

	/**
	 * Background step for scheduled scans.
	 */
	public static function cron_step() {
		self::step( 20 );
		if ( self::running() ) {
			Network::schedule_single( time() + 5, self::CRON_STEP );
		}
	}

	/**
	 * Processes files until the time budget runs out.
	 *
	 * @param int $seconds Time budget.
	 * @return array Progress.
	 */
	public static function step( $seconds = 8 ) {
		$state = Network::get_option( self::STATE_OPTION );
		if ( ! is_array( $state ) || 'running' !== $state['status'] ) {
			return self::progress();
		}

		$until = microtime( true ) + $seconds;
		$total = count( $state['queue'] );
		if ( ! isset( $state['hashes'] ) ) {
			$state['hashes'] = array();
		}
		while ( $state['pos'] < $total && microtime( true ) < $until ) {
			$entry = $state['queue'][ $state['pos'] ];
			$watch = self::watched( $entry );
			if ( $watch ) {
				$path = WP_CONTENT_DIR . '/' . substr( $watch, 9 );
				$hash = is_readable( $path ) ? md5_file( $path ) : false;
				if ( $hash ) {
					$state['hashes'][ $watch ] = $hash;
				}
			}
			$finding = self::check_entry( $entry, $state );
			if ( $finding ) {
				$state['findings'][] = $finding;
			}
			++$state['pos'];
			++$state['scanned'];
		}

		if ( $state['pos'] >= $total ) {
			self::finish( $state );
			return self::progress();
		}

		Network::update_option( self::STATE_OPTION, $state, false );
		return self::progress();
	}

	/**
	 * Stores results, logs and alerts.
	 *
	 * @param array $state Finished state.
	 */
	private static function finish( array $state ) {
		$state['findings'] = array_merge( $state['findings'], self::compare_baseline( $state ) );
		$results           = array(
			'finished'      => time(),
			'started'       => $state['started'],
			'trigger'       => $state['trigger'],
			'core_checked'  => $state['core'],
			'org_checked'   => isset( $state['org_done'] ) ? count( array_filter( $state['org_done'] ) ) : 0,
			'files_scanned' => $state['scanned'],
			'findings'      => $state['findings'],
		);
		Network::update_option( self::RESULTS_OPTION, $results, false );
		Network::delete_option( self::STATE_OPTION );

		$open = self::open_findings( $results );
		$high = count(
			array_filter(
				$open,
				static function ( $f ) {
					return 'high' === $f['severity'];
				}
			)
		);

		Events::add(
			'scan',
			sprintf(
				/* translators: 1: files scanned, 2: number of findings. */
				__( 'Scan finished: %1$d files checked, %2$d issues found.', 'sentinel-shield' ),
				$state['scanned'],
				count( $open )
			),
			'',
			array(
				'severity' => $high ? Events::CRITICAL : ( $open ? Events::NOTICE : Events::INFO ),
				'action'   => 'scan.finished',
			)
		);

		if ( $open ) {
			$lines = array();
			foreach ( array_slice( $open, 0, 20 ) as $f ) {
				$lines[] = '- [' . strtoupper( $f['severity'] ) . '] ' . $f['file'] . ': ' . $f['label'];
			}
			Alerts::send(
				'alert_scan',
				/* translators: %d: number of issues. */
				sprintf( _n( 'Scan found %d issue', 'Scan found %d issues', count( $open ), 'sentinel-shield' ), count( $open ) ),
				__( 'The latest Sentinel Shield scan found files that need a look:', 'sentinel-shield' ) . "\n\n" . implode( "\n", $lines ),
				md5( wp_json_encode( wp_list_pluck( $open, 'id' ) ) )
			);
		}
	}

	/**
	 * Name of a plugin, theme or must-use plugin file whose changes are watched, or ''.
	 *
	 * @param string $entry Queue entry.
	 * @return string
	 */
	private static function watched( $entry ) {
		if ( 0 !== strpos( $entry, 'm|@content/' ) ) {
			return '';
		}
		$file = substr( $entry, 2 );
		return preg_match( '#^@content/(plugins|themes|mu-plugins)/#', $file ) ? $file : '';
	}

	/**
	 * Compares watched files with the last accepted copy and updates the baseline.
	 *
	 * A changed or new file keeps being reported until it is marked reviewed, so
	 * an attacker cannot hide a change by waiting for the next scan. Files updated
	 * through the WordPress updater are accepted automatically.
	 *
	 * @param array $state Finished scan state.
	 * @return array Findings.
	 */
	private static function compare_baseline( array $state ) {
		$current  = isset( $state['hashes'] ) ? $state['hashes'] : array();
		$baseline = Network::get_option( self::BASELINE );
		$expected = (array) Network::get_option( self::EXPECTED, array() );
		$started  = (int) $state['started'];
		// Updates that landed while this scan ran stay expected for the next one too.
		Network::update_option(
			self::EXPECTED,
			array_filter(
				$expected,
				static function ( $time ) use ( $started ) {
					return (int) $time >= $started;
				}
			),
			false
		);

		if ( ! is_array( $baseline ) ) {
			// First scan: remember what is there now.
			Network::update_option( self::BASELINE, $current, false );
			return array();
		}

		$ignored  = (array) Network::get_option( self::IGNORE_OPTION, array() );
		$flagged  = array_flip( wp_list_pluck( $state['findings'], 'file' ) );
		$findings = array();
		$next     = array();

		foreach ( $current as $file => $hash ) {
			$old = isset( $baseline[ $file ] ) ? $baseline[ $file ] : null;
			if ( $old === $hash || self::expected( $file, $expected ) ) {
				$next[ $file ] = $hash;
				continue;
			}
			$rule = null === $old ? 'new_file' : 'changed_file';
			$id   = md5( $file . '|' . $rule );
			if ( isset( $ignored[ $id ] ) && $ignored[ $id ] === $hash ) {
				// Reviewed: this version becomes the new baseline.
				$next[ $file ] = $hash;
				continue;
			}
			if ( null !== $old ) {
				$next[ $file ] = $old;
			}
			if ( isset( $flagged[ 'wp-content/' . substr( $file, 9 ) ] ) ) {
				// Already reported as malware.
				continue;
			}
			$findings[] = array(
				'id'       => $id,
				'file'     => 'wp-content/' . substr( $file, 9 ),
				'rule'     => $rule,
				'severity' => 'medium',
				'label'    => null === $old
					? __( 'New PHP file since the last scan, not added by an update', 'sentinel-shield' )
					: __( 'File changed since the last scan, not by an update', 'sentinel-shield' ),
				'line'     => 0,
				'snippet'  => '',
				'hash'     => $hash,
			);
		}
		Network::update_option( self::BASELINE, $next, false );
		return $findings;
	}

	/**
	 * Whether a file sits in a folder the updater changed.
	 *
	 * @param string $file     Watched file name.
	 * @param array  $expected Folder prefixes.
	 * @return bool
	 */
	private static function expected( $file, array $expected ) {
		foreach ( array_keys( $expected ) as $prefix ) {
			if ( 0 === strpos( $file, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Remembers that the updater changed a plugin or theme, so the next scan accepts it.
	 *
	 * @param string $prefix Watched name prefix, such as @content/plugins/akismet/.
	 */
	public static function expect_changes( $prefix ) {
		$expected            = (array) Network::get_option( self::EXPECTED, array() );
		$expected[ $prefix ] = time();
		Network::update_option( self::EXPECTED, $expected, false );
	}

	/**
	 * Findings that are not ignored, or whose file changed since it was ignored.
	 *
	 * @param array|null $results Optional results.
	 * @return array
	 */
	public static function open_findings( $results = null ) {
		$results = null === $results ? self::results() : $results;
		if ( ! $results ) {
			return array();
		}
		$ignored = (array) Network::get_option( self::IGNORE_OPTION, array() );
		return array_values(
			array_filter(
				$results['findings'],
				static function ( $f ) use ( $ignored ) {
					return ! isset( $ignored[ $f['id'] ] ) || $ignored[ $f['id'] ] !== $f['hash'];
				}
			)
		);
	}

	/**
	 * Marks a finding as reviewed. It comes back if the file changes.
	 *
	 * @param string $id Finding ID.
	 * @return bool
	 */
	public static function ignore( $id ) {
		$results = self::results();
		if ( ! $results ) {
			return false;
		}
		foreach ( $results['findings'] as $f ) {
			if ( $f['id'] === $id ) {
				$ignored        = (array) Network::get_option( self::IGNORE_OPTION, array() );
				$ignored[ $id ] = $f['hash'];
				Network::update_option( self::IGNORE_OPTION, $ignored, false );
				return true;
			}
		}
		return false;
	}

	/**
	 * Clears every ignored finding.
	 */
	public static function unignore_all() {
		Network::delete_option( self::IGNORE_OPTION );
	}

	/**
	 * Checks one queue entry.
	 *
	 * @param string $entry Queue entry: c|file|md5, u|file or m|file.
	 * @param array  $state Scan state, which caches the official checksums of the current plugin or theme.
	 * @return array|null Finding.
	 */
	private static function check_entry( $entry, array &$state = array() ) {
		$parts = explode( '|', $entry, 3 );
		$kind  = $parts[0];
		$file  = $parts[1];
		$path  = ABSPATH . $file;
		if ( 0 === strpos( $file, '@content/' ) ) {
			$path = WP_CONTENT_DIR . '/' . substr( $file, 9 );
		}

		if ( 'c' === $kind ) {
			if ( ! file_exists( $path ) ) {
				return self::finding( $file, 'missing', 'medium', __( 'Core file is missing', 'sentinel-shield' ), '' );
			}
			if ( md5_file( $path ) === $parts[2] ) {
				return null;
			}
			$malware = self::match_signatures( $file, $path );
			return $malware ? $malware : self::finding( $file, 'modified', 'high', __( 'Core file differs from the official WordPress copy', 'sentinel-shield' ), $path );
		}

		if ( 'x' === $kind ) {
			if ( ! is_file( $path ) ) {
				return null;
			}
			return preg_match( '/\.(?:php|phtml)$/i', $file ) && ! preg_match( '/^(?:phpinfo|info|adminer)/i', basename( $file ) )
				? null
				: self::finding( $file, 'exposed', preg_match( '/(?:debug\.log|error_log)$/', $file ) ? 'medium' : 'high', __( 'Backup, log or secret file that anyone may be able to download', 'sentinel-shield' ), $path );
		}

		if ( ! is_readable( $path ) ) {
			return null;
		}

		$malware = self::match_signatures( $file, $path );
		if ( $malware ) {
			return $malware;
		}
		if ( 'u' === $kind ) {
			return self::finding( $file, 'unknown', 'medium', __( 'File in a WordPress core folder that WordPress did not ship', 'sentinel-shield' ), $path );
		}
		if ( preg_match( '#^@content/uploads/#', $file ) ) {
			return self::finding( $file, 'php_upload', 'medium', __( 'PHP file inside the uploads folder', 'sentinel-shield' ), $path );
		}
		return self::check_official( $file, $path, $state );
	}

	/**
	 * Files in the web root and wp-content that often leak passwords or the database.
	 *
	 * The web server hands these out directly, so the firewall never sees the request.
	 *
	 * @return string[] Names relative to ABSPATH, or @content/... inside wp-content.
	 */
	public static function exposed_files() {
		$names = array(
			'wp-config.php.bak',
			'wp-config.bak',
			'wp-config.php.old',
			'wp-config.old',
			'wp-config.php~',
			'wp-config.php.save',
			'wp-config.php.orig',
			'wp-config.php.swp',
			'.wp-config.php.swp',
			'wp-config.php.txt',
			'wp-config.txt',
			'.env',
			'.env.local',
			'.env.production',
			'.git/config',
			'debug.log',
			'error_log',
			'phpinfo.php',
			'info.php',
			'adminer.php',
		);
		$out   = array();
		foreach ( $names as $name ) {
			if ( file_exists( ABSPATH . $name ) ) {
				$out[] = $name;
			}
		}
		foreach ( array( 'debug.log', 'error_log' ) as $name ) {
			if ( file_exists( WP_CONTENT_DIR . '/' . $name ) ) {
				$out[] = '@content/' . $name;
			}
		}
		foreach ( (array) glob( ABSPATH . '*' ) as $match ) {
			if ( is_file( $match ) && preg_match( '/\.(?:sql|sql\.gz|sql\.zip|tar|tar\.gz|tgz|zip|bak|7z|rar)$/i', $match ) ) {
				$out[] = basename( $match );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Compares a plugin or theme file with the official WordPress.org release.
	 *
	 * @param string $file  Relative name.
	 * @param string $path  Absolute path.
	 * @param array  $state Scan state.
	 * @return array|null Finding.
	 */
	private static function check_official( $file, $path, array &$state ) {
		if ( empty( $state['org'] ) || ! preg_match( '#^@content/(plugins|themes)/([^/]+)/(.+)$#', $file, $m ) ) {
			return null;
		}
		$type = 'plugins' === $m[1] ? 'plugin' : 'theme';
		$key  = $type . ':' . $m[2];
		if ( ! isset( $state['org'][ $key ] ) ) {
			return null;
		}
		$version = $state['org'][ $key ];
		if ( ! isset( $state['org_sums'] ) || $state['org_sums']['key'] !== $key ) {
			// Files are listed folder by folder, so one plugin's checksums are needed at a time.
			$state['org_sums']         = array(
				'key'  => $key,
				'sums' => self::official_sums( $type, $m[2], $version ),
			);
			$state['org_done'][ $key ] = is_array( $state['org_sums']['sums'] );
		}
		$sums = $state['org_sums']['sums'];
		if ( ! is_array( $sums ) ) {
			return null;
		}
		$rel = $m[3];
		if ( ! isset( $sums[ $rel ] ) ) {
			$finding = self::finding( $file, 'org_unknown', 'medium', __( 'PHP file that is not part of the official WordPress.org release', 'sentinel-shield' ), $path );
		} elseif ( in_array( md5_file( $path ), $sums[ $rel ], true ) ) {
			return null;
		} else {
			$finding = self::finding( $file, 'org_modified', 'high', __( 'File differs from the official WordPress.org release', 'sentinel-shield' ), $path );
		}
		$finding['source'] = array(
			'type'    => $type,
			'slug'    => $m[2],
			'version' => $version,
			'rel'     => $rel,
		);
		return $finding;
	}

	/**
	 * Official file checksums of a plugin or theme release, cached for a week.
	 *
	 * Plugins use the WordPress.org checksum API. Themes have none, so the release
	 * zip is downloaded once and hashed.
	 *
	 * @param string $type    plugin or theme.
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @return array|false Relative path => list of md5 hashes, or false when the release is not on WordPress.org.
	 */
	public static function official_sums( $type, $slug, $version ) {
		$key    = 'sshield_osum_' . md5( $type . '|' . $slug . '|' . $version );
		$cached = Network::get_transient( $key );
		if ( false !== $cached ) {
			return is_array( $cached ) ? $cached : false;
		}
		$sums = 'plugin' === $type ? self::plugin_sums( $slug, $version ) : self::theme_sums( $slug, $version );
		if ( null === $sums ) {
			// Network trouble: try again on the next scan.
			return false;
		}
		Network::set_transient( $key, $sums ? $sums : 'none', WEEK_IN_SECONDS );
		return $sums ? $sums : false;
	}

	/**
	 * Plugin checksums from WordPress.org.
	 *
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @return array|null Sums, an empty array when there are none, or null on network errors.
	 */
	private static function plugin_sums( $slug, $version ) {
		$response = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json', array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			return array();
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return 200 === $code ? array() : null;
		}
		$sums = array();
		foreach ( $data['files'] as $rel => $hashes ) {
			if ( isset( $hashes['md5'] ) ) {
				$sums[ (string) $rel ] = array_map( 'strval', (array) $hashes['md5'] );
			}
		}
		return $sums;
	}

	/**
	 * Theme checksums, from the release zip on WordPress.org.
	 *
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @return array|null Sums, an empty array when there are none, or null on network errors.
	 */
	private static function theme_sums( $slug, $version ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return array();
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$tmp      = wp_tempnam( 'sshield-theme' );
		$response = wp_remote_get(
			'https://downloads.wordpress.org/theme/' . rawurlencode( $slug ) . '.' . rawurlencode( $version ) . '.zip',
			array(
				'timeout'  => 30,
				'stream'   => true,
				'filename' => $tmp,
			)
		);
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			wp_delete_file( $tmp );
			return 404 === $code ? array() : null;
		}
		$zip  = new \ZipArchive();
		$sums = array();
		if ( true === $zip->open( $tmp ) ) {
			$prefix = $slug . '/';
			for ( $i = 0; $i < $zip->numFiles; $i++ ) { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- ZipArchive property.
				$name = (string) $zip->getNameIndex( $i );
				if ( 0 !== strpos( $name, $prefix ) || '/' === substr( $name, -1 ) ) {
					continue;
				}
				$data = $zip->getFromIndex( $i );
				if ( false !== $data ) {
					$sums[ substr( $name, strlen( $prefix ) ) ] = array( md5( $data ) );
				}
			}
			$zip->close();
		}
		wp_delete_file( $tmp );
		return $sums;
	}

	/**
	 * Malware signatures.
	 *
	 * @return array Key => [ label, severity, pattern ].
	 */
	public static function signatures() {
		$signatures = array(
			'eval_decode'   => array(
				'label'    => __( 'Runs hidden code (eval of decoded data)', 'sentinel-shield' ),
				'severity' => 'high',
				'pattern'  => '/\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\(/i',
			),
			'request_exec'  => array(
				'label'    => __( 'Runs commands or code sent by visitors', 'sentinel-shield' ),
				'severity' => 'high',
				'pattern'  => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|eval|assert|create_function)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*|base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/i',
			),
			'request_call'  => array(
				'label'    => __( 'Calls a function named by visitor input', 'sentinel-shield' ),
				'severity' => 'high',
				'pattern'  => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/',
			),
			'preg_e'        => array(
				'label'    => __( 'preg_replace with the /e code execution modifier', 'sentinel-shield' ),
				'severity' => 'high',
				'pattern'  => '/preg_replace\s*\(\s*([\'"])([^\w\s\\\\]).{0,300}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1\s*,/i',
			),
			'webshell'      => array(
				'label'    => __( 'Known web shell marker', 'sentinel-shield' ),
				'severity' => 'high',
				'pattern'  => '/(?:FilesMan|c99shell|r57shell|b374k|IndoXploit|WSOsetcookie|wso_version|Weevely|AnonymousFox|\bgaestebuch_shell)/i',
			),
			'hex_eval'      => array(
				'label'    => __( 'Function name hidden with escape codes', 'sentinel-shield' ),
				'severity' => 'medium',
				'pattern'  => '/(?:\\\\x65\\\\x76\\\\x61\\\\x6c|\\\\145\\\\166\\\\141\\\\154|\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34|\\\\x73\\\\x79\\\\x73\\\\x74\\\\x65\\\\x6d)/i',
			),
			'globals_obf'   => array(
				'label'    => __( 'Obfuscated globals access', 'sentinel-shield' ),
				'severity' => 'medium',
				'pattern'  => '/\$\{\s*[\'"]\\\\x47|\$GLOBALS\s*\[\s*[\'"]\\\\x[0-9a-f]{2}/i',
			),
			'upload_writer' => array(
				'label'    => __( 'Writes visitor input straight to a file', 'sentinel-shield' ),
				'severity' => 'medium',
				'pattern'  => '/\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
			),
		);

		/**
		 * Filters the malware signatures.
		 *
		 * @param array $signatures Key => [ label, severity (high|medium), pattern ].
		 */
		return (array) apply_filters( 'sshield_scan_signatures', $signatures );
	}

	/**
	 * Matches a file against the signatures.
	 *
	 * @param string $file Relative name.
	 * @param string $path Absolute path.
	 * @return array|null Finding.
	 */
	private static function match_signatures( $file, $path ) {
		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable files are skipped.
		if ( $size <= 0 ) {
			return null;
		}
		$content = file_get_contents( $path, false, null, 0, self::MAX_BYTES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( false === $content ) {
			return null;
		}

		foreach ( self::signatures() as $key => $sig ) {
			if ( preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$line  = substr_count( $content, "\n", 0, $m[0][1] ) + 1;
				$start = max( 0, $m[0][1] - 40 );
				$snip  = substr( $content, $start, 160 );
				$snip  = preg_replace( '/\s+/', ' ', wp_check_invalid_utf8( $snip, true ) );
				return self::finding( $file, $key, $sig['severity'], $sig['label'], $path, $line, $snip );
			}
		}

		// Huge encoded blobs next to a code runner are a classic dropper pattern.
		if ( preg_match( '/[\'"][A-Za-z0-9+\/=]{3000,}[\'"]/', $content ) && preg_match( '/\b(?:eval|assert|create_function|gzinflate|base64_decode)\s*\(/i', $content ) ) {
			return self::finding( $file, 'encoded_blob', 'medium', __( 'Large encoded data block next to code that decodes or runs it', 'sentinel-shield' ), $path );
		}
		return null;
	}

	/**
	 * Builds a finding.
	 *
	 * @param string $file     Relative name.
	 * @param string $rule     Rule key.
	 * @param string $severity high or medium.
	 * @param string $label    Description.
	 * @param string $path     Absolute path, for the file hash.
	 * @param int    $line     Line number.
	 * @param string $snippet  Matched text.
	 * @return array
	 */
	private static function finding( $file, $rule, $severity, $label, $path, $line = 0, $snippet = '' ) {
		$display = 0 === strpos( $file, '@content/' ) ? 'wp-content/' . substr( $file, 9 ) : $file;
		return array(
			'id'       => md5( $file . '|' . $rule ),
			'file'     => $display,
			'rule'     => $rule,
			'severity' => $severity,
			'label'    => $label,
			'line'     => (int) $line,
			'snippet'  => (string) $snippet,
			'hash'     => $path && is_readable( $path ) ? (string) md5_file( $path ) : '',
		);
	}

	/**
	 * Official checksums for this WordPress version, cached for a day.
	 *
	 * @return array|false Relative path => md5, or false when WordPress.org cannot be reached.
	 */
	public static function core_checksums() {
		global $wp_version;
		$locale = get_locale();
		$key    = 'sshield_sums_' . md5( $wp_version . $locale );
		$cached = Network::get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$sums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $sums ) || ! $sums ) {
			return false;
		}
		Network::set_transient( $key, $sums, DAY_IN_SECONDS );
		return $sums;
	}

	/**
	 * Lists PHP-capable files under a folder.
	 *
	 * @param string $dir       Absolute folder.
	 * @param bool   $recursive Whether to descend.
	 * @return string[] Names relative to ABSPATH, or prefixed with @content/ inside wp-content.
	 */
	private static function walk( $dir, $recursive ) {
		$files = array();
		if ( ! is_dir( $dir ) ) {
			return $files;
		}
		$skip = array( '.git', '.svn', 'node_modules', 'cache' );
		if ( $recursive ) {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
					static function ( $current ) use ( $skip ) {
						return ! ( $current->isDir() && in_array( $current->getFilename(), $skip, true ) );
					}
				),
				\RecursiveIteratorIterator::LEAVES_ONLY,
				\RecursiveIteratorIterator::CATCH_GET_CHILD
			);
		} else {
			$iterator = new \FilesystemIterator( $dir, \FilesystemIterator::SKIP_DOTS );
		}
		foreach ( $iterator as $info ) {
			if ( $info->isFile() && in_array( strtolower( $info->getExtension() ), self::$php_ext, true ) ) {
				$files[] = self::relative( $info->getPathname() );
				if ( count( $files ) >= self::MAX_FILES ) {
					break;
				}
			}
		}
		return $files;
	}

	/**
	 * Path relative to ABSPATH, or @content/... for wp-content which may live elsewhere.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private static function relative( $path ) {
		$path    = wp_normalize_path( $path );
		$content = wp_normalize_path( WP_CONTENT_DIR ) . '/';
		$root    = wp_normalize_path( ABSPATH );
		if ( 0 === strpos( $path, $content ) ) {
			return '@content/' . substr( $path, strlen( $content ) );
		}
		if ( 0 === strpos( $path, $root ) ) {
			return substr( $path, strlen( $root ) );
		}
		return $path;
	}
}
