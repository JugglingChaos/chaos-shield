<?php
/**
 * Fingerprints of critical files, checked every hour.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps an accepted fingerprint (SHA-256 and MD5) of the files an attacker
 * changes first, and reports any difference until it is accepted or put back.
 *
 * The full scan compares core with WordPress.org and plugins with their
 * releases. This covers what no release can vouch for: wp-config.php, the
 * server config files, drop-ins and must-use plugins, plus the core files that
 * run on every request, checked often instead of once a day.
 */
final class Integrity {

	const OPTION   = 'cshield_integrity';
	const HOOK     = 'cshield_integrity_check';
	const ACTION   = 'cshield_integrity';
	const MAX_TEXT = 65536;

	/**
	 * Files that may change within a few minutes without a report: name => time.
	 *
	 * @var array
	 */
	private static $expect = array();

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'check' ) );
		add_action( 'init', array( __CLASS__, 'schedule' ) );
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		// Changes WordPress makes itself on an administrator's request.
		add_action( '_core_updated_successfully', array( __CLASS__, 'after_core_update' ) );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'after_update' ), 30, 2 );
		add_action( 'generate_rewrite_rules', array( __CLASS__, 'rewrite_rules_saved' ) );
		add_action( 'after_switch_theme', array( __CLASS__, 'after_theme_switch' ) );
	}

	/**
	 * Whether the watch is switched on.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return Settings::enabled( 'file_watch' );
	}

	/**
	 * Runs the hourly check on the main site.
	 */
	public static function schedule() {
		$next = Network::next_scheduled( self::HOOK );
		if ( self::enabled() && ! $next && Network::on_main_site() ) {
			Network::schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'hourly', self::HOOK );
		} elseif ( ! self::enabled() && $next ) {
			Network::clear_scheduled( self::HOOK );
		}
	}

	/**
	 * Path of wp-config.php, which may sit one folder above WordPress.
	 *
	 * @return string
	 */
	private static function config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$up = dirname( ABSPATH ) . '/wp-config.php';
		return file_exists( $up ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ? $up : ABSPATH . 'wp-config.php';
	}

	/**
	 * The watched files.
	 *
	 * @return array Name => path, group, text (keep a copy to compare and put back), appear (a new file is suspicious).
	 */
	public static function files() {
		$root    = wp_normalize_path( ABSPATH );
		$content = wp_normalize_path( WP_CONTENT_DIR );
		$uploads = wp_upload_dir( null, false );
		$list    = array();
		$add     = static function ( $name, $path, $group, $text = false, $appear = false ) use ( &$list ) {
			$list[ $name ] = array(
				'path'   => wp_normalize_path( $path ),
				'group'  => $group,
				'text'   => $text,
				'appear' => $appear,
			);
		};

		$add( 'wp-config.php', self::config_path(), 'config' );
		foreach ( array( '.htaccess', '.user.ini', 'php.ini', 'web.config' ) as $file ) {
			$add( $file, $root . $file, 'config', true, true );
		}
		$add( 'wp-content/.htaccess', $content . '/.htaccess', 'config', true, true );
		if ( empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) ) {
			$add( 'wp-content/uploads/.htaccess', $uploads['basedir'] . '/.htaccess', 'config', true, true );
		}
		foreach ( array( 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'wp-login.php', 'wp-cron.php', 'xmlrpc.php', 'wp-includes/version.php', 'wp-includes/load.php', 'wp-includes/plugin.php', 'wp-includes/pluggable.php', 'wp-includes/functions.php', 'wp-admin/admin.php', 'wp-admin/index.php' ) as $file ) {
			$add( $file, $root . $file, 'core' );
		}
		if ( ! function_exists( '_get_dropins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( array_keys( _get_dropins() ) as $file ) {
			$add( 'wp-content/' . $file, $content . '/' . $file, 'dropin', false, true );
		}
		$add( 'wp-content/index.php', $content . '/index.php', 'dropin', false, true );
		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? wp_normalize_path( WPMU_PLUGIN_DIR ) : $content . '/mu-plugins';
		foreach ( (array) glob( $mu . '/*.php' ) as $file ) {
			$add( 'wp-content/mu-plugins/' . basename( $file ), $file, 'mu', false, true );
		}
		foreach ( array_unique( array( get_stylesheet_directory(), get_template_directory() ) ) as $dir ) {
			$add( 'wp-content/themes/' . basename( $dir ) . '/functions.php', $dir . '/functions.php', 'theme' );
		}
		/**
		 * Filters the files whose fingerprints are watched.
		 *
		 * @param array $list Name => path, group, text, appear.
		 */
		return (array) apply_filters( 'cshield_critical_files', $list );
	}

	/**
	 * Group names.
	 *
	 * @return array
	 */
	public static function groups() {
		return array(
			'config' => __( 'Site and server config', 'chaos-shield' ),
			'core'   => __( 'WordPress core, runs on every request', 'chaos-shield' ),
			'dropin' => __( 'Drop-in, loads before plugins', 'chaos-shield' ),
			'mu'     => __( 'Must-use plugin, always runs', 'chaos-shield' ),
			'theme'  => __( 'Active theme', 'chaos-shield' ),
		);
	}

	/**
	 * Fingerprint of one file as it is now.
	 *
	 * @param array $file Entry of files().
	 * @param bool  $name_is_config Whether to keep line fingerprints, for wp-config.php.
	 * @return array exists, sha256, md5, size, mtime, and text or lines.
	 */
	public static function fingerprint( array $file, $name_is_config = false ) {
		clearstatcache( true, $file['path'] );
		if ( ! is_file( $file['path'] ) || ! is_readable( $file['path'] ) ) {
			return array( 'exists' => false );
		}
		$data = (string) file_get_contents( $file['path'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$rec  = array(
			'exists' => true,
			'sha256' => hash( 'sha256', $data ),
			'md5'    => md5( $data ),
			'size'   => strlen( $data ),
			'mtime'  => (int) filemtime( $file['path'] ),
		);
		if ( $file['text'] && strlen( $data ) <= self::MAX_TEXT ) {
			$rec['text'] = $data;
		} elseif ( $name_is_config && strlen( $data ) <= self::MAX_TEXT ) {
			// Line fingerprints only: the file holds the database password and salts.
			$rec['lines'] = array_map(
				static function ( $line ) {
					return substr( md5( rtrim( $line ) ), 0, 12 );
				},
				preg_split( '/\R/', $data )
			);
		}
		return $rec;
	}

	/**
	 * Stored state.
	 *
	 * @return array checked, files => name => base, now, seen.
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION );
		return is_array( $state ) ? $state + array(
			'checked' => 0,
			'files'   => array(),
		) : array(
			'checked' => 0,
			'files'   => array(),
		);
	}

	/**
	 * Whether two fingerprints are the same file.
	 *
	 * @param array $a Fingerprint.
	 * @param array $b Fingerprint.
	 * @return bool
	 */
	private static function same( array $a, array $b ) {
		if ( empty( $a['exists'] ) || empty( $b['exists'] ) ) {
			return empty( $a['exists'] ) === empty( $b['exists'] );
		}
		return $a['sha256'] === $b['sha256'];
	}

	/**
	 * Compares every watched file with its accepted fingerprint.
	 *
	 * @param bool $notify Log and alert new changes.
	 * @return array Names that changed and are not accepted.
	 */
	public static function check( $notify = true ) {
		if ( ! self::enabled() ) {
			return array();
		}
		$state   = self::state();
		$first   = ! $state['checked'];
		$expect  = array_merge( (array) Network::get_option( self::OPTION . '_expect', array() ), self::$expect );
		$fresh   = array();
		$changed = array();
		$files   = self::files();
		foreach ( $files as $name => $file ) {
			$now  = self::fingerprint( $file, 'wp-config.php' === $name );
			$prev = isset( $state['files'][ $name ] ) ? $state['files'][ $name ] : null;
			if ( null === $prev ) {
				// A watched file seen for the first time joins as it is, unless it should not
				// suddenly exist, such as a new drop-in or must-use plugin.
				$appeared                = ! $first && $file['appear'] && $now['exists'];
				$state['files'][ $name ] = array(
					'base' => $appeared ? array( 'exists' => false ) : $now,
					'now'  => $appeared ? $now : null,
					'seen' => $appeared ? time() : 0,
				);
				if ( $appeared ) {
					$fresh[]   = $name;
					$changed[] = $name;
				}
				continue;
			}
			if ( self::same( $prev['base'], $now ) || ( isset( $expect[ $name ] ) && $expect[ $name ] > time() - 10 * MINUTE_IN_SECONDS ) ) {
				$state['files'][ $name ] = array(
					'base' => $now,
					'now'  => null,
					'seen' => 0,
				);
				continue;
			}
			if ( empty( $prev['now'] ) || ! self::same( $prev['now'], $now ) ) {
				$fresh[] = $name;
			}
			$state['files'][ $name ] = array(
				'base' => $prev['base'],
				'now'  => $now,
				'seen' => ! empty( $prev['seen'] ) && ! empty( $prev['now'] ) && self::same( $prev['now'], $now ) ? $prev['seen'] : time(),
			);
			$changed[]               = $name;
		}
		// Files that left the list, such as an old theme's functions.php or a removed must-use plugin.
		foreach ( array_keys( $state['files'] ) as $name ) {
			if ( ! isset( $files[ $name ] ) ) {
				unset( $state['files'][ $name ] );
			}
		}
		$state['checked'] = time();
		Network::update_option( self::OPTION, $state, false );
		Network::delete_option( self::OPTION . '_expect' );

		if ( $notify && $fresh ) {
			$lines = array();
			foreach ( $fresh as $name ) {
				$lines[] = '- ' . $name . ': ' . self::describe( $state['files'][ $name ] );
			}
			Events::add(
				'scan',
				/* translators: %s: list of files. */
				sprintf( __( 'Critical file changed: %s.', 'chaos-shield' ), implode( ', ', $fresh ) ),
				'',
				array(
					'severity' => Events::CRITICAL,
					'action'   => 'integrity.changed',
					'subject'  => implode( ',', $fresh ),
				)
			);
			Alerts::send(
				'alert_scan',
				/* translators: %d: number of files. */
				sprintf( _n( '%d critical file changed', '%d critical files changed', count( $fresh ), 'chaos-shield' ), count( $fresh ) ),
				__( 'These files no longer match their accepted fingerprint. If you did not change them, treat this as a break-in:', 'chaos-shield' ) . "\n\n" . implode( "\n", $lines ) . "\n\n" . Network::admin_url( 'admin.php?page=' . Admin::SLUG . '&tab=scan#cshield-integrity' ),
				'integrity-' . md5( wp_json_encode( wp_list_pluck( array_intersect_key( $state['files'], array_flip( $fresh ) ), 'now' ) ) )
			);
		}
		return $changed;
	}

	/**
	 * What happened to a file, in words.
	 *
	 * @param array $entry State entry.
	 * @return string
	 */
	public static function describe( array $entry ) {
		$base = $entry['base'];
		$now  = $entry['now'];
		if ( empty( $now['exists'] ) ) {
			return __( 'deleted', 'chaos-shield' );
		}
		if ( empty( $base['exists'] ) ) {
			return __( 'new file', 'chaos-shield' );
		}
		/* translators: 1: old size in bytes, 2: new size in bytes. */
		return sprintf( __( 'contents changed (%1$s to %2$s bytes)', 'chaos-shield' ), number_format_i18n( $base['size'] ), number_format_i18n( $now['size'] ) );
	}

	/**
	 * Files that differ from their accepted fingerprint.
	 *
	 * @return array Name => state entry.
	 */
	public static function changed() {
		return array_filter(
			self::state()['files'],
			static function ( $entry ) {
				return ! empty( $entry['now'] );
			}
		);
	}

	/**
	 * Accepts the current version of a file as its fingerprint.
	 *
	 * @param string $name File name, or '' for every changed file.
	 * @return int Files accepted.
	 */
	public static function accept( $name = '' ) {
		$state = self::state();
		$done  = 0;
		foreach ( $state['files'] as $key => $entry ) {
			if ( ( '' === $name || $key === $name ) && ! empty( $entry['now'] ) ) {
				$state['files'][ $key ] = array(
					'base' => $entry['now'],
					'now'  => null,
					'seen' => 0,
				);
				++$done;
			}
		}
		Network::update_option( self::OPTION, $state, false );
		return $done;
	}

	/**
	 * Lets one file change during the next few minutes, for changes made on request.
	 *
	 * @param string $name File name.
	 */
	public static function expect( $name ) {
		self::$expect[ $name ] = time();
		$saved                 = (array) Network::get_option( self::OPTION . '_expect', array() );
		$saved[ $name ]        = time();
		Network::update_option( self::OPTION . '_expect', $saved, false );
	}

	/**
	 * Re-fingerprints a group after WordPress changed it on request.
	 *
	 * @param string $group Group key.
	 */
	private static function accept_group( $group ) {
		foreach ( self::files() as $name => $file ) {
			if ( $group === $file['group'] ) {
				self::expect( $name );
			}
		}
		self::check( false );
	}

	/**
	 * Core was updated: its files changed on purpose.
	 */
	public static function after_core_update() {
		self::accept_group( 'core' );
	}

	/**
	 * A theme was updated: its functions.php changed on purpose.
	 *
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param array        $extra    Details.
	 */
	public static function after_update( $upgrader, $extra ) {
		if ( isset( $extra['type'] ) && 'theme' === $extra['type'] ) {
			self::accept_group( 'theme' );
		} elseif ( isset( $extra['type'] ) && 'core' === $extra['type'] ) {
			self::accept_group( 'core' );
		}
	}

	/**
	 * The active theme changed, so its functions.php joins the list as it is.
	 */
	public static function after_theme_switch() {
		self::accept_group( 'theme' );
	}

	/**
	 * WordPress is about to write its rewrite rules to .htaccess.
	 */
	public static function rewrite_rules_saved() {
		if ( current_user_can( 'manage_options' ) ) {
			self::expect( '.htaccess' );
		}
	}

	/**
	 * Lines of wp-config.php that are new since the accepted version, with secrets masked.
	 *
	 * @param array $entry State entry for wp-config.php.
	 * @return array|null Line number => masked text, or null when it cannot be told.
	 */
	public static function config_changes( array $entry ) {
		if ( empty( $entry['base']['lines'] ) || empty( $entry['now']['exists'] ) ) {
			return null;
		}
		$files = self::files();
		$data  = is_readable( $files['wp-config.php']['path'] ) ? (string) file_get_contents( $files['wp-config.php']['path'] ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$lines = preg_split( '/\R/', $data );
		$known = array_count_values( $entry['base']['lines'] );
		$new   = array();
		foreach ( $lines as $i => $line ) {
			$hash = substr( md5( rtrim( $line ) ), 0, 12 );
			if ( ! empty( $known[ $hash ] ) ) {
				--$known[ $hash ];
				continue;
			}
			$new[ $i + 1 ] = self::mask( $line );
		}
		return array_slice( $new, 0, 40, true );
	}

	/**
	 * Lines of the accepted version that are gone now.
	 *
	 * @param array $entry State entry for wp-config.php.
	 * @return int
	 */
	public static function config_removed( array $entry ) {
		if ( empty( $entry['base']['lines'] ) || empty( $entry['now']['lines'] ) ) {
			return 0;
		}
		$now     = array_count_values( $entry['now']['lines'] );
		$removed = 0;
		foreach ( $entry['base']['lines'] as $hash ) {
			if ( empty( $now[ $hash ] ) ) {
				++$removed;
			} else {
				--$now[ $hash ];
			}
		}
		return $removed;
	}

	/**
	 * A config line with password, key and salt values hidden.
	 *
	 * @param string $line Line.
	 * @return string
	 */
	public static function mask( $line ) {
		$line = (string) preg_replace( '/(define\s*\(\s*[\'"][A-Z0-9_]*(?:KEY|SALT|PASSWORD|PASS|SECRET|TOKEN|USER)[A-Z0-9_]*[\'"]\s*,\s*)([\'"]).*?\2/i', '$1$2••••••$2', $line );
		return mb_substr( $line, 0, 300 );
	}

	/**
	 * Puts the accepted copy of a text file back, after saving the current one as a restore point.
	 *
	 * @param string $name File name.
	 * @return true|\WP_Error
	 */
	public static function restore( $name ) {
		$state = self::state();
		$files = self::files();
		if ( ! isset( $state['files'][ $name ], $files[ $name ] ) || empty( $state['files'][ $name ]['now'] ) ) {
			return new \WP_Error( 'cshield_int_none', __( 'That file has nothing to put back.', 'chaos-shield' ) );
		}
		$base = $state['files'][ $name ]['base'];
		$path = $files[ $name ]['path'];
		if ( ! empty( $base['exists'] ) && ! isset( $base['text'] ) ) {
			return new \WP_Error( 'cshield_int_text', __( 'Only config files can be put back from here. Use a restore point or a repair from the scan for this one.', 'chaos-shield' ) );
		}
		if ( is_file( $path ) ) {
			$point = Restore_Points::create( 'repair', $name, array( $path ), array(), false );
			if ( is_wp_error( $point ) ) {
				return $point;
			}
		}
		if ( empty( $base['exists'] ) ) {
			wp_delete_file( $path );
			$ok = ! file_exists( $path );
		} else {
			$ok = false !== file_put_contents( $path, $base['text'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Puts back the accepted copy on request.
		}
		if ( ! $ok ) {
			return new \WP_Error( 'cshield_int_write', __( 'Could not write the file. Check its permissions.', 'chaos-shield' ) );
		}
		Events::add(
			'scan',
			/* translators: %s: file name. */
			sprintf( __( 'Put back the accepted version of %s.', 'chaos-shield' ), $name ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'integrity.restored',
				'subject'  => $name,
			)
		);
		self::check( false );
		return true;
	}

	/**
	 * Every fingerprint as JSON, to keep outside the site and compare later.
	 */
	public static function export() {
		$out = array();
		foreach ( self::state()['files'] as $name => $entry ) {
			$rec = empty( $entry['now'] ) ? $entry['base'] : $entry['now'];
			if ( empty( $rec['exists'] ) ) {
				continue;
			}
			$out[ $name ] = array(
				'sha256'   => $rec['sha256'],
				'md5'      => $rec['md5'],
				'size'     => $rec['size'],
				'modified' => gmdate( 'c', $rec['mtime'] ),
				'accepted' => empty( $entry['now'] ),
			);
		}
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="chaos-shield-fingerprints-' . gmdate( 'Y-m-d' ) . '.json"' );
		echo wp_json_encode( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- A JSON download.
			array(
				'site'    => network_home_url(),
				'made'    => gmdate( 'c' ),
				'version' => CSHIELD_VERSION,
				'files'   => $out,
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		);
		exit;
	}

	/**
	 * Check, accept, put back and export from the Scan tab.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( self::ACTION );
		$op   = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$name = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$note = 'int_checked';
		if ( 'export' === $op ) {
			self::export();
		} elseif ( 'accept' === $op || 'accept_all' === $op ) {
			$count = self::accept( 'accept' === $op ? $name : '' );
			Events::add(
				'scan',
				'accept' === $op
					/* translators: %s: file name. */
					? sprintf( __( 'Accepted the change to %s as the new fingerprint.', 'chaos-shield' ), $name )
					/* translators: %d: number of files. */
					: sprintf( __( 'Accepted %d changed critical files as their new fingerprints.', 'chaos-shield' ), $count ),
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => 'integrity.accepted',
					'subject'  => $name,
				)
			);
			$note = 'int_accepted';
		} elseif ( 'restore' === $op ) {
			$done = self::restore( $name );
			if ( is_wp_error( $done ) ) {
				Network::set_transient( 'cshield_error_' . get_current_user_id(), $done->get_error_message(), MINUTE_IN_SECONDS );
				$note = '';
			} else {
				$note = 'int_restored';
			}
		} else {
			self::check();
		}
		wp_safe_redirect( Admin::url( 'scan', $note ? array( 'cshield_notice' => $note ) : array() ) . '#cshield-integrity' );
		exit;
	}
}
