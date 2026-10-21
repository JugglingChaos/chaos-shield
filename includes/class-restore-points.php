<?php
/**
 * Restore points: copies of settings and files taken before risky changes.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Saves what a change is about to replace, so it can be put back in one click.
 *
 * A restore point is taken before plugin and theme updates, before a file is
 * repaired from WordPress.org, before Chaos Shield settings change and on
 * request. Each point is a folder in wp-content/cshield-restore holding the
 * compressed files and a manifest. Every stored file starts with a PHP exit
 * line, so even on a server that ignores the folder's deny rules, a direct
 * request runs nothing and shows nothing.
 */
final class Restore_Points {

	const INDEX        = 'cshield_restore_points';
	const DIR          = 'cshield-restore';
	const ACTION       = 'cshield_restore';
	const MAX_POINTS   = 20;
	const MAX_AGE      = 30 * DAY_IN_SECONDS;
	const MAX_BYTES    = 250 * MB_IN_BYTES;
	const MAX_FOLDER   = 60 * MB_IN_BYTES;
	const MAX_FILES    = 6000;
	const GUARD        = "<?php exit; ?>\n";
	const SETTINGS_GAP = 600;

	/**
	 * Set while a restore writes settings back, so that write is not itself saved.
	 *
	 * @var bool
	 */
	private static $restoring = false;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
		if ( self::enabled() ) {
			add_filter( 'upgrader_pre_install', array( $this, 'before_update' ), 10, 2 );
		}
	}

	/**
	 * Whether automatic restore points are on.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return Settings::enabled( 'restore_points' );
	}

	/**
	 * Restore points, newest first.
	 *
	 * @return array ID => [ time, reason, label, user, bytes, files, settings ].
	 */
	public static function all() {
		$index = Network::get_option( self::INDEX, array() );
		$index = is_array( $index ) ? $index : array();
		uasort(
			$index,
			static function ( $a, $b ) {
				// Points taken within the same second keep the order they were taken in.
				$a_at = isset( $a['at'] ) ? (float) $a['at'] : (float) $a['time'];
				$b_at = isset( $b['at'] ) ? (float) $b['at'] : (float) $b['time'];
				return $b_at <=> $a_at;
			}
		);
		return $index;
	}

	/**
	 * Labels for the reasons a point was taken.
	 *
	 * @return array
	 */
	public static function reasons() {
		return array(
			'manual'   => __( 'Made by hand', 'chaos-shield' ),
			'update'   => __( 'Before an update', 'chaos-shield' ),
			'repair'   => __( 'Before a file repair', 'chaos-shield' ),
			'settings' => __( 'Before a settings change', 'chaos-shield' ),
			'import'   => __( 'Before a settings import', 'chaos-shield' ),
			'restore'  => __( 'Before a restore', 'chaos-shield' ),
		);
	}

	// Taking points.

	/**
	 * Takes a restore point.
	 *
	 * @param string $reason   One of reasons().
	 * @param string $label    What is about to change, for the list.
	 * @param array  $files    Absolute paths of single files. Missing files are noted, so a restore removes them again.
	 * @param array  $folders  Absolute paths of folders, saved whole (a plugin or theme).
	 * @param bool   $settings Whether to include the Chaos Shield settings.
	 * @return string|\WP_Error Point ID.
	 */
	public static function create( $reason, $label, array $files = array(), array $folders = array(), $settings = true ) {
		$base = self::base();
		if ( is_wp_error( $base ) ) {
			return $base;
		}
		$id  = strtolower( wp_generate_password( 20, false ) );
		$dir = $base . '/' . $id;
		if ( ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'cshield_rp_dir', __( 'Could not create the restore point folder. Check the permissions of wp-content.', 'chaos-shield' ) );
		}
		self::guard( $dir );

		$items = array();
		$bytes = 0;
		$n     = 0;
		$fail  = null;
		foreach ( $files as $path ) {
			$key = self::key( $path );
			if ( '' === $key ) {
				continue;
			}
			if ( ! is_file( $path ) ) {
				$items[] = array(
					'kind' => 'absent',
					'path' => $key,
				);
				continue;
			}
			$item = self::store( $dir, ++$n, $path );
			if ( is_wp_error( $item ) ) {
				$fail = $item;
				break;
			}
			$item['kind'] = 'file';
			$item['path'] = $key;
			$bytes       += $item['stored'];
			$items[]      = $item;
		}
		foreach ( $folders as $folder ) {
			$folder = untrailingslashit( wp_normalize_path( $folder ) );
			$key    = self::key( $folder );
			if ( $fail || '' === $key || ! is_dir( $folder ) ) {
				continue;
			}
			$list = self::walk( $folder );
			if ( is_wp_error( $list ) ) {
				$fail = $list;
				break;
			}
			$items[] = array(
				'kind' => 'folder',
				'path' => $key,
			);
			foreach ( $list as $path ) {
				$item = self::store( $dir, ++$n, $path );
				if ( is_wp_error( $item ) ) {
					$fail = $item;
					break 2;
				}
				$item['kind']   = 'member';
				$item['folder'] = $key;
				$item['path']   = self::key( $path );
				$bytes         += $item['stored'];
				$items[]        = $item;
			}
		}
		if ( $fail ) {
			self::remove_dir( $dir );
			return $fail;
		}

		$manifest = array(
			'items'    => $items,
			'settings' => $settings ? Network::get_option( Settings::OPTION, array() ) : null,
		);
		if ( false === file_put_contents( $dir . '/manifest.php', self::GUARD . wp_json_encode( $manifest ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The plugin's own restore folder.
			self::remove_dir( $dir );
			return new \WP_Error( 'cshield_rp_write', __( 'Could not write the restore point. Check the free disk space.', 'chaos-shield' ) );
		}

		$index        = self::all();
		$index[ $id ] = array(
			'time'     => time(),
			'at'       => microtime( true ),
			'reason'   => array_key_exists( $reason, self::reasons() ) ? $reason : 'manual',
			'label'    => mb_substr( sanitize_text_field( $label ), 0, 160 ),
			'user'     => get_current_user_id(),
			'bytes'    => $bytes,
			'files'    => count(
				array_filter(
					$items,
					static function ( $i ) {
						return in_array( $i['kind'], array( 'file', 'member' ), true );
					}
				)
			),
			'settings' => (bool) $settings,
		);
		Network::update_option( self::INDEX, $index, false );
		self::prune( $id );
		return $id;
	}

	/**
	 * Takes a point of the settings before they change, at most one per ten minutes
	 * so a burst of saves keeps the state from before the burst.
	 */
	public static function before_settings_change() {
		if ( self::$restoring || ! self::enabled() ) {
			return;
		}
		foreach ( self::all() as $point ) {
			if ( in_array( $point['reason'], array( 'settings', 'import', 'restore' ), true ) && time() - (int) $point['time'] < self::SETTINGS_GAP ) {
				return;
			}
			break;
		}
		self::create( 'settings', __( 'Chaos Shield settings', 'chaos-shield' ) );
	}

	/**
	 * Saves a plugin or theme before the upgrader replaces it.
	 *
	 * @param bool|\WP_Error $response   Install response so far.
	 * @param array          $hook_extra Upgrade details.
	 * @return bool|\WP_Error Unchanged.
	 */
	public function before_update( $response, $hook_extra ) {
		if ( is_wp_error( $response ) || ! is_array( $hook_extra ) ) {
			return $response;
		}
		$folder = '';
		$label  = '';
		if ( ! empty( $hook_extra['plugin'] ) && is_string( $hook_extra['plugin'] ) ) {
			$file = wp_normalize_path( WP_PLUGIN_DIR . '/' . $hook_extra['plugin'] );
			if ( ! is_file( $file ) ) {
				return $response;
			}
			if ( ! function_exists( 'get_plugin_data' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$data   = get_plugin_data( $file, false, false );
			$folder = false === strpos( $hook_extra['plugin'], '/' ) ? '' : dirname( $file );
			/* translators: 1: plugin name, 2: version. */
			$label = sprintf( __( 'Plugin %1$s %2$s', 'chaos-shield' ), $data['Name'] ? $data['Name'] : $hook_extra['plugin'], $data['Version'] );
			if ( '' === $folder ) {
				self::create( 'update', $label, array( $file ), array(), false );
				return $response;
			}
		} elseif ( ! empty( $hook_extra['theme'] ) && is_string( $hook_extra['theme'] ) ) {
			$theme = wp_get_theme( $hook_extra['theme'] );
			if ( ! $theme->exists() ) {
				return $response;
			}
			$folder = $theme->get_stylesheet_directory();
			/* translators: 1: theme name, 2: version. */
			$label = sprintf( __( 'Theme %1$s %2$s', 'chaos-shield' ), $theme->get( 'Name' ), $theme->get( 'Version' ) );
		}
		if ( '' === $folder ) {
			return $response;
		}
		$result = self::create( 'update', $label, array(), array( $folder ), false );
		if ( is_wp_error( $result ) ) {
			// Never block an update, which may be a security fix. Say why there is no point.
			Events::add(
				'system',
				/* translators: 1: plugin or theme, 2: reason. */
				sprintf( __( 'No restore point before updating %1$s: %2$s', 'chaos-shield' ), $label, $result->get_error_message() ),
				Request::ip(),
				array( 'severity' => Events::NOTICE )
			);
		}
		return $response;
	}

	// Restoring.

	/**
	 * Puts a restore point back. The current state is saved first, so a restore can be undone.
	 *
	 * @param string $id Point ID.
	 * @return true|\WP_Error
	 */
	public static function restore( $id ) {
		$id       = sanitize_key( $id );
		$index    = self::all();
		$manifest = self::manifest( $id );
		if ( ! isset( $index[ $id ] ) || ! $manifest ) {
			return new \WP_Error( 'cshield_rp_missing', __( 'That restore point is gone.', 'chaos-shield' ) );
		}
		$dir = self::base() . '/' . $id;

		// Check every stored copy before touching anything.
		$files   = array();
		$folders = array();
		foreach ( $manifest['items'] as $item ) {
			$path = self::path( isset( $item['path'] ) ? $item['path'] : '' );
			if ( '' === $path ) {
				return new \WP_Error( 'cshield_rp_bad', __( 'The restore point names a file outside the site, so it was not used.', 'chaos-shield' ) );
			}
			if ( 'folder' === $item['kind'] ) {
				$folders[] = $path;
			} elseif ( 'member' !== $item['kind'] ) {
				$files[] = $path;
			}
			if ( in_array( $item['kind'], array( 'file', 'member' ), true ) && sha1( self::read_blob( $dir, $item ) ) !== $item['sha1'] ) {
				return new \WP_Error( 'cshield_rp_damaged', __( 'A file in this restore point is damaged, so nothing was restored.', 'chaos-shield' ) );
			}
		}

		$label = $index[ $id ]['label'];
		$undo  = self::create( 'restore', $label, $files, $folders, is_array( $manifest['settings'] ) );
		if ( is_wp_error( $undo ) ) {
			return $undo;
		}

		$moved = array();
		foreach ( $manifest['items'] as $item ) {
			$path = self::path( $item['path'] );
			if ( 'folder' === $item['kind'] && is_dir( $path ) ) {
				// Move the current folder aside so files the update added go away too.
				$aside = $path . '.cshield-old-' . strtolower( wp_generate_password( 6, false ) );
				if ( ! @rename( $path, $aside ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Reported below.
					self::undo_moves( $moved );
					return new \WP_Error( 'cshield_rp_move', __( 'Could not replace the folder. Check the file permissions.', 'chaos-shield' ) );
				}
				$moved[ $path ] = $aside;
			} elseif ( 'absent' === $item['kind'] && is_file( $path ) ) {
				wp_delete_file( $path );
			} elseif ( in_array( $item['kind'], array( 'file', 'member' ), true ) ) {
				wp_mkdir_p( dirname( $path ) );
				if ( false === file_put_contents( $path, self::read_blob( $dir, $item ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes back a verified copy.
					self::undo_moves( $moved );
					return new \WP_Error( 'cshield_rp_write', __( 'Could not write a file back. Check the file permissions. The state from before the restore was saved as a new restore point.', 'chaos-shield' ) );
				}
			}
		}
		foreach ( $moved as $aside ) {
			self::remove_dir( $aside );
		}

		if ( is_array( $manifest['settings'] ) ) {
			self::$restoring = true;
			Network::update_option( Settings::OPTION, $manifest['settings'] );
			Settings::forget();
			Request::reset();
			self::$restoring = false;
		}
		Events::add(
			'system',
			/* translators: 1: what was restored, 2: date. */
			sprintf( __( 'Restored %1$s from the restore point of %2$s.', 'chaos-shield' ), $label, wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $index[ $id ]['time'] ) ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'system.restore',
				'subject'  => $label,
			)
		);
		// Put-back plugin and theme files should not show up as changes in the next scan.
		foreach ( $manifest['items'] as $item ) {
			if ( 'folder' === $item['kind'] && 0 === strpos( $item['path'], '@content/' ) ) {
				Scanner::expect_changes( trailingslashit( $item['path'] ) );
			}
		}
		return true;
	}

	/**
	 * Puts folders moved aside back after a failed restore.
	 *
	 * @param array $moved Original path => moved path.
	 */
	private static function undo_moves( array $moved ) {
		foreach ( $moved as $path => $aside ) {
			if ( is_dir( $path ) ) {
				self::remove_dir( $path );
			}
			@rename( $aside, $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Best effort rollback.
		}
	}

	/**
	 * Deletes a restore point.
	 *
	 * @param string $id Point ID.
	 */
	public static function delete( $id ) {
		$id    = sanitize_key( $id );
		$index = self::all();
		if ( isset( $index[ $id ] ) ) {
			unset( $index[ $id ] );
			Network::update_option( self::INDEX, $index, false );
		}
		$base = self::base();
		if ( ! is_wp_error( $base ) && '' !== $id && is_dir( $base . '/' . $id ) ) {
			self::remove_dir( $base . '/' . $id );
		}
	}

	/**
	 * Keeps the newest points within the count, age and size limits.
	 *
	 * @param string $keep A point that always stays, such as the one just taken.
	 */
	public static function prune( $keep = '' ) {
		$total = 0;
		$count = 0;
		foreach ( self::all() as $id => $point ) {
			++$count;
			$total += (int) $point['bytes'];
			$old    = time() - (int) $point['time'] > self::MAX_AGE;
			if ( $id !== $keep && ( $old || $count > self::MAX_POINTS || $total > self::MAX_BYTES ) ) {
				self::delete( $id );
			}
		}
	}

	/**
	 * Total size of all points.
	 *
	 * @return int Bytes.
	 */
	public static function size() {
		return array_sum( array_map( 'intval', wp_list_pluck( self::all(), 'bytes' ) ) );
	}

	/**
	 * What a point holds, for the list.
	 *
	 * @param string $id Point ID.
	 * @return array|null items, settings.
	 */
	public static function manifest( $id ) {
		$base = self::base();
		$file = is_wp_error( $base ) ? '' : $base . '/' . sanitize_key( $id ) . '/manifest.php';
		if ( '' === $file || ! is_file( $file ) ) {
			return null;
		}
		$data = json_decode( substr( (string) file_get_contents( $file ), strlen( self::GUARD ) ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return is_array( $data ) && isset( $data['items'] ) && is_array( $data['items'] ) ? $data : null;
	}

	// Admin.

	/**
	 * Handles the Backups tab forms.
	 */
	public function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( self::ACTION );
		$op     = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$id     = isset( $_POST['point'] ) ? sanitize_key( wp_unslash( $_POST['point'] ) ) : '';
		$result = true;
		$notice = '';
		if ( 'create' === $op ) {
			$files = array( self::config_file() );
			$label = __( 'wp-config.php and Chaos Shield settings', 'chaos-shield' );
			if ( is_file( wp_normalize_path( ABSPATH ) . '.htaccess' ) ) {
				$files[] = wp_normalize_path( ABSPATH ) . '.htaccess';
				$label   = __( 'wp-config.php, .htaccess and Chaos Shield settings', 'chaos-shield' );
			}
			$result = self::create( 'manual', $label, $files );
			$notice = 'rp_created';
		} elseif ( 'restore' === $op ) {
			$result = self::restore( $id );
			$notice = 'rp_restored';
		} elseif ( 'delete' === $op ) {
			self::delete( $id );
			$notice = 'rp_deleted';
		} elseif ( 'export' === $op ) {
			Backup::export_settings();
		} elseif ( 'import' === $op ) {
			$result = Backup::import_settings( isset( $_FILES['settings'] ) && is_array( $_FILES['settings'] ) ? $_FILES['settings'] : array() ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The upload is read and validated in Backup::import_settings().
			$notice = 'settings_imported';
		} elseif ( 'database' === $op ) {
			$result = Backup::database();
		}
		if ( is_wp_error( $result ) ) {
			Network::set_transient( 'cshield_error_' . get_current_user_id(), $result->get_error_message(), MINUTE_IN_SECONDS );
			$notice = '';
		}
		wp_safe_redirect( Admin::url( 'backups', array( 'cshield_notice' => $notice ) ) );
		exit;
	}

	// Storage.

	/**
	 * The restore folder, created and locked down on first use.
	 *
	 * @return string|\WP_Error
	 */
	public static function base() {
		$dir = wp_normalize_path( WP_CONTENT_DIR ) . '/' . self::DIR;
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'cshield_rp_dir', __( 'Could not create the restore folder in wp-content. Check the folder permissions.', 'chaos-shield' ) );
		}
		self::guard( $dir );
		return $dir;
	}

	/**
	 * Writes deny rules and an empty index into a folder.
	 *
	 * @param string $dir Folder.
	 */
	private static function guard( $dir ) {
		$guards = array(
			'.htaccess'  => "Require all denied\nDeny from all\n",
			'web.config' => '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
			'index.php'  => "<?php\n// Silence is golden.\n",
		);
		foreach ( $guards as $name => $content ) {
			if ( ! file_exists( $dir . '/' . $name ) ) {
				file_put_contents( $dir . '/' . $name, $content ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Small guard files in the plugin's own folder.
			}
		}
	}

	/**
	 * Saves one file into a point.
	 *
	 * @param string $dir  Point folder.
	 * @param int    $n    Sequence number.
	 * @param string $path Source file.
	 * @return array|\WP_Error blob, size, stored, sha1, mode.
	 */
	private static function store( $dir, $n, $path ) {
		$body = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( false === $body ) {
			/* translators: %s: file. */
			return new \WP_Error( 'cshield_rp_read', sprintf( __( 'Could not read %s.', 'chaos-shield' ), self::key( $path ) ) );
		}
		$packed = function_exists( 'gzencode' ) ? gzencode( $body, 6 ) : $body;
		$blob   = $n . '.php';
		if ( false === file_put_contents( $dir . '/' . $blob, self::GUARD . $packed ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The plugin's own restore folder.
			return new \WP_Error( 'cshield_rp_write', __( 'Could not write the restore point. Check the free disk space.', 'chaos-shield' ) );
		}
		return array(
			'blob'   => $blob,
			'gz'     => function_exists( 'gzencode' ),
			'size'   => strlen( $body ),
			'stored' => strlen( $packed ),
			'sha1'   => sha1( $body ),
		);
	}

	/**
	 * Reads a stored file back.
	 *
	 * @param string $dir  Point folder.
	 * @param array  $item Manifest item.
	 * @return string Contents, or '' when unreadable.
	 */
	private static function read_blob( $dir, array $item ) {
		$blob = isset( $item['blob'] ) ? basename( (string) $item['blob'] ) : '';
		$raw  = '' !== $blob && is_file( $dir . '/' . $blob ) ? (string) file_get_contents( $dir . '/' . $blob ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$raw  = substr( $raw, strlen( self::GUARD ) );
		if ( ! empty( $item['gz'] ) ) {
			$raw = function_exists( 'gzdecode' ) ? (string) @gzdecode( $raw ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A damaged copy is caught by the checksum.
		}
		return $raw;
	}

	/**
	 * Files of a folder, within the size limits.
	 *
	 * @param string $folder Folder.
	 * @return string[]|\WP_Error
	 */
	private static function walk( $folder ) {
		$files = array();
		$bytes = 0;
		$it    = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $folder, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isFile() || $file->isLink() ) {
				continue;
			}
			$bytes  += $file->getSize();
			$files[] = wp_normalize_path( $file->getPathname() );
			if ( count( $files ) > self::MAX_FILES || $bytes > self::MAX_FOLDER ) {
				/* translators: %s: size such as 60 MB. */
				return new \WP_Error( 'cshield_rp_big', sprintf( __( 'the folder is larger than %s, so it was not copied.', 'chaos-shield' ), size_format( self::MAX_FOLDER ) ) );
			}
		}
		return $files;
	}

	/**
	 * Removes a folder and everything in it.
	 *
	 * @param string $dir Folder.
	 */
	private static function remove_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $it as $file ) {
			if ( $file->isDir() && ! $file->isLink() ) {
				@rmdir( $file->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
			} else {
				wp_delete_file( $file->getPathname() );
			}
		}
		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
	}

	/**
	 * Path of wp-config.php, which may sit one folder above WordPress.
	 *
	 * @return string
	 */
	public static function config_file() {
		$here = wp_normalize_path( ABSPATH ) . 'wp-config.php';
		$up   = wp_normalize_path( dirname( ABSPATH ) ) . '/wp-config.php';
		return ! is_file( $here ) && is_file( $up ) ? $up : $here;
	}

	/**
	 * Portable name of a site file: @content/... inside wp-content, @root/... inside
	 * the WordPress folder, @config for a wp-config.php above it.
	 *
	 * @param string $path Absolute path.
	 * @return string Key, or '' when the file is outside the site.
	 */
	public static function key( $path ) {
		$path    = wp_normalize_path( (string) $path );
		$content = wp_normalize_path( WP_CONTENT_DIR ) . '/';
		$root    = wp_normalize_path( ABSPATH );
		if ( false !== strpos( $path, '/../' ) || '..' === substr( $path, -2 ) ) {
			return '';
		}
		if ( 0 === strpos( $path, $content ) ) {
			return '@content/' . substr( $path, strlen( $content ) );
		}
		if ( 0 === strpos( $path, $root ) ) {
			return '@root/' . substr( $path, strlen( $root ) );
		}
		if ( self::config_file() === $path ) {
			return '@config';
		}
		return '';
	}

	/**
	 * Absolute path for a key. Never leaves the site, and never points into the restore folder itself.
	 *
	 * @param string $key Key from key().
	 * @return string Path, or '' when invalid.
	 */
	public static function path( $key ) {
		$key = (string) $key;
		if ( '@config' === $key ) {
			return self::config_file();
		}
		if ( false !== strpos( $key, '..' ) || false !== strpos( $key, "\0" ) ) {
			return '';
		}
		$path = '';
		if ( 0 === strpos( $key, '@content/' ) && '' !== substr( $key, 9 ) ) {
			$path = wp_normalize_path( WP_CONTENT_DIR ) . '/' . substr( $key, 9 );
		} elseif ( 0 === strpos( $key, '@root/' ) && '' !== substr( $key, 6 ) ) {
			$path = wp_normalize_path( ABSPATH ) . substr( $key, 6 );
		}
		$own = wp_normalize_path( WP_CONTENT_DIR ) . '/' . self::DIR;
		if ( $path === $own || 0 === strpos( $path, $own . '/' ) ) {
			return '';
		}
		return $path;
	}
}
