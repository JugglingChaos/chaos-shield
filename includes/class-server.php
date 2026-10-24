<?php
/**
 * Server hardening: file permissions, hotlinks, user agents, REST API, feeds and the table prefix.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Settings that close doors at the server level, each one switched on its
 * own, plus the two fixes that touch the site's files: tightening loose file
 * permissions and moving the tables to a new prefix.
 */
final class Server {

	const HOTLINK_MARKER = 'Chaos Shield hotlinks';
	const RULES_SEEN     = 'cshield_exposure_rules';
	const PREFIX_PATTERN = '/\$table_prefix\s*=\s*([\'"])([A-Za-z0-9_]+)\1\s*;/';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'plugins_loaded', array( $this, 'screen_agent' ), 1 );
		if ( Settings::enabled( 'rest_private' ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'rest_gate' ), 5, 3 );
		}
		if ( Settings::enabled( 'disable_feeds' ) ) {
			remove_action( 'wp_head', 'feed_links', 2 );
			remove_action( 'wp_head', 'feed_links_extra', 3 );
			foreach ( array( 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom', 'do_feed_rss2_comments', 'do_feed_atom_comments' ) as $hook ) {
				add_action( $hook, array( $this, 'no_feed' ), 1 );
			}
		}
		add_action( 'admin_init', array( __CLASS__, 'refresh_rules' ) );
		add_action( 'admin_post_cshield_server', array( __CLASS__, 'handle' ) );
	}

	// User agents.

	/**
	 * Refuses listed user agents, and form posts that send none.
	 */
	public function screen_agent() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || Firewall::allowlisted() || Page_Check::is_self() || current_user_can( Network::cap() ) ) {
			return;
		}
		$agent = Request::server( 'HTTP_USER_AGENT' );
		if ( '' !== $agent && self::agent_listed( $agent, (array) Settings::get( 'ua_blocklist' ) ) ) {
			$this->refuse_agent( __( 'A request from a blocked user agent was refused.', 'chaos-shield' ), $agent );
		}
		if ( Settings::enabled( 'block_blank_ua' ) && '' === trim( $agent ) && 'POST' === Request::server( 'REQUEST_METHOD' ) && ! is_user_logged_in() ) {
			$this->refuse_agent( __( 'A form post with no user agent was refused.', 'chaos-shield' ), '' );
		}
	}

	/**
	 * Whether a user agent contains one of the listed words.
	 *
	 * @param string   $agent   User agent.
	 * @param string[] $entries Entries, matched anywhere and in any case.
	 * @return bool
	 */
	public static function agent_listed( $agent, array $entries ) {
		foreach ( $entries as $entry ) {
			if ( '' !== (string) $entry && false !== stripos( $agent, (string) $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Cleans the user agent block list typed on the Access tab.
	 *
	 * @param string $text One entry per line.
	 * @param string $own  User agent of the person saving, which is never accepted.
	 * @return array valid, self (entries dropped because they match the person saving).
	 */
	public static function parse_agents( $text, $own ) {
		$out = array(
			'valid' => array(),
			'self'  => array(),
		);
		foreach ( preg_split( '/[\r\n]+/', (string) $text ) as $line ) {
			$line = trim( sanitize_text_field( $line ) );
			if ( strlen( $line ) < 3 || in_array( $line, $out['valid'], true ) ) {
				continue;
			}
			if ( '' !== $own && self::agent_listed( $own, array( $line ) ) ) {
				$out['self'][] = $line;
				continue;
			}
			$out['valid'][] = substr( $line, 0, 100 );
		}
		$out['valid'] = array_slice( $out['valid'], 0, 200 );
		return $out;
	}

	/**
	 * Logs and refuses the request.
	 *
	 * @param string $message Log message.
	 * @param string $agent   User agent.
	 */
	private function refuse_agent( $message, $agent ) {
		Events::add(
			'blocked',
			$message,
			Request::ip(),
			array(
				'action'  => 'firewall.agent',
				'subject' => substr( $agent, 0, 190 ),
			)
		);
		Login_Guard::bump_stat( 'firewall_blocks' );
		Firewall::deny( 'agent' );
	}

	// REST API.

	/**
	 * Routes that stay open to visitors when the REST API is closed.
	 *
	 * @return string[] Route prefixes, each starting with a slash.
	 */
	public static function rest_open() {
		$routes = array( '/oembed/', '/contact-form-7/', '/wpforms/', '/wc/store/', '/jetpack/' );
		foreach ( (array) Settings::get( 'rest_allow' ) as $route ) {
			$routes[] = '/' . ltrim( (string) $route, '/' );
		}

		/**
		 * Filters the REST routes visitors can still reach when the API is closed.
		 *
		 * @param string[] $routes Route prefixes, such as /wc/store/.
		 */
		return array_values( array_unique( (array) apply_filters( 'cshield_rest_open_routes', $routes ) ) );
	}

	/**
	 * Cleans the REST allow list.
	 *
	 * @param string $text One route per line, such as /my-plugin/v1/.
	 * @return string[]
	 */
	public static function parse_routes( $text ) {
		$out = array();
		foreach ( preg_split( '/[\s,]+/', (string) $text ) as $route ) {
			$route = trim( $route );
			if ( preg_match( '#^/?[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/?$#', $route ) ) {
				$out[] = '/' . ltrim( $route, '/' );
			}
		}
		return array_slice( array_values( array_unique( $out ) ), 0, 50 );
	}

	/**
	 * Refuses REST requests from visitors who are not logged in, outside the open routes.
	 *
	 * @param mixed            $result  Response so far.
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public function rest_gate( $result, $server, $request ) {
		if ( null !== $result || is_user_logged_in() ) {
			return $result;
		}
		$route = '/' . ltrim( (string) $request->get_route(), '/' );
		foreach ( self::rest_open() as $open ) {
			if ( 0 === strpos( trailingslashit( $route ), trailingslashit( $open ) ) ) {
				return $result;
			}
		}
		return new \WP_Error( 'rest_login_required', __( 'The REST API on this site is only open to logged-in users.', 'chaos-shield' ), array( 'status' => 401 ) );
	}

	// Feeds.

	/**
	 * Answers feed requests with 410 Gone.
	 */
	public function no_feed() {
		wp_die(
			esc_html__( 'This site has no RSS feeds.', 'chaos-shield' ),
			esc_html__( 'No feed', 'chaos-shield' ),
			array(
				'response'  => 410,
				'link_url'  => esc_url( home_url( '/' ) ),
				'link_text' => esc_html__( 'Go to the home page', 'chaos-shield' ),
			)
		);
	}

	// Hotlinks.

	/**
	 * Hosts allowed to show the site's images.
	 *
	 * @return string[]
	 */
	public static function hotlink_hosts() {
		$hosts = array();
		foreach ( array_merge( array( home_url(), site_url() ), (array) Settings::get( 'hotlink_allow' ) ) as $url ) {
			$host = false !== strpos( (string) $url, '//' ) ? (string) wp_parse_url( (string) $url, PHP_URL_HOST ) : (string) $url;
			$host = preg_replace( '/^www\./', '', strtolower( $host ) );
			if ( '' !== $host ) {
				$hosts[] = $host;
			}
		}
		return array_values( array_unique( $hosts ) );
	}

	/**
	 * Cleans the hotlink allow list.
	 *
	 * @param string $text Domains, one per line or comma separated.
	 * @return string[]
	 */
	public static function parse_hosts( $text ) {
		$out = array();
		foreach ( preg_split( '/[\s,]+/', strtolower( (string) $text ) ) as $host ) {
			$host = preg_replace( '#^https?://#', '', trim( $host ) );
			$host = preg_replace( '#[/:].*$#', '', (string) $host );
			if ( preg_match( '/^([a-z0-9-]+\.)+[a-z]{2,}$/', (string) $host ) ) {
				$out[] = preg_replace( '/^www\./', '', $host );
			}
		}
		return array_slice( array_values( array_unique( $out ) ), 0, 50 );
	}

	/**
	 * The .htaccess rules that refuse images shown on other sites.
	 *
	 * Visits with no referrer, from this site, from the allowed hosts and from
	 * search engines still get the images.
	 *
	 * @return string[]
	 */
	public static function hotlink_rules() {
		$lines = array( '<IfModule mod_rewrite.c>', 'RewriteEngine On', 'RewriteCond %{HTTP_REFERER} !^$' );
		foreach ( self::hotlink_hosts() as $host ) {
			$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?' . preg_quote( $host, '#' ) . '(:[0-9]+)?(/|$) [NC]';
		}
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?(google|bing|duckduckgo|yahoo|yandex|baidu|ecosia)\.[a-z.]+(/|$) [NC]';
		$lines[] = 'RewriteRule \.(jpe?g|png|gif|webp|avif|bmp|svg)$ - [F,NC]';
		$lines[] = '</IfModule>';
		return $lines;
	}

	/**
	 * The same rule for nginx, to copy.
	 *
	 * @return string
	 */
	public static function hotlink_nginx() {
		$hosts = array();
		foreach ( self::hotlink_hosts() as $host ) {
			$hosts[] = '*.' . $host . ' ' . $host;
		}
		return "location ~* \\.(jpe?g|png|gif|webp|avif|bmp|svg)\$ {\n\tvalid_referers none blocked server_names " . implode( ' ', $hosts ) . " ~\\.google\\. ~\\.bing\\. ~\\.duckduckgo\\.;\n\tif (\$invalid_referer) { return 403; }\n}";
	}

	/**
	 * Path of the root .htaccess.
	 *
	 * @return string
	 */
	private static function htaccess() {
		return ABSPATH . '.htaccess';
	}

	/**
	 * The lines between one of this plugin's markers in .htaccess.
	 *
	 * @param string $marker Marker.
	 * @return string[]|null Null when the block is not there.
	 */
	public static function block_lines( $marker ) {
		$file = self::htaccess();
		if ( ! is_file( $file ) ) {
			return null;
		}
		$body = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( ! preg_match( '/# BEGIN ' . preg_quote( $marker, '/' ) . '\r?\n(.*?)# END ' . preg_quote( $marker, '/' ) . '/s', $body, $m ) ) {
			return null;
		}
		$lines = array();
		foreach ( preg_split( '/\r?\n/', $m[1] ) as $line ) {
			// insert_with_markers adds its own comment lines at the top.
			if ( '' !== $line && 0 !== strpos( $line, '#' ) ) {
				$lines[] = $line;
			}
		}
		return $lines;
	}

	/**
	 * Adds, updates or removes one of this plugin's blocks in .htaccess.
	 *
	 * The home page is checked after a change, and the change is taken back if
	 * the server answers 500.
	 *
	 * @param string   $marker Marker.
	 * @param string[] $lines  Rules, or none to remove the block.
	 * @return true|\WP_Error
	 */
	public static function write_block( $marker, array $lines ) {
		$file   = self::htaccess();
		$before = self::block_lines( $marker );
		if ( ( $lines ? $lines : null ) === $before ) {
			return true;
		}
		if ( ( file_exists( $file ) && ! wp_is_writable( $file ) ) || ( ! file_exists( $file ) && ! wp_is_writable( ABSPATH ) ) ) {
			return new \WP_Error( 'cshield_htaccess', __( 'The .htaccess file in the site root cannot be written. Add the rules by hand, or ask your host.', 'chaos-shield' ) );
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		Integrity::expect( '.htaccess' );
		if ( ! insert_with_markers( $file, $marker, $lines ) ) {
			return new \WP_Error( 'cshield_htaccess', __( 'The rules could not be saved to .htaccess.', 'chaos-shield' ) );
		}
		if ( ! $lines ) {
			// insert_with_markers leaves empty markers behind; take them out.
			$body = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			$body = (string) preg_replace( '/\n?# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s', "\n", $body );
			file_put_contents( $file, ltrim( $body ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Removes this plugin's own block from the site's .htaccess, which the owner turned on.
			return true;
		}
		if ( Exposure::broken() ) {
			self::write_block( $marker, null === $before ? array() : $before );
			return new \WP_Error( 'cshield_htaccess', __( 'The server did not accept the rules, so they were taken out again. Your host may not allow these settings in .htaccess.', 'chaos-shield' ) );
		}
		return true;
	}

	/**
	 * Puts the hotlink block in .htaccess, or takes it out, to match the setting.
	 *
	 * @return true|\WP_Error
	 */
	public static function sync_hotlinks() {
		$on = Settings::enabled( 'block_hotlinks' );
		if ( ! Exposure::apache() ) {
			return true;
		}
		$was    = null !== self::block_lines( self::HOTLINK_MARKER );
		$result = self::write_block( self::HOTLINK_MARKER, $on ? self::hotlink_rules() : array() );
		if ( true === $result && $was !== $on ) {
			Events::add(
				'settings',
				$on ? __( 'Image hotlink blocking added to .htaccess.', 'chaos-shield' ) : __( 'Image hotlink blocking removed from .htaccess.', 'chaos-shield' ),
				Request::ip(),
				array( 'action' => 'settings.hotlinks' )
			);
		}
		return $result;
	}

	/**
	 * Brings an older sensitive files block in .htaccess up to date, once per change of the rules.
	 */
	public static function refresh_rules() {
		if ( ! current_user_can( Network::cap() ) || wp_doing_ajax() ) {
			return;
		}
		$want = md5( implode( "\n", Exposure::rules() ) );
		if ( Network::get_option( self::RULES_SEEN, '' ) === $want ) {
			return;
		}
		Network::update_option( self::RULES_SEEN, $want, false );
		$have = self::block_lines( Exposure::MARKER );
		if ( null !== $have && Exposure::rules() !== $have ) {
			self::write_block( Exposure::MARKER, Exposure::rules() );
		}
	}

	// File permissions.

	/**
	 * Files and folders to check, with the most open permissions they need.
	 *
	 * @return array[] Each: label, path, want.
	 */
	public static function permission_targets() {
		$uploads = wp_get_upload_dir();
		$items   = array(
			array( 'wp-config.php', Salts::config_path(), 0640 ),
			array( '.htaccess', ABSPATH . '.htaccess', 0644 ),
			array( 'index.php', ABSPATH . 'index.php', 0644 ),
			array( __( 'Site folder', 'chaos-shield' ), untrailingslashit( ABSPATH ), 0755 ),
			array( 'wp-admin', ABSPATH . 'wp-admin', 0755 ),
			array( 'wp-includes', ABSPATH . WPINC, 0755 ),
			array( 'wp-content', WP_CONTENT_DIR, 0755 ),
			array( 'plugins', WP_PLUGIN_DIR, 0755 ),
			array( 'themes', get_theme_root(), 0755 ),
			array( 'uploads', empty( $uploads['basedir'] ) ? '' : $uploads['basedir'], 0755 ),
		);
		$out     = array();
		foreach ( $items as $item ) {
			if ( '' !== $item[1] && file_exists( $item[1] ) ) {
				$out[] = array(
					'label' => $item[0],
					'path'  => $item[1],
					'want'  => $item[2],
				);
			}
		}
		return $out;
	}

	/**
	 * Current permissions of each target.
	 *
	 * @return array[] Each: label, path, mode, want, status (Posture::PASS, WARN or FAIL).
	 */
	public static function permissions() {
		clearstatcache();
		$rows = array();
		foreach ( self::permission_targets() as $item ) {
			$perms = fileperms( $item['path'] );
			if ( false === $perms ) {
				continue;
			}
			$mode  = $perms & 0777;
			$extra = $mode & ~$item['want'];
			if ( $extra & 0002 ) {
				$status = Posture::FAIL;
			} elseif ( $extra ) {
				$status = Posture::WARN;
			} else {
				$status = Posture::PASS;
			}
			$rows[] = $item + array(
				'mode'   => $mode,
				'status' => $status,
			);
		}
		return $rows;
	}

	/**
	 * Mode as the usual four digits.
	 *
	 * @param int $mode Mode.
	 * @return string
	 */
	public static function octal( $mode ) {
		return sprintf( '%04o', $mode );
	}

	/**
	 * Takes away the extra permissions, one item at a time.
	 *
	 * Only ever removes permissions. After each change the site must still be
	 * able to read the item, and write it if it could before; if not, the old
	 * permissions are put back.
	 *
	 * @return array fixed (labels), failed (labels).
	 */
	public static function fix_permissions() {
		$out = array(
			'fixed'  => array(),
			'failed' => array(),
		);
		foreach ( self::permissions() as $row ) {
			if ( Posture::PASS === $row['status'] ) {
				continue;
			}
			$could_write = wp_is_writable( $row['path'] );
			$new         = $row['mode'] & $row['want'];
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- A refused chmod is reported, not shown as a warning.
			if ( ! @chmod( $row['path'], $new ) ) {
				$out['failed'][] = $row['label'];
				continue;
			}
			clearstatcache();
			if ( ! is_readable( $row['path'] ) || ( $could_write && ! wp_is_writable( $row['path'] ) ) ) {
				chmod( $row['path'], $row['mode'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Puts the old permissions back.
				$out['failed'][] = $row['label'];
				continue;
			}
			$out['fixed'][] = $row['label'] . ' ' . self::octal( $row['mode'] ) . ' → ' . self::octal( $new );
		}
		if ( $out['fixed'] ) {
			Events::add(
				'settings',
				/* translators: %s: list of files and folders with old and new permissions. */
				sprintf( __( 'File permissions tightened: %s.', 'chaos-shield' ), implode( ', ', $out['fixed'] ) ),
				Request::ip(),
				array( 'action' => 'settings.permissions' )
			);
		}
		return $out;
	}

	// Table prefix.

	/**
	 * Whether the table prefix can be changed from the dashboard, and if not, why.
	 *
	 * @return true|\WP_Error
	 */
	public static function prefix_ready() {
		global $wpdb;
		if ( is_multisite() ) {
			return new \WP_Error( 'cshield_prefix_multisite', __( 'On a multisite network the prefix is shared by every site, so it cannot be changed from here.', 'chaos-shield' ) );
		}
		$path = Salts::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return new \WP_Error( 'cshield_prefix_config', __( 'wp-config.php could not be found or read.', 'chaos-shield' ) );
		}
		if ( ! wp_is_writable( $path ) || ! wp_is_writable( dirname( $path ) ) ) {
			return new \WP_Error( 'cshield_prefix_config', __( 'wp-config.php is read-only, so the prefix cannot be changed from here.', 'chaos-shield' ) );
		}
		$body = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( 1 !== preg_match_all( self::PREFIX_PATTERN, $body, $m ) || $m[2][0] !== $wpdb->prefix ) {
			return new \WP_Error( 'cshield_prefix_config', __( 'The $table_prefix line in wp-config.php is not in the usual form, so it cannot be changed safely from here.', 'chaos-shield' ) );
		}
		// Another site with a longer prefix, such as wp_shop_, would have its tables renamed too.
		foreach ( self::tables( $wpdb->prefix ) as $table ) {
			if ( preg_match( '/options$/', $table ) && $wpdb->prefix . 'options' !== $table ) {
				return new \WP_Error( 'cshield_prefix_shared', __( 'Another WordPress site shares this database with a similar prefix, so the prefix cannot be changed safely from here.', 'chaos-shield' ) );
			}
		}
		return true;
	}

	/**
	 * Tables that start with a prefix.
	 *
	 * @param string $prefix Prefix.
	 * @return string[]
	 */
	private static function tables( $prefix ) {
		global $wpdb;
		$tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $prefix ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Lists tables for a one-off rename.
		return array_values( array_filter( (array) $tables, array( __CLASS__, 'plain_name' ) ) );
	}

	/**
	 * Whether a table name is safe to quote with backticks.
	 *
	 * @param string $name Table name.
	 * @return bool
	 */
	private static function plain_name( $name ) {
		return (bool) preg_match( '/^[A-Za-z0-9_$]+$/', (string) $name );
	}

	/**
	 * A new random prefix to suggest.
	 *
	 * @return string
	 */
	public static function suggest_prefix() {
		return 'wp' . strtolower( wp_generate_password( 5, false ) ) . '_';
	}

	/**
	 * Renames every table to a new prefix and writes it to wp-config.php.
	 *
	 * Tables are renamed in one statement, which the database does all at
	 * once. If wp-config.php cannot be written, everything is put back.
	 *
	 * @param string $prefix New prefix: a letter, then letters and digits, ending with _.
	 * @return true|\WP_Error
	 */
	public static function change_prefix( $prefix ) {
		global $wpdb;
		$ready = self::prefix_ready();
		if ( is_wp_error( $ready ) ) {
			return $ready;
		}
		$new = strtolower( trim( (string) $prefix ) );
		$old = $wpdb->prefix;
		if ( ! preg_match( '/^[a-z][a-z0-9]{1,14}_$/', $new ) ) {
			return new \WP_Error( 'cshield_prefix_name', __( 'Use a letter, then 1 to 14 letters or digits, ending with an underscore, such as wpk3x9_.', 'chaos-shield' ) );
		}
		if ( $new === $old || 0 === strpos( $new, $old ) || 0 === strpos( $old, $new ) ) {
			return new \WP_Error( 'cshield_prefix_name', __( 'Pick a prefix that does not start with the current one.', 'chaos-shield' ) );
		}
		if ( self::tables( $new ) ) {
			return new \WP_Error( 'cshield_prefix_name', __( 'Tables with that prefix already exist. Pick another one.', 'chaos-shield' ) );
		}
		$tables = self::tables( $old );
		if ( ! in_array( $old . 'options', $tables, true ) || ! in_array( $old . 'usermeta', $tables, true ) ) {
			return new \WP_Error( 'cshield_prefix_tables', __( 'The site tables could not be listed, so nothing was changed.', 'chaos-shield' ) );
		}

		if ( ! self::rename_tables( $tables, $old, $new ) ) {
			return new \WP_Error( 'cshield_prefix_rename', __( 'The database did not allow the tables to be renamed, so nothing was changed. The database user may lack the ALTER permission.', 'chaos-shield' ) );
		}
		self::rename_keys( $new, $old, $new );

		$path    = Salts::config_path();
		$body    = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$written = Salts::write_config(
			$path,
			(string) preg_replace_callback(
				self::PREFIX_PATTERN,
				static function () use ( $new ) {
					return "\$table_prefix = '" . $new . "';";
				},
				$body,
				1
			)
		);
		if ( is_wp_error( $written ) ) {
			self::rename_keys( $new, $new, $old );
			$back = array();
			foreach ( $tables as $table ) {
				$back[] = $new . substr( $table, strlen( $old ) );
			}
			self::rename_tables( $back, $new, $old );
			return $written;
		}

		$wpdb->set_prefix( $new );
		wp_cache_flush();
		// Roles and capabilities are read from keys named after the prefix.
		wp_roles()->for_site();
		if ( is_user_logged_in() ) {
			wp_get_current_user()->for_site();
		}
		Events::add(
			'settings',
			/* translators: 1: old prefix, 2: new prefix, 3: number of tables. */
			sprintf( __( 'Database table prefix changed from %1$s to %2$s (%3$d tables).', 'chaos-shield' ), $old, $new, count( $tables ) ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'settings.prefix',
			)
		);
		return true;
	}

	/**
	 * Renames tables from one prefix to another in one statement.
	 *
	 * @param string[] $tables Current names.
	 * @param string   $from   Prefix they have.
	 * @param string   $to     Prefix they get.
	 * @return bool
	 */
	private static function rename_tables( array $tables, $from, $to ) {
		global $wpdb;
		$pairs = array();
		foreach ( $tables as $table ) {
			$pairs[] = '`' . $table . '` TO `' . $to . substr( $table, strlen( $from ) ) . '`';
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table names come from SHOW TABLES and are checked by plain_name().
		return false !== $wpdb->query( 'RENAME TABLE ' . implode( ', ', $pairs ) );
	}

	/**
	 * Renames the option and user meta keys WordPress names after the prefix.
	 *
	 * @param string $tables Prefix the tables have now.
	 * @param string $from   Prefix the keys have.
	 * @param string $to     Prefix the keys get.
	 */
	private static function rename_keys( $tables, $from, $to ) {
		global $wpdb;
		$options  = $tables . 'options';
		$usermeta = $tables . 'usermeta';
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- One-off rename; the table names are the site's own.
		$wpdb->query( $wpdb->prepare( "UPDATE `{$options}` SET option_name = %s WHERE option_name = %s", $to . 'user_roles', $from . 'user_roles' ) );
		$wpdb->query( $wpdb->prepare( "UPDATE `{$usermeta}` SET meta_key = CONCAT( %s, SUBSTRING( meta_key, %d ) ) WHERE meta_key LIKE %s", $to, strlen( $from ) + 1, $wpdb->esc_like( $from ) . '%' ) );
		// phpcs:enable
	}

	// Dashboard.

	/**
	 * Handles the buttons on the Server card.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to change Chaos Shield settings.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( 'cshield_server' );
		$op     = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$notice = '';
		$error  = '';
		if ( 'permissions' === $op ) {
			$res    = self::fix_permissions();
			$notice = $res['fixed'] ? 'perms_fixed' : '';
			if ( $res['failed'] ) {
				/* translators: %s: list of files and folders. */
				$error = sprintf( __( 'These could not be changed from here, because the server does not allow it or the site would stop working: %s. Ask your host to set them.', 'chaos-shield' ), implode( ', ', $res['failed'] ) );
			}
		} elseif ( 'prefix' === $op ) {
			if ( empty( $_POST['backup'] ) ) {
				$error = __( 'Tick the box to confirm you have a fresh database backup first.', 'chaos-shield' );
			} else {
				$res = self::change_prefix( isset( $_POST['prefix'] ) ? sanitize_text_field( wp_unslash( $_POST['prefix'] ) ) : '' );
				if ( is_wp_error( $res ) ) {
					$error = $res->get_error_message();
				} else {
					$notice = 'prefix_changed';
				}
			}
		}
		if ( '' !== $error ) {
			Network::set_transient( 'cshield_hardening_error_' . get_current_user_id(), $error, MINUTE_IN_SECONDS );
		}
		wp_safe_redirect( Admin::url( 'hardening', array( 'cshield_notice' => $notice ) ) . '#cshield-server' );
		exit;
	}
}
