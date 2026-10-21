<?php
/**
 * Exposed files and leaked keys.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Looks for files that should never be downloadable, such as backups, database
 * dumps, logs, .env and .git, and for secret keys printed in pages or scripts.
 *
 * Each file is asked for over the web and matched against what that kind of
 * file starts with, so a theme's friendly 404 page is never mistaken for a leak.
 */
final class Exposure {

	const OPTION = 'cshield_exposure';
	const MARKER = 'Chaos Shield sensitive files';

	/**
	 * What each kind of file starts with.
	 *
	 * @return array Kind => [ label, pattern ].
	 */
	private static function kinds() {
		return array(
			'env'     => array( __( 'Environment file with passwords and keys', 'chaos-shield' ), '/^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=/m' ),
			'git'     => array( __( 'Git repository, with your code and its history', 'chaos-shield' ), '/^ref:\s*refs\/|\[core\]/m' ),
			'svn'     => array( __( 'Subversion working copy', 'chaos-shield' ), '/^SQLite format 3|^\d+\s*\n\s*dir/' ),
			'config'  => array( __( 'Copy of wp-config.php with the database password', 'chaos-shield' ), '/DB_PASSWORD|DB_NAME|define\s*\(\s*[\'"]AUTH_KEY/' ),
			'sql'     => array( __( 'Database dump', 'chaos-shield' ), '/CREATE TABLE|INSERT INTO|-- MySQL dump|-- MariaDB dump|-- phpMyAdmin SQL Dump/i' ),
			'archive' => array( __( 'Backup archive of the site', 'chaos-shield' ), '/^(?:PK\x03\x04|\x1f\x8b|7z\xBC\xAF\x27\x1C|Rar!)/' ),
			'log'     => array( __( 'Error log with file paths and details', 'chaos-shield' ), '/PHP (?:Fatal error|Warning|Notice|Parse error|Deprecated)|\[\d{2}-[A-Z][a-z]{2}-\d{4} /' ),
			'phpinfo' => array( __( 'phpinfo() page listing the server setup', 'chaos-shield' ), '/phpinfo\(\)|<title>PHP \d|PHP Version \d/i' ),
			'passwd'  => array( __( 'Password file', 'chaos-shield' ), '/^[\w.-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)/m' ),
			'dsstore' => array( __( 'Mac folder listing (.DS_Store)', 'chaos-shield' ), '/^\x00\x00\x00\x01Bud1/' ),
			'adminer' => array( __( 'Database admin tool', 'chaos-shield' ), '/adminer|phpMyAdmin/i' ),
			'listing' => array( __( 'Folder listing that shows every file', 'chaos-shield' ), '/<title>Index of \//i' ),
		);
	}

	/**
	 * Addresses asked for, by kind.
	 *
	 * @return array Path => kind.
	 */
	public static function probes() {
		$host  = preg_replace( '/^www\./', '', (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$paths = array(
			'.env'                 => 'env',
			'.git/HEAD'            => 'git',
			'.git/config'          => 'git',
			'.svn/wc.db'           => 'svn',
			'.htpasswd'            => 'passwd',
			'.DS_Store'            => 'dsstore',
			'wp-config.php.bak'    => 'config',
			'wp-config.php.old'    => 'config',
			'wp-config.php.orig'   => 'config',
			'wp-config.php.save'   => 'config',
			'wp-config.php~'       => 'config',
			'wp-config.php.txt'    => 'config',
			'wp-config.bak'        => 'config',
			'wp-config.old'        => 'config',
			'.wp-config.php.swp'   => 'config',
			'backup.zip'           => 'archive',
			'backup.tar.gz'        => 'archive',
			'site.zip'             => 'archive',
			'www.zip'              => 'archive',
			'public_html.zip'      => 'archive',
			$host . '.zip'         => 'archive',
			'backup.sql'           => 'sql',
			'database.sql'         => 'sql',
			'db.sql'               => 'sql',
			'dump.sql'             => 'sql',
			'wordpress.sql'        => 'sql',
			$host . '.sql'         => 'sql',
			'wp-content/debug.log' => 'log',
			'debug.log'            => 'log',
			'error_log'            => 'log',
			'wp-admin/error_log'   => 'log',
			'phpinfo.php'          => 'phpinfo',
			'info.php'             => 'phpinfo',
			'adminer.php'          => 'adminer',
			'wp-content/uploads/'  => 'listing',
			'wp-content/plugins/'  => 'listing',
			'wp-includes/'         => 'listing',
		);
		/**
		 * Filters the addresses the exposure check asks for.
		 *
		 * @param array $paths Path relative to the site root => kind (env, git, config, sql, archive, log, phpinfo, ...).
		 */
		return (array) apply_filters( 'cshield_exposure_paths', $paths );
	}

	/**
	 * Files on the server that should not sit in a public folder, by name.
	 *
	 * @return array Kind => pattern.
	 */
	private static function local_patterns() {
		return array(
			'config'  => '/^(?:wp-config\.php.+|wp-config\.(?:bak|old|txt)|\.wp-config\.php\.sw[op])$/i',
			'sql'     => '/\.sql(?:\.gz|\.zip)?$/i',
			'archive' => '/\.(?:zip|tar|tgz|tar\.gz|7z|rar|wpress)$/i',
			'env'     => '/^\.env(?:\.\w+)?$/',
			'log'     => '/^(?:debug\.log|error_log|php_errors?\.log)$/i',
			'phpinfo' => '/^(?:phpinfo|info|php_info|test_info)\.php$/i',
			'adminer' => '/^adminer[\w.-]*\.php$/i',
		);
	}

	/**
	 * The last check: checked, files (id => finding), keys (list), htaccess.
	 *
	 * @return array
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION, array() );
		return wp_parse_args(
			is_array( $state ) ? $state : array(),
			array(
				'checked' => 0,
				'files'   => array(),
				'keys'    => array(),
			)
		);
	}

	/**
	 * Runs the check.
	 *
	 * @param array $pages   Page address => HTML.
	 * @param array $scripts Script address => code.
	 * @return array State.
	 */
	public static function check( array $pages, array $scripts ) {
		$before = self::state();
		$kinds  = self::kinds();
		$files  = array();
		$root   = trailingslashit( home_url() );
		foreach ( self::probes() as $path => $kind ) {
			if ( ! isset( $kinds[ $kind ] ) ) {
				continue;
			}
			$res = Page_Check::fetch(
				$root . ltrim( $path, '/' ),
				array(
					'redirection'         => 0,
					'limit_response_size' => 8192,
					'headers'             => array(
						'Range'  => 'bytes=0-8191',
						'Accept' => '*/*',
					),
				)
			);
			if ( is_wp_error( $res ) || ! in_array( (int) wp_remote_retrieve_response_code( $res ), array( 200, 206 ), true ) ) {
				continue;
			}
			$body = substr( (string) wp_remote_retrieve_body( $res ), 0, 8192 );
			if ( ! preg_match( $kinds[ $kind ][1], $body ) || ( 'env' === $kind && false !== stripos( $body, '<html' ) ) ) {
				continue;
			}
			$id           = md5( $path );
			$files[ $id ] = array(
				'id'     => $id,
				'path'   => $path,
				'kind'   => $kind,
				'public' => true,
				'local'  => file_exists( ABSPATH . $path ),
				'size'   => is_file( ABSPATH . $path ) ? (int) filesize( ABSPATH . $path ) : 0,
			);
		}
		foreach ( self::local() as $path => $kind ) {
			$id = md5( $path );
			if ( isset( $files[ $id ] ) ) {
				continue;
			}
			$files[ $id ] = array(
				'id'     => $id,
				'path'   => $path,
				'kind'   => $kind,
				'public' => false,
				'local'  => true,
				'size'   => (int) filesize( ABSPATH . $path ),
			);
		}

		$keys = array();
		foreach ( array_merge( $pages, $scripts ) as $where => $text ) {
			foreach ( self::secrets( (string) $text ) as $hit ) {
				$sig = md5( $hit['type'] . $hit['value'] );
				if ( isset( $keys[ $sig ] ) || count( $keys ) >= 30 ) {
					continue;
				}
				$keys[ $sig ] = array(
					'type'   => $hit['type'],
					'masked' => self::mask( $hit['value'] ),
					'where'  => isset( $pages[ $where ] ) ? Page_Check::short( $where ) : ( is_string( $where ) && Scripts::own( 'https://' . $where ) ? '/' . implode( '/', array_slice( explode( '/', $where ), 1 ) ) : $where ),
				);
			}
		}

		$state = array(
			'checked' => time(),
			'files'   => $files,
			'keys'    => array_values( $keys ),
		);
		Network::update_option( self::OPTION, $state, false );

		$new = array();
		foreach ( $files as $id => $f ) {
			if ( $f['public'] && empty( $before['files'][ $id ]['public'] ) ) {
				$new[] = '- ' . $f['path'] . ': ' . $kinds[ $f['kind'] ][0];
			}
		}
		$old_keys = wp_list_pluck( $before['keys'], 'masked' );
		foreach ( $keys as $k ) {
			if ( ! in_array( $k['masked'], $old_keys, true ) ) {
				$new[] = '- ' . $k['type'] . ' ' . $k['masked'] . ' in ' . $k['where'];
			}
		}
		if ( $new ) {
			Alerts::send(
				'alert_exposure',
				__( 'Private files or keys can be downloaded from your site', 'chaos-shield' ),
				sprintf(
					/* translators: 1: site address, 2: list. */
					__( "Anyone can download these from %1\$s:\n\n%2\$s\n\nDelete the files or block them on the Edge tab. A key that was public should be replaced with a new one by the service that issued it, as it may already have been copied.", 'chaos-shield' ),
					home_url(),
					implode( "\n", $new )
				),
				md5( implode( '|', $new ) )
			);
			Events::add(
				'scan',
				/* translators: %d: number of findings. */
				sprintf( _n( '%d private file or key is publicly reachable.', '%d private files or keys are publicly reachable.', count( $new ), 'chaos-shield' ), count( $new ) ),
				'',
				array(
					'severity' => Events::CRITICAL,
					'action'   => 'exposure.found',
				)
			);
		}
		return $state;
	}

	/**
	 * Risky files in the site root, wp-content and the uploads root.
	 *
	 * @return array Path relative to ABSPATH => kind.
	 */
	public static function local() {
		$out     = array();
		$uploads = wp_upload_dir( null, false );
		$dirs    = array_unique( array( untrailingslashit( ABSPATH ), WP_CONTENT_DIR, untrailingslashit( $uploads['basedir'] ) ) );
		foreach ( $dirs as $dir ) {
			$list = is_dir( $dir ) ? scandir( $dir ) : false;
			if ( ! $list ) {
				continue;
			}
			foreach ( $list as $name ) {
				$full = $dir . '/' . $name;
				if ( '.' === $name || '..' === $name || ! is_file( $full ) || 'wp-config.php' === $name || 'wp-config-sample.php' === $name ) {
					continue;
				}
				foreach ( self::local_patterns() as $kind => $pattern ) {
					if ( preg_match( $pattern, $name ) ) {
						$rel = ltrim( substr( wp_normalize_path( $full ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' );
						if ( 0 !== strpos( wp_normalize_path( $full ), wp_normalize_path( ABSPATH ) ) ) {
							break;
						}
						$out[ $rel ] = $kind;
						break;
					}
				}
			}
		}
		return $out;
	}

	/**
	 * Secret keys in a page or script.
	 *
	 * @param string $text Text.
	 * @return array[] Each: type, value.
	 */
	public static function secrets( $text ) {
		$patterns = array(
			'AWS access key'     => '/\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/',
			'Stripe secret key'  => '/\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b/',
			'GitHub token'       => '/\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/',
			'Slack token'        => '/\b(xox[baprs]-[A-Za-z0-9-]{20,})\b/',
			'Slack webhook'      => '#(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})#',
			'Private key'        => '/(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)/',
			'OpenAI API key'     => '/\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})\b/',
			'Anthropic API key'  => '/\b(sk-ant-[A-Za-z0-9_-]{40,})\b/',
			'SendGrid API key'   => '/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/',
			'Mailgun API key'    => '/\b(key-[0-9a-f]{32})\b/',
			'Google service key' => '/("private_key_id"\s*:\s*"[0-9a-f]{40}")/',
		);
		$out      = array();
		foreach ( $patterns as $type => $pattern ) {
			if ( preg_match_all( $pattern, $text, $m ) ) {
				foreach ( array_unique( $m[1] ) as $value ) {
					// Anthropic keys also match the OpenAI shape; report them once.
					if ( 'OpenAI API key' === $type && 0 === strpos( $value, 'sk-ant-' ) ) {
						continue;
					}
					$out[] = array(
						'type'  => $type,
						'value' => $value,
					);
				}
			}
		}
		return $out;
	}

	/**
	 * A key with most of it hidden.
	 *
	 * @param string $value Key.
	 * @return string
	 */
	public static function mask( $value ) {
		if ( 0 === strpos( $value, '-----' ) || 0 === strpos( $value, '"private_key_id"' ) ) {
			return $value;
		}
		return substr( $value, 0, 8 ) . str_repeat( '•', 6 ) . substr( $value, -3 );
	}

	/**
	 * How a finding's kind is described.
	 *
	 * @param string $kind Kind.
	 * @return string
	 */
	public static function describe( $kind ) {
		$kinds = self::kinds();
		return isset( $kinds[ $kind ] ) ? $kinds[ $kind ][0] : $kind;
	}

	/**
	 * Deletes a risky file found on the server.
	 *
	 * @param string $id Finding ID.
	 * @return true|\WP_Error
	 */
	public static function delete( $id ) {
		$state = self::state();
		if ( ! isset( $state['files'][ $id ] ) ) {
			return new \WP_Error( 'cshield_exposure', __( 'That file is no longer listed. Check again.', 'chaos-shield' ) );
		}
		$f    = $state['files'][ $id ];
		$path = wp_normalize_path( ABSPATH . $f['path'] );
		$real = realpath( $path );
		// Only plain files the check itself found by name, and never the live config.
		if ( ! $real || ! is_file( $real ) || 0 !== strpos( wp_normalize_path( $real ), wp_normalize_path( realpath( ABSPATH ) ) ) || in_array( basename( $real ), array( 'wp-config.php', '.htaccess', 'index.php' ), true ) || ! isset( self::local()[ $f['path'] ] ) ) {
			return new \WP_Error( 'cshield_exposure', __( 'This one cannot be deleted from here. Remove it with your host\'s file manager, or block it.', 'chaos-shield' ) );
		}
		wp_delete_file( $real );
		if ( file_exists( $real ) ) {
			return new \WP_Error( 'cshield_exposure', __( 'The file could not be deleted. Check its permissions, or remove it with your host\'s file manager.', 'chaos-shield' ) );
		}
		unset( $state['files'][ $id ] );
		Network::update_option( self::OPTION, $state, false );
		Events::add(
			'scan',
			/* translators: %s: file path. */
			sprintf( __( 'Deleted the exposed file %s.', 'chaos-shield' ), $f['path'] ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'exposure.deleted',
				'subject'  => $f['path'],
			)
		);
		return true;
	}

	// Blocking with .htaccess.

	/**
	 * Whether the web server reads .htaccess files.
	 *
	 * @return bool
	 */
	public static function apache() {
		$software = strtolower( Request::server( 'SERVER_SOFTWARE' ) );
		return false !== strpos( $software, 'apache' ) || false !== strpos( $software, 'litespeed' ) || ( '' === $software && is_file( ABSPATH . '.htaccess' ) );
	}

	/**
	 * The rules that refuse risky files.
	 *
	 * @return string[]
	 */
	public static function rules() {
		return array(
			'<IfModule mod_authz_core.c>',
			'<FilesMatch "(^\.(?!well-known)|\.(sql|sql\.gz|bak|old|orig|save|swp|log|env)$|^(wp-config\.php.+|error_log|debug\.log|phpinfo\.php|info\.php|adminer.*\.php)$)">',
			'Require all denied',
			'</FilesMatch>',
			'<If "%{REQUEST_URI} =~ m#^/[^/]+\.(zip|tar|tgz|gz|7z|rar|wpress)$#">',
			'Require all denied',
			'</If>',
			'</IfModule>',
			'RedirectMatch 404 /\.(git|svn|hg)(/|$)',
			'Options -Indexes',
		);
	}

	/**
	 * The same rules for nginx, to copy.
	 *
	 * @return string
	 */
	public static function nginx() {
		return "location ~ /\\.(?!well-known) { deny all; }\nlocation ~* \\.(sql|bak|old|orig|save|swp|log|env)\$ { deny all; }\nlocation ~* ^/(wp-config\\.php.+|error_log|debug\\.log|phpinfo\\.php|info\\.php)\$ { deny all; }\nlocation ~* ^/[^/]+\\.(zip|tar|tgz|gz|7z|rar|wpress)\$ { deny all; }\nautoindex off;";
	}

	/**
	 * Whether the block is in the root .htaccess.
	 *
	 * @return bool
	 */
	public static function protected_now() {
		$file = ABSPATH . '.htaccess';
		return is_file( $file ) && false !== strpos( (string) file_get_contents( $file ), '# BEGIN ' . self::MARKER ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Adds or removes the block in the root .htaccess.
	 *
	 * @param bool $on Add or remove.
	 * @return true|\WP_Error
	 */
	public static function protect( $on ) {
		$file = ABSPATH . '.htaccess';
		if ( ( file_exists( $file ) && ! wp_is_writable( $file ) ) || ( ! file_exists( $file ) && ! wp_is_writable( ABSPATH ) ) ) {
			return new \WP_Error( 'cshield_exposure', __( 'The .htaccess file in the site root cannot be written. Add the rules by hand, or ask your host.', 'chaos-shield' ) );
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		Integrity::expect( '.htaccess' );
		if ( ! insert_with_markers( $file, self::MARKER, $on ? self::rules() : array() ) ) {
			return new \WP_Error( 'cshield_exposure', __( 'The rules could not be saved to .htaccess.', 'chaos-shield' ) );
		}
		if ( ! $on ) {
			// insert_with_markers leaves empty markers behind; take them out.
			$body = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			$body = (string) preg_replace( '/\n?# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\n?/s', "\n", $body );
			file_put_contents( $file, ltrim( $body ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Local file.
		}
		if ( $on && self::broken() ) {
			// The server refused the rules: put the file back as it was.
			self::protect( false );
			return new \WP_Error( 'cshield_exposure', __( 'The server did not accept the rules, so they were taken out again. Your host may not allow these settings in .htaccess.', 'chaos-shield' ) );
		}
		Integrity::accept( '.htaccess' );
		Events::add(
			'settings',
			$on ? __( 'Blocked downloads of backups, logs and hidden files in .htaccess.', 'chaos-shield' ) : __( 'Removed the block on backups, logs and hidden files from .htaccess.', 'chaos-shield' ),
			Request::ip(),
			array( 'action' => 'settings.exposure' )
		);
		return true;
	}

	/**
	 * Whether the home page fails after a .htaccess change.
	 *
	 * @return bool
	 */
	private static function broken() {
		$res = Page_Check::fetch( home_url( '/' ), array( 'redirection' => 3 ) );
		return ! is_wp_error( $res ) && 500 === (int) wp_remote_retrieve_response_code( $res );
	}
}
