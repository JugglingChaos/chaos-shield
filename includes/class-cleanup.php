<?php
/**
 * Cleanup tools: quarantine, core file repair and a database scan.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Fixes what the scanner finds.
 */
final class Cleanup {

	/**
	 * Finding rules fixed by putting back the official copy.
	 *
	 * @var string[]
	 */
	const REPAIRABLE = array( 'modified', 'missing', 'org_modified' );

	const QUARANTINE_OPTION = 'cshield_quarantine';
	const DB_RESULTS        = 'cshield_db_scan';
	const DIR               = 'cshield-quarantine';

	/**
	 * Absolute path of a finding's file, or '' when it is outside the site.
	 *
	 * @param string $display File as shown in findings (wp-content/... or relative to ABSPATH).
	 * @return string
	 */
	public static function path( $display ) {
		$display = ltrim( wp_normalize_path( (string) $display ), '/' );
		$path    = 0 === strpos( $display, 'wp-content/' )
			? wp_normalize_path( WP_CONTENT_DIR ) . '/' . substr( $display, 11 )
			: wp_normalize_path( ABSPATH ) . $display;
		if ( false !== strpos( $display, '..' ) ) {
			return '';
		}
		return $path;
	}

	/**
	 * The quarantine folder, created and locked down on first use.
	 *
	 * @return string|\WP_Error
	 */
	private static function dir() {
		$dir = wp_normalize_path( WP_CONTENT_DIR ) . '/' . self::DIR;
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'cshield_q_dir', __( 'Could not create the quarantine folder in wp-content. Check the folder permissions.', 'chaos-shield' ) );
		}
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
		return $dir;
	}

	/**
	 * Quarantined files.
	 *
	 * @return array ID => [ file, stored, time, hash ].
	 */
	public static function quarantined() {
		$q = Network::get_option( self::QUARANTINE_OPTION, array() );
		return is_array( $q ) ? $q : array();
	}

	/**
	 * Moves a flagged file into quarantine, where it can no longer run.
	 *
	 * @param string $finding_id Scan finding ID.
	 * @return true|\WP_Error
	 */
	public static function quarantine( $finding_id ) {
		$finding = self::finding( $finding_id );
		if ( ! $finding ) {
			return new \WP_Error( 'cshield_q_missing', __( 'That finding is no longer in the scan results. Run a new scan.', 'chaos-shield' ) );
		}
		if ( in_array( $finding['rule'], self::REPAIRABLE, true ) ) {
			return new \WP_Error( 'cshield_q_core', __( 'Official files are repaired, not quarantined.', 'chaos-shield' ) );
		}
		$path = self::path( $finding['file'] );
		if ( ! $path || ! is_file( $path ) ) {
			return new \WP_Error( 'cshield_q_gone', __( 'The file is no longer there.', 'chaos-shield' ) );
		}
		$self = wp_normalize_path( CSHIELD_DIR );
		if ( 'wp-config.php' === basename( $path ) || 0 === strpos( wp_normalize_path( $path ), $self ) ) {
			return new \WP_Error( 'cshield_q_protected', __( 'This file cannot be quarantined from here.', 'chaos-shield' ) );
		}
		$dir = self::dir();
		if ( is_wp_error( $dir ) ) {
			return $dir;
		}
		// A random name ending in .php that exits first, so the copy can neither run nor be downloaded,
		// even where the web server ignores the folder's .htaccess.
		$id     = bin2hex( random_bytes( 6 ) );
		$stored = $dir . '/' . bin2hex( random_bytes( 16 ) ) . '.php';
		$body   = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$hash   = md5( (string) $body );
		if ( false === $body || false === file_put_contents( $stored, Restore_Points::GUARD . $body ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The plugin's own quarantine folder.
			return new \WP_Error( 'cshield_q_move', __( 'Could not move the file. Check the file permissions.', 'chaos-shield' ) );
		}
		wp_delete_file( $path );
		if ( file_exists( $path ) ) {
			wp_delete_file( $stored );
			return new \WP_Error( 'cshield_q_move', __( 'Could not move the file. Check the file permissions.', 'chaos-shield' ) );
		}
		$q        = self::quarantined();
		$q[ $id ] = array(
			'file'   => $finding['file'],
			'stored' => $stored,
			'time'   => time(),
			'hash'   => $hash,
			'label'  => $finding['label'],
		);
		Network::update_option( self::QUARANTINE_OPTION, $q, false );
		self::drop_finding( $finding_id );
		/* translators: %s: file. */
		Events::add( 'scan', sprintf( __( 'Quarantined %s.', 'chaos-shield' ), $finding['file'] ), Request::ip(), array( 'severity' => Events::NOTICE ) );
		return true;
	}

	/**
	 * Puts a quarantined file back.
	 *
	 * @param string $id Quarantine ID.
	 * @return true|\WP_Error
	 */
	public static function restore( $id ) {
		$q = self::quarantined();
		if ( ! isset( $q[ $id ] ) ) {
			return new \WP_Error( 'cshield_q_missing', __( 'Unknown quarantined file.', 'chaos-shield' ) );
		}
		$path = self::path( $q[ $id ]['file'] );
		if ( ! $path || file_exists( $path ) ) {
			return new \WP_Error( 'cshield_q_exists', __( 'A file already exists at the original place, so nothing was restored.', 'chaos-shield' ) );
		}
		wp_mkdir_p( dirname( $path ) );
		$stored = (string) $q[ $id ]['stored'];
		$body   = is_file( $stored ) ? (string) file_get_contents( $stored ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$guard  = 0 === strpos( $body, Restore_Points::GUARD );
		if ( $guard ) {
			$moved = false !== file_put_contents( $path, substr( $body, strlen( Restore_Points::GUARD ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Puts the file back.
			if ( $moved ) {
				wp_delete_file( $stored );
			}
		} else {
			// Quarantined before 1.14, moved as it was.
			$moved = @rename( $stored, $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Reported below.
		}
		if ( ! $moved ) {
			return new \WP_Error( 'cshield_q_move', __( 'Could not move the file back. Check the file permissions.', 'chaos-shield' ) );
		}
		/* translators: %s: file. */
		Events::add( 'scan', sprintf( __( 'Restored %s from quarantine.', 'chaos-shield' ), $q[ $id ]['file'] ), Request::ip(), array( 'severity' => Events::NOTICE ) );
		unset( $q[ $id ] );
		Network::update_option( self::QUARANTINE_OPTION, $q, false );
		return true;
	}

	/**
	 * Deletes a quarantined file for good.
	 *
	 * @param string $id Quarantine ID.
	 */
	public static function delete( $id ) {
		$q = self::quarantined();
		if ( isset( $q[ $id ] ) ) {
			wp_delete_file( $q[ $id ]['stored'] );
			/* translators: %s: file. */
			Events::add( 'scan', sprintf( __( 'Deleted quarantined copy of %s.', 'chaos-shield' ), $q[ $id ]['file'] ), Request::ip() );
			unset( $q[ $id ] );
			Network::update_option( self::QUARANTINE_OPTION, $q, false );
		}
	}

	/**
	 * Replaces a modified or missing core file with the official copy, checked against its checksum.
	 *
	 * @param string $finding_id Scan finding ID.
	 * @return true|\WP_Error
	 */
	public static function repair_core( $finding_id ) {
		global $wp_version;
		$finding = self::finding( $finding_id );
		if ( ! $finding || ! in_array( $finding['rule'], self::REPAIRABLE, true ) ) {
			return new \WP_Error( 'cshield_r_missing', __( 'That finding is not an official file, or it is gone. Run a new scan.', 'chaos-shield' ) );
		}
		$file = $finding['file'];
		if ( 'org_modified' === $finding['rule'] ) {
			$body = self::official_copy( $finding['source'] );
			if ( is_wp_error( $body ) ) {
				return $body;
			}
			// The repaired file should not come back as a change in the next scan.
			Scanner::expect_changes( '@content/' . $finding['source']['type'] . 's/' . $finding['source']['slug'] . '/' );
		} else {
			$sums = Scanner::core_checksums();
			if ( ! is_array( $sums ) || empty( $sums[ $file ] ) ) {
				return new \WP_Error( 'cshield_r_sums', __( 'The official checksum for this file is not available, so it was not replaced.', 'chaos-shield' ) );
			}
			$response = wp_remote_get( 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . self::url_path( $file ), array( 'timeout' => 20 ) );
			$body     = is_wp_error( $response ) ? '' : (string) wp_remote_retrieve_body( $response );
			if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) || md5( $body ) !== $sums[ $file ] ) {
				return new \WP_Error( 'cshield_r_download', __( 'Could not download a copy that matches the official checksum. Reinstall WordPress from Dashboard > Updates instead.', 'chaos-shield' ) );
			}
		}
		$path = self::path( $file );
		if ( Restore_Points::enabled() ) {
			// One click puts the modified file back if the repair turns out to break something.
			$point = Restore_Points::create( 'repair', $file, array( $path ), array(), false );
			if ( is_wp_error( $point ) ) {
				return $point;
			}
		} elseif ( is_file( $path ) ) {
			// Keep the modified copy for later inspection.
			$dir = self::dir();
			if ( ! is_wp_error( $dir ) ) {
				copy( $path, $dir . '/' . substr( md5( $path . microtime() ), 0, 12 ) . '-' . sanitize_file_name( basename( $path ) ) . '.modified' );
			}
		}
		wp_mkdir_p( dirname( $path ) );
		if ( false === file_put_contents( $path, $body ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes a verified core file.
			return new \WP_Error( 'cshield_r_write', __( 'Could not write the file. Check the file permissions.', 'chaos-shield' ) );
		}
		self::drop_finding( $finding_id );
		/* translators: %s: file. */
		Events::add( 'scan', sprintf( __( 'Repaired %s from the official WordPress.org copy.', 'chaos-shield' ), $file ), Request::ip(), array( 'severity' => Events::NOTICE ) );
		return true;
	}

	/**
	 * Downloads the official copy of a plugin or theme file and checks it against the release checksums.
	 *
	 * @param array $source type, slug, version, rel.
	 * @return string|\WP_Error File contents.
	 */
	private static function official_copy( $source ) {
		$fail = new \WP_Error( 'cshield_r_download', __( 'Could not download a copy that matches the official release. Reinstall the plugin or theme instead.', 'chaos-shield' ) );
		if ( ! is_array( $source ) || empty( $source['slug'] ) ) {
			return $fail;
		}
		$sums = Scanner::official_sums( $source['type'], $source['slug'], $source['version'] );
		if ( ! is_array( $sums ) || empty( $sums[ $source['rel'] ] ) ) {
			return $fail;
		}
		$rel  = self::url_path( $source['rel'] );
		$slug = rawurlencode( $source['slug'] );
		$ver  = rawurlencode( $source['version'] );
		$urls = 'plugin' === $source['type']
			? array( "https://plugins.svn.wordpress.org/{$slug}/tags/{$ver}/{$rel}", "https://plugins.svn.wordpress.org/{$slug}/trunk/{$rel}" )
			: array( "https://themes.svn.wordpress.org/{$slug}/{$ver}/{$rel}" );
		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
			$body     = is_wp_error( $response ) ? '' : (string) wp_remote_retrieve_body( $response );
			// Trunk can differ from the release, so only a copy matching the release checksum is used.
			if ( 200 === (int) wp_remote_retrieve_response_code( $response ) && in_array( md5( $body ), $sums[ $source['rel'] ], true ) ) {
				return $body;
			}
		}
		return $fail;
	}

	/**
	 * URL-encodes each part of a relative path.
	 *
	 * @param string $file Relative path.
	 * @return string
	 */
	private static function url_path( $file ) {
		return str_replace( '%2F', '/', rawurlencode( $file ) );
	}

	/**
	 * A finding from the last scan.
	 *
	 * @param string $id Finding ID.
	 * @return array|null
	 */
	private static function finding( $id ) {
		$results = Scanner::results();
		foreach ( $results ? $results['findings'] : array() as $f ) {
			if ( $f['id'] === $id ) {
				return $f;
			}
		}
		return null;
	}

	/**
	 * Removes a fixed finding from the stored results.
	 *
	 * @param string $id Finding ID.
	 */
	private static function drop_finding( $id ) {
		$results = Scanner::results();
		if ( ! $results ) {
			return;
		}
		$results['findings'] = array_values(
			array_filter(
				$results['findings'],
				static function ( $f ) use ( $id ) {
					return $f['id'] !== $id;
				}
			)
		);
		Network::update_option( Scanner::RESULTS_OPTION, $results, false );
	}

	/**
	 * Searches posts and options for injected scripts, hidden iframes and obfuscated code.
	 *
	 * @return array Findings: where, id, title, label, snippet, edit.
	 */
	public static function scan_database() {
		global $wpdb;
		$home     = wp_parse_url( home_url(), PHP_URL_HOST );
		$findings = array();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- One-off scan of core tables.
		$posts = $wpdb->get_results(
			"SELECT ID, post_title, post_type, post_content FROM {$wpdb->posts}
			WHERE post_status NOT IN ('trash','auto-draft','inherit')
			AND ( post_content LIKE '%<script%' OR post_content LIKE '%<iframe%' OR post_content LIKE '%eval(%' OR post_content LIKE '%fromCharCode%' OR post_content LIKE '%atob(%' )
			LIMIT 2000",
			ARRAY_A
		);
		foreach ( (array) $posts as $post ) {
			$hit = self::match_content( (string) $post['post_content'], $home );
			if ( $hit ) {
				$findings[] = array(
					'where'   => 'post',
					'id'      => (int) $post['ID'],
					/* translators: 1: post type, 2: title. */
					'title'   => sprintf( __( '%1$s "%2$s"', 'chaos-shield' ), $post['post_type'], $post['post_title'] ),
					'label'   => $hit['label'],
					'snippet' => $hit['snippet'],
					'edit'    => get_edit_post_link( (int) $post['ID'], 'raw' ),
				);
			}
		}

		$options = $wpdb->get_results(
			"SELECT option_name, option_value FROM {$wpdb->options}
			WHERE option_name NOT LIKE '\\_transient%' AND option_name NOT LIKE '\\_site\\_transient%'
			AND ( option_value LIKE '%<script%' OR option_value LIKE '%<iframe%' OR option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode(%' OR option_value LIKE '%fromCharCode%' )
			LIMIT 500",
			ARRAY_A
		);
		// phpcs:enable
		foreach ( (array) $options as $option ) {
			if ( 0 === strpos( $option['option_name'], 'cshield_' ) ) {
				continue;
			}
			$hit = self::match_content( (string) $option['option_value'], $home );
			if ( $hit ) {
				$findings[] = array(
					'where'   => 'option',
					'id'      => 0,
					/* translators: %s: option name. */
					'title'   => sprintf( __( 'Setting %s', 'chaos-shield' ), $option['option_name'] ),
					'label'   => $hit['label'],
					'snippet' => $hit['snippet'],
					'edit'    => '',
				);
			}
		}

		// The site address itself is a favourite target: a changed home URL sends every visitor elsewhere.
		foreach ( array( 'siteurl', 'home' ) as $name ) {
			$value = (string) get_option( $name );
			if ( defined( 'WP_HOME' ) || defined( 'WP_SITEURL' ) || ! $value ) {
				break;
			}
			if ( preg_match( '#<|javascript:|\s#i', $value ) ) {
				$findings[] = array(
					'where'   => 'option',
					'id'      => 0,
					/* translators: %s: option name. */
					'title'   => sprintf( __( 'Setting %s', 'chaos-shield' ), $name ),
					'label'   => __( 'Site address contains code', 'chaos-shield' ),
					'snippet' => substr( $value, 0, 160 ),
					'edit'    => admin_url( 'options-general.php' ),
				);
			}
		}

		Network::update_option(
			self::DB_RESULTS,
			array(
				'checked'  => time(),
				'findings' => $findings,
			),
			false
		);
		Events::add(
			'scan',
			/* translators: %d: number of findings. */
			sprintf( __( 'Database scan finished: %d items need a look.', 'chaos-shield' ), count( $findings ) ),
			Request::ip(),
			array( 'severity' => $findings ? Events::NOTICE : Events::INFO )
		);
		return $findings;
	}

	/**
	 * Last database scan.
	 *
	 * @return array|null
	 */
	public static function db_results() {
		$r = Network::get_option( self::DB_RESULTS );
		return is_array( $r ) ? $r : null;
	}

	/**
	 * Looks for injected code in stored content.
	 *
	 * @param string $content Content.
	 * @param string $home    This site's host.
	 * @return array|null label and snippet.
	 */
	public static function match_content( $content, $home ) {
		$rules = array(
			array( '/<script[^>]+src\s*=\s*["\']?(?:https?:)?\/\/([^\/"\'\s>]+)/i', __( 'Script loaded from another site', 'chaos-shield' ), 'external' ),
			array( '/<script\b[^>]*>[^<]{0,2000}?(?:eval\s*\(|String\.fromCharCode|atob\s*\(|unescape\s*\(|document\.write\s*\(\s*unescape)/i', __( 'Obfuscated inline script', 'chaos-shield' ), '' ),
			array( '/<iframe[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["\']?0["\'\s>]|height\s*=\s*["\']?0["\'\s>])/i', __( 'Hidden iframe', 'chaos-shield' ), '' ),
			array( '/\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|atob)\s*\(/i', __( 'Code that decodes and runs hidden data', 'chaos-shield' ), '' ),
		);
		foreach ( $rules as $rule ) {
			if ( ! preg_match( $rule[0], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}
			if ( 'external' === $rule[2] ) {
				$host = strtolower( $m[1][0] );
				if ( $host === $home || in_array( $host, self::trusted_script_hosts(), true ) ) {
					continue;
				}
			}
			$snip = substr( $content, max( 0, $m[0][1] - 20 ), 180 );
			return array(
				'label'   => $rule[1],
				'snippet' => preg_replace( '/\s+/', ' ', wp_check_invalid_utf8( $snip, true ) ),
			);
		}
		return null;
	}

	/**
	 * Script hosts that are normal on WordPress sites.
	 *
	 * @return string[]
	 */
	private static function trusted_script_hosts() {
		$hosts = array( 'www.googletagmanager.com', 'www.google-analytics.com', 'www.google.com', 'www.gstatic.com', 'js.stripe.com', 'platform.twitter.com', 'connect.facebook.net', 'www.youtube.com', 'player.vimeo.com', 'static.cloudflareinsights.com', 'challenges.cloudflare.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'code.jquery.com' );
		/**
		 * Filters the script hosts the database scan does not report.
		 *
		 * @param string[] $hosts Host names.
		 */
		return (array) apply_filters( 'cshield_trusted_script_hosts', $hosts );
	}
}
