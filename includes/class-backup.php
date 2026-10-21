<?php
/**
 * Database backup download and settings export and import.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Downloads the database as a compressed SQL file, and moves settings between sites.
 */
final class Backup {

	const MAX_IMPORT = 262144;

	/**
	 * Streams every WordPress table as a gzip-compressed SQL file.
	 *
	 * Rows are read in batches and written as they are read, so memory stays flat
	 * on large sites. Restore it with phpMyAdmin, Adminer or `wp db import`.
	 *
	 * @return \WP_Error Only on failure; on success the download ends the request.
	 */
	public static function database() {
		global $wpdb;
		$tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->base_prefix ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Backup reads every table.
		if ( ! $tables ) {
			return new \WP_Error( 'cshield_db_none', __( 'No WordPress tables were found to back up.', 'chaos-shield' ) );
		}
		Events::add(
			'system',
			__( 'A database backup was downloaded.', 'chaos-shield' ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'data.backup',
			)
		);

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Some hosts disable it.
		}
		while ( ob_get_level() ) {
			ob_end_clean();
		}
		$gzip = function_exists( 'deflate_init' ) ? deflate_init( ZLIB_ENCODING_GZIP, array( 'level' => 6 ) ) : false;
		$name = sanitize_file_name( wp_parse_url( network_home_url(), PHP_URL_HOST ) . '-' . gmdate( 'Y-m-d-His' ) ) . '.sql' . ( $gzip ? '.gz' : '' );
		nocache_headers();
		header( 'Content-Type: ' . ( $gzip ? 'application/gzip' : 'application/sql' ) );
		header( 'Content-Disposition: attachment; filename="' . $name . '"' );
		header( 'X-Content-Type-Options: nosniff' );

		$out = static function ( $text ) use ( $gzip ) {
			echo $gzip ? deflate_add( $gzip, $text, ZLIB_NO_FLUSH ) : $text; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- A file download, not HTML.
		};
		$out( "-- Chaos Shield database backup\n-- Site: " . network_home_url() . "\n-- Made: " . gmdate( 'c' ) . "\n\nSET NAMES " . ( $wpdb->charset ? $wpdb->charset : 'utf8mb4' ) . ";\nSET FOREIGN_KEY_CHECKS = 0;\nSET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n\n" );
		foreach ( $tables as $table ) {
			$table  = (string) $table;
			$quoted = '`' . str_replace( '`', '``', $table ) . '`';
			$create = $wpdb->get_row( "SHOW CREATE TABLE {$quoted}", ARRAY_N ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names come from SHOW TABLES.
			if ( empty( $create[1] ) ) {
				continue;
			}
			$out( "DROP TABLE IF EXISTS {$quoted};\n" . $create[1] . ";\n\n" );
			for ( $offset = 0; ; $offset += 500 ) {
				$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$quoted} LIMIT %d OFFSET %d", 500, $offset ), ARRAY_N ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names come from SHOW TABLES.
				if ( ! $rows ) {
					break;
				}
				$values = array();
				foreach ( $rows as $row ) {
					$cells = array();
					foreach ( $row as $cell ) {
						$cells[] = null === $cell ? 'NULL' : "'" . $wpdb->remove_placeholder_escape( $wpdb->_real_escape( $cell ) ) . "'";
					}
					$values[] = '(' . implode( ',', $cells ) . ')';
				}
				$out( "INSERT INTO {$quoted} VALUES\n" . implode( ",\n", $values ) . ";\n" );
				flush();
				if ( count( $rows ) < 500 ) {
					break;
				}
			}
			$out( "\n" );
		}
		$out( "SET FOREIGN_KEY_CHECKS = 1;\n" );
		if ( $gzip ) {
			echo deflate_add( $gzip, '', ZLIB_FINISH ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- A file download, not HTML.
		}
		exit;
	}

	/**
	 * Downloads the Chaos Shield settings as JSON.
	 */
	public static function export_settings() {
		Events::add( 'settings', __( 'Chaos Shield settings were exported.', 'chaos-shield' ), Request::ip(), array( 'action' => 'data.export_settings' ) );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="chaos-shield-settings-' . gmdate( 'Y-m-d' ) . '.json"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo wp_json_encode( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- A JSON download.
			array(
				'plugin'   => 'chaos-shield',
				'version'  => CSHIELD_VERSION,
				'exported' => gmdate( 'c' ),
				'site'     => network_home_url(),
				'settings' => Network::get_option( Settings::OPTION, array() ),
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		);
		exit;
	}

	/**
	 * Imports settings from an uploaded export.
	 *
	 * Values are checked against the type of each default, unknown keys are
	 * dropped, this site's login address is kept, and the importer's own IP is
	 * taken off the block list, so an import can never lock its admin out.
	 *
	 * @param array $upload Entry of $_FILES.
	 * @return true|\WP_Error
	 */
	public static function import_settings( array $upload ) {
		$bad = new \WP_Error( 'cshield_import', __( 'That file is not a Chaos Shield settings export.', 'chaos-shield' ) );
		if ( empty( $upload['tmp_name'] ) || ! empty( $upload['error'] ) || ! is_uploaded_file( $upload['tmp_name'] ) || (int) $upload['size'] > self::MAX_IMPORT ) {
			return $bad;
		}
		$data = json_decode( (string) file_get_contents( $upload['tmp_name'] ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the uploaded file.
		if ( ! is_array( $data ) || 'chaos-shield' !== ( isset( $data['plugin'] ) ? $data['plugin'] : '' ) || empty( $data['settings'] ) || ! is_array( $data['settings'] ) ) {
			return $bad;
		}
		$clean = self::clean( $data['settings'] );
		Restore_Points::create( 'import', __( 'Chaos Shield settings', 'chaos-shield' ) );
		Settings::import( $clean );
		Events::add(
			'settings',
			/* translators: %s: site the settings came from. */
			sprintf( __( 'Chaos Shield settings were imported from %s.', 'chaos-shield' ), isset( $data['site'] ) ? esc_url_raw( (string) $data['site'] ) : '?' ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'data.import_settings',
			)
		);
		return true;
	}

	/**
	 * Settings from an import, cast to the type of each default.
	 *
	 * @param array $input Imported settings.
	 * @return array
	 */
	public static function clean( array $input ) {
		$current = Settings::all();
		$clean   = $current;
		foreach ( Settings::defaults() as $key => $default ) {
			if ( ! array_key_exists( $key, $input ) ) {
				continue;
			}
			$value = $input[ $key ];
			if ( is_bool( $default ) ) {
				$clean[ $key ] = (bool) $value;
			} elseif ( is_int( $default ) ) {
				$clean[ $key ] = is_numeric( $value ) ? max( 0, (int) $value ) : $default;
			} elseif ( is_array( $default ) ) {
				$clean[ $key ] = is_array( $value ) ? array_values( array_map( 'sanitize_text_field', array_filter( $value, 'is_scalar' ) ) ) : array();
			} else {
				$clean[ $key ] = is_scalar( $value ) ? sanitize_text_field( (string) $value ) : $default;
			}
		}
		// Belongs to this site: a different login address would surprise its users.
		$clean['login_slug'] = $current['login_slug'];
		// HTTPS redirects need this site's own certificate.
		$clean['force_https'] = $current['force_https'];
		if ( ! array_key_exists( $clean['proxy_header'], Settings::proxy_headers() ) ) {
			$clean['proxy_header'] = '';
		}
		$own = Request::ip();
		if ( $own ) {
			$clean['ip_blocklist'] = array_values(
				array_filter(
					$clean['ip_blocklist'],
					static function ( $entry ) use ( $own ) {
						return ! Request::ip_matches( $own, array( $entry ) );
					}
				)
			);
		}
		return $clean;
	}
}
