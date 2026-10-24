<?php
/**
 * Replaces the security keys and salts in wp-config.php.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Writes eight new keys into wp-config.php, which signs everyone out and
 * voids stolen cookies, and seals this plugin's stored secrets again so
 * two-factor, the hub and connected services keep working.
 */
final class Salts {

	const NAMES   = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
	const ROTATED = 'cshield_salts_rotated';

	/**
	 * The wp-config.php WordPress loads, found the same way it does.
	 *
	 * @return string Path, or '' when there is none.
	 */
	public static function config_path() {
		if ( is_file( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$up = dirname( ABSPATH ) . '/wp-config.php';
		return is_file( $up ) && ! is_file( dirname( ABSPATH ) . '/wp-settings.php' ) ? $up : '';
	}

	/**
	 * Whether the keys can be replaced from the dashboard, and if not, why.
	 *
	 * @return true|\WP_Error
	 */
	public static function can_rotate() {
		$path = self::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return new \WP_Error( 'cshield_salts_missing', __( 'wp-config.php could not be found or read.', 'chaos-shield' ) );
		}
		if ( ! is_writable( $path ) || ! is_writable( dirname( $path ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Local file.
			return new \WP_Error( 'cshield_salts_locked', __( 'wp-config.php is read-only, so the keys cannot be changed from here.', 'chaos-shield' ) );
		}
		if ( has_filter( 'salt' ) ) {
			return new \WP_Error( 'cshield_salts_filtered', __( 'Another plugin changes the security keys, so they cannot be replaced safely from here.', 'chaos-shield' ) );
		}
		$body = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		foreach ( self::NAMES as $name ) {
			if ( ! defined( $name ) || 1 !== preg_match_all( self::pattern( $name ), $body ) ) {
				return new \WP_Error( 'cshield_salts_layout', __( 'The keys in wp-config.php are not in the usual form, so they cannot be changed safely from here.', 'chaos-shield' ) );
			}
		}
		return true;
	}

	/**
	 * Matches one define() line.
	 *
	 * @param string $name Constant name.
	 * @return string
	 */
	private static function pattern( $name ) {
		return '/define\(\s*([\'"])' . $name . '\1\s*,\s*([\'"])(?:\\\\.|(?!\2).)*\2\s*\)\s*;/';
	}

	/**
	 * Eight new random keys.
	 *
	 * Built from characters that need no escaping in a single-quoted PHP string.
	 *
	 * @return array Name => value.
	 */
	public static function generate() {
		$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&()*+,-./:;<=>?@[]^_{|}~';
		$keys  = array();
		foreach ( self::NAMES as $name ) {
			$value = '';
			for ( $i = 0; $i < 64; $i++ ) {
				$value .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
			}
			$keys[ $name ] = $value;
		}
		return $keys;
	}

	/**
	 * The lines to paste by hand when the file cannot be written.
	 *
	 * @param array|null $keys Keys, new ones when empty.
	 * @return string
	 */
	public static function block( $keys = null ) {
		$keys  = $keys ? $keys : self::generate();
		$lines = array();
		foreach ( $keys as $name => $value ) {
			$lines[] = "define( '" . $name . "', " . str_repeat( ' ', 16 - strlen( $name ) ) . "'" . $value . "' );";
		}
		return implode( "\n", $lines );
	}

	/**
	 * Every secret this plugin keeps sealed with the current keys.
	 *
	 * @return array[] Each: get (callable returning the sealed value), set (callable taking a new sealed value).
	 */
	private static function sealed() {
		$items = array();
		foreach ( array( Cloudflare::TOKEN, Api::SEALED, Connections::CHAT_URL ) as $option ) {
			$items[] = self::option_item( $option );
		}
		foreach ( Captcha::providers() as $provider ) {
			$items[] = self::option_item( $provider['secret'] );
		}
		foreach ( array_keys( Hub::sites() ) as $id ) {
			$items[] = array(
				'get' => static function () use ( $id ) {
					$sites = Hub::sites();
					return isset( $sites[ $id ]['key'] ) ? (string) $sites[ $id ]['key'] : '';
				},
				'set' => static function ( $value ) use ( $id ) {
					$sites = Hub::sites();
					if ( isset( $sites[ $id ] ) ) {
						$sites[ $id ]['key'] = $value;
						Network::update_option( Hub::SITES_OPTION, $sites, false );
					}
				},
			);
		}
		foreach ( array( Two_Factor::META_SECRET, Two_Factor::META_PENDING ) as $meta ) {
			$ids = get_users(
				array(
					'meta_key' => $meta, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- One-off, on request.
					'fields'   => 'ID',
					'number'   => -1,
					'blog_id'  => 0,
				)
			);
			foreach ( $ids as $user_id ) {
				$items[] = array(
					'get' => static function () use ( $user_id, $meta ) {
						return (string) get_user_meta( (int) $user_id, $meta, true );
					},
					'set' => static function ( $value ) use ( $user_id, $meta ) {
						update_user_meta( (int) $user_id, $meta, $value );
					},
				);
			}
		}
		return $items;
	}

	/**
	 * A sealed secret stored as one option.
	 *
	 * @param string $option Option name.
	 * @return array
	 */
	private static function option_item( $option ) {
		return array(
			'get' => static function () use ( $option ) {
				return (string) Network::get_option( $option, '' );
			},
			'set' => static function ( $value ) use ( $option ) {
				Network::update_option( $option, $value, false );
			},
		);
	}

	/**
	 * Replaces the keys, then seals the stored secrets with the new ones.
	 *
	 * @param string $why What led to it, for the log.
	 * @return true|\WP_Error
	 */
	public static function rotate( $why = '' ) {
		$ready = self::can_rotate();
		if ( is_wp_error( $ready ) ) {
			return $ready;
		}
		$path = self::config_path();
		$body = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$keys = self::generate();

		// Read every secret while the old keys still work.
		$open = array();
		foreach ( self::sealed() as $item ) {
			$sealed = call_user_func( $item['get'] );
			$plain  = '' !== $sealed ? Totp::open( $sealed ) : false;
			if ( false !== $plain ) {
				$open[] = array( $item['set'], $plain );
			}
		}

		$new = $body;
		foreach ( $keys as $name => $value ) {
			$new = preg_replace_callback(
				self::pattern( $name ),
				static function () use ( $name, $value ) {
					return "define( '" . $name . "', '" . $value . "' );";
				},
				$new,
				1
			);
		}
		foreach ( $keys as $name => $value ) {
			if ( false === strpos( $new, "define( '" . $name . "', '" . $value . "' );" ) ) {
				return new \WP_Error( 'cshield_salts_layout', __( 'The keys in wp-config.php are not in the usual form, so they cannot be changed safely from here.', 'chaos-shield' ) );
			}
		}

		// Write a copy next to the file, then swap it in, so the site never loads half a file.
		// A hidden .php name means a copy left behind by a crash is run, never shown, if requested.
		$temp = dirname( $path ) . '/.cshield-keys-' . wp_generate_password( 12, false ) . '.php';
		$mode = fileperms( $path ) & 0777;
		if ( false === file_put_contents( $temp, $new ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Writes wp-config.php on the owner's request.
			wp_delete_file( $temp );
			return new \WP_Error( 'cshield_salts_write', __( 'wp-config.php could not be written. Nothing was changed.', 'chaos-shield' ) );
		}
		chmod( $temp, $mode ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Keeps the original permissions.
		if ( ! rename( $temp, $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic swap of wp-config.php.
			wp_delete_file( $temp );
			return new \WP_Error( 'cshield_salts_write', __( 'wp-config.php could not be written. Nothing was changed.', 'chaos-shield' ) );
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}

		$key = Totp::key_for( $keys['SECURE_AUTH_KEY'] . $keys['SECURE_AUTH_SALT'] );
		foreach ( $open as $pair ) {
			call_user_func( $pair[0], Totp::seal( $pair[1], $key ) );
		}
		Network::update_option( self::ROTATED, time(), false );
		Events::add(
			'settings',
			'' !== $why
				/* translators: %s: reason. */
				? sprintf( __( 'Security keys in wp-config.php replaced (%s). Everyone was signed out.', 'chaos-shield' ), $why )
				: __( 'Security keys in wp-config.php replaced. Everyone was signed out.', 'chaos-shield' ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'settings.salts_rotated',
			)
		);
		return true;
	}

	/**
	 * Login address to send the current user to once their cookies stopped working.
	 *
	 * @param string $back Where to go after logging in.
	 * @return string
	 */
	public static function login_url( $back ) {
		return add_query_arg( 'cshield_keys', '1', wp_login_url( $back ) );
	}
}
