<?php
/**
 * Multisite support: one protection layer for the whole network.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Where Sentinel Shield keeps its data and who may manage it.
 *
 * On a single site, and on a multisite network where the plugin is active on
 * one site only, everything stays per site, as before. When the plugin is
 * network activated, the whole network shares one set of settings, one log,
 * one ban list and one set of background jobs, and only super admins manage it
 * from Network Admin. A lockout earned on one site then applies on all of them,
 * which matters because they share one user table and one login.
 */
final class Network {

	/**
	 * Cached result of active().
	 *
	 * @var bool|null
	 */
	private static $active = null;

	/**
	 * Whether the plugin is network activated on a multisite network.
	 *
	 * @return bool
	 */
	public static function active() {
		if ( null === self::$active ) {
			$plugins      = is_multisite() ? (array) get_site_option( 'active_sitewide_plugins', array() ) : array();
			self::$active = isset( $plugins[ plugin_basename( SSHIELD_FILE ) ] );
		}
		return self::$active;
	}

	/**
	 * Forgets the cached state.
	 */
	public static function reset() {
		self::$active = null;
	}

	/**
	 * Sets the state ahead of WordPress, during network activation.
	 *
	 * @param bool $active Network activated.
	 */
	public static function assume( $active ) {
		self::$active = (bool) $active;
	}

	/**
	 * Capability that manages Sentinel Shield.
	 *
	 * @return string
	 */
	public static function cap() {
		return self::active() ? 'manage_network_options' : 'manage_options';
	}

	/**
	 * Table name with the right prefix: the network's main tables when network
	 * activated, otherwise this site's.
	 *
	 * @param string $name Table name without prefix.
	 * @return string
	 */
	public static function table( $name ) {
		global $wpdb;
		return ( self::active() ? $wpdb->base_prefix : $wpdb->prefix ) . $name;
	}

	/**
	 * Admin URL of the plugin screens: Network Admin when network activated.
	 *
	 * @param string $path Path relative to the admin.
	 * @return string
	 */
	public static function admin_url( $path = '' ) {
		return self::active() ? network_admin_url( $path ) : admin_url( $path );
	}

	/**
	 * ID of the site that runs background jobs and holds the files.
	 *
	 * @return int
	 */
	public static function main_site() {
		return is_multisite() ? (int) get_main_site_id() : get_current_blog_id();
	}

	/**
	 * Whether this request runs on the site that owns the background jobs.
	 *
	 * @return bool
	 */
	public static function on_main_site() {
		return ! self::active() || get_current_blog_id() === self::main_site();
	}

	/**
	 * Runs a callback on the main site, for cron and uploads paths.
	 *
	 * @param callable $callback Callback.
	 * @return mixed Its result.
	 */
	public static function on_main( callable $callback ) {
		if ( self::on_main_site() ) {
			return $callback();
		}
		switch_to_blog( self::main_site() );
		try {
			return $callback();
		} finally {
			restore_current_blog();
		}
	}

	// Options and transients.

	/**
	 * Reads a plugin option.
	 *
	 * @param string $name     Option name.
	 * @param mixed  $fallback Value when the option is not set.
	 * @return mixed
	 */
	public static function get_option( $name, $fallback = false ) {
		return self::active() ? get_site_option( $name, $fallback ) : get_option( $name, $fallback );
	}

	/**
	 * Moving from one site to the whole network: copies the main site's plugin
	 * options to the network once, so settings, bans and scan results carry over.
	 */
	public static function migrate() {
		global $wpdb;
		if ( ! self::active() || get_site_option( 'sshield_network_since' ) ) {
			return;
		}
		$table = $wpdb->get_blog_prefix( self::main_site() ) . 'options';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- One-off copy from the main site's options table.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value FROM {$table} WHERE option_name LIKE %s", $wpdb->esc_like( 'sshield_' ) . '%' ), ARRAY_A );
		foreach ( (array) $rows as $row ) {
			if ( false === get_site_option( $row['option_name'] ) ) {
				update_site_option( $row['option_name'], maybe_unserialize( $row['option_value'] ) );
			}
		}
		update_site_option( 'sshield_network_since', time() );
	}

	/**
	 * Saves a plugin option.
	 *
	 * @param string    $name     Option name.
	 * @param mixed     $value    Value.
	 * @param bool|null $autoload Autoload, for single sites.
	 * @return bool
	 */
	public static function update_option( $name, $value, $autoload = null ) {
		return self::active() ? update_site_option( $name, $value ) : update_option( $name, $value, $autoload );
	}

	/**
	 * Adds a plugin option when it does not exist yet.
	 *
	 * @param string $name     Option name.
	 * @param mixed  $value    Value.
	 * @param bool   $autoload Autoload, for single sites.
	 * @return bool
	 */
	public static function add_option( $name, $value, $autoload = true ) {
		if ( self::active() ) {
			return add_site_option( $name, $value );
		}
		return false === get_option( $name ) && update_option( $name, $value, $autoload );
	}

	/**
	 * Deletes a plugin option.
	 *
	 * @param string $name Option name.
	 * @return bool
	 */
	public static function delete_option( $name ) {
		return self::active() ? delete_site_option( $name ) : delete_option( $name );
	}

	/**
	 * Reads a plugin transient.
	 *
	 * @param string $name Transient name.
	 * @return mixed
	 */
	public static function get_transient( $name ) {
		return self::active() ? get_site_transient( $name ) : get_transient( $name );
	}

	/**
	 * Saves a plugin transient.
	 *
	 * @param string $name   Transient name.
	 * @param mixed  $value  Value.
	 * @param int    $expire Seconds.
	 * @return bool
	 */
	public static function set_transient( $name, $value, $expire = 0 ) {
		return self::active() ? set_site_transient( $name, $value, $expire ) : set_transient( $name, $value, $expire );
	}

	/**
	 * Deletes a plugin transient.
	 *
	 * @param string $name Transient name.
	 * @return bool
	 */
	public static function delete_transient( $name ) {
		return self::active() ? delete_site_transient( $name ) : delete_transient( $name );
	}

	// Background jobs, always on the main site so a network runs each job once.

	/**
	 * Next run of a hook.
	 *
	 * @param string $hook Hook.
	 * @param array  $args Arguments.
	 * @return int|false
	 */
	public static function next_scheduled( $hook, array $args = array() ) {
		return self::on_main(
			static function () use ( $hook, $args ) {
				return wp_next_scheduled( $hook, $args );
			}
		);
	}

	/**
	 * Schedules a one-off job.
	 *
	 * @param int    $time When.
	 * @param string $hook Hook.
	 * @param array  $args Arguments.
	 * @return bool|\WP_Error
	 */
	public static function schedule_single( $time, $hook, array $args = array() ) {
		return self::on_main(
			static function () use ( $time, $hook, $args ) {
				return wp_schedule_single_event( $time, $hook, $args );
			}
		);
	}

	/**
	 * Schedules a repeating job.
	 *
	 * @param int    $time       First run.
	 * @param string $recurrence Schedule name.
	 * @param string $hook       Hook.
	 * @return bool|\WP_Error
	 */
	public static function schedule_event( $time, $recurrence, $hook ) {
		return self::on_main(
			static function () use ( $time, $recurrence, $hook ) {
				return wp_schedule_event( $time, $recurrence, $hook );
			}
		);
	}

	/**
	 * Removes every scheduled run of a hook.
	 *
	 * @param string $hook Hook.
	 */
	public static function clear_scheduled( $hook ) {
		self::on_main(
			static function () use ( $hook ) {
				wp_unschedule_hook( $hook );
			}
		);
	}

	/**
	 * The main site's uploads folder, shared by the whole network.
	 *
	 * @return string Absolute path without trailing slash, or '' on error.
	 */
	public static function uploads_dir() {
		$uploads = self::on_main(
			static function () {
				return wp_upload_dir( null, false );
			}
		);
		return empty( $uploads['error'] ) ? untrailingslashit( wp_normalize_path( $uploads['basedir'] ) ) : '';
	}

	/**
	 * Name of a site in the network, for the log.
	 *
	 * @param int $blog_id Site ID.
	 * @return string
	 */
	public static function site_name( $blog_id ) {
		static $names = array();
		$blog_id      = (int) $blog_id;
		if ( ! isset( $names[ $blog_id ] ) ) {
			$site              = is_multisite() ? get_site( $blog_id ) : null;
			$names[ $blog_id ] = $site ? untrailingslashit( $site->domain . $site->path ) : '';
		}
		return $names[ $blog_id ];
	}

	/**
	 * Finds a network site by ID, path or address.
	 *
	 * @param string $value Such as 3, shop, /shop/ or shop.example.com.
	 * @return int Site ID, or 0 when none matches.
	 */
	public static function site_id( $value ) {
		$value = trim( (string) $value );
		if ( ! is_multisite() || '' === $value ) {
			return 0;
		}
		if ( ctype_digit( $value ) ) {
			return get_site( (int) $value ) ? (int) $value : 0;
		}
		$value = strtolower( preg_replace( '#^https?://#i', '', $value ) );
		foreach ( get_sites( array( 'number' => 500 ) ) as $site ) {
			$full = untrailingslashit( $site->domain . $site->path );
			$path = trim( $site->path, '/' );
			if ( untrailingslashit( $value ) === $full || trim( $value, '/' ) === $path || ( '' === $path && $value === $site->domain ) ) {
				return (int) $site->blog_id;
			}
		}
		return 0;
	}
}
