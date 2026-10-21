<?php
/**
 * Built-in IP to country database.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Looks up the country of an IP address without an account, a key or a web service.
 *
 * Once a week the public domain user-country lists from the ip-location-db project
 * (compiled from the five regional internet registries, BGP routing tables and
 * operator geofeeds) are downloaded and turned into two small sorted binary files
 * in the uploads folder. A lookup is a binary search over one of them: about twenty
 * file reads, with no database query and nothing sent anywhere.
 */
final class Geo_Db {

	const STATUS = 'cshield_geo_status';
	const HOOK   = 'cshield_geo_refresh';
	const SOURCE = 'https://github.com/sapics/ip-location-db/releases/download/latest/';

	/**
	 * Record sizes: v4 is start and end as 32-bit numbers, v6 the first 64 bits of each; both end with the country.
	 */
	const SIZE4 = 10;
	const SIZE6 = 18;

	/**
	 * Lookups made in this request.
	 *
	 * @var array
	 */
	private static $memo = array();

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'refresh' ) );
		if ( self::enabled() ) {
			add_action( 'init', array( __CLASS__, 'schedule' ) );
		}
	}

	/**
	 * Whether lookups are wanted.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return Settings::enabled( 'geo_db' );
	}

	/**
	 * Keeps the weekly download scheduled.
	 */
	public static function schedule() {
		if ( ! Network::next_scheduled( self::HOOK ) ) {
			$status = self::status();
			Network::schedule_single( time() + ( $status['updated'] && self::ready() ? WEEK_IN_SECONDS : 60 ), self::HOOK );
		}
	}

	/**
	 * Download status.
	 *
	 * @return array updated, v4, v6 (ranges), error.
	 */
	public static function status() {
		$status = Network::get_option( self::STATUS );
		return wp_parse_args(
			is_array( $status ) ? $status : array(),
			array(
				'updated' => 0,
				'v4'      => 0,
				'v6'      => 0,
				'error'   => '',
			)
		);
	}

	/**
	 * Folder that holds the database files.
	 *
	 * @return string
	 */
	public static function dir() {
		// One copy for the whole network, in the main site's uploads.
		return Network::uploads_dir() . '/chaos-shield-geo';
	}

	/**
	 * Path of one database file.
	 *
	 * @param int $family 4 or 6.
	 * @return string
	 */
	private static function file( $family ) {
		return self::dir() . '/countries-v' . $family . '.bin';
	}

	/**
	 * Whether the IPv4 file is in place.
	 *
	 * @return bool
	 */
	public static function ready() {
		return is_readable( self::file( 4 ) );
	}

	/**
	 * Country of an IP address.
	 *
	 * @param string $ip IP address.
	 * @return string Two-letter code, or '' when unknown, private or not downloaded yet.
	 */
	public static function lookup( $ip ) {
		$ip = (string) $ip;
		if ( isset( self::$memo[ $ip ] ) ) {
			return self::$memo[ $ip ];
		}
		$code = '';
		if ( self::enabled() && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			$packed = inet_pton( $ip );
			$code   = 4 === strlen( $packed )
				? self::search( self::file( 4 ), self::SIZE4, $packed )
				: self::search( self::file( 6 ), self::SIZE6, substr( $packed, 0, 8 ) );
		}
		if ( count( self::$memo ) > 500 ) {
			self::$memo = array();
		}
		self::$memo[ $ip ] = $code;
		return $code;
	}

	/**
	 * Binary search over a file of sorted, non-overlapping ranges.
	 *
	 * @param string $path File.
	 * @param int    $size Record size.
	 * @param string $key  Packed address, as wide as one range bound.
	 * @return string
	 */
	private static function search( $path, $size, $key ) {
		$width = ( $size - 2 ) / 2;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Seeking reads of our own data file.
		$fh = is_readable( $path ) ? fopen( $path, 'rb' ) : false;
		if ( ! $fh ) {
			return '';
		}
		$low  = 0;
		$high = (int) floor( filesize( $path ) / $size ) - 1;
		$code = '';
		while ( $low <= $high ) {
			$mid = ( $low + $high ) >> 1;
			fseek( $fh, $mid * $size );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- See above.
			$rec = fread( $fh, $size );
			if ( strlen( $rec ) !== $size ) {
				break;
			}
			if ( strcmp( $key, substr( $rec, 0, $width ) ) < 0 ) {
				$high = $mid - 1;
			} elseif ( strcmp( $key, substr( $rec, $width, $width ) ) > 0 ) {
				$low = $mid + 1;
			} else {
				$code = substr( $rec, 2 * $width, 2 );
				break;
			}
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
		return preg_match( '/^[A-Z]{2}$/', $code ) ? $code : '';
	}

	/**
	 * Downloads both lists and rebuilds the files. Runs from cron.
	 *
	 * @return true|\WP_Error
	 */
	public static function refresh() {
		if ( ! self::enabled() ) {
			return true;
		}
		if ( function_exists( 'set_time_limit' ) ) {
			set_time_limit( 300 ); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- Large download in a cron request.
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$status = self::status();
		$dir    = self::dir();
		if ( ! wp_mkdir_p( $dir ) ) {
			return self::failed( $status, __( 'The uploads folder is not writable.', 'chaos-shield' ) );
		}
		self::protect( $dir );

		$counts = array();
		foreach ( array(
			4 => 'user-country-ipv4-num.csv',
			6 => 'user-country-ipv6.csv',
		) as $family => $name ) {
			$tmp = download_url( self::SOURCE . $name, 240 );
			if ( is_wp_error( $tmp ) ) {
				/* translators: %s: error message. */
				return self::failed( $status, sprintf( __( 'Country database download failed: %s', 'chaos-shield' ), $tmp->get_error_message() ) );
			}
			$count = self::build( $tmp, self::file( $family ), $family );
			wp_delete_file( $tmp );
			// A truncated or empty download must never replace a good file.
			if ( $count < ( 4 === $family ? 50000 : 20000 ) ) {
				return self::failed( $status, __( 'The country database download looked incomplete, so the previous copy was kept.', 'chaos-shield' ) );
			}
			$counts[ $family ] = $count;
		}

		self::$memo = array();
		Network::update_option(
			self::STATUS,
			array(
				'updated' => time(),
				'v4'      => $counts[4],
				'v6'      => $counts[6],
				'error'   => '',
			),
			false
		);
		Network::clear_scheduled( self::HOOK );
		Network::schedule_single( time() + WEEK_IN_SECONDS, self::HOOK );
		return true;
	}

	/**
	 * Records a failed refresh and retries later.
	 *
	 * @param array  $status Current status.
	 * @param string $error  Message.
	 * @return \WP_Error
	 */
	private static function failed( array $status, $error ) {
		$status['error'] = $error;
		Network::update_option( self::STATUS, $status, false );
		Network::clear_scheduled( self::HOOK );
		Network::schedule_single( time() + 6 * HOUR_IN_SECONDS, self::HOOK );
		return new \WP_Error( 'cshield_geo', $error );
	}

	/**
	 * Turns a downloaded list into a sorted binary file, merging neighbouring ranges of the same country.
	 *
	 * @param string $source Downloaded CSV: start,end,country per line.
	 * @param string $target Binary file to write.
	 * @param int    $family 4 (numeric bounds) or 6 (address bounds).
	 * @return int Ranges written, or 0 on failure.
	 */
	public static function build( $source, $target, $family ) {
		// phpcs:disable WordPress.WP.AlternativeFunctions -- Streaming a large file line by line.
		$in  = fopen( $source, 'rb' );
		$tmp = $target . '.tmp';
		$out = $in ? fopen( $tmp, 'wb' ) : false;
		if ( ! $out ) {
			if ( $in ) {
				fclose( $in );
			}
			return 0;
		}
		$count = 0;
		$cur   = null;
		$buf   = '';
		while ( ! feof( $in ) ) {
			$line = fgets( $in );
			if ( false === $line ) {
				break;
			}
			$parts = explode( ',', trim( $line ) );
			if ( 3 !== count( $parts ) || ! preg_match( '/^[A-Z]{2}$/', $parts[2] ) ) {
				continue;
			}
			if ( 4 === $family ) {
				if ( ! ctype_digit( $parts[0] ) || ! ctype_digit( $parts[1] ) ) {
					continue;
				}
				$start = pack( 'N', (int) $parts[0] );
				$end   = pack( 'N', (int) $parts[1] );
			} else {
				$a = inet_pton( $parts[0] );
				$b = inet_pton( $parts[1] );
				if ( ! $a || ! $b || 16 !== strlen( $a ) || 16 !== strlen( $b ) ) {
					continue;
				}
				$start = substr( $a, 0, 8 );
				$end   = substr( $b, 0, 8 );
			}
			if ( null !== $cur && strcmp( $start, $cur[1] ) <= 0 ) {
				// Cut to 64 bits, small IPv6 ranges can share a prefix with the one before: the first keeps it.
				if ( strcmp( $end, $cur[1] ) <= 0 ) {
					continue;
				}
				if ( $parts[2] === $cur[2] ) {
					$cur[1] = $end;
					continue;
				}
				$start = self::next( $cur[1] );
			}
			if ( null !== $cur && $parts[2] === $cur[2] && self::next( $cur[1] ) === $start ) {
				$cur[1] = $end;
				continue;
			}
			if ( null !== $cur ) {
				$buf .= $cur[0] . $cur[1] . $cur[2];
				++$count;
				if ( strlen( $buf ) > 65536 ) {
					fwrite( $out, $buf );
					$buf = '';
				}
			}
			$cur = array( $start, $end, $parts[2] );
		}
		if ( null !== $cur ) {
			$buf .= $cur[0] . $cur[1] . $cur[2];
			++$count;
		}
		fwrite( $out, $buf );
		fclose( $in );
		fclose( $out );
		if ( $count < 1000 || ! rename( $tmp, $target ) ) {
			wp_delete_file( $tmp );
			return 0;
		}
		// phpcs:enable
		return $count;
	}

	/**
	 * The packed number one above a packed bound.
	 *
	 * @param string $bin Big-endian bytes.
	 * @return string
	 */
	private static function next( $bin ) {
		for ( $i = strlen( $bin ) - 1; $i >= 0; $i-- ) {
			$byte = ord( $bin[ $i ] );
			if ( 255 !== $byte ) {
				$bin[ $i ] = chr( $byte + 1 );
				return $bin;
			}
			$bin[ $i ] = "\0";
		}
		return $bin;
	}

	/**
	 * Keeps the folder from being listed or downloaded.
	 *
	 * @param string $dir Folder.
	 */
	private static function protect( $dir ) {
		// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Tiny guard files.
		if ( ! file_exists( $dir . '/index.php' ) ) {
			file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" );
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			file_put_contents( $dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
		}
		// phpcs:enable
	}

	/**
	 * Deletes the files and the status.
	 */
	public static function forget() {
		$dir = self::dir();
		foreach ( array( 'countries-v4.bin', 'countries-v6.bin', 'countries-v4.bin.tmp', 'countries-v6.bin.tmp', 'index.php', '.htaccess' ) as $name ) {
			if ( file_exists( $dir . '/' . $name ) ) {
				wp_delete_file( $dir . '/' . $name );
			}
		}
		if ( is_dir( $dir ) ) {
			@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort; the folder may hold other files.
		}
		Network::delete_option( self::STATUS );
		Network::clear_scheduled( self::HOOK );
	}

	/**
	 * Country names, in the admin's language when PHP intl is available.
	 *
	 * @param string $code Two-letter code.
	 * @param string $fallback English name.
	 * @return string
	 */
	public static function name( $code, $fallback = '' ) {
		if ( class_exists( '\Locale' ) ) {
			$name = \Locale::getDisplayRegion( '-' . $code, get_user_locale() );
			if ( $name && $name !== $code ) {
				return $name;
			}
		}
		return '' !== $fallback ? $fallback : $code;
	}
}
