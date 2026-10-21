<?php
/**
 * Threat intelligence IP blocklist.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Blocks networks on free, public threat lists: Spamhaus DROP, and Tor exit nodes when chosen.
 *
 * Lists are downloaded once a day and stored as sorted, merged IP ranges, so the
 * check on each request is a binary search over a few kilobytes.
 */
final class Threat_Feed {

	const OPTION = 'cshield_threat_ranges';
	const STATUS = 'cshield_threat_status';
	const HOOK   = 'cshield_threat_refresh';

	/**
	 * Ranges decoded for this request.
	 *
	 * @var array|null
	 */
	private static $ranges = null;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'refresh' ) );
		if ( ! Settings::enabled( 'threat_feed' ) ) {
			return;
		}
		// Only the IP is needed, so this runs while the plugin loads.
		$this->enforce();
		add_action( 'init', array( __CLASS__, 'schedule' ) );
	}

	/**
	 * Keeps the daily download scheduled.
	 */
	public static function schedule() {
		if ( ! Network::next_scheduled( self::HOOK ) ) {
			$status = self::status();
			Network::schedule_single( time() + ( $status['updated'] ? DAY_IN_SECONDS : 30 ), self::HOOK );
		}
	}

	/**
	 * The lists, with where they come from.
	 *
	 * @return array Key => [ label, urls, on ].
	 */
	public static function sources() {
		return array(
			'drop' => array(
				'label' => 'Spamhaus DROP',
				'urls'  => array( 'https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json' ),
				'on'    => true,
			),
			'tor'  => array(
				'label' => 'Tor exit nodes',
				'urls'  => array( 'https://check.torproject.org/torbulkexitlist' ),
				'on'    => (bool) Settings::get( 'threat_tor' ),
			),
		);
	}

	/**
	 * Download status.
	 *
	 * @return array updated, counts (source => ranges), error.
	 */
	public static function status() {
		$status = Network::get_option( self::STATUS );
		return is_array( $status ) ? $status + array(
			'updated' => 0,
			'counts'  => array(),
			'error'   => '',
		) : array(
			'updated' => 0,
			'counts'  => array(),
			'error'   => '',
		);
	}

	/**
	 * Refuses requests from listed networks.
	 */
	private function enforce() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || Firewall::allowlisted() ) {
			return;
		}
		$ip     = Request::ip();
		$source = self::lookup( $ip );
		if ( ! $source ) {
			return;
		}
		Login_Guard::bump_stat( 'threat_blocks' );
		$throttle = 'cshield_tf_' . md5( $ip );
		if ( ! Network::get_transient( $throttle ) ) {
			Network::set_transient( $throttle, 1, HOUR_IN_SECONDS );
			$sources = self::sources();
			// Plain English: this runs before translations may be loaded.
			Events::add( 'blocked', sprintf( 'Threat blocklist stopped a visitor from a network on the %s list.', $sources[ $source ]['label'] ), $ip, array( 'action' => 'fw.threat' ) );
		}
		Traffic::note_block( 'threat' );
		Firewall::deny( 'threat' );
	}

	/**
	 * Which list an IP is on.
	 *
	 * @param string $ip IP address.
	 * @return string Source key, or ''.
	 */
	public static function lookup( $ip ) {
		$packed = $ip ? @inet_pton( $ip ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid input returns false.
		if ( false === $packed ) {
			return '';
		}
		if ( null === self::$ranges ) {
			$stored       = Network::get_option( self::OPTION );
			self::$ranges = array();
			foreach ( is_array( $stored ) ? $stored : array() as $source => $blob ) {
				self::$ranges[ $source ] = base64_decode( $blob ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Stored binary ranges.
			}
		}
		$width = strlen( $packed );
		foreach ( self::$ranges as $source => $blob ) {
			if ( self::search( $blob, $packed, $width ) ) {
				return (string) $source;
			}
		}
		return '';
	}

	/**
	 * Binary search for a packed IP in a blob of sorted ranges.
	 *
	 * Each record is a one-byte family width (4 or 16), then start and end padded to 16 bytes.
	 *
	 * @param string $blob   Ranges.
	 * @param string $packed Packed IP.
	 * @param int    $width  4 or 16.
	 * @return bool
	 */
	private static function search( $blob, $packed, $width ) {
		$size  = 33;
		$count = (int) ( strlen( $blob ) / $size );
		$key   = chr( $width ) . str_pad( $packed, 16, "\0", STR_PAD_LEFT );
		$low   = 0;
		$high  = $count - 1;
		while ( $low <= $high ) {
			$mid   = ( $low + $high ) >> 1;
			$start = substr( $blob, $mid * $size, 17 );
			if ( strcmp( $key, $start ) < 0 ) {
				$high = $mid - 1;
				continue;
			}
			$end = substr( $blob, $mid * $size, 1 ) . substr( $blob, $mid * $size + 17, 16 );
			if ( strcmp( $key, $end ) <= 0 ) {
				return true;
			}
			$low = $mid + 1;
		}
		return false;
	}

	/**
	 * Downloads every list that is switched on.
	 *
	 * @return true|\WP_Error
	 */
	public static function refresh() {
		$stored = Network::get_option( self::OPTION );
		$stored = is_array( $stored ) ? $stored : array();
		$status = self::status();
		$errors = array();
		foreach ( self::sources() as $key => $source ) {
			if ( ! $source['on'] ) {
				unset( $stored[ $key ], $status['counts'][ $key ] );
				continue;
			}
			$ranges = array();
			foreach ( $source['urls'] as $url ) {
				$response = wp_remote_get(
					$url,
					array(
						'timeout'    => 20,
						'user-agent' => 'ChaosShield/' . CSHIELD_VERSION,
					)
				);
				$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
				if ( 200 !== $code ) {
					$errors[] = $source['label'] . ': ' . ( is_wp_error( $response ) ? $response->get_error_message() : 'HTTP ' . $code );
					continue 2;
				}
				$ranges = array_merge( $ranges, self::parse( (string) wp_remote_retrieve_body( $response ) ) );
			}
			// An empty answer is a broken download, not an empty list: keep the last good copy.
			if ( ! $ranges ) {
				$errors[] = $source['label'] . ': empty list';
				continue;
			}
			$merged                   = self::merge( $ranges );
			$stored[ $key ]           = base64_encode( implode( '', $merged ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary ranges in an option.
			$status['counts'][ $key ] = count( $merged );
		}
		// Loaded on every request, so autoloading saves a query.
		Network::update_option( self::OPTION, $stored, true );
		$status['updated'] = time();
		$status['error']   = $errors ? implode( '; ', $errors ) : '';
		Network::update_option( self::STATUS, $status, false );
		self::$ranges = null;
		Network::clear_scheduled( self::HOOK );
		if ( Settings::enabled( 'threat_feed' ) ) {
			Network::schedule_single( time() + ( $errors ? HOUR_IN_SECONDS : DAY_IN_SECONDS ), self::HOOK );
		}
		return $errors ? new \WP_Error( 'cshield_threat', $status['error'] ) : true;
	}

	/**
	 * Reads IPs and CIDR ranges out of a list in JSON lines or plain text.
	 *
	 * @param string $body List.
	 * @return array Records: width byte, start and end, each padded to 16 bytes.
	 */
	public static function parse( $body ) {
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || ';' === $line[0] || '#' === $line[0] ) {
				continue;
			}
			if ( '{' === $line[0] ) {
				if ( ! preg_match( '/"cidr"\s*:\s*"([^"]+)"/', $line, $m ) ) {
					continue;
				}
				$entry = $m[1];
			} else {
				$entry = strtok( $line, " \t;" );
			}
			$range = self::range( (string) $entry );
			if ( $range ) {
				$out[] = $range;
			}
		}
		return $out;
	}

	/**
	 * One IP or CIDR range as a record.
	 *
	 * @param string $entry Such as 192.0.2.0/24, 2001:db8::/32 or 198.51.100.7.
	 * @return string|null
	 */
	private static function range( $entry ) {
		$parts  = explode( '/', $entry, 2 );
		$packed = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid input returns false.
		if ( false === $packed ) {
			return null;
		}
		$bits   = strlen( $packed ) * 8;
		$prefix = isset( $parts[1] ) ? (int) $parts[1] : $bits;
		// Very wide ranges in a list are a mistake; never block a whole internet region.
		if ( $prefix < ( 4 === strlen( $packed ) ? 8 : 19 ) || $prefix > $bits ) {
			return null;
		}
		$start = '';
		$end   = '';
		$bytes = strlen( $packed );
		for ( $i = 0; $i < $bytes; $i++ ) {
			$keep   = max( 0, min( 8, $prefix - $i * 8 ) );
			$mask   = $keep ? ( 0xFF << ( 8 - $keep ) ) & 0xFF : 0;
			$byte   = ord( $packed[ $i ] );
			$start .= chr( $byte & $mask );
			$end   .= chr( ( $byte & $mask ) | ( ~$mask & 0xFF ) );
		}
		$width = chr( strlen( $packed ) );
		return $width . str_pad( $start, 16, "\0", STR_PAD_LEFT ) . str_pad( $end, 16, "\0", STR_PAD_LEFT );
	}

	/**
	 * Sorts records and merges overlapping ones.
	 *
	 * @param array $records Records.
	 * @return array
	 */
	private static function merge( array $records ) {
		sort( $records, SORT_STRING );
		$out = array();
		foreach ( $records as $r ) {
			$last = count( $out ) - 1;
			if ( $last >= 0 && $out[ $last ][0] === $r[0] && strcmp( substr( $r, 1, 16 ), substr( $out[ $last ], 17, 16 ) ) <= 0 ) {
				if ( strcmp( substr( $r, 17, 16 ), substr( $out[ $last ], 17, 16 ) ) > 0 ) {
					$out[ $last ] = substr( $out[ $last ], 0, 17 ) . substr( $r, 17, 16 );
				}
				continue;
			}
			$out[] = $r;
		}
		return $out;
	}

	/**
	 * Removes the lists, used when the module is switched off.
	 */
	public static function forget() {
		Network::delete_option( self::OPTION );
		Network::delete_option( self::STATUS );
		Network::clear_scheduled( self::HOOK );
	}
}
