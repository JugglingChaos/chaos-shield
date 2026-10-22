<?php
/**
 * Request helpers.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Small helpers for reading the current request safely.
 */
final class Request {

	/**
	 * Resolved client IP for this request.
	 *
	 * @var string|null
	 */
	private static $ip = null;

	/**
	 * Direct connection that sent a proxy header without being trusted, if any.
	 *
	 * @var string
	 */
	private static $untrusted = '';

	/**
	 * Client IP address.
	 *
	 * Uses REMOTE_ADDR unless a proxy header is configured. A proxy header is
	 * only believed when the direct connection comes from a trusted proxy. With
	 * no list, that means a private network address (a local load balancer or
	 * reverse proxy), plus Cloudflare's own ranges for the Cloudflare header, so
	 * a visitor who reaches the server directly cannot pick their own IP.
	 *
	 * @return string IP address, or an empty string when unknown.
	 */
	public static function ip() {
		if ( null !== self::$ip ) {
			return self::$ip;
		}

		$remote  = self::server( 'REMOTE_ADDR' );
		$ip      = $remote;
		$header  = (string) Settings::get( 'proxy_header' );
		$proxies = (array) Settings::get( 'trusted_proxies' );

		if ( $header && '' !== self::server( $header ) ) {
			if ( self::trusted_proxy( $remote, $header, $proxies ) ) {
				$forwarded = self::forwarded_ip( self::server( $header ), $proxies );
				if ( $forwarded ) {
					$ip = $forwarded;
				}
			} else {
				self::$untrusted = $remote;
			}
		}

		/**
		 * Filters the client IP Chaos Shield uses for lockouts, lists and the firewall.
		 *
		 * @param string $ip     Resolved IP.
		 * @param string $remote Direct connection IP (REMOTE_ADDR).
		 */
		$ip       = (string) apply_filters( 'cshield_client_ip', $ip, $remote );
		self::$ip = filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
		return self::$ip;
	}

	/**
	 * Whether the direct connection may set the client IP through a proxy header.
	 *
	 * @param string $remote  REMOTE_ADDR.
	 * @param string $header  Configured header.
	 * @param array  $proxies Trusted proxies from the settings.
	 * @return bool
	 */
	public static function trusted_proxy( $remote, $header, array $proxies ) {
		if ( $proxies ) {
			return self::ip_matches( $remote, $proxies );
		}
		if ( filter_var( $remote, FILTER_VALIDATE_IP ) && ! filter_var( $remote, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return true;
		}
		return 'HTTP_CF_CONNECTING_IP' === $header && self::ip_matches( $remote, self::cloudflare_ranges() );
	}

	/**
	 * Cloudflare's published edge ranges (cloudflare.com/ips).
	 *
	 * @return string[]
	 */
	public static function cloudflare_ranges() {
		return array(
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22',
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		);
	}

	/**
	 * The direct connection that sent the configured proxy header but is not a
	 * trusted proxy, so the header was ignored. Empty when that did not happen.
	 *
	 * Only the current request counts, so a visitor cannot plant this for the
	 * admin to see.
	 *
	 * @return string
	 */
	public static function untrusted() {
		self::ip();
		return self::$untrusted;
	}

	/**
	 * Whether the browser says this request was made by another site's page as
	 * an embedded resource (image, script, frame, fetch), not a visit the person
	 * chose to make. Such requests are still blocked, but they do not count
	 * toward a ban, so a hostile page cannot get its visitors banned here.
	 *
	 * @return bool
	 */
	public static function embedded_cross_site() {
		return 'cross-site' === strtolower( self::server( 'HTTP_SEC_FETCH_SITE' ) )
			&& 'document' !== strtolower( self::server( 'HTTP_SEC_FETCH_DEST' ) );
	}

	/**
	 * Clears the cached IP. Used after settings change and in tests.
	 */
	public static function reset() {
		self::$ip        = null;
		self::$untrusted = '';
	}

	/**
	 * Proxy headers present on the current request, for setup hints.
	 *
	 * @return array Header key => value.
	 */
	public static function detected_proxy_headers() {
		$found = array();
		foreach ( array_keys( Settings::proxy_headers() ) as $key ) {
			if ( $key && self::server( $key ) ) {
				$found[ $key ] = self::server( $key );
			}
		}
		return $found;
	}

	/**
	 * Picks the visitor IP from a forwarded header.
	 *
	 * For a comma separated chain the right-most address that is not a trusted
	 * proxy is used, because entries further left can be set by the visitor.
	 *
	 * @param string $value   Header value.
	 * @param array  $proxies Trusted proxies.
	 * @return string
	 */
	private static function forwarded_ip( $value, array $proxies ) {
		$chain = array_reverse( array_map( 'trim', explode( ',', $value ) ) );
		foreach ( $chain as $candidate ) {
			if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return '';
			}
			if ( ! $proxies || ! self::ip_matches( $candidate, $proxies ) ) {
				return $candidate;
			}
		}
		return '';
	}

	/**
	 * Whether an IP matches any entry in a list of IPs and CIDR ranges.
	 *
	 * @param string $ip   IP address.
	 * @param array  $entries Entries such as 203.0.113.7, 203.0.113.0/24 or 2001:db8::/32.
	 * @return bool
	 */
	public static function ip_matches( $ip, array $entries ) {
		$packed = $ip ? @inet_pton( $ip ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid input returns false.
		if ( false === $packed ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			if ( self::in_range( $packed, (string) $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Splits textarea input into valid and invalid IP or CIDR entries.
	 *
	 * @param string $text One entry per line or comma separated. # starts a comment.
	 * @return array 'valid' and 'invalid' lists.
	 */
	public static function parse_list( $text ) {
		$out = array(
			'valid'   => array(),
			'invalid' => array(),
		);
		foreach ( preg_split( '/[\s,]+/', preg_replace( '/#.*$/m', '', $text ) ) as $entry ) {
			$entry = trim( $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( self::valid_entry( $entry ) ) {
				$out['valid'][] = $entry;
			} else {
				$out['invalid'][] = sanitize_text_field( $entry );
			}
		}
		$out['valid'] = array_values( array_unique( $out['valid'] ) );
		return $out;
	}

	/**
	 * Whether a string is an IP or a CIDR range.
	 *
	 * @param string $entry Entry.
	 * @return bool
	 */
	private static function valid_entry( $entry ) {
		$parts = explode( '/', $entry, 2 );
		if ( ! filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( ! isset( $parts[1] ) ) {
			return true;
		}
		$max = false !== strpos( $parts[0], ':' ) ? 128 : 32;
		return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max;
	}

	/**
	 * Whether a packed IP falls inside an entry.
	 *
	 * @param string $packed Packed IP from inet_pton().
	 * @param string $entry  IP or CIDR range.
	 * @return bool
	 */
	private static function in_range( $packed, $entry ) {
		$parts  = explode( '/', $entry, 2 );
		$subnet = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid input returns false.
		if ( false === $subnet || strlen( $subnet ) !== strlen( $packed ) ) {
			return false;
		}
		$bits = isset( $parts[1] ) ? (int) $parts[1] : strlen( $packed ) * 8;
		$full = intdiv( $bits, 8 );
		if ( substr( $packed, 0, $full ) !== substr( $subnet, 0, $full ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( ! $rest ) {
			return true;
		}
		$mask = chr( ( 0xff << ( 8 - $rest ) ) & 0xff );
		return ( $packed[ $full ] & $mask ) === ( $subnet[ $full ] & $mask );
	}

	/**
	 * The network an IP belongs to: its /24 for IPv4 and /64 for IPv6, where one
	 * person or host usually holds every address.
	 *
	 * @param string $ip IP address.
	 * @return string Such as 203.0.113.0/24, or '' for an invalid IP.
	 */
	public static function range( $ip ) {
		$packed = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid input returns false.
		if ( false === $packed ) {
			return '';
		}
		if ( 4 === strlen( $packed ) ) {
			return inet_ntop( substr( $packed, 0, 3 ) . "\0" ) . '/24';
		}
		return inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) ) . '/64';
	}

	/**
	 * Reads a sanitized $_SERVER value.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	public static function server( $key ) {
		return isset( $_SERVER[ $key ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) : '';
	}
}
