<?php
/**
 * Country blocking from a country header set by a CDN or the web server.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Blocks or allows countries for the whole site or only the login page.
 */
final class Geo {

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( Settings::enabled( 'country_block' ) && Settings::get( 'country_source' ) && ( Settings::get( 'country_list' ) || Settings::get( 'country_pages' ) ) ) {
			add_action( 'plugins_loaded', array( $this, 'check' ), 2 );
		}
	}

	/**
	 * Where the country can come from.
	 *
	 * @return array Key => label.
	 */
	public static function sources() {
		return array(
			''           => __( 'Off', 'chaos-shield' ),
			'cloudflare' => __( 'Cloudflare (CF-IPCountry header)', 'chaos-shield' ),
			'server'     => __( 'Web server or host (GEOIP_COUNTRY_CODE or X-Country-Code)', 'chaos-shield' ),
			'builtin'    => __( 'Built-in database (no account, updated weekly)', 'chaos-shield' ),
		);
	}

	/**
	 * Two-letter country code of the visitor, or ''.
	 *
	 * @return string
	 */
	public static function country() {
		$source  = (string) Settings::get( 'country_source' );
		$code    = '';
		$remote  = Request::server( 'REMOTE_ADDR' );
		$proxies = (array) Settings::get( 'trusted_proxies' );
		if ( 'cloudflare' === $source ) {
			// Only believe the header when the request really came through Cloudflare.
			if ( Request::trusted_proxy( $remote, 'HTTP_CF_CONNECTING_IP', $proxies ) ) {
				$code = Request::server( 'HTTP_CF_IPCOUNTRY' );
			}
		} elseif ( 'server' === $source ) {
			// GEOIP_COUNTRY_CODE comes from the web server itself. The X- headers can be
			// sent by anyone, so they only count when a trusted proxy added them.
			$vars = array( 'GEOIP_COUNTRY_CODE' );
			if ( Request::trusted_proxy( $remote, '', $proxies ) ) {
				$vars[] = 'HTTP_X_COUNTRY_CODE';
				$vars[] = 'HTTP_X_GEOIP_COUNTRY';
			}
			foreach ( $vars as $var ) {
				$value = Request::server( $var );
				if ( '' !== $value ) {
					$code = $value;
					break;
				}
			}
		} elseif ( 'builtin' === $source ) {
			$code = Geo_Db::lookup( Request::ip() );
		}
		$code = strtoupper( substr( $code, 0, 2 ) );
		return preg_match( '/^[A-Z][A-Z0-9]$/', $code ) ? $code : '';
	}

	/**
	 * Whether the visitor's country should have been found. False for private
	 * network visitors and while the built-in database is still downloading, so
	 * allow mode never locks everyone out.
	 *
	 * @return bool
	 */
	public static function should_know() {
		$ip = Request::ip();
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}
		return 'builtin' !== Settings::get( 'country_source' ) || Geo_Db::ready();
	}

	/**
	 * Parses a list of country codes.
	 *
	 * @param string $text Codes separated by commas, spaces or lines.
	 * @return string[]
	 */
	public static function parse( $text ) {
		$codes = preg_split( '/[\s,;]+/', strtoupper( (string) $text ), -1, PREG_SPLIT_NO_EMPTY );
		$codes = array_filter(
			$codes,
			static function ( $c ) {
				return (bool) preg_match( '/^[A-Z][A-Z0-9]$/', $c );
			}
		);
		return array_values( array_unique( $codes ) );
	}

	/**
	 * Cleans the per-page country rules typed on the Access tab.
	 *
	 * @param string $text One rule per line: a path, block or allow, then country codes.
	 * @return array valid (rules as "path mode CC,CC"), invalid (lines that were skipped).
	 */
	public static function parse_page_rules( $text ) {
		$out = array(
			'valid'   => array(),
			'invalid' => array(),
		);
		foreach ( preg_split( '/[\r\n]+/', (string) $text ) as $line ) {
			$line = trim( sanitize_text_field( $line ) );
			if ( '' === $line ) {
				continue;
			}
			$rule = self::page_rule_parts( $line );
			if ( ! $rule ) {
				$out['invalid'][] = $line;
				continue;
			}
			$out['valid'][] = $rule['path'] . ' ' . $rule['mode'] . ' ' . implode( ',', $rule['countries'] );
		}
		$out['valid'] = array_slice( array_values( array_unique( $out['valid'] ) ), 0, 50 );
		return $out;
	}

	/**
	 * One page rule, split into its parts.
	 *
	 * @param string $line Rule, such as "/shop allow US, CA".
	 * @return array|null path, mode, countries.
	 */
	public static function page_rule_parts( $line ) {
		if ( ! preg_match( '#^(/[^\s]*)\s+(block|allow)\s+(.+)$#i', trim( (string) $line ), $m ) ) {
			return null;
		}
		$countries = self::parse( $m[3] );
		$path      = '/' . trim( strtolower( $m[1] ), '/' );
		if ( ! $countries || ! preg_match( '#^/[a-z0-9._~%/-]*$#', $path ) ) {
			return null;
		}
		return array(
			'path'      => '/' === $path ? '/' : $path,
			'mode'      => strtolower( $m[2] ),
			'countries' => $countries,
		);
	}

	/**
	 * Path of the current request below the site address, such as /shop/cart.
	 *
	 * @return string
	 */
	public static function request_path() {
		$path = strtolower( (string) wp_parse_url( Request::server( 'REQUEST_URI' ), PHP_URL_PATH ) );
		$base = rtrim( strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ), '/' );
		if ( '' !== $base && 0 === strpos( $path, $base . '/' ) ) {
			$path = substr( $path, strlen( $base ) );
		}
		return '/' . trim( $path, '/' );
	}

	/**
	 * The first page rule that covers a path.
	 *
	 * A rule covers its own page and everything below it.
	 *
	 * @param string $path Path, as request_path() gives it.
	 * @return array|null path, mode, countries.
	 */
	public static function page_rule( $path ) {
		foreach ( (array) Settings::get( 'country_pages' ) as $line ) {
			$rule = self::page_rule_parts( (string) $line );
			if ( $rule && ( '/' === $rule['path'] || $path === $rule['path'] || 0 === strpos( $path, $rule['path'] . '/' ) ) ) {
				return $rule;
			}
		}
		return null;
	}

	/**
	 * Stops the request when the visitor's country is not allowed here.
	 */
	public function check() {
		global $pagenow;
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || Firewall::allowlisted() ) {
			return;
		}
		$login = 'wp-login.php' === $pagenow || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || Passkeys::is_login_request();
		// Someone already signed in, such as an admin travelling, keeps using the site.
		$member = ! $login && is_user_logged_in();
		if ( Settings::get( 'country_list' ) && ( $login || 'site' === Settings::get( 'country_scope' ) ) && ! $member ) {
			$this->judge( 'allow' === Settings::get( 'country_mode' ), (array) Settings::get( 'country_list' ) );
		}
		if ( ! $member && Settings::get( 'country_pages' ) ) {
			$rule = self::page_rule( self::request_path() );
			if ( $rule ) {
				$this->judge( 'allow' === $rule['mode'], $rule['countries'] );
			}
		}
	}

	/**
	 * Refuses the visitor when one rule keeps their country out.
	 *
	 * @param bool     $allow Whether the list names the countries let in.
	 * @param string[] $codes Country codes.
	 */
	private function judge( $allow, array $codes ) {
		$country = self::country();
		if ( '' === $country ) {
			// In allow mode a visitor whose country could have been known but was not
			// (no Cloudflare header because they went around it, say) is kept out.
			if ( ! $allow || ! self::should_know() ) {
				return;
			}
			$country = '??';
		}
		$listed  = in_array( $country, $codes, true );
		$blocked = $allow ? ! $listed : $listed;
		if ( ! $blocked ) {
			return;
		}
		Login_Guard::bump_stat( 'firewall_blocks' );
		$throttle = 'cshield_geo_' . md5( Request::ip() );
		if ( ! Network::get_transient( $throttle ) ) {
			Network::set_transient( $throttle, 1, HOUR_IN_SECONDS );
			// Plain English: this runs before translations may be loaded.
			Events::add( 'blocked', ( '??' === $country ? 'Blocked a visitor whose country could not be found (allow mode).' : sprintf( 'Blocked a visitor from country %s.', $country ) ), Request::ip(), array( 'action' => 'fw.country' ) );
		}
		Firewall::deny( 'country' );
	}
}
