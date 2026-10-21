<?php
/**
 * Page script monitor and Content Security Policy.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps a list of every script the site's pages load, alerts when a new or
 * suspicious one appears, and can tell browsers to run only the approved ones.
 *
 * Skimmers and injected ads usually arrive as one extra script from a new
 * domain, so the list is the early warning, and the policy the lock.
 */
final class Scripts {

	const OPTION  = 'sshield_scripts';
	const MAX     = 300;
	const ROUTE   = '/csp';
	const KEEP    = 30 * DAY_IN_SECONDS;
	const FETCH   = 30;
	const SCHEMES = array( 'chrome-extension', 'moz-extension', 'safari-extension', 'safari-web-extension', 'ms-browser-extension', 'webkit-masked-url', 'about' );

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_action( 'send_headers', array( __CLASS__, 'send_policy' ) );
	}

	/**
	 * Stored list: baseline (bool), checked, items (key => item).
	 *
	 * @return array
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION, array() );
		$state = is_array( $state ) ? $state : array();
		return wp_parse_args(
			$state,
			array(
				'baseline' => false,
				'checked'  => 0,
				'items'    => array(),
				'reports'  => 0,
			)
		);
	}

	/**
	 * Saves the list.
	 *
	 * @param array $state State.
	 */
	private static function save( array $state ) {
		if ( count( $state['items'] ) > self::MAX ) {
			uasort(
				$state['items'],
				static function ( $a, $b ) {
					return $b['last'] - $a['last'];
				}
			);
			$state['items'] = array_slice( $state['items'], 0, self::MAX, true );
		}
		Network::update_option( self::OPTION, $state, false );
	}

	/**
	 * Every script on the list, newest problems first.
	 *
	 * @return array
	 */
	public static function items() {
		$items = self::state()['items'];
		$rank  = array(
			'new'      => 0,
			'blocked'  => 2,
			'approved' => 3,
		);
		uasort(
			$items,
			static function ( $a, $b ) use ( $rank ) {
				$fa = $a['flag'] ? 0 : 1;
				$fb = $b['flag'] ? 0 : 1;
				if ( $fa !== $fb ) {
					return $fa - $fb;
				}
				$ra = isset( $rank[ $a['status'] ] ) ? $rank[ $a['status'] ] : 9;
				$rb = isset( $rank[ $b['status'] ] ) ? $rank[ $b['status'] ] : 9;
				return $ra === $rb ? strcmp( $a['key'], $b['key'] ) : $ra - $rb;
			}
		);
		return $items;
	}

	/**
	 * Counts by status, and flagged.
	 *
	 * @return array new, approved, blocked, flagged, total.
	 */
	public static function counts() {
		$out = array(
			'new'      => 0,
			'approved' => 0,
			'blocked'  => 0,
			'flagged'  => 0,
			'total'    => 0,
		);
		foreach ( self::state()['items'] as $item ) {
			++$out['total'];
			if ( isset( $out[ $item['status'] ] ) ) {
				++$out[ $item['status'] ];
			}
			if ( $item['flag'] ) {
				++$out['flagged'];
			}
		}
		return $out;
	}

	// Reading pages.

	/**
	 * The script tags of a page.
	 *
	 * @param string $html Page.
	 * @param string $page Page address, to resolve relative sources.
	 * @return array[] Each: src (absolute, or '' for inline), code.
	 */
	public static function tags( $html, $page ) {
		$out = array();
		if ( ! preg_match_all( '#<script\b([^>]*)>(.*?)</script\s*>#is', $html, $m, PREG_SET_ORDER ) ) {
			return $out;
		}
		foreach ( $m as $tag ) {
			$attrs = $tag[1];
			if ( preg_match( '#\btype\s*=\s*["\']?([^"\'\s>]+)#i', $attrs, $type ) ) {
				$type = strtolower( $type[1] );
				if ( ! in_array( $type, array( 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript' ), true ) ) {
					continue; // JSON, templates and import maps hold no code.
				}
			}
			$src = '';
			if ( preg_match( '#\bsrc\s*=\s*(["\'])(.*?)\1#is', $attrs, $s ) || preg_match( '#\bsrc\s*=\s*([^\s>]+)#i', $attrs, $s ) ) {
				$src = self::absolute( html_entity_decode( trim( end( $s ) ), ENT_QUOTES ), $page );
				if ( '' === $src ) {
					continue;
				}
			}
			$out[] = array(
				'src'  => $src,
				'code' => '' === $src ? $tag[2] : '',
			);
		}
		return $out;
	}

	/**
	 * Resolves a script address against the page.
	 *
	 * @param string $src  Source as written.
	 * @param string $page Page address.
	 * @return string Absolute http(s) address, or ''.
	 */
	public static function absolute( $src, $page ) {
		$scheme = (string) wp_parse_url( $page, PHP_URL_SCHEME );
		$scheme = $scheme ? $scheme : 'https';
		if ( 0 === strpos( $src, '//' ) ) {
			$src = $scheme . ':' . $src;
		} elseif ( 0 === strpos( $src, '/' ) ) {
			$origin = $scheme . '://' . wp_parse_url( $page, PHP_URL_HOST ) . ( wp_parse_url( $page, PHP_URL_PORT ) ? ':' . wp_parse_url( $page, PHP_URL_PORT ) : '' );
			$src    = $origin . $src;
		} elseif ( ! preg_match( '#^[a-z][a-z0-9+.-]*:#i', $src ) ) {
			$base = preg_replace( '#[^/]*$#', '', (string) strtok( $page, '?#' ) );
			$src  = $base . $src;
		}
		return preg_match( '#^https?://[^/\s]+#i', $src ) ? $src : '';
	}

	/**
	 * The list key of an address: host and path, without the query.
	 *
	 * @param string $url Address.
	 * @return string
	 */
	public static function key( $url ) {
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$port = wp_parse_url( $url, PHP_URL_PORT );
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return $host . ( $port ? ':' . $port : '' ) . ( '' === $path ? '/' : $path );
	}

	/**
	 * Whether an address is on this site.
	 *
	 * @param string $url Address.
	 * @return bool
	 */
	public static function own( $url ) {
		return strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ) === strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Signs of a skimmer, a miner or hidden code in a script.
	 *
	 * Payment libraries read card fields and send requests too; what gives a
	 * skimmer away is encoding the card data on its way out.
	 *
	 * @param string $code Script.
	 * @return string Plain English reason, or ''.
	 */
	public static function suspicious( $code ) {
		$signs = array(
			'/coinhive|cryptonight|coin-hive|webminepool|crypto-loot|cryptoloot|minero\.cc|jsecoin/i' => __( 'Looks like a cryptocurrency miner', 'sentinel-shield' ),
			'/eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/i' => __( 'Runs hidden code with eval', 'sentinel-shield' ),
			'/(?:atob|unescape)\s*\(\s*["\'][A-Za-z0-9+\/=%]{400,}/' => __( 'Carries a long block of encoded code', 'sentinel-shield' ),
			'/document\.write\s*\(\s*unescape\s*\(/i' => __( 'Writes hidden code into the page', 'sentinel-shield' ),
			'/(?:cc_?num(?:ber)?|card_?number|cc-number|card\[number\]|cvv|cvc2?)\b(?=.{0,600}?\b(?:btoa|atob)\s*\()(?=.{0,600}?(?:sendBeacon|new\s+Image|WebSocket|fetch\s*\(|XMLHttpRequest))/is' => __( 'Reads card details and sends them somewhere', 'sentinel-shield' ),
		);
		foreach ( $signs as $pattern => $reason ) {
			if ( preg_match( $pattern, $code ) ) {
				return $reason;
			}
		}
		return '';
	}

	/**
	 * Finds the scripts on the pages, fetches the outside ones and updates the list.
	 *
	 * @param array $pages Page address => HTML.
	 * @return array Script address => code, for the exposure check.
	 */
	public static function analyze( array $pages ) {
		$state    = self::state();
		$items    = $state['items'];
		$baseline = ! $state['baseline'];
		$now      = time();
		$found    = array();
		$inline   = array();
		foreach ( $pages as $page => $html ) {
			foreach ( self::tags( $html, $page ) as $tag ) {
				if ( '' === $tag['src'] ) {
					$inline[] = array(
						'page' => $page,
						'code' => $tag['code'],
					);
					continue;
				}
				$key = self::key( $tag['src'] );
				if ( ! isset( $found[ $key ] ) ) {
					$found[ $key ] = array(
						'src'   => $tag['src'],
						'pages' => array(),
					);
				}
				$found[ $key ]['pages'][ Page_Check::short( $page ) ] = true;
			}
		}

		$code    = array();
		$fetched = 0;
		$alerts  = array();
		foreach ( $found as $key => $f ) {
			$item = isset( $items[ $key ] ) ? $items[ $key ] : self::blank( $key, $f['src'], self::own( $f['src'] ) ? 'own' : 'external', $baseline );
			if ( ! isset( $items[ $key ] ) && ! $baseline ) {
				$alerts[] = $key;
			}
			$item['src']   = $f['src'];
			$item['last']  = $now;
			$item['pages'] = array_slice( array_keys( $f['pages'] ), 0, 5 );
			if ( 'report' === $item['kind'] ) {
				$item['kind'] = self::own( $f['src'] ) ? 'own' : 'external';
			}
			if ( $fetched < self::FETCH ) {
				++$fetched;
				$res = Page_Check::fetch( $f['src'], array( 'headers' => array( 'Accept' => '*/*' ) ) );
				if ( ! is_wp_error( $res ) && 200 === (int) wp_remote_retrieve_response_code( $res ) ) {
					$body         = (string) wp_remote_retrieve_body( $res );
					$code[ $key ] = $body;
					$hash         = hash( 'sha256', $body );
					if ( $item['hash'] && $item['hash'] !== $hash ) {
						$item['changed'] = $now;
					}
					$item['hash'] = $hash;
					$item['size'] = strlen( $body );
					$flag         = self::suspicious( $body );
					if ( $flag && $flag !== $item['flag'] ) {
						$alerts[] = $key;
					}
					$item['flag'] = $flag;
				}
			}
			// A script served from the uploads folder is almost never placed there on purpose.
			if ( 'own' === $item['kind'] && false !== strpos( (string) wp_parse_url( $f['src'], PHP_URL_PATH ), '/wp-content/uploads/' ) && ! $item['flag'] ) {
				$item['flag'] = __( 'Loaded from the uploads folder, where scripts do not belong', 'sentinel-shield' );
				$alerts[]     = $key;
			}
			$items[ $key ] = $item;
		}

		foreach ( $inline as $in ) {
			$flag = self::suspicious( $in['code'] );
			if ( '' === $flag ) {
				continue;
			}
			$key = 'inline:' . substr( sha1( trim( $in['code'] ) ), 0, 16 );
			if ( ! isset( $items[ $key ] ) ) {
				$items[ $key ] = self::blank( $key, '', 'inline', false );
				$alerts[]      = $key;
			}
			$items[ $key ]['flag']    = $flag;
			$items[ $key ]['last']    = $now;
			$items[ $key ]['pages']   = array_values( array_unique( array_merge( $items[ $key ]['pages'], array( Page_Check::short( $in['page'] ) ) ) ) );
			$items[ $key ]['snippet'] = mb_substr( preg_replace( '/\s+/', ' ', trim( $in['code'] ) ), 0, 160 );
		}

		// Scripts not seen on any page for a month are dropped; browser reports stay until handled.
		foreach ( $items as $key => $item ) {
			if ( 'report' !== $item['kind'] && 0 !== strpos( $key, 'keyword:' ) && $item['last'] < $now - self::KEEP ) {
				unset( $items[ $key ] );
			}
		}
		$state['items']    = $items;
		$state['baseline'] = true;
		$state['checked']  = $now;
		self::save( $state );
		if ( $alerts ) {
			self::alert( array_unique( $alerts ) );
		}
		return $code;
	}

	/**
	 * A new list entry.
	 *
	 * @param string $key      Key.
	 * @param string $src      Address.
	 * @param string $kind     own, external, inline, report or keyword.
	 * @param bool   $approved Approved from the start (the first look at the site).
	 * @return array
	 */
	private static function blank( $key, $src, $kind, $approved ) {
		return array(
			'key'     => $key,
			'src'     => $src,
			'kind'    => $kind,
			'status'  => $approved ? 'approved' : 'new',
			'first'   => time(),
			'last'    => time(),
			'pages'   => array(),
			'hash'    => '',
			'size'    => 0,
			'changed' => 0,
			'flag'    => '',
			'snippet' => '',
		);
	}

	/**
	 * Emails the owner about new and suspicious scripts.
	 *
	 * @param string[] $keys Keys.
	 */
	private static function alert( array $keys ) {
		$items = self::state()['items'];
		$lines = array();
		foreach ( $keys as $key ) {
			if ( ! isset( $items[ $key ] ) ) {
				continue;
			}
			$item    = $items[ $key ];
			$lines[] = '- ' . self::label( $item ) . ( $item['flag'] ? ' (' . $item['flag'] . ')' : '' ) . ( $item['pages'] ? ' on ' . implode( ', ', $item['pages'] ) : '' );
		}
		if ( ! $lines ) {
			return;
		}
		Alerts::send(
			'alert_scripts',
			__( 'New or suspicious scripts on your pages', 'sentinel-shield' ),
			sprintf(
				/* translators: 1: site address, 2: list of scripts. */
				__( "Your pages at %1\$s load scripts that were not there before, or that look harmful:\n\n%2\$s\n\nIf you did not add them, a plugin, theme or attacker did. Review them on the Edge tab: approve the ones you expect, and block the rest.", 'sentinel-shield' ),
				home_url(),
				implode( "\n", $lines )
			),
			md5( implode( '|', $keys ) )
		);
		Events::add(
			'scan',
			/* translators: %d: number of scripts. */
			sprintf( _n( '%d new or suspicious script found on the site\'s pages.', '%d new or suspicious scripts found on the site\'s pages.', count( $lines ), 'sentinel-shield' ), count( $lines ) ),
			'',
			array(
				'severity' => Events::NOTICE,
				'action'   => 'scripts.new',
			)
		);
	}

	/**
	 * How an entry is shown.
	 *
	 * @param array $item Entry.
	 * @return string
	 */
	public static function label( array $item ) {
		if ( 'inline' === $item['kind'] ) {
			return __( 'Code written into the page', 'sentinel-shield' );
		}
		if ( 0 === strpos( $item['key'], 'keyword:' ) ) {
			$names = array(
				'keyword:eval'   => __( 'Code built at run time (eval)', 'sentinel-shield' ),
				'keyword:blob'   => __( 'Scripts made in the browser (blob:)', 'sentinel-shield' ),
				'keyword:data'   => __( 'Scripts written into an address (data:)', 'sentinel-shield' ),
				'keyword:inline' => __( 'Code written into the page', 'sentinel-shield' ),
			);
			return isset( $names[ $item['key'] ] ) ? $names[ $item['key'] ] : $item['key'];
		}
		return $item['key'];
	}

	/**
	 * Approves, blocks or forgets entries.
	 *
	 * @param string   $op   approve, block or forget.
	 * @param string[] $keys Keys, or array( '*' ) for every new entry.
	 * @return int How many changed.
	 */
	public static function mark( $op, array $keys ) {
		$state = self::state();
		$n     = 0;
		foreach ( $state['items'] as $key => $item ) {
			$all = array( '*' ) === $keys && 'new' === $item['status'];
			if ( ! $all && ! in_array( $key, $keys, true ) ) {
				continue;
			}
			++$n;
			if ( 'forget' === $op ) {
				unset( $state['items'][ $key ] );
			} else {
				$state['items'][ $key ]['status'] = 'approve' === $op ? 'approved' : 'blocked';
				if ( 'approve' === $op ) {
					$state['items'][ $key ]['flag']    = '';
					$state['items'][ $key ]['changed'] = 0;
				}
			}
		}
		self::save( $state );
		return $n;
	}

	// The policy.

	/**
	 * The Content-Security-Policy value for scripts.
	 *
	 * @return string
	 */
	public static function policy() {
		$sources = array( "'self'", "'unsafe-inline'" );
		$extra   = array(
			'keyword:eval' => "'unsafe-eval'",
			'keyword:blob' => 'blob:',
			'keyword:data' => 'data:',
		);
		foreach ( self::state()['items'] as $key => $item ) {
			if ( 'approved' !== $item['status'] ) {
				continue;
			}
			if ( isset( $extra[ $key ] ) ) {
				$sources[] = $extra[ $key ];
			} elseif ( in_array( $item['kind'], array( 'external', 'report' ), true ) && $item['src'] ) {
				$scheme    = (string) wp_parse_url( $item['src'], PHP_URL_SCHEME );
				$host      = strtok( $key, '/' );
				$sources[] = ( 'http' === $scheme ? 'http://' : 'https://' ) . $host;
			}
		}
		$sources = array_values( array_unique( $sources ) );
		return 'script-src ' . implode( ' ', $sources ) . "; object-src 'none'; base-uri 'self'; report-uri " . esc_url_raw( rest_url( Api::NS . self::ROUTE ) );
	}

	/**
	 * Sends the policy with front-end pages.
	 */
	public static function send_policy() {
		if ( headers_sent() || is_admin() ) {
			return;
		}
		if ( Settings::get( 'https_upgrade' ) && is_ssl() ) {
			// Loads http:// images and scripts over https instead of leaving them out.
			header( 'Content-Security-Policy: upgrade-insecure-requests', false );
		}
		$mode = (string) Settings::get( 'csp_mode' );
		if ( ! in_array( $mode, array( 'report', 'enforce' ), true ) ) {
			return;
		}
		// Page builders run on the front end for editors; they only get reports, never blocks.
		$name = 'enforce' === $mode && ! current_user_can( 'edit_posts' ) ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
		header( $name . ': ' . self::policy(), false );
	}

	/**
	 * Registers the report address.
	 */
	public static function routes() {
		register_rest_route(
			Api::NS,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'report' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Takes a browser's report of a script the policy stopped.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public static function report( $request ) {
		$ok = new \WP_REST_Response( null, 204 );
		if ( ! in_array( (string) Settings::get( 'csp_mode' ), array( 'report', 'enforce' ), true ) ) {
			return $ok;
		}
		$ip       = Request::ip();
		$throttle = 'sshield_csp_' . md5( (string) $ip );
		$count    = (int) Network::get_transient( $throttle );
		if ( $count >= 30 ) {
			return $ok;
		}
		Network::set_transient( $throttle, $count + 1, HOUR_IN_SECONDS );
		$data = json_decode( (string) $request->get_body(), true );
		if ( ! is_array( $data ) ) {
			return $ok;
		}
		// The old report-uri format, or the Reporting API's list.
		$reports = isset( $data['csp-report'] ) ? array( $data['csp-report'] ) : array();
		if ( ! $reports && isset( $data[0] ) ) {
			foreach ( array_slice( $data, 0, 10 ) as $r ) {
				if ( is_array( $r ) && isset( $r['body'] ) && is_array( $r['body'] ) ) {
					$reports[] = array(
						'blocked-uri'         => isset( $r['body']['blockedURL'] ) ? $r['body']['blockedURL'] : '',
						'effective-directive' => isset( $r['body']['effectiveDirective'] ) ? $r['body']['effectiveDirective'] : '',
						'document-uri'        => isset( $r['body']['documentURL'] ) ? $r['body']['documentURL'] : '',
					);
				}
			}
		}
		foreach ( $reports as $r ) {
			if ( is_array( $r ) ) {
				self::record( $r );
			}
		}
		return $ok;
	}

	/**
	 * Adds a reported script to the list.
	 *
	 * @param array $r blocked-uri, effective-directive or violated-directive, document-uri.
	 * @return string Key recorded, or ''.
	 */
	public static function record( array $r ) {
		$directive = isset( $r['effective-directive'] ) ? (string) $r['effective-directive'] : ( isset( $r['violated-directive'] ) ? (string) $r['violated-directive'] : '' );
		if ( 0 !== strpos( $directive, 'script-src' ) ) {
			return '';
		}
		$blocked = isset( $r['blocked-uri'] ) ? trim( (string) $r['blocked-uri'] ) : '';
		$scheme  = strtolower( (string) strtok( $blocked, ':' ) );
		if ( in_array( $scheme, self::SCHEMES, true ) ) {
			return ''; // Browser extensions, not the site.
		}
		$keywords = array(
			'eval'   => 'keyword:eval',
			'inline' => 'keyword:inline',
			'blob'   => 'keyword:blob',
			'data'   => 'keyword:data',
		);
		if ( isset( $keywords[ $blocked ] ) || isset( $keywords[ $scheme ] ) ) {
			$key = isset( $keywords[ $blocked ] ) ? $keywords[ $blocked ] : $keywords[ $scheme ];
			$src = '';
		} elseif ( preg_match( '#^https?://#i', $blocked ) ) {
			$src = esc_url_raw( substr( $blocked, 0, 500 ) );
			$key = self::key( $src );
		} else {
			return '';
		}
		$page  = isset( $r['document-uri'] ) ? Page_Check::short( esc_url_raw( (string) $r['document-uri'] ) ) : '';
		$state = self::state();
		++$state['reports'];
		$new = ! isset( $state['items'][ $key ] );
		if ( $new ) {
			if ( count( $state['items'] ) >= self::MAX ) {
				return '';
			}
			$kind                   = 0 === strpos( $key, 'keyword:' ) ? 'keyword' : 'report';
			$state['items'][ $key ] = self::blank( $key, $src, $kind, false );
		}
		$item                   = $state['items'][ $key ];
		$item['last']           = time();
		$item['pages']          = array_slice( array_values( array_unique( array_merge( array( strtok( $page, '?' ) ), $item['pages'] ) ) ), 0, 5 );
		$state['items'][ $key ] = $item;
		self::save( $state );
		if ( $new && 'keyword:inline' !== $key ) {
			self::alert( array( $key ) );
		}
		return $key;
	}
}
