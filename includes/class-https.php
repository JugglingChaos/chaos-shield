<?php
/**
 * HTTPS checks: the certificate, the redirect from http, and mixed content.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Watches the site's own certificate and HTTPS setup, and can send visitors to
 * HTTPS and have browsers load http:// files over HTTPS.
 *
 * Certificates themselves come from the host (or Cloudflare); most hosts issue
 * free ones. What a plugin can do is notice when one is about to lapse or the
 * setup leaks visitors onto plain http.
 */
final class Https {

	const OPTION = 'sshield_https';

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( Settings::get( 'force_https' ) ) {
			add_action( 'init', array( __CLASS__, 'redirect' ), 1 );
		}
	}

	/**
	 * The last check: checked, site_https, cert, redirect, mixed.
	 *
	 * @return array
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION, array() );
		return wp_parse_args(
			is_array( $state ) ? $state : array(),
			array(
				'checked'    => 0,
				'site_https' => false,
				'cert'       => array(),
				'redirect'   => array(),
				'mixed'      => array(),
			)
		);
	}

	/**
	 * Whether this request reached the visitor over HTTPS, also behind a trusted proxy.
	 *
	 * @return bool
	 */
	public static function secure_request() {
		if ( is_ssl() ) {
			return true;
		}
		$proxy = (string) Settings::get( 'proxy_header' );
		if ( '' === $proxy || ! Request::trusted_proxy( Request::server( 'REMOTE_ADDR' ), $proxy, (array) Settings::get( 'trusted_proxies' ) ) ) {
			return false;
		}
		return 'https' === strtolower( Request::server( 'HTTP_X_FORWARDED_PROTO' ) ) || false !== strpos( Request::server( 'HTTP_CF_VISITOR' ), 'https' );
	}

	/**
	 * Sends plain http visits to the same address on HTTPS.
	 */
	public static function redirect() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || self::secure_request() ) {
			return;
		}
		$method = Request::server( 'REQUEST_METHOD' );
		if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) ) {
			return; // A redirect would drop the form the visitor sent.
		}
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		wp_safe_redirect( 'https://' . $host . Request::server( 'REQUEST_URI' ), 301, 'Sentinel Shield' );
		exit;
	}

	/**
	 * Whether HTTPS redirects can be switched on without locking anyone out.
	 *
	 * @return true|string True, or why not.
	 */
	public static function can_force() {
		$cert = Uptime::certificate( 'https://' . wp_parse_url( home_url(), PHP_URL_HOST ) . '/' );
		if ( empty( $cert['expires'] ) ) {
			return __( 'This site does not answer on HTTPS yet. Ask your host for a free certificate (most offer Let\'s Encrypt), or connect Cloudflare, then try again.', 'sentinel-shield' );
		}
		if ( ! $cert['trusted'] ) {
			return __( 'The site answers on HTTPS, but browsers do not trust its certificate. Fix the certificate first, or visitors would see a warning on every page.', 'sentinel-shield' );
		}
		if ( Uptime::days_left( (int) $cert['expires'] ) < 0 ) {
			return __( 'The certificate has expired. Renew it first.', 'sentinel-shield' );
		}
		return true;
	}

	/**
	 * Checks the certificate, the redirect and the pages for http:// files.
	 *
	 * @param array $pages Page address => HTML.
	 * @return array State.
	 */
	public static function check( array $pages ) {
		$home  = home_url( '/' );
		$state = array(
			'checked'    => time(),
			'site_https' => 0 === strpos( $home, 'https://' ),
			'cert'       => array(),
			'redirect'   => array(),
			'mixed'      => array(),
		);
		$host  = (string) wp_parse_url( $home, PHP_URL_HOST );
		if ( $state['site_https'] ) {
			$state['cert'] = Uptime::certificate( $home );
			$days          = isset( $state['cert']['expires'] ) ? Uptime::days_left( (int) $state['cert']['expires'] ) : null;
			if ( null !== $days && $days <= Uptime::SSL_WARN ) {
				Alerts::send(
					'alert_uptime',
					$days < 0 ? __( 'Your HTTPS certificate has expired', 'sentinel-shield' )
						/* translators: %d: days. */
						: sprintf( _n( 'Your HTTPS certificate expires in %d day', 'Your HTTPS certificate expires in %d days', $days, 'sentinel-shield' ), $days ),
					sprintf(
						/* translators: 1: site address, 2: date, 3: issuer. */
						__( "The certificate of %1\$s expires on %2\$s (issued by %3\$s). After that, visitors see a security warning instead of the site.\n\nMost hosts renew free certificates on their own. If yours did not, renew it in your hosting panel or ask your host.", 'sentinel-shield' ),
						$home,
						wp_date( get_option( 'date_format' ), (int) $state['cert']['expires'] ),
						isset( $state['cert']['issuer'] ) ? $state['cert']['issuer'] : '?'
					),
					'own-ssl|' . gmdate( 'Y-m-d' )
				);
			}
			$res               = Page_Check::fetch(
				'http://' . $host . '/',
				array(
					'redirection' => 0,
					'method'      => 'HEAD',
				)
			);
			$code              = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
			$location          = is_wp_error( $res ) ? '' : (string) wp_remote_retrieve_header( $res, 'location' );
			$state['redirect'] = array(
				'code'     => $code,
				'location' => $location,
				'ok'       => in_array( $code, array( 301, 302, 307, 308 ), true ) && 0 === strpos( $location, 'https://' ),
				'error'    => is_wp_error( $res ) ? $res->get_error_message() : '',
			);
		}
		foreach ( $pages as $page => $html ) {
			if ( 0 !== strpos( $page, 'https://' ) && ! $state['site_https'] ) {
				continue;
			}
			foreach ( self::mixed( $html ) as $m ) {
				if ( count( $state['mixed'] ) >= 50 ) {
					break 2;
				}
				$m['page']        = Page_Check::short( $page );
				$state['mixed'][] = $m;
			}
		}
		Network::update_option( self::OPTION, $state, false );
		return $state;
	}

	/**
	 * Files a page loads over plain http.
	 *
	 * @param string $html Page.
	 * @return array[] Each: tag, url.
	 */
	public static function mixed( $html ) {
		$out  = array();
		$seen = array();
		// Scripts, styles, frames and media; plain links to http pages are fine.
		if ( ! preg_match_all( '#<(script|img|iframe|audio|video|source|embed|track|link)\b([^>]*)>#i', $html, $m, PREG_SET_ORDER ) ) {
			return $out;
		}
		foreach ( $m as $hit ) {
			$tag = strtolower( $hit[1] );
			if ( ! preg_match( '#\s(?:src|href|data-src)\s*=\s*["\']?(http://[^"\'\s>]+)#i', ' ' . $hit[2], $url ) ) {
				continue;
			}
			if ( 'link' === $tag && ! preg_match( '#\brel\s*=\s*["\']?[^"\'>]*\b(?:stylesheet|preload|icon|modulepreload)\b#i', $hit[2] ) ) {
				continue;
			}
			$url = html_entity_decode( $url[1], ENT_QUOTES );
			if ( isset( $seen[ $url ] ) ) {
				continue;
			}
			$seen[ $url ] = true;
			$out[]        = array(
				'tag' => $tag,
				'url' => $url,
			);
		}
		return $out;
	}
}
