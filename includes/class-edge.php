<?php
/**
 * The Edge tab: under attack mode, Cloudflare and other edge services, HTTPS, page scripts and exposed files.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Handles the tab's forms, the ban list feed for other firewalls, and the
 * security score checks for the Edge features.
 */
final class Edge {

	const ACTION   = 'sshield_edge';
	const FEED_KEY = 'sshield_ban_feed_key';
	const ROUTE    = '/banlist';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
	}

	// The ban list feed.

	/**
	 * Secret part of the feed address, made on first use.
	 *
	 * @param bool $renew Make a new one, so the old address stops working.
	 * @return string
	 */
	public static function feed_key( $renew = false ) {
		$key = (string) Network::get_option( self::FEED_KEY );
		if ( $renew || strlen( $key ) < 24 ) {
			$key = wp_generate_password( 32, false );
			Network::update_option( self::FEED_KEY, $key, false );
		}
		return $key;
	}

	/**
	 * Address of the feed.
	 *
	 * @return string
	 */
	public static function feed_url() {
		return add_query_arg( 'key', self::feed_key(), rest_url( Api::NS . self::ROUTE ) );
	}

	/**
	 * Registers the feed.
	 */
	public static function routes() {
		register_rest_route(
			Api::NS,
			self::ROUTE,
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'feed' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Every banned and blocked IP, one per line, for server firewalls and other edge services.
	 *
	 * @param \WP_REST_Request $request Request.
	 */
	public static function feed( $request ) {
		$key = (string) $request->get_param( 'key' );
		if ( ! Settings::get( 'ban_feed' ) || '' === $key || ! hash_equals( self::feed_key(), $key ) ) {
			return new \WP_Error( 'sshield_feed', 'Not found', array( 'status' => 404 ) );
		}
		$lines = array_keys( Bans::bans() );
		foreach ( (array) Settings::get( 'ip_blocklist' ) as $entry ) {
			$lines[] = (string) $entry;
		}
		$lines = array_values( array_unique( array_filter( $lines ) ) );
		if ( ! headers_sent() ) {
			status_header( 200 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'X-Robots-Tag: noindex' );
		}
		echo '# Sentinel Shield ban list for ' . esc_html( home_url() ) . ', ' . esc_html( gmdate( 'c' ) ) . "\n";
		echo esc_html( implode( "\n", $lines ) ) . ( $lines ? "\n" : '' );
		exit;
	}

	// The tab's forms.

	/**
	 * Handles every form on the tab.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to change Sentinel Shield settings.', 'sentinel-shield' ), 403 );
		}
		check_admin_referer( self::ACTION );
		$op     = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$notice = 'edge_saved';
		$error  = '';
		switch ( $op ) {
			case 'attack_on':
			case 'attack_off':
				Attack_Mode::manual( 'attack_on' === $op );
				$notice = 'attack_on' === $op ? 'attack_on' : 'attack_off';
				break;
			case 'save':
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each field is checked in save_edge().
				$input = isset( $_POST['sshield'] ) && is_array( $_POST['sshield'] ) ? wp_unslash( $_POST['sshield'] ) : array();
				if ( ! empty( $input['force_https'] ) && ! Settings::get( 'force_https' ) ) {
					$can = Https::can_force();
					if ( true !== $can ) {
						$input['force_https'] = '';
						$error                = $can;
					}
				}
				$fields = isset( $_POST['fields'] ) ? array_map( 'sanitize_key', explode( ',', sanitize_text_field( wp_unslash( $_POST['fields'] ) ) ) ) : array();
				Settings::save_edge( $input, $fields );
				Events::add( 'settings', __( 'Edge settings updated.', 'sentinel-shield' ), Request::ip(), array( 'action' => 'settings.edge' ) );
				break;
			case 'check':
				Page_Check::run();
				$notice = 'edge_checked';
				break;
			case 'approve':
			case 'block':
			case 'forget':
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Matched against the stored keys.
				$keys = isset( $_POST['script'] ) ? array_map( 'strval', (array) wp_unslash( $_POST['script'] ) ) : array();
				Scripts::mark( $op, $keys );
				$notice = 'scripts_' . $op;
				break;
			case 'approve_all':
				Scripts::mark( 'approve', array( '*' ) );
				$notice = 'scripts_approve';
				break;
			case 'delete_file':
				$res = Exposure::delete( isset( $_POST['file'] ) ? sanitize_key( wp_unslash( $_POST['file'] ) ) : '' );
				if ( is_wp_error( $res ) ) {
					$error = $res->get_error_message();
				}
				$notice = 'file_deleted';
				break;
			case 'protect':
			case 'unprotect':
				$res = Exposure::protect( 'protect' === $op );
				if ( is_wp_error( $res ) ) {
					$error = $res->get_error_message();
				}
				$notice = 'protect' === $op ? 'files_protected' : 'edge_saved';
				break;
			case 'cf_sync':
				$res = Cloudflare::sync();
				Cloudflare::read_settings();
				if ( is_wp_error( $res ) ) {
					$error = $res->get_error_message();
				} elseif ( Cloudflare::status()['error'] ) {
					$error = Cloudflare::status()['error'];
				}
				$notice = 'cf_synced';
				break;
			case 'cf_purge':
				$res = Cloudflare::purge();
				if ( is_wp_error( $res ) ) {
					$error = $res->get_error_message();
				}
				$notice = 'cf_purged';
				break;
			case 'cf_https':
				$res = Cloudflare::set( 'always_use_https', 'on' );
				if ( is_wp_error( $res ) ) {
					$error = $res->get_error_message();
				}
				break;
			case 'cf_ip':
				Settings::use_cloudflare_ip();
				$notice = 'cf_ip';
				break;
			case 'feed_new':
				self::feed_key( true );
				$notice = 'feed_new';
				break;
		}
		if ( $error ) {
			Network::set_transient( 'sshield_error_' . get_current_user_id(), $error, MINUTE_IN_SECONDS );
		}
		wp_safe_redirect( Admin::url( 'edge', array( 'sshield_notice' => $error ? 'edge_error' : $notice ) ) . '#' . self::anchor( $op ) );
		exit;
	}

	/**
	 * Card to scroll back to after a form.
	 *
	 * @param string $op Operation.
	 * @return string
	 */
	private static function anchor( $op ) {
		if ( in_array( $op, array( 'approve', 'block', 'forget', 'approve_all' ), true ) ) {
			return 'sshield-scripts';
		}
		if ( in_array( $op, array( 'delete_file', 'protect', 'unprotect' ), true ) ) {
			return 'sshield-exposure';
		}
		if ( 0 === strpos( $op, 'cf_' ) || 'feed_new' === $op ) {
			return 'sshield-cloudflare';
		}
		return 'sshield-attack';
	}

	// Security score.

	/**
	 * Score checks for the Edge features, once they have something to report.
	 *
	 * @return array[] Each: id, label, status, detail, weight.
	 */
	public static function checks() {
		$out   = array();
		$https = Https::state();
		if ( $https['checked'] && $https['site_https'] ) {
			$cert = $https['cert'];
			$days = isset( $cert['expires'] ) ? Uptime::days_left( (int) $cert['expires'] ) : null;
			if ( null === $days ) {
				$status = Posture::WARN;
				$detail = __( 'The certificate could not be read in the last check.', 'sentinel-shield' );
			} elseif ( $days < 0 || empty( $cert['trusted'] ) ) {
				$status = Posture::FAIL;
				$detail = $days < 0 ? __( 'The HTTPS certificate has expired. Visitors see a security warning.', 'sentinel-shield' ) : __( 'Browsers do not trust the HTTPS certificate.', 'sentinel-shield' );
			} elseif ( $days <= Uptime::SSL_WARN ) {
				$status = Posture::WARN;
				/* translators: %d: days. */
				$detail = sprintf( _n( 'The HTTPS certificate expires in %d day.', 'The HTTPS certificate expires in %d days.', $days, 'sentinel-shield' ), $days );
			} else {
				$status = Posture::PASS;
				/* translators: %d: days. */
				$detail = sprintf( __( 'The certificate is valid for %d more days.', 'sentinel-shield' ), $days );
			}
			$out[] = array( 'tls_cert', __( 'HTTPS certificate', 'sentinel-shield' ), $status, $detail, 2 );
			if ( $https['redirect'] ) {
				$ok    = $https['redirect']['ok'] || Settings::get( 'force_https' );
				$out[] = array( 'https_redirect', __( 'HTTPS redirect', 'sentinel-shield' ), $ok ? Posture::PASS : Posture::WARN, $ok ? __( 'Visitors who type http:// are sent to HTTPS.', 'sentinel-shield' ) : __( 'The site still answers on plain http. Switch on "Send every visitor to HTTPS" on the Edge tab.', 'sentinel-shield' ), 1 );
			}
			$mixed = $https['mixed'] && ! Settings::get( 'https_upgrade' );
			$out[] = array( 'mixed_content', __( 'Mixed content', 'sentinel-shield' ), $mixed ? Posture::WARN : Posture::PASS, $mixed ? __( 'Some pages load images or scripts over plain http. Switch on the fix on the Edge tab.', 'sentinel-shield' ) : __( 'Pages load their files over HTTPS.', 'sentinel-shield' ), 1 );
		}
		$exp = Exposure::state();
		if ( $exp['checked'] && Settings::enabled( 'exposure_check' ) ) {
			$public = count(
				array_filter(
					$exp['files'],
					static function ( $f ) {
						return $f['public'];
					}
				)
			);
			$local  = count( $exp['files'] ) - $public;
			if ( $public || $exp['keys'] ) {
				$status = Posture::FAIL;
				$detail = __( 'Private files or secret keys can be downloaded by anyone. See the Edge tab.', 'sentinel-shield' );
			} elseif ( $local ) {
				$status = Posture::WARN;
				$detail = __( 'Backups or logs sit in a public folder. They cannot be downloaded now, but should be moved or deleted.', 'sentinel-shield' );
			} else {
				$status = Posture::PASS;
				$detail = __( 'No backups, logs, .env or .git can be downloaded, and no keys show in your pages.', 'sentinel-shield' );
			}
			$out[] = array( 'exposure', __( 'Exposed files and keys', 'sentinel-shield' ), $status, $detail, 3 );
		}
		$scripts = Scripts::state();
		if ( $scripts['checked'] && Settings::enabled( 'script_watch' ) ) {
			$c     = Scripts::counts();
			$out[] = array(
				'page_scripts',
				__( 'Page scripts', 'sentinel-shield' ),
				$c['flagged'] ? Posture::FAIL : ( $c['new'] ? Posture::WARN : Posture::PASS ),
				$c['flagged'] ? __( 'A script on your pages looks harmful. Review it on the Edge tab.', 'sentinel-shield' ) : ( $c['new'] ? __( 'New scripts appeared on your pages and wait for your review on the Edge tab.', 'sentinel-shield' ) : __( 'Every script on your pages is one you approved.', 'sentinel-shield' ) ),
				2,
			);
		}
		return $out;
	}
}
