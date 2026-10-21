<?php
/**
 * One-click hardening modules.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Applies each enabled hardening module.
 */
final class Hardening {

	/**
	 * Registers hooks for enabled modules.
	 */
	public function register() {
		if ( Settings::enabled( 'disable_xmlrpc' ) ) {
			$this->disable_xmlrpc();
		}
		if ( Settings::enabled( 'disable_file_edit' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
		if ( Settings::enabled( 'hide_version' ) ) {
			$this->hide_version();
		}
		if ( Settings::enabled( 'block_user_enum' ) ) {
			$this->block_user_enumeration();
		}
		if ( Settings::enabled( 'security_headers' ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
			add_action( 'login_init', array( $this, 'send_security_headers' ) );
		}
		if ( Settings::enabled( 'disable_app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
	}

	/**
	 * Blocks XML-RPC entirely, including pingbacks.
	 */
	private function disable_xmlrpc() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'XML-RPC is disabled on this site.'; // Plain text: runs before translations may be loaded.
			exit;
		}

		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'pings_open', '__return_false', 99 );
		add_filter(
			'xmlrpc_methods',
			static function ( $methods ) {
				unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
				return $methods;
			}
		);
		add_filter(
			'wp_headers',
			static function ( $headers ) {
				unset( $headers['X-Pingback'] );
				return $headers;
			}
		);
		remove_action( 'wp_head', 'rsd_link' );
	}

	/**
	 * Removes version disclosure from markup, feeds, assets and headers.
	 */
	private function hide_version() {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
		add_filter( 'style_loader_src', array( $this, 'strip_version_arg' ), 9999 );
		add_filter( 'script_loader_src', array( $this, 'strip_version_arg' ), 9999 );
		add_action(
			'send_headers',
			static function () {
				if ( ! headers_sent() ) {
					header_remove( 'X-Powered-By' );
				}
			}
		);
	}

	/**
	 * Removes ?ver= from asset URLs when it equals the WordPress version.
	 *
	 * Plugin and theme versions are left alone so cache busting still works.
	 *
	 * @param string $src Asset URL.
	 * @return string
	 */
	public function strip_version_arg( $src ) {
		if ( ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}
		$query = wp_parse_url( $src, PHP_URL_QUERY );
		if ( ! $query ) {
			return $src;
		}
		parse_str( $query, $args );
		if ( isset( $args['ver'] ) && get_bloginfo( 'version' ) === $args['ver'] ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Stops anonymous visitors from discovering usernames.
	 */
	private function block_user_enumeration() {
		// ?author=N redirects reveal the author slug.
		add_action(
			'parse_request',
			static function ( $wp ) {
				if ( is_admin() || is_user_logged_in() ) {
					return;
				}
				// WordPress reads author from GET and POST alike, so check what it parsed.
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check of a public query var.
				if ( isset( $_REQUEST['author'] ) || ! empty( $wp->query_vars['author'] ) ) {
					wp_safe_redirect( home_url( '/' ), 301 );
					exit;
				}
			}
		);

		// REST API user listing.
		add_filter(
			'rest_pre_dispatch',
			static function ( $result, $server, $request ) {
				if ( null !== $result || is_user_logged_in() ) {
					return $result;
				}
				if ( preg_match( '#^/wp/v2/users(/|$)#i', $request->get_route() ) ) {
					return new \WP_Error(
						'rest_user_cannot_view',
						__( 'Sorry, you are not allowed to list users.', 'chaos-shield' ),
						array( 'status' => 401 )
					);
				}
				return $result;
			},
			10,
			3
		);

		// User sitemap.
		add_filter(
			'wp_sitemaps_add_provider',
			static function ( $provider, $name ) {
				return 'users' === $name ? false : $provider;
			},
			10,
			2
		);

		// oEmbed author data.
		add_filter(
			'oembed_response_data',
			static function ( $data ) {
				unset( $data['author_name'], $data['author_url'] );
				return $data;
			}
		);
	}

	/**
	 * Headers sent on every front end, admin and login response.
	 *
	 * @return array
	 */
	public static function security_headers() {
		$headers = array(
			'X-Content-Type-Options' => 'nosniff',
			'X-Frame-Options'        => 'SAMEORIGIN',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=(), payment=()',
		);
		if ( is_ssl() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}

		/**
		 * Filters the security headers Chaos Shield sends.
		 *
		 * @param array $headers Header name => value. Remove a key to skip it.
		 */
		return (array) apply_filters( 'cshield_security_headers', $headers );
	}

	/**
	 * Sends the security headers.
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( self::security_headers() as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}
}
