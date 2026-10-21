<?php
/**
 * REST API.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Routes under /wp-json/sentinel-shield/v1.
 *
 * Read routes accept an administrator (cookie with nonce, or an application
 * password) or this site's hub key in the X-Sentinel-Key header. Routes that
 * change anything need an administrator.
 */
final class Api {

	const NS         = 'sentinel-shield/v1';
	const KEY_OPTION = 'sshield_hub_key';
	const KEY_HEADER = 'X-Sentinel-Key';
	const SCOPE      = 'sshield_hub_key_scope';
	const SEALED     = 'sshield_hub_key_sealed';
	const TIME_HDR   = 'X-Sentinel-Time';
	const SIG_HDR    = 'X-Sentinel-Signature';
	const NONCE_HDR  = 'X-Sentinel-Nonce';
	const SKEW       = 300;

	/**
	 * Settings a hub may push to this site. Site-specific values such as
	 * the login address, IP lists and email addresses are never pushed.
	 *
	 * @return string[]
	 */
	public static function pushable() {
		return array_merge(
			array_keys( Settings::modules() ),
			array( 'login_max_attempts', 'login_window', 'login_lockout', 'autoban_strikes', 'autoban_hours', 'probe_404_limit', 'rate_login', 'rate_api', 'rate_search', 'rate_pages', 'pw_min_length', 'pw_classes', 'pw_roles', 'pw_max_age' )
		);
	}

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'rest_api_init', array( $this, 'routes' ) );
	}

	/**
	 * Registers routes.
	 */
	public function routes() {
		$read  = array( $this, 'can_read' );
		$admin = array( $this, 'can_admin' );

		register_rest_route(
			self::NS,
			'/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_status' ),
				'permission_callback' => $read,
			)
		);
		register_rest_route(
			self::NS,
			'/events',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_events' ),
				'permission_callback' => $read,
				'args'                => array(
					'type'     => array(
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_key',
						'default'           => '',
					),
					'page'     => array(
						'type'    => 'integer',
						'minimum' => 1,
						'default' => 1,
					),
					'per_page' => array(
						'type'    => 'integer',
						'minimum' => 1,
						'maximum' => 100,
						'default' => 50,
					),
				),
			)
		);
		register_rest_route(
			self::NS,
			'/scan',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_scan' ),
					'permission_callback' => $read,
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'start_scan' ),
					'permission_callback' => $admin,
				),
			)
		);
		register_rest_route(
			self::NS,
			'/scan/step',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'step_scan' ),
				'permission_callback' => $admin,
			)
		);
		register_rest_route(
			self::NS,
			'/lockouts',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_lockouts' ),
				'permission_callback' => $read,
			)
		);
		register_rest_route(
			self::NS,
			'/lockouts/(?P<ip>[0-9a-fA-F:.]+)',
			array(
				'methods'             => 'DELETE',
				'callback'            => array( $this, 'delete_lockout' ),
				'permission_callback' => $admin,
			)
		);
		register_rest_route(
			self::NS,
			'/blocklist',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'block_ip' ),
				'permission_callback' => $admin,
				'args'                => array(
					'ip' => array(
						'type'     => 'string',
						'required' => true,
					),
				),
			)
		);
		$hub = array( $this, 'can_manage_hub' );
		foreach ( array( 'scan', 'release', 'settings' ) as $action ) {
			register_rest_route(
				self::NS,
				'/hub/' . $action,
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'hub_' . $action ),
					'permission_callback' => $hub,
				)
			);
		}
		register_rest_route(
			self::NS,
			'/settings',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_settings' ),
					'permission_callback' => $admin,
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_settings' ),
					'permission_callback' => $admin,
				),
			)
		);
	}

	/**
	 * Read access: an administrator or a valid hub key.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return true|\WP_Error
	 */
	public function can_read( $request ) {
		if ( current_user_can( Network::cap() ) ) {
			return true;
		}
		$key    = (string) $request->get_header( self::KEY_HEADER );
		$signed = '' !== (string) $request->get_header( self::SIG_HDR );
		if ( '' === $key && ! $signed ) {
			return new \WP_Error( 'rest_forbidden', __( 'Authentication required.', 'sentinel-shield' ), array( 'status' => rest_authorization_required_code() ) );
		}

		$ip = Request::ip();
		if ( $ip && ! Firewall::allowlisted() && Login_Guard::locked_until( $ip ) ) {
			return new \WP_Error( 'sshield_locked_out', __( 'Too many failed attempts. Try again later.', 'sentinel-shield' ), array( 'status' => 429 ) );
		}
		// Hubs from 1.6.2 sign reads with the key's hash, so the key itself never travels.
		$stored = (string) Network::get_option( self::KEY_OPTION, '' );
		if ( $signed && '' !== $stored ) {
			$check = self::verify_signature( $request, $stored );
			if ( true === $check ) {
				return true;
			}
			if ( is_wp_error( $check ) && 'sshield_hub_replay' === $check->get_error_code() ) {
				return $check;
			}
		} elseif ( '' !== $key && self::key_valid( $key ) ) {
			return true;
		}

		// A wrong key counts as a failed login, so keys cannot be brute forced.
		if ( Settings::enabled( 'limit_login' ) ) {
			( new Login_Guard() )->record_failure( 'hub key' );
		}
		return new \WP_Error( 'rest_forbidden', __( 'Invalid hub key.', 'sentinel-shield' ), array( 'status' => 403 ) );
	}

	/**
	 * Hub actions: a request signed with a hub key that allows actions.
	 *
	 * The key itself is never sent. The hub signs the time, method, route and
	 * body, so a captured request cannot be changed or replayed.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return true|\WP_Error
	 */
	public function can_manage_hub( $request ) {
		$ip = Request::ip();
		if ( $ip && ! Firewall::allowlisted() && Login_Guard::locked_until( $ip ) ) {
			return new \WP_Error( 'sshield_locked_out', __( 'Too many failed attempts. Try again later.', 'sentinel-shield' ), array( 'status' => 429 ) );
		}
		if ( 'manage' !== self::key_scope() ) {
			return new \WP_Error( 'sshield_hub_read_only', __( 'This site only allows the hub to read its status. Create a key that allows actions on its Hub tab.', 'sentinel-shield' ), array( 'status' => 403 ) );
		}
		$key   = Totp::open( Network::get_option( self::SEALED, '' ) );
		$check = $key ? self::verify_signature( $request, $key ) : false;
		if ( true !== $check ) {
			if ( is_wp_error( $check ) ) {
				return $check;
			}
			if ( Settings::enabled( 'limit_login' ) ) {
				( new Login_Guard() )->record_failure( 'hub action' );
			}
			return new \WP_Error( 'rest_forbidden', __( 'The hub signature is not valid. Check the clocks of both servers, or connect the site again with its current key.', 'sentinel-shield' ), array( 'status' => 403 ) );
		}
		return true;
	}

	/**
	 * Checks a signed request: fresh time, well-formed nonce, matching HMAC, and never seen before.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @param string           $secret  Signing secret.
	 * @return true|false|\WP_Error False for a bad signature, an error for a replay.
	 */
	private static function verify_signature( $request, $secret ) {
		$time  = (int) $request->get_header( self::TIME_HDR );
		$sig   = strtolower( (string) $request->get_header( self::SIG_HDR ) );
		$nonce = (string) $request->get_header( self::NONCE_HDR );
		if ( ! $time || abs( time() - $time ) > self::SKEW || ! preg_match( '/^[0-9a-f]{64}$/', $sig ) || ! preg_match( '/^[A-Za-z0-9]{16,64}$/', $nonce ) ) {
			return false;
		}
		$expected = self::sign( $secret, $time, $nonce, $request->get_method(), $request->get_route(), (string) $request->get_body() );
		if ( ! hash_equals( $expected, $sig ) ) {
			return false;
		}
		// Each request works once.
		$seen = 'sshield_hub_sig_' . md5( $nonce . $sig );
		if ( Network::get_transient( $seen ) ) {
			return new \WP_Error( 'sshield_hub_replay', __( 'This hub request was already used.', 'sentinel-shield' ), array( 'status' => 403 ) );
		}
		Network::set_transient( $seen, 1, 2 * self::SKEW );
		return true;
	}

	/**
	 * Signature over a hub action.
	 *
	 * @param string $key    Hub key.
	 * @param int    $time   Unix time.
	 * @param string $nonce  Random value unique to the request.
	 * @param string $method HTTP method.
	 * @param string $route  REST route, such as /sentinel-shield/v1/hub/scan.
	 * @param string $body   Raw body.
	 * @return string Hex HMAC-SHA256.
	 */
	public static function sign( $key, $time, $nonce, $method, $route, $body ) {
		return hash_hmac( 'sha256', (int) $time . "\n" . $nonce . "\n" . strtoupper( $method ) . "\n" . $route . "\n" . hash( 'sha256', $body ), $key );
	}

	/**
	 * What the current hub key allows: read, manage, or '' with no key.
	 *
	 * @return string
	 */
	public static function key_scope() {
		if ( ! self::has_key() ) {
			return '';
		}
		return 'manage' === Network::get_option( self::SCOPE ) && Network::get_option( self::SEALED ) ? 'manage' : 'read';
	}

	/**
	 * POST /hub/scan.
	 *
	 * @return \WP_REST_Response
	 */
	public function hub_scan() {
		if ( ! Scanner::running() ) {
			Scanner::start( 'hub' );
		}
		Events::add( 'scan', __( 'Scan started from the hub.', 'sentinel-shield' ), Request::ip() );
		return rest_ensure_response( array( 'started' => true ) );
	}

	/**
	 * POST /hub/release: ends every lockout and ban.
	 *
	 * @return \WP_REST_Response
	 */
	public function hub_release() {
		$count = count( Login_Guard::lockouts() ) + count( Bans::bans() );
		Login_Guard::release();
		Bans::release();
		/* translators: %d: number of lockouts and bans. */
		Events::add( 'settings', sprintf( __( 'All lockouts and bans released from the hub (%d).', 'sentinel-shield' ), $count ), Request::ip(), array( 'severity' => Events::NOTICE ) );
		return rest_ensure_response( array( 'released' => $count ) );
	}

	/**
	 * POST /hub/settings: applies hardening settings pushed by the hub.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function hub_settings( $request ) {
		$pushed = $request->get_param( 'settings' );
		if ( ! is_array( $pushed ) ) {
			return new \WP_Error( 'sshield_bad_request', __( 'Send a "settings" object.', 'sentinel-shield' ), array( 'status' => 400 ) );
		}
		$input   = Settings::all();
		$applied = array();
		foreach ( self::pushable() as $key ) {
			if ( array_key_exists( $key, $pushed ) && is_scalar( $pushed[ $key ] ) ) {
				$input[ $key ] = $pushed[ $key ];
				$applied[]     = $key;
			}
		}
		Settings::save_hardening( $input );
		Events::add(
			'settings',
			/* translators: %d: number of settings. */
			sprintf( __( 'Hardening settings pushed from the hub (%d values).', 'sentinel-shield' ), count( $applied ) ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'settings.hardening',
			)
		);
		return rest_ensure_response( array( 'applied' => $applied ) );
	}

	/**
	 * Write access: administrators only.
	 *
	 * @return true|\WP_Error
	 */
	public function can_admin() {
		if ( current_user_can( Network::cap() ) ) {
			return true;
		}
		return new \WP_Error( 'rest_forbidden', __( 'Only administrators can do this.', 'sentinel-shield' ), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Creates a new hub key, replacing any old one.
	 *
	 * @param bool $manage Whether the hub may also run actions.
	 * @return string The key. Only its hash is stored, plus an encrypted copy when actions are allowed.
	 */
	public static function new_key( $manage = false ) {
		$key = 'ssk_' . wp_generate_password( 40, false );
		Network::update_option( self::KEY_OPTION, hash( 'sha256', $key ), false );
		if ( $manage ) {
			// Actions are signed, so the key is kept encrypted with this site's security keys.
			Network::update_option( self::SEALED, Totp::seal( $key ), false );
			Network::update_option( self::SCOPE, 'manage', false );
		} else {
			Network::delete_option( self::SEALED );
			Network::update_option( self::SCOPE, 'read', false );
		}
		return $key;
	}

	/**
	 * Removes the hub key.
	 */
	public static function revoke_key() {
		Network::delete_option( self::KEY_OPTION );
		Network::delete_option( self::SEALED );
		Network::delete_option( self::SCOPE );
	}

	/**
	 * Whether a hub key is set.
	 *
	 * @return bool
	 */
	public static function has_key() {
		return '' !== (string) Network::get_option( self::KEY_OPTION, '' );
	}

	/**
	 * Checks a key against the stored hash.
	 *
	 * @param string $key Key.
	 * @return bool
	 */
	private static function key_valid( $key ) {
		$stored = (string) Network::get_option( self::KEY_OPTION, '' );
		return '' !== $stored && hash_equals( $stored, hash( 'sha256', $key ) );
	}

	/**
	 * GET /status.
	 *
	 * @return \WP_REST_Response
	 */
	public function get_status() {
		return rest_ensure_response( self::status() );
	}

	/**
	 * Security status of this site. Also used by the hub for the local row.
	 *
	 * @return array
	 */
	public static function status() {
		global $wp_version;
		$checks  = Posture::checks();
		$score   = Posture::score( $checks );
		$results = Scanner::results();
		$open    = Scanner::open_findings( $results );
		$issues  = array();
		foreach ( $checks as $check ) {
			if ( Posture::PASS !== $check['status'] ) {
				$issues[] = array(
					'id'     => $check['id'],
					'label'  => $check['label'],
					'status' => $check['status'],
					'detail' => $check['detail'],
				);
			}
		}
		$modules = array();
		foreach ( array_keys( Settings::modules() ) as $key ) {
			$modules[ $key ] = Settings::enabled( $key );
		}

		return array(
			'site'      => array(
				'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				'url'  => home_url( '/' ),
			),
			'plugin'    => SSHIELD_VERSION,
			'wordpress' => $wp_version,
			'php'       => PHP_VERSION,
			'score'     => $score,
			'band'      => Admin::band( $score ),
			'issues'    => $issues,
			'modules'   => $modules,
			'stats'     => Login_Guard::stats(),
			'lockouts'  => count( Login_Guard::lockouts() ),
			'bans'      => count( Bans::bans() ),
			'vulns'     => count( Vulns::open() ),
			'incidents' => Incidents::summary(),
			'scan'      => array(
				'running'  => Scanner::running(),
				'finished' => $results ? (int) $results['finished'] : null,
				'files'    => $results ? (int) $results['files_scanned'] : 0,
				'findings' => count( $open ),
				'high'     => count(
					array_filter(
						$open,
						static function ( $f ) {
							return 'high' === $f['severity'];
						}
					)
				),
			),
			'actions'   => 'manage' === self::key_scope(),
			'generated' => time(),
		);
	}

	/**
	 * GET /events.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function get_events( $request ) {
		$per   = (int) $request['per_page'];
		$type  = (string) $request['type'];
		$rows  = Events::query(
			array(
				'type'   => $type,
				'limit'  => $per,
				'offset' => ( (int) $request['page'] - 1 ) * $per,
			)
		);
		$total = Events::count( $type );
		$out   = rest_ensure_response( $rows );
		$out->header( 'X-WP-Total', (string) $total );
		$out->header( 'X-WP-TotalPages', (string) max( 1, (int) ceil( $total / $per ) ) );
		return $out;
	}

	/**
	 * GET /scan.
	 *
	 * @return \WP_REST_Response
	 */
	public function get_scan() {
		$results = Scanner::results();
		return rest_ensure_response(
			array(
				'progress' => Scanner::progress(),
				'finished' => $results ? (int) $results['finished'] : null,
				'files'    => $results ? (int) $results['files_scanned'] : 0,
				'core'     => $results ? (bool) $results['core_checked'] : null,
				'findings' => array_map(
					static function ( $f ) {
						unset( $f['hash'] );
						return $f;
					},
					Scanner::open_findings( $results )
				),
			)
		);
	}

	/**
	 * POST /scan.
	 *
	 * @return \WP_REST_Response
	 */
	public function start_scan() {
		if ( ! Scanner::running() ) {
			Scanner::start( 'api' );
		}
		return rest_ensure_response( Scanner::progress() );
	}

	/**
	 * POST /scan/step.
	 *
	 * @return \WP_REST_Response
	 */
	public function step_scan() {
		return rest_ensure_response( Scanner::step( 8 ) );
	}

	/**
	 * GET /lockouts.
	 *
	 * @return \WP_REST_Response
	 */
	public function get_lockouts() {
		$out = array();
		foreach ( Login_Guard::lockouts() as $ip => $until ) {
			$out[] = array(
				'ip'    => $ip,
				'until' => (int) $until,
			);
		}
		return rest_ensure_response( $out );
	}

	/**
	 * DELETE /lockouts/{ip}.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function delete_lockout( $request ) {
		$ip = (string) $request['ip'];
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return new \WP_Error( 'sshield_bad_ip', __( 'Not a valid IP address.', 'sentinel-shield' ), array( 'status' => 400 ) );
		}
		Login_Guard::release( $ip );
		/* translators: %s: IP address. */
		Events::add( 'settings', sprintf( __( 'Lockout released for %s through the API.', 'sentinel-shield' ), $ip ), Request::ip() );
		return rest_ensure_response( array( 'released' => $ip ) );
	}

	/**
	 * POST /blocklist.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function block_ip( $request ) {
		$ip = (string) $request['ip'];
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return new \WP_Error( 'sshield_bad_ip', __( 'Not a valid IP address.', 'sentinel-shield' ), array( 'status' => 400 ) );
		}
		if ( Request::ip() === $ip ) {
			return new \WP_Error( 'sshield_self_block', __( 'You cannot block your own IP address.', 'sentinel-shield' ), array( 'status' => 400 ) );
		}
		Settings::block_ip( $ip );
		Login_Guard::release( $ip );
		/* translators: %s: IP address. */
		Events::add( 'settings', sprintf( __( '%s added to the block list through the API.', 'sentinel-shield' ), $ip ), Request::ip() );
		return rest_ensure_response( array( 'blocked' => $ip ) );
	}

	/**
	 * GET /settings.
	 *
	 * @return \WP_REST_Response
	 */
	public function get_settings() {
		return rest_ensure_response( Settings::all() );
	}

	/**
	 * POST /settings: switches modules on or off. Body: {"modules": {"firewall": true}}.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function update_settings( $request ) {
		$modules = $request->get_param( 'modules' );
		if ( ! is_array( $modules ) ) {
			return new \WP_Error( 'sshield_bad_request', __( 'Send a "modules" object of module names and true or false.', 'sentinel-shield' ), array( 'status' => 400 ) );
		}
		$input = Settings::all();
		foreach ( array_keys( Settings::modules() ) as $key ) {
			if ( array_key_exists( $key, $modules ) ) {
				$input[ $key ] = rest_sanitize_boolean( $modules[ $key ] );
			}
		}
		Settings::save_hardening( $input );
		Events::add( 'settings', __( 'Hardening settings updated through the API.', 'sentinel-shield' ), Request::ip(), array( 'action' => 'settings.hardening' ) );
		return rest_ensure_response( Settings::all() );
	}
}
