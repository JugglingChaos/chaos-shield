<?php
/**
 * Under attack mode: a quick browser check in front of the site during a flood.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * While on, visitors without a pass solve a small proof of work in their browser
 * before WordPress builds a page for them. Browsers pass in about a second and
 * keep the pass for 12 hours; simple bots and scripts never get through.
 *
 * It switches itself on when blocked requests pile up, and off again an hour
 * after the flood stops. A volumetric flood that fills the server's connection
 * can only be stopped upstream, which is what the Cloudflare connection is for.
 */
final class Attack_Mode {

	const OPTION = 'sshield_attack';
	const SECRET = 'sshield_attack_secret';
	const COOKIE = 'sshield_pass';
	const EVENT  = 'sshield_attack_changed';
	const LASTS  = HOUR_IN_SECONDS;
	const PASS   = 12 * HOUR_IN_SECONDS;
	const ZEROS  = 4;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::EVENT, array( __CLASS__, 'changed' ) );
		// Pluggable functions exist from here, which the logged-in check needs.
		add_action( 'plugins_loaded', array( __CLASS__, 'gate' ), 1 );
	}

	/**
	 * Stored state.
	 *
	 * @return array on, auto, since, until, reason.
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION, array() );
		return wp_parse_args(
			is_array( $state ) ? $state : array(),
			array(
				'on'     => false,
				'auto'   => false,
				'since'  => 0,
				'until'  => 0,
				'reason' => '',
				'last'   => 0,
			)
		);
	}

	/**
	 * Whether the browser check is in front of the site now. An automatic run ends on its own.
	 *
	 * @return bool
	 */
	public static function active() {
		$state = self::state();
		if ( ! $state['on'] ) {
			return false;
		}
		if ( $state['auto'] && $state['until'] && $state['until'] < time() ) {
			self::turn_off( 'The flood stopped, so under attack mode switched itself off.' );
			return false;
		}
		return true;
	}

	/**
	 * Switches the browser check on.
	 *
	 * @param bool   $auto   Switched on by the flood detector, so it ends on its own.
	 * @param string $reason Plain English, for the log.
	 */
	public static function turn_on( $auto, $reason ) {
		$was = self::state();
		Network::update_option(
			self::OPTION,
			array(
				'on'     => true,
				'auto'   => (bool) $auto,
				'since'  => $was['on'] ? (int) $was['since'] : time(),
				'until'  => $auto ? time() + self::LASTS : 0,
				'reason' => (string) $reason,
				'last'   => (int) $was['last'],
			)
		);
		if ( $was['on'] ) {
			return;
		}
		Events::add(
			'system',
			$reason,
			Request::ip(),
			array(
				'severity' => Events::CRITICAL,
				'action'   => 'attack.on',
				'subject'  => $auto ? 'auto' : 'manual',
			)
		);
		// The alert and the Cloudflare call run in their own request, away from the flood.
		Network::schedule_single( time(), self::EVENT, array( 'on' ) );
	}

	/**
	 * Switches the browser check off.
	 *
	 * @param string $reason Plain English, for the log.
	 */
	public static function turn_off( $reason ) {
		$was = self::state();
		if ( ! $was['on'] ) {
			return;
		}
		Network::update_option(
			self::OPTION,
			array(
				'on'     => false,
				'auto'   => false,
				'since'  => 0,
				'until'  => 0,
				'reason' => '',
				'last'   => time(),
			)
		);
		Events::add(
			'system',
			$reason,
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'attack.off',
			)
		);
		Network::schedule_single( time(), self::EVENT, array( 'off' ) );
	}

	/**
	 * Tells the owner and the edge network that the mode changed.
	 *
	 * @param string $what on or off.
	 */
	public static function changed( $what ) {
		$on = 'on' === $what;
		if ( $on ) {
			$state = self::state();
			Alerts::send(
				'alert_attack',
				__( 'Your site is under attack', 'sentinel-shield' ),
				sprintf(
					/* translators: 1: site address, 2: what was seen. */
					__( "Under attack mode is now on for %1\$s: %2\$s\n\nVisitors see a short browser check before each first page view, and bots are kept out. It switches itself off an hour after the flood stops; you can switch it off on the Edge tab.\n\nA flood large enough to fill your server's connection has to be stopped before it reaches the server. Connect Cloudflare on the Edge tab to switch on its own Under Attack mode at the same time.", 'sentinel-shield' ),
					home_url(),
					$state['reason']
				),
				'attack'
			);
		}
		/**
		 * Fires after under attack mode switched on or off.
		 *
		 * @param bool $on Whether it is on now.
		 */
		do_action( 'sshield_attack_mode', $on );
	}

	/**
	 * Counts a blocked request and switches the mode on when a flood is under way.
	 */
	public static function note() {
		if ( ! Settings::enabled( 'attack_auto' ) ) {
			return;
		}
		$limit = (int) Settings::get( 'attack_threshold' );
		$count = self::count( 'sshield_atk_' . (int) floor( time() / 60 ) );
		if ( $limit <= 0 || $count < $limit ) {
			return;
		}
		$state = self::state();
		if ( $state['on'] && ! $state['auto'] ) {
			return;
		}
		// Keep an automatic run going while the flood lasts, rewriting the state at most once a minute.
		if ( $state['on'] && $state['until'] - self::LASTS > time() - MINUTE_IN_SECONDS ) {
			return;
		}
		// Plain English: this can run before translations load.
		self::turn_on( true, sprintf( 'Under attack mode switched on: more than %d requests were blocked in one minute.', $limit ) );
	}

	/**
	 * Adds one to a per-minute counter, in memory when a persistent cache is there.
	 *
	 * @param string $key Counter.
	 * @return int New value.
	 */
	private static function count( $key ) {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $key, 0, 'sshield', 2 * MINUTE_IN_SECONDS );
			return (int) wp_cache_incr( $key, 1, 'sshield' );
		}
		$value = (int) Network::get_transient( $key ) + 1;
		Network::set_transient( $key, $value, 2 * MINUTE_IN_SECONDS );
		return $value;
	}

	// The browser check.

	/**
	 * Secret that signs challenges and passes.
	 *
	 * @return string
	 */
	private static function secret() {
		$secret = (string) Network::get_option( self::SECRET );
		if ( strlen( $secret ) < 32 ) {
			$secret = bin2hex( random_bytes( 32 ) );
			Network::update_option( self::SECRET, $secret );
		}
		return $secret;
	}

	/**
	 * Signature of a value.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function sign( $value ) {
		return substr( hash_hmac( 'sha256', $value, self::secret() ), 0, 32 );
	}

	/**
	 * Hash of the visitor's browser name, so a pass cannot be handed to another program.
	 *
	 * @return string
	 */
	private static function agent() {
		return md5( Request::server( 'HTTP_USER_AGENT' ) );
	}

	/**
	 * A fresh challenge.
	 *
	 * @return string
	 */
	public static function challenge() {
		$base = time() . '.' . bin2hex( random_bytes( 8 ) );
		return $base . '.' . self::sign( 'c|' . $base );
	}

	/**
	 * Checks a solved challenge: signed here, under ten minutes old, and the hash starts with enough zeros.
	 *
	 * @param string $challenge Challenge.
	 * @param string $nonce     The visitor's answer.
	 * @return bool
	 */
	public static function solved( $challenge, $nonce ) {
		$parts = explode( '.', (string) $challenge );
		if ( 3 !== count( $parts ) || ! ctype_digit( $parts[0] ) || ! preg_match( '/^\d{1,12}$/', (string) $nonce ) ) {
			return false;
		}
		$age = time() - (int) $parts[0];
		if ( $age < 0 || $age > 10 * MINUTE_IN_SECONDS || ! hash_equals( self::sign( 'c|' . $parts[0] . '.' . $parts[1] ), $parts[2] ) ) {
			return false;
		}
		return 0 === strpos( hash( 'sha256', $challenge . ':' . $nonce ), str_repeat( '0', self::ZEROS ) );
	}

	/**
	 * A pass for this browser.
	 *
	 * @param int $expires Unix time.
	 * @return string
	 */
	public static function pass( $expires ) {
		return (int) $expires . '.' . self::sign( 'p|' . (int) $expires . '|' . self::agent() );
	}

	/**
	 * Whether the request carries a valid pass.
	 *
	 * @return bool
	 */
	private static function has_pass() {
		$value = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		$parts = explode( '.', $value, 2 );
		return 2 === count( $parts ) && ctype_digit( $parts[0] ) && (int) $parts[0] > time() && hash_equals( self::pass( (int) $parts[0] ), $value );
	}

	/**
	 * Requests the check never stands in front of.
	 *
	 * @return bool
	 */
	private static function exempt() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || wp_doing_ajax() || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return true;
		}
		$uri = Request::server( 'REQUEST_URI' );
		// The REST API has its own rate limit, and apps that use it cannot solve a browser check.
		if ( preg_match( '#^/(?:[^?]*/)?(wp-json/|\?rest_route=)|[?&]rest_route=|/\.well-known/|/robots\.txt$#', $uri ) ) {
			return true;
		}
		if ( Firewall::allowlisted() || Page_Check::is_self() ) {
			return true;
		}
		if ( function_exists( 'wp_validate_auth_cookie' ) && wp_validate_auth_cookie( '', 'logged_in' ) ) {
			return true;
		}
		return Bans::is_verified_crawler( Request::ip() );
	}

	/**
	 * Stands in front of the request while the mode is on.
	 */
	public static function gate() {
		if ( ! self::active() || self::exempt() || self::has_pass() ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The challenge is signed and checked in solved().
		if ( isset( $_POST['sshield_pow'], $_POST['sshield_nonce'] ) ) {
			$challenge = sanitize_text_field( wp_unslash( $_POST['sshield_pow'] ) );
			$nonce     = sanitize_text_field( wp_unslash( $_POST['sshield_nonce'] ) );
			// phpcs:enable
			if ( self::solved( $challenge, $nonce ) ) {
				$expires = time() + self::PASS;
				setcookie(
					self::COOKIE,
					self::pass( $expires ),
					array(
						'expires'  => $expires,
						'path'     => '/',
						'secure'   => is_ssl(),
						'httponly' => true,
						'samesite' => 'Lax',
					)
				);
				nocache_headers();
				header( 'Location: ' . wp_sanitize_redirect( Request::server( 'REQUEST_URI' ) ), true, 303 );
				exit;
			}
		}
		self::page();
	}

	/**
	 * Sends the browser check and stops.
	 */
	private static function page() {
		Traffic::note_block( 'challenged' );
		if ( ! headers_sent() ) {
			status_header( 503 );
			nocache_headers();
			header( 'Retry-After: 5' );
			header( 'X-Robots-Tag: noindex' );
		}
		if ( ! Help::wants_html() ) {
			if ( ! headers_sent() ) {
				header( 'Content-Type: text/plain; charset=utf-8' );
			}
			echo esc_html( '503 This site is busy and only lets browsers in right now. Please try again in a few minutes.' );
			exit;
		}
		Help::prepare_strings();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		$site  = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$title = __( 'Checking your browser', 'sentinel-shield' );
		$data  = array(
			'c'     => self::challenge(),
			'zeros' => self::ZEROS,
			'slow'  => __( 'Still checking. This can take a few seconds on older devices.', 'sentinel-shield' ),
		);
		// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Every value below is escaped where it is built.
		echo '<!doctype html><html lang="' . esc_attr( (string) get_bloginfo( 'language' ) ) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">'
			. '<title>' . esc_html( $title ) . '</title><style>' . Help::asset( 'css' ) . '.ssh-wait{display:flex;align-items:center;gap:12px;margin:18px 0 4px}.ssh-spin{width:22px;height:22px;border-radius:50%;border:3px solid var(--ssh-line);border-top-color:var(--ssh-accent);animation:ssh-spin .8s linear infinite}@keyframes ssh-spin{to{transform:rotate(360deg)}}@media (prefers-reduced-motion:reduce){.ssh-spin{animation:none}}</style></head>'
			. '<body class="ssh-page" style="--ssh-accent:' . esc_attr( (string) Settings::get( 'help_color' ) ) . '"><main class="ssh-card">'
			. '<p class="ssh-site">' . esc_html( $site ) . '</p>'
			. '<h1>' . esc_html( $title ) . '</h1><p class="ssh-lead">' . esc_html__( 'The site is getting a lot of unusual traffic, so it checks that you are a person with a real browser. This happens once and takes about a second.', 'sentinel-shield' ) . '</p>'
			. '<form method="post" id="ssh-pow"><input type="hidden" name="sshield_pow" value="' . esc_attr( $data['c'] ) . '"><input type="hidden" name="sshield_nonce" value=""></form>'
			. '<div class="ssh-wait" role="status"><span class="ssh-spin" aria-hidden="true"></span><span id="ssh-pow-msg">' . esc_html__( 'Checking…', 'sentinel-shield' ) . '</span></div>'
			. '<noscript><p class="ssh-lead">' . esc_html__( 'Turn on JavaScript and reload the page to continue.', 'sentinel-shield' ) . '</p></noscript>'
			. '<p class="ssh-foot">' . esc_html__( 'Protected by Sentinel Shield', 'sentinel-shield' ) . '</p></main>'
			. '<script>window.sshieldPow=' . wp_json_encode( $data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ) . ';</script>'
			. '<script>' . self::script() . '</script></body></html>';
		// phpcs:enable
		exit;
	}

	/**
	 * The proof of work: finds a number that makes SHA-256 of the challenge start with zeros.
	 *
	 * @return string
	 */
	private static function script() {
		$path = SSHIELD_DIR . 'assets/js/pow.js';
		return is_readable( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- The plugin's own asset, inlined.
	}

	/**
	 * Saves the switch on the Edge tab.
	 *
	 * @param bool $on On or off.
	 */
	public static function manual( $on ) {
		if ( $on ) {
			self::turn_on( false, __( 'Under attack mode switched on by an administrator.', 'sentinel-shield' ) );
		} else {
			self::turn_off( __( 'Under attack mode switched off by an administrator.', 'sentinel-shield' ) );
		}
	}
}
