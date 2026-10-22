<?php
/**
 * Visitor help: friendly block pages, a help assistant and a way to ask the owner for access.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Answers simple questions from a built-in FAQ plus the owner's own, on the
 * block and rate-limit pages, the login page and, if switched on, every page.
 *
 * Answers are matched in the visitor's browser, so nothing is sent anywhere
 * and the assistant keeps working during an attack. Block pages never say which
 * rule fired, so an attacker learns nothing from them.
 */
final class Help {

	const FAQ      = 'cshield_help_faq';
	const REQUESTS = 'cshield_help_requests';
	const SECRET   = 'cshield_help_secret';
	const ACTION   = 'cshield_help';
	const NOTIFY   = 'cshield_help_notify';
	const MAX_FAQ  = 50;
	const MAX_OPEN = 50;

	/**
	 * Registers hooks.
	 */
	public function register() {
		// Before the firewall (0), so a visitor's own words in the form cannot get them banned.
		add_action( 'plugins_loaded', array( __CLASS__, 'intercept' ), -5 );
		add_action( self::NOTIFY, array( __CLASS__, 'notify' ) );
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		if ( ! Settings::enabled( 'visitor_help' ) ) {
			return;
		}
		add_action( 'login_footer', array( __CLASS__, 'login_bubble' ) );
		if ( Settings::enabled( 'help_bubble' ) ) {
			add_action( 'wp_footer', array( __CLASS__, 'site_bubble' ), 50 );
		}
	}

	/**
	 * Whether this request is the help form being sent.
	 *
	 * @return bool
	 */
	public static function is_ask() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked with a signed token in intercept().
		return isset( $_SERVER['REQUEST_METHOD'], $_POST['cshield_help'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] && 'ask' === $_POST['cshield_help'];
	}

	/**
	 * Whether a request expects a web page, rather than an API answer.
	 *
	 * @return bool
	 */
	public static function wants_html() {
		if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only matched.
		if ( preg_match( '#/(wp-json|xmlrpc\.php|wp-admin/admin-ajax\.php)#', $uri ) ) {
			return false;
		}
		$accept = isset( $_SERVER['HTTP_ACCEPT'] ) ? strtolower( (string) wp_unslash( $_SERVER['HTTP_ACCEPT'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only matched.
		return false !== strpos( $accept, 'text/html' );
	}

	// Translations.

	/**
	 * Makes translated strings safe to ask for, however early this runs.
	 *
	 * Block pages can be sent while plugins are still loading. From the point
	 * the user functions exist the plugin's translations are loaded by hand;
	 * before that, English is used without waking WordPress's loader too early.
	 */
	public static function prepare_strings() {
		if ( did_action( 'after_setup_theme' ) || is_textdomain_loaded( 'chaos-shield' ) ) {
			return;
		}
		if ( function_exists( 'wp_get_current_user' ) ) {
			load_plugin_textdomain( 'chaos-shield', false, dirname( plugin_basename( CSHIELD_FILE ) ) . '/languages' );
			return;
		}
		$GLOBALS['l10n_unloaded']                 = (array) ( isset( $GLOBALS['l10n_unloaded'] ) ? $GLOBALS['l10n_unloaded'] : array() ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Marks the domain as not loaded, the documented way.
		$GLOBALS['l10n_unloaded']['chaos-shield'] = true; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- See above.
	}

	// The assistant's knowledge.

	/**
	 * What each kind of block means to the visitor.
	 *
	 * @param string $reason Reason key.
	 * @return array title, text, tips, length.
	 */
	public static function reason( $reason ) {
		$ip    = Request::ip();
		$hours = 0;
		if ( 'ban' === $reason && $ip ) {
			$hours = max( 1, (int) ceil( ( Bans::until( $ip ) - time() ) / HOUR_IN_SECONDS ) );
		}
		$all = array(
			'firewall'  => array(
				'title'  => __( 'This request was blocked', 'chaos-shield' ),
				'text'   => __( 'Something in it looked like an attack, so the site\'s firewall stopped it. Real visitors run into this now and then, for example with an unusual link, text that looks like code, or a browser extension.', 'chaos-shield' ),
				'tips'   => array(
					__( 'Go back and try again without the link or text you used.', 'chaos-shield' ),
					__( 'Turn off browser extensions or a VPN, then reload.', 'chaos-shield' ),
					__( 'Still blocked? Ask the site owner below and include the reference.', 'chaos-shield' ),
				),
				'length' => __( 'Only this request was stopped. Other pages of the site still work for you.', 'chaos-shield' ),
			),
			'ban'       => array(
				'title'  => __( 'Access from your network is paused', 'chaos-shield' ),
				'text'   => __( 'Your IP address sent several requests that looked like attacks or failed sign-ins, so the site paused it for a while. On a shared network, someone else may have caused this.', 'chaos-shield' ),
				'tips'   => array(
					__( 'Wait: the pause lifts on its own.', 'chaos-shield' ),
					__( 'Try another network, for example mobile data instead of Wi-Fi.', 'chaos-shield' ),
					__( 'Ask the site owner below if you need in sooner.', 'chaos-shield' ),
				),
				/* translators: %d: hours. */
				'length' => sprintf( _n( 'The pause ends in about %d hour.', 'The pause ends in about %d hours.', $hours, 'chaos-shield' ), $hours ),
			),
			'blocklist' => array(
				'title'  => __( 'Access from your network is blocked', 'chaos-shield' ),
				'text'   => __( 'The site owner has blocked your IP address.', 'chaos-shield' ),
				'tips'   => array(
					__( 'If you think this is a mistake, ask the site owner below.', 'chaos-shield' ),
				),
				'length' => __( 'The block stays until the site owner removes it.', 'chaos-shield' ),
			),
			'country'   => array(
				'title'  => __( 'This site is not available in your region', 'chaos-shield' ),
				'text'   => __( 'The site owner limits access by country, and your connection appears to come from a region that is not included.', 'chaos-shield' ),
				'tips'   => array(
					__( 'If your location was detected wrongly, ask the site owner below.', 'chaos-shield' ),
				),
				'length' => __( 'This stays as long as the site limits access by country.', 'chaos-shield' ),
			),
			'threat'    => array(
				'title'  => __( 'Your network is on a blocklist', 'chaos-shield' ),
				'text'   => __( 'Your IP address is on a public list of networks used for spam or attacks, or it is a Tor exit. Shared, hosting and cloud networks sometimes end up on such lists.', 'chaos-shield' ),
				'tips'   => array(
					__( 'Try another network, for example mobile data instead of Wi-Fi.', 'chaos-shield' ),
					__( 'Ask the site owner below if you need access from this network.', 'chaos-shield' ),
				),
				'length' => __( 'The lists are refreshed every day, so this can change on its own.', 'chaos-shield' ),
			),
			'rate'      => array(
				'title'  => __( 'Slow down a little', 'chaos-shield' ),
				'text'   => __( 'Your browser sent a lot of requests in a short time, so the site asked it to wait.', 'chaos-shield' ),
				'tips'   => array(
					__( 'Wait a minute, then reload once.', 'chaos-shield' ),
					__( 'Close other tabs of this site, and stop any tool that refreshes the page.', 'chaos-shield' ),
				),
				'length' => __( 'It clears after about a minute.', 'chaos-shield' ),
			),
		);
		return isset( $all[ $reason ] ) ? $all[ $reason ] : $all['firewall'];
	}

	/**
	 * Built-in answers for one place.
	 *
	 * Keywords are translatable, so the assistant understands questions in the site's language.
	 *
	 * @param string $context block, rate, login, site or 404.
	 * @param string $reason  Block reason, on block pages.
	 * @return array List of q, a, k (keywords), action.
	 */
	public static function builtin( $context, $reason = '' ) {
		$lost  = wp_lostpassword_url();
		$items = array();
		if ( in_array( $context, array( 'block', 'rate' ), true ) ) {
			$r       = self::reason( 'rate' === $context ? 'rate' : $reason );
			$items[] = array(
				'q' => __( 'Why was I blocked?', 'chaos-shield' ),
				'a' => $r['text'],
				'k' => __( 'why, blocked, block, forbidden, denied, 403, 429, stopped, error, reason, banned', 'chaos-shield' ),
			);
			$items[] = array(
				'q' => __( 'What can I do?', 'chaos-shield' ),
				'a' => implode( ' ', $r['tips'] ),
				'k' => __( 'fix, help, unblock, solve, access, get in, what do, try, again', 'chaos-shield' ),
			);
			$items[] = array(
				'q' => __( 'How long does it last?', 'chaos-shield' ),
				'a' => $r['length'],
				'k' => __( 'how long, long, wait, time, minutes, hours, when, end, last, expire', 'chaos-shield' ),
			);
			if ( 'block' === $context ) {
				$items[] = array(
					'q' => __( 'Could my VPN or an extension cause this?', 'chaos-shield' ),
					'a' => __( 'Yes, sometimes. VPNs and shared networks carry other people\'s traffic, and some extensions add odd text to every request. Turning them off for this site often helps.', 'chaos-shield' ),
					'k' => __( 'vpn, proxy, extension, addon, plugin, adblock, network, wifi, shared, tor', 'chaos-shield' ),
				);
				$items[] = array(
					'q' => __( 'What is the reference code?', 'chaos-shield' ),
					'a' => __( 'It identifies your request, so the site owner can find it and let it through. Include it when you contact them.', 'chaos-shield' ),
					'k' => __( 'reference, code, ref, number, id, identifier', 'chaos-shield' ),
				);
			}
		}
		if ( 'login' === $context ) {
			$ip      = Request::ip();
			$until   = $ip ? Login_Guard::locked_until( $ip ) : 0;
			$minutes = $until ? max( 1, (int) ceil( ( $until - time() ) / MINUTE_IN_SECONDS ) ) : (int) Settings::get( 'login_lockout' );
			$items[] = array(
				'q' => __( 'I am locked out after wrong passwords', 'chaos-shield' ),
				/* translators: %d: minutes. */
				'a' => sprintf( _n( 'After several wrong passwords, sign-in pauses for your network for %d minute. Wait, then reset your password instead of guessing: [Lost your password?](lost)', 'After several wrong passwords, sign-in pauses for your network for %d minutes. Wait, then reset your password instead of guessing: [Lost your password?](lost)', $minutes, 'chaos-shield' ), $minutes ),
				'k' => __( 'locked, lockout, locked out, too many, attempts, failed, wrong password, try again, blocked', 'chaos-shield' ),
			);
			$items[] = array(
				'q' => __( 'I forgot my password', 'chaos-shield' ),
				'a' => __( 'Use [Lost your password?](lost) and enter your username or email address. A reset link is emailed to you.', 'chaos-shield' ),
				'k' => __( 'forgot, forgotten, password, reset, lost, remember, change password', 'chaos-shield' ),
			);
			$items[] = array(
				'q' => __( 'The reset email never arrived', 'chaos-shield' ),
				'a' => __( 'Give it a few minutes and check your spam or junk folder. It goes to the address on your account, which may be an older one. Still nothing? Ask the site owner.', 'chaos-shield' ),
				'k' => __( 'email, mail, arrive, arrived, never, spam, junk, inbox, received, link', 'chaos-shield' ),
			);
			if ( Settings::enabled( 'two_factor' ) ) {
				$items[] = array(
					'q' => __( 'I lost my two-factor device', 'chaos-shield' ),
					'a' => __( 'Type one of the recovery codes you saved when you set up two-factor, in place of the six-digit code. No codes left? Ask a site administrator to switch two-factor off for your account.', 'chaos-shield' ),
					'k' => __( 'two factor, 2fa, authenticator, phone, lost, new phone, device, recovery, backup code, otp', 'chaos-shield' ),
				);
				$items[] = array(
					'q' => __( 'My two-factor code is not accepted', 'chaos-shield' ),
					'a' => __( 'Codes change every 30 seconds and depend on your phone\'s clock. Set the phone\'s time to automatic, then type the newest code.', 'chaos-shield' ),
					'k' => __( 'code, wrong code, invalid, not accepted, rejected, six digit, 2fa, authenticator, expired', 'chaos-shield' ),
				);
			}
			if ( Settings::enabled( 'passkeys' ) ) {
				$items[] = array(
					'q' => __( 'How do I sign in with a passkey?', 'chaos-shield' ),
					'a' => __( 'Choose Sign in with a passkey on the login form, then confirm with your fingerprint, face or device PIN. Add a passkey first from your profile after signing in.', 'chaos-shield' ),
					'k' => __( 'passkey, fingerprint, face id, touch id, windows hello, security key, passwordless', 'chaos-shield' ),
				);
			}
		}
		if ( in_array( $context, array( 'login', 'site' ), true ) && Captcha::active() ) {
			$items[] = array(
				'q' => __( 'The security check will not finish', 'chaos-shield' ),
				'a' => __( 'Allow this site in your ad or script blocker, make sure cookies are on, or try another browser. The check is run by Cloudflare Turnstile or hCaptcha.', 'chaos-shield' ),
				'k' => __( 'captcha, security check, robot, human, verify, turnstile, hcaptcha, challenge, stuck, loading', 'chaos-shield' ),
			);
		}
		if ( '404' === $context ) {
			$items[] = array(
				'q' => __( 'Why can\'t I find this page?', 'chaos-shield' ),
				'a' => __( 'The link may be old or mistyped. Try the [home page](home) or search the site.', 'chaos-shield' ),
				'k' => __( 'page, missing, not found, 404, broken, link, gone, moved, find', 'chaos-shield' ),
			);
		}
		if ( Settings::enabled( 'help_contact' ) ) {
			$items[] = array(
				'q'      => __( 'How do I contact the site owner?', 'chaos-shield' ),
				'a'      => __( 'Send a short message here and it goes straight to them.', 'chaos-shield' ),
				'k'      => __( 'contact, owner, admin, administrator, human, person, support, email, message, talk, someone', 'chaos-shield' ),
				'action' => 'contact',
			);
		}
		return $items;
	}

	/**
	 * The owner's own questions and answers.
	 *
	 * @return array List of q, a, k.
	 */
	public static function faq() {
		$faq = Network::get_option( self::FAQ, array() );
		return is_array( $faq ) ? array_values( $faq ) : array();
	}

	/**
	 * Saves the owner's questions and answers.
	 *
	 * @param array $rows Rows with q, a and k.
	 * @return int Rows kept.
	 */
	public static function save_faq( array $rows ) {
		$clean = array();
		foreach ( $rows as $row ) {
			$q = isset( $row['q'] ) ? mb_substr( sanitize_text_field( (string) $row['q'] ), 0, 200 ) : '';
			$a = isset( $row['a'] ) ? mb_substr( sanitize_textarea_field( (string) $row['a'] ), 0, 1500 ) : '';
			$k = isset( $row['k'] ) ? mb_substr( sanitize_text_field( (string) $row['k'] ), 0, 300 ) : '';
			if ( '' !== $q && '' !== $a ) {
				$clean[] = array(
					'q' => $q,
					'a' => $a,
					'k' => $k,
				);
			}
			if ( count( $clean ) >= self::MAX_FAQ ) {
				break;
			}
		}
		Network::update_option( self::FAQ, $clean, false );
		return count( $clean );
	}

	// The form for asking the owner.

	/**
	 * Secret that signs the form token.
	 *
	 * @return string
	 */
	private static function secret() {
		$secret = (string) Network::get_option( self::SECRET );
		if ( strlen( $secret ) < 32 ) {
			$secret = bin2hex( random_bytes( 32 ) );
			Network::update_option( self::SECRET, $secret, false );
		}
		return $secret;
	}

	/**
	 * A token proving the form was loaded from this site, and when.
	 *
	 * It is not tied to the visitor, so it survives page caching.
	 *
	 * @param int $time Issue time, for tests.
	 * @return string
	 */
	public static function token( $time = 0 ) {
		$time = $time ? (int) $time : time();
		return $time . '.' . substr( hash_hmac( 'sha256', 'help|' . $time, self::secret() ), 0, 32 );
	}

	/**
	 * Checks a form token: signed here, at least three seconds old, at most a week.
	 *
	 * @param string $token Token.
	 * @return bool
	 */
	public static function token_ok( $token ) {
		$parts = explode( '.', (string) $token, 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) ) {
			return false;
		}
		$age = time() - (int) $parts[0];
		return $age >= 3 && $age <= WEEK_IN_SECONDS && hash_equals( self::token( (int) $parts[0] ), (string) $token );
	}

	/**
	 * Answers the help form, wherever it was sent, and stops.
	 *
	 * Runs before the firewall and is also called from the block page, so a
	 * blocked visitor can still reach the owner. Nothing else in the request runs.
	 */
	public static function intercept() {
		if ( ! self::is_ask() ) {
			return;
		}
		$result = self::ask( wp_unslash( $_POST ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked with a signed token in ask().
		if ( ! headers_sent() ) {
			status_header( 200 );
			nocache_headers();
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'X-Content-Type-Options: nosniff' );
		}
		echo wp_json_encode( $result ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON.
		exit;
	}

	/**
	 * Stores a visitor's message for the owner.
	 *
	 * @param array $post Unslashed form fields.
	 * @return array ok, message.
	 */
	public static function ask( array $post ) {
		self::prepare_strings();
		$fail = static function ( $message ) {
			return array(
				'ok'      => false,
				'message' => $message,
			);
		};
		if ( ! Settings::enabled( 'visitor_help' ) || ! Settings::enabled( 'help_contact' ) ) {
			return $fail( __( 'Messages are switched off on this site.', 'chaos-shield' ) );
		}
		$ip = Request::ip();
		// Bots fill the hidden field or send the form in under three seconds.
		if ( ! empty( $post['website'] ) || ! self::token_ok( isset( $post['token'] ) ? $post['token'] : '' ) ) {
			return $fail( __( 'The form expired. Reload the page and try again.', 'chaos-shield' ) );
		}
		// Three an hour per IP and six per network, and no network may fill the inbox.
		$throttle = 'cshield_help_ip_' . md5( (string) $ip );
		$net      = Request::range( $ip );
		$net_key  = 'cshield_help_net_' . md5( $net );
		$sent     = (int) Network::get_transient( $throttle );
		$net_sent = (int) Network::get_transient( $net_key );
		$open     = 0;
		$net_open = 0;
		foreach ( self::requests() as $r ) {
			if ( 'open' === $r['status'] ) {
				++$open;
				$net_open += Request::range( $r['ip'] ) === $net ? 1 : 0;
			}
		}
		if ( $sent >= 3 || $net_sent >= 6 || $open >= self::MAX_OPEN || $net_open >= self::MAX_OPEN / 10 ) {
			return $fail( __( 'Your message could not be sent right now. Please try again later.', 'chaos-shield' ) );
		}
		$email   = isset( $post['email'] ) ? sanitize_email( (string) $post['email'] ) : '';
		$message = isset( $post['message'] ) ? trim( sanitize_textarea_field( (string) $post['message'] ) ) : '';
		if ( ! is_email( $email ) ) {
			return $fail( __( 'Enter an email address the owner can reply to.', 'chaos-shield' ) );
		}
		if ( mb_strlen( $message ) < 10 ) {
			return $fail( __( 'Tell the owner a little more, in at least a sentence.', 'chaos-shield' ) );
		}
		$ref    = isset( $post['reference'] ) ? strtoupper( (string) $post['reference'] ) : '';
		$reason = isset( $post['reason'] ) ? sanitize_key( (string) $post['reason'] ) : '';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$ua     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$entry  = array(
			'id'      => bin2hex( random_bytes( 6 ) ),
			'time'    => time(),
			'ip'      => (string) $ip,
			'name'    => isset( $post['name'] ) ? mb_substr( sanitize_text_field( (string) $post['name'] ), 0, 80 ) : '',
			'email'   => mb_substr( $email, 0, 120 ),
			'message' => mb_substr( $message, 0, 1000 ),
			'ref'     => preg_match( '/^[A-Z0-9]{6,12}$/', $ref ) ? $ref : '',
			'reason'  => in_array( $reason, array( 'firewall', 'ban', 'blocklist', 'country', 'threat', 'rate', 'login', 'site', '404' ), true ) ? $reason : 'site',
			'page'    => mb_substr( (string) strtok( $uri, '?' ), 0, 200 ),
			'agent'   => mb_substr( $ua, 0, 200 ),
			'status'  => 'open',
		);
		Network::set_transient( $throttle, $sent + 1, HOUR_IN_SECONDS );
		Network::set_transient( $net_key, $net_sent + 1, HOUR_IN_SECONDS );
		$list = self::requests();
		array_unshift( $list, $entry );
		Network::update_option( self::REQUESTS, array_slice( $list, 0, 200 ), false );
		Events::add(
			'system',
			// Plain English: this can run before translations are loaded.
			sprintf( 'A visitor sent a help message (%1$s%2$s).', $entry['reason'], $entry['ref'] ? ', ref ' . $entry['ref'] : '' ),
			(string) $ip,
			array(
				'severity' => Events::NOTICE,
				'action'   => 'help.request',
				'subject'  => $entry['id'],
			)
		);
		// Mail can need functions that do not exist yet here, so it is sent from cron.
		Network::schedule_single( time() + 5, self::NOTIFY, array( $entry['id'] ) );
		return array(
			'ok'      => true,
			'message' => __( 'Thanks, your message was sent to the site owner. They will reply by email.', 'chaos-shield' ),
		);
	}

	/**
	 * Visitor messages, newest first.
	 *
	 * @return array
	 */
	public static function requests() {
		$list = Network::get_option( self::REQUESTS, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * Emails the owner about a new message.
	 *
	 * @param string $id Message ID.
	 */
	public static function notify( $id ) {
		foreach ( self::requests() as $r ) {
			if ( $r['id'] !== $id ) {
				continue;
			}
			$reasons = self::reason_names();
			Alerts::send(
				'alert_help',
				/* translators: %s: visitor email. */
				sprintf( __( 'A visitor asked for help: %s', 'chaos-shield' ), $r['email'] ),
				sprintf(
					/* translators: 1: name and email, 2: IP, 3: what happened, 4: reference, 5: message. */
					__( "From: %1\$s\nIP: %2\$s\nWhat happened: %3\$s\nReference: %4\$s\n\n%5\$s", 'chaos-shield' ),
					trim( $r['name'] . ' <' . $r['email'] . '>' ),
					$r['ip'],
					isset( $reasons[ $r['reason'] ] ) ? $reasons[ $r['reason'] ] : $r['reason'],
					$r['ref'] ? $r['ref'] : '-',
					$r['message']
				) . "\n\n" . __( 'Let them in or dismiss it:', 'chaos-shield' ) . "\n" . Network::admin_url( 'admin.php?page=' . Admin::SLUG . '&tab=help' ),
				'help-' . $r['id']
			);
			return;
		}
	}

	/**
	 * What happened to the visitor, in a word or two, for the inbox.
	 *
	 * @return array
	 */
	public static function reason_names() {
		return array(
			'firewall'  => __( 'Blocked by the firewall', 'chaos-shield' ),
			'ban'       => __( 'IP banned for a while', 'chaos-shield' ),
			'blocklist' => __( 'IP on your block list', 'chaos-shield' ),
			'country'   => __( 'Country not allowed', 'chaos-shield' ),
			'threat'    => __( 'IP on a threat list', 'chaos-shield' ),
			'rate'      => __( 'Too many requests', 'chaos-shield' ),
			'login'     => __( 'Login help', 'chaos-shield' ),
			'site'      => __( 'Question from the site', 'chaos-shield' ),
			'404'       => __( 'Missing page', 'chaos-shield' ),
		);
	}

	/**
	 * Lets a visitor in: lifts their ban and lockout, unblocks their exact IP and allows the blocked request.
	 *
	 * @param string $id     Message ID.
	 * @param bool   $always Also put the IP on the allow list.
	 * @return bool
	 */
	public static function allow( $id, $always = false ) {
		$list = self::requests();
		foreach ( $list as $i => $r ) {
			if ( $r['id'] !== $id ) {
				continue;
			}
			if ( $r['ip'] ) {
				Bans::release( $r['ip'] );
				Login_Guard::release( $r['ip'] );
				Settings::unblock_ip( $r['ip'], $always );
			}
			$list[ $i ]['status'] = 'allowed';
			Network::update_option( self::REQUESTS, $list, false );
			Events::add(
				'settings',
				/* translators: %s: IP address. */
				sprintf( $always ? __( 'Let %s in from a help message and added it to the allow list.', 'chaos-shield' ) : __( 'Let %s in from a help message.', 'chaos-shield' ), $r['ip'] ),
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => 'help.allowed',
					'subject'  => $r['ip'],
				)
			);
			return true;
		}
		return false;
	}

	/**
	 * Lets the request a message is about through the firewall from now on.
	 *
	 * Kept apart from Allow, so the owner sees which rule, field and page it
	 * switches off first. Only a block of the sender's own IP counts.
	 *
	 * @param string $id Message ID.
	 * @return bool Whether exceptions were added.
	 */
	public static function except( $id ) {
		foreach ( self::requests() as $r ) {
			if ( $r['id'] === $id ) {
				return '' !== $r['ref'] && Firewall::allow_reference( $r['ref'], $r['ip'] );
			}
		}
		return false;
	}

	/**
	 * Marks a message handled, or removes handled ones.
	 *
	 * @param string $id Message ID, or '' to remove every handled message.
	 */
	public static function dismiss( $id ) {
		$list = self::requests();
		foreach ( $list as $i => $r ) {
			if ( '' === $id && 'open' !== $r['status'] ) {
				unset( $list[ $i ] );
			} elseif ( $r['id'] === $id ) {
				$list[ $i ]['status'] = 'dismissed';
			}
		}
		Network::update_option( self::REQUESTS, array_values( $list ), false );
	}

	/**
	 * Drops messages older than 30 days, from the daily job.
	 */
	public static function prune() {
		$cut = time() - 30 * DAY_IN_SECONDS;
		Network::update_option(
			self::REQUESTS,
			array_values(
				array_filter(
					self::requests(),
					static function ( $r ) use ( $cut ) {
						return (int) $r['time'] >= $cut;
					}
				)
			),
			false
		);
	}

	// Output.

	/**
	 * Settings for the assistant script.
	 *
	 * @param string $context block, rate, login, site or 404.
	 * @param string $reason  Block reason.
	 * @param string $ref     Block reference.
	 * @return array
	 */
	public static function config( $context, $reason = '', $ref = '' ) {
		$items = self::builtin( $context, $reason );
		if ( in_array( $context, array( 'site', '404' ), true ) ) {
			$items = array_merge( self::faq(), $items );
		}
		$title    = (string) Settings::get( 'help_title' );
		$greeting = (string) Settings::get( 'help_greeting' );
		if ( 'login' === $context ) {
			$greeting = __( 'Trouble signing in? Pick a question or type your own.', 'chaos-shield' );
			$ip       = Request::ip();
			if ( $ip && Login_Guard::locked_until( $ip ) ) {
				$greeting = __( 'Sign-in is paused for your network after too many failed attempts. Ask me what to do.', 'chaos-shield' );
			}
		} elseif ( in_array( $context, array( 'block', 'rate' ), true ) ) {
			$greeting = __( 'I can explain what happened and what you can do. Pick a question or type your own.', 'chaos-shield' );
		} elseif ( '404' === $context ) {
			$greeting = __( 'That page could not be found. Can I help you find what you need?', 'chaos-shield' );
		}
		$color = sanitize_hex_color( (string) Settings::get( 'help_color' ) );
		return array(
			'context' => $context,
			'title'   => '' !== $title ? $title : __( 'Help', 'chaos-shield' ),
			'hello'   => '' !== $greeting ? $greeting : __( 'Hi! Ask a question or pick one below.', 'chaos-shield' ),
			'color'   => $color ? $color : '#2563eb',
			'items'   => $items,
			'links'   => array(
				'lost' => wp_lostpassword_url(),
				'home' => home_url( '/' ),
			),
			'contact' => Settings::enabled( 'help_contact' ) ? array(
				'token'  => self::token(),
				'ref'    => (string) $ref,
				'reason' => 'block' === $context ? $reason : $context,
			) : null,
			'i18n'    => array(
				'open'        => __( 'Open help', 'chaos-shield' ),
				'close'       => __( 'Close help', 'chaos-shield' ),
				'ask'         => __( 'Type a question', 'chaos-shield' ),
				'send'        => __( 'Ask', 'chaos-shield' ),
				'none'        => __( 'I do not have an answer for that. Try one of these, or send the site owner a message.', 'chaos-shield' ),
				'also'        => __( 'Related:', 'chaos-shield' ),
				'contact'     => __( 'Message the site owner', 'chaos-shield' ),
				'name'        => __( 'Your name (optional)', 'chaos-shield' ),
				'email'       => __( 'Your email, for the reply', 'chaos-shield' ),
				'message'     => __( 'What happened, and what were you trying to do?', 'chaos-shield' ),
				'submit'      => __( 'Send message', 'chaos-shield' ),
				'sending'     => __( 'Sending...', 'chaos-shield' ),
				'failed'      => __( 'The message could not be sent. Check your connection and try again.', 'chaos-shield' ),
				'refIncluded' => __( 'Your reference is included.', 'chaos-shield' ),
				'you'         => __( 'You', 'chaos-shield' ),
				'bot'         => __( 'Assistant', 'chaos-shield' ),
			),
		);
	}

	/**
	 * The assistant's script and styles, read once.
	 *
	 * @param string $file js or css.
	 * @return string
	 */
	public static function asset( $file ) {
		static $cache = array();
		if ( ! isset( $cache[ $file ] ) ) {
			$path           = CSHIELD_DIR . ( 'js' === $file ? 'assets/js/help.js' : 'assets/css/help.css' );
			$cache[ $file ] = is_readable( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- The plugin's own asset, inlined.
		}
		return $cache[ $file ];
	}

	/**
	 * The script tag that starts the assistant.
	 *
	 * @param array $config From config().
	 * @param bool  $inline Show the conversation in the page instead of a bubble.
	 * @return string
	 */
	private static function boot( array $config, $inline ) {
		$config['inline'] = $inline;
		return '<script>window.cshieldHelp=' . wp_json_encode( $config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ) . ';</script>'
			. '<script>' . self::asset( 'js' ) . '</script>';
	}

	/**
	 * Sends the block or rate-limit page and stops.
	 *
	 * Browsers get a page with the help assistant; everything else gets the short text it always got.
	 *
	 * @param int    $status 403 or 429.
	 * @param string $reason Reason key.
	 * @param string $ref    Block reference, or ''.
	 */
	public static function block_page( $status, $reason, $ref = '' ) {
		self::intercept();
		$plain = 429 === $status
			? '429 Too Many Requests. Please slow down and try again in a minute.'
			: '403 Forbidden. This request was blocked for security reasons.' . ( '' !== $ref ? "\nReference: " . $ref : '' );
		if ( ! headers_sent() ) {
			status_header( $status );
			nocache_headers();
			if ( 429 === $status ) {
				header( 'Retry-After: 60' );
			}
			header( 'X-Robots-Tag: noindex' );
		}
		if ( ! Settings::enabled( 'visitor_help' ) || ! self::wants_html() ) {
			if ( ! headers_sent() ) {
				header( 'Content-Type: text/plain; charset=utf-8' );
			}
			echo esc_html( $plain );
			exit;
		}
		self::prepare_strings();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		$r      = self::reason( 429 === $status ? 'rate' : $reason );
		$config = self::config( 429 === $status ? 'rate' : 'block', $reason, $ref );
		$site   = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$lang   = function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'language' ) : 'en';
		// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Every value below is escaped where it is built.
		echo '<!doctype html><html lang="' . esc_attr( $lang ) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">'
			. '<title>' . esc_html( $r['title'] ) . '</title><style>' . self::asset( 'css' ) . '</style></head>'
			. '<body class="ssh-page" style="--ssh-accent:' . esc_attr( $config['color'] ) . '"><main class="ssh-card">'
			. '<div class="ssh-badge" aria-hidden="true"><svg viewBox="0 0 24 24" width="28" height="28"><path fill="currentColor" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3Zm0 5a1.3 1.3 0 0 1 1.3 1.3v4.4a1.3 1.3 0 0 1-2.6 0V8.3A1.3 1.3 0 0 1 12 7Zm0 9.2a1.4 1.4 0 1 1 0 2.8 1.4 1.4 0 0 1 0-2.8Z"/></svg></div>'
			. '<p class="ssh-site">' . esc_html( $site ) . '</p>'
			. '<h1>' . esc_html( $r['title'] ) . '</h1><p class="ssh-lead">' . esc_html( $r['text'] ) . '</p><ul class="ssh-tips">';
		foreach ( $r['tips'] as $tip ) {
			echo '<li>' . esc_html( $tip ) . '</li>';
		}
		echo '</ul>';
		if ( '' !== $ref ) {
			echo '<p class="ssh-ref">' . esc_html__( 'Reference', 'chaos-shield' ) . ' <code>' . esc_html( $ref ) . '</code></p>';
		}
		echo '<div class="ssh-assistant" id="ssh-assistant"></div>'
			. '<noscript><p class="ssh-lead">' . esc_html__( 'Turn on JavaScript to use the help assistant, or contact the site owner and quote the reference above.', 'chaos-shield' ) . '</p></noscript>'
			. '<p class="ssh-foot">' . esc_html( 429 === $status ? '429' : '403' ) . ' · ' . esc_html__( 'Protected by Chaos Shield', 'chaos-shield' ) . '</p>'
			. '</main>' . self::boot( $config, true ) . '</body></html>';
		// phpcs:enable
		exit;
	}

	/**
	 * Prints the help bubble on the login page.
	 */
	public static function login_bubble() {
		self::bubble( 'login' );
	}

	/**
	 * Prints the help bubble on the site's pages.
	 */
	public static function site_bubble() {
		if ( is_admin() || is_feed() || is_embed() || ( function_exists( 'wp_is_json_request' ) && wp_is_json_request() ) ) {
			return;
		}
		self::bubble( is_404() ? '404' : 'site' );
	}

	/**
	 * Prints the bubble, its styles and its script.
	 *
	 * @param string $context login, site or 404.
	 */
	private static function bubble( $context ) {
		$config = self::config( $context );
		if ( ! $config['items'] ) {
			return;
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The plugin's own stylesheet and JSON-encoded settings.
		echo '<style id="cshield-help-css">' . self::asset( 'css' ) . '</style><div class="ssh-bubble-root" style="--ssh-accent:' . esc_attr( $config['color'] ) . '"></div>' . self::boot( $config, false );
	}

	// Admin.

	/**
	 * Saves the Visitor help tab and handles the inbox.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to change Chaos Shield settings.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( self::ACTION );
		$op     = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$id     = isset( $_POST['request'] ) ? sanitize_key( wp_unslash( $_POST['request'] ) ) : '';
		$notice = 'help_saved';
		if ( 'save' === $op ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each field is sanitized in save_help() and save_faq().
			$input = isset( $_POST['cshield'] ) && is_array( $_POST['cshield'] ) ? wp_unslash( $_POST['cshield'] ) : array();
			Settings::save_help( $input );
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized in save_faq().
			$rows = isset( $_POST['faq'] ) && is_array( $_POST['faq'] ) ? wp_unslash( $_POST['faq'] ) : array();
			self::save_faq( array_values( array_filter( $rows, 'is_array' ) ) );
			Events::add( 'settings', __( 'Visitor help settings updated.', 'chaos-shield' ), Request::ip(), array( 'action' => 'settings.help' ) );
		} elseif ( 'allow' === $op || 'always' === $op ) {
			self::allow( $id, 'always' === $op );
			$notice = 'help_allowed';
		} elseif ( 'except' === $op ) {
			$notice = self::except( $id ) ? 'fw_allowed' : 'help_saved';
		} elseif ( 'dismiss' === $op ) {
			self::dismiss( $id );
			$notice = 'help_dismissed';
		} elseif ( 'clear' === $op ) {
			self::dismiss( '' );
			$notice = 'help_dismissed';
		} elseif ( 'preview' === $op ) {
			$reason = isset( $_POST['reason'] ) ? sanitize_key( wp_unslash( $_POST['reason'] ) ) : 'firewall';
			self::block_page( 'rate' === $reason ? 429 : 403, $reason, 'rate' === $reason ? '' : 'PREVIEW1' );
		}
		wp_safe_redirect( Admin::url( 'help', array( 'cshield_notice' => $notice ) ) );
		exit;
	}
}
