<?php
/**
 * Outside services: CAPTCHA keys and team chat webhooks, connected without leaving WordPress.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Describes each outside service, checks what the user pastes, stores it, and posts chat alerts.
 *
 * The provider's own sign-up page opens in a small window beside the dashboard,
 * because their pages refuse to load inside an iframe. Everything else, including
 * the check that the keys work, happens in a dialog on the plugin page.
 */
final class Connections {

	const AJAX        = 'cshield_connect';
	const CHAT_URL    = 'cshield_chat_webhook';
	const CHAT_STATUS = 'cshield_chat_status';
	const CHECKED     = 'cshield_connections_checked';

	/**
	 * Every service, with where to sign up and the steps to follow there.
	 *
	 * @return array Key => details.
	 */
	public static function services() {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		return array(
			'turnstile'  => array(
				'kind'   => 'captcha',
				'name'   => 'Cloudflare Turnstile',
				'blurb'  => __( 'Free and private: most visitors never see a puzzle.', 'chaos-shield' ),
				'open'   => 'https://dash.cloudflare.com/?to=/:account/turnstile', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A link the admin opens to sign up, not an asset.
				'button' => __( 'Open Cloudflare', 'chaos-shield' ),
				'steps'  => array(
					__( 'Sign in, or create a free Cloudflare account. Your site does not need to use Cloudflare.', 'chaos-shield' ),
					/* translators: %s: this site's host name. */
					sprintf( __( 'Choose Add widget, name it after this site and add the hostname %s. Leave the mode on Managed.', 'chaos-shield' ), $host ),
					__( 'Copy the Site Key and the Secret Key into the boxes here.', 'chaos-shield' ),
				),
				'fields' => array(
					'site_key' => __( 'Site key', 'chaos-shield' ),
					'secret'   => __( 'Secret key', 'chaos-shield' ),
				),
			),
			'hcaptcha'   => array(
				'kind'   => 'captcha',
				'name'   => 'hCaptcha',
				'blurb'  => __( 'Free, and an option where Cloudflare is not wanted.', 'chaos-shield' ),
				'open'   => 'https://dashboard.hcaptcha.com/sites',
				'button' => __( 'Open hCaptcha', 'chaos-shield' ),
				'steps'  => array(
					__( 'Sign in, or sign up for the free plan.', 'chaos-shield' ),
					/* translators: %s: this site's host name. */
					sprintf( __( 'Under Sites, choose New site, add the hostname %s and copy its Sitekey.', 'chaos-shield' ), $host ),
					__( 'Open your account settings, copy the Secret under Secrets, and paste both here.', 'chaos-shield' ),
				),
				'fields' => array(
					'site_key' => __( 'Sitekey', 'chaos-shield' ),
					'secret'   => __( 'Secret', 'chaos-shield' ),
				),
			),
			'cloudflare' => array(
				'kind'   => 'edge',
				'name'   => 'Cloudflare',
				'blurb'  => __( 'Free plan: stops floods and banned IPs before they reach your server.', 'chaos-shield' ),
				'open'   => 'https://dash.cloudflare.com/profile/api-tokens', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A link the admin opens to make a token, not an asset.
				'button' => __( 'Open Cloudflare', 'chaos-shield' ),
				'steps'  => array(
					/* translators: %s: this site's host name. */
					sprintf( __( 'Sign in. If %s is not on Cloudflare yet, add it first under Add a domain (the free plan is enough) and follow the steps to point the domain at Cloudflare.', 'chaos-shield' ), $host ),
					__( 'Choose Create Token, then Create Custom Token. Name it Chaos Shield.', 'chaos-shield' ),
					__( 'Add these permissions, all under Zone: Zone, Read; Zone Settings, Edit; Firewall Services, Edit; Cache Purge, Purge.', 'chaos-shield' ),
					__( 'Under Zone Resources, include this site\'s zone. Create the token, copy it and paste it here.', 'chaos-shield' ),
				),
				'fields' => array( 'token' => __( 'API token', 'chaos-shield' ) ),
			),
			'slack'      => array(
				'kind'    => 'chat',
				'name'    => 'Slack',
				'blurb'   => __( 'Alerts in a Slack channel.', 'chaos-shield' ),
				'open'    => 'https://api.slack.com/apps?new_app=1',
				'button'  => __( 'Open Slack', 'chaos-shield' ),
				'steps'   => array(
					__( 'Choose From scratch, name the app Chaos Shield and pick your workspace.', 'chaos-shield' ),
					__( 'Open Incoming Webhooks, switch it on, then choose Add New Webhook and pick the channel.', 'chaos-shield' ),
					__( 'Copy the webhook URL and paste it here.', 'chaos-shield' ),
				),
				'fields'  => array( 'url' => __( 'Webhook URL', 'chaos-shield' ) ),
				'pattern' => '#^https://hooks\.slack\.com/(services|triggers|workflows)/[A-Za-z0-9/_-]+$#',
				'example' => 'https://hooks.slack.com/services/...',
			),
			'discord'    => array(
				'kind'    => 'chat',
				'name'    => 'Discord',
				'blurb'   => __( 'Alerts in a Discord channel.', 'chaos-shield' ),
				'open'    => 'https://discord.com/channels/@me',
				'button'  => __( 'Open Discord', 'chaos-shield' ),
				'steps'   => array(
					__( 'Open your server, then the settings of the channel the alerts should go to.', 'chaos-shield' ),
					__( 'Under Integrations, choose Webhooks, then New Webhook, and name it Chaos Shield.', 'chaos-shield' ),
					__( 'Choose Copy Webhook URL and paste it here.', 'chaos-shield' ),
				),
				'fields'  => array( 'url' => __( 'Webhook URL', 'chaos-shield' ) ),
				'pattern' => '#^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+$#',
				'example' => 'https://discord.com/api/webhooks/...',
			),
			'teams'      => array(
				'kind'    => 'chat',
				'name'    => 'Microsoft Teams',
				'blurb'   => __( 'Alerts in a Teams channel, through Workflows.', 'chaos-shield' ),
				'open'    => 'https://teams.microsoft.com/v2/',
				'button'  => __( 'Open Teams', 'chaos-shield' ),
				'steps'   => array(
					__( 'Open the channel, choose the three dots next to its name, then Workflows.', 'chaos-shield' ),
					__( 'Pick "Post to a channel when a webhook request is received" and follow its steps.', 'chaos-shield' ),
					__( 'Copy the URL it shows at the end and paste it here.', 'chaos-shield' ),
				),
				'fields'  => array( 'url' => __( 'Workflow URL', 'chaos-shield' ) ),
				'pattern' => '#^https://[A-Za-z0-9.-]+\.(?:logic\.azure\.com|powerplatform\.com|powerautomate\.com|webhook\.office\.com)(?::443)?/\S+$#',
				'example' => 'https://...logic.azure.com/workflows/...',
			),
			'gchat'      => array(
				'kind'    => 'chat',
				'name'    => 'Google Chat',
				'blurb'   => __( 'Alerts in a Google Chat space (Google Workspace).', 'chaos-shield' ),
				'open'    => 'https://chat.google.com/',
				'button'  => __( 'Open Google Chat', 'chaos-shield' ),
				'steps'   => array(
					__( 'Open the space, choose its name at the top, then Apps and integrations.', 'chaos-shield' ),
					__( 'Choose Add webhooks, name it Chaos Shield and save.', 'chaos-shield' ),
					__( 'Copy the webhook URL and paste it here.', 'chaos-shield' ),
				),
				'fields'  => array( 'url' => __( 'Webhook URL', 'chaos-shield' ) ),
				'pattern' => '#^https://chat\.googleapis\.com/v1/spaces/[A-Za-z0-9_-]+/messages\?\S+$#',
				'example' => 'https://chat.googleapis.com/v1/spaces/...',
			),
		);
	}

	/**
	 * Services of one kind.
	 *
	 * @param string $kind captcha, chat or edge.
	 * @return array
	 */
	public static function of( $kind ) {
		return array_filter(
			self::services(),
			static function ( $s ) use ( $kind ) {
				return $kind === $s['kind'];
			}
		);
	}

	/**
	 * The connected chat service, or ''.
	 *
	 * @return string
	 */
	public static function chat() {
		$service = (string) Settings::get( 'chat_service' );
		return isset( self::of( 'chat' )[ $service ] ) && self::chat_url() ? $service : '';
	}

	/**
	 * The chat webhook address, or ''.
	 *
	 * @return string
	 */
	private static function chat_url() {
		$sealed = Network::get_option( self::CHAT_URL );
		return $sealed ? (string) Totp::open( $sealed ) : '';
	}

	/**
	 * The chat webhook with its secret part hidden, for display.
	 *
	 * @return string
	 */
	public static function chat_hint() {
		$url = self::chat_url();
		if ( '' === $url ) {
			return '';
		}
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		return $host . '/…' . substr( preg_replace( '/[^A-Za-z0-9]/', '', $url ), -4 );
	}

	/**
	 * When each connection was last checked.
	 *
	 * @param string $service Service key.
	 * @return int Unix time, or 0.
	 */
	public static function checked( $service ) {
		$all = (array) Network::get_option( self::CHECKED, array() );
		return isset( $all[ $service ] ) ? (int) $all[ $service ] : 0;
	}

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'wp_ajax_' . self::AJAX, array( $this, 'ajax' ) );
	}

	/**
	 * Tests, saves, tests again or removes a connection from the dashboard dialog.
	 */
	public function ajax() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to change this.', 'chaos-shield' ) ), 403 );
		}
		check_ajax_referer( self::AJAX );
		$service  = isset( $_POST['service'] ) ? sanitize_key( wp_unslash( $_POST['service'] ) ) : '';
		$op       = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : 'save';
		$services = self::services();
		if ( ! isset( $services[ $service ] ) ) {
			wp_send_json_error( array( 'message' => __( 'Unknown service.', 'chaos-shield' ) ), 400 );
		}
		$values = array();
		foreach ( array( 'site_key', 'secret', 'url', 'token' ) as $field ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each value is trimmed and checked against the service's own format.
			$values[ $field ] = isset( $_POST[ $field ] ) ? trim( (string) wp_unslash( $_POST[ $field ] ) ) : '';
		}
		if ( 'disconnect' === $op ) {
			self::disconnect( $service );
			wp_send_json_success( array( 'message' => __( 'Disconnected.', 'chaos-shield' ) ) );
		}
		if ( 'test' === $op ) {
			$result = 'chat' === $services[ $service ]['kind'] && self::chat() === $service ? self::send_chat( self::test_title(), self::test_body() ) : new \WP_Error( 'cshield_connect', __( 'Nothing to test yet.', 'chaos-shield' ) );
			if ( is_wp_error( $result ) ) {
				wp_send_json_error( array( 'message' => $result->get_error_message() ) );
			}
			wp_send_json_success( array( 'message' => __( 'Test message sent. Check the channel.', 'chaos-shield' ) ) );
		}
		$result = self::connect( $service, $values, ! empty( $_POST['force'] ) );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message'     => $result->get_error_message(),
					'unreachable' => 'cshield_unreachable' === $result->get_error_code(),
				)
			);
		}
		wp_send_json_success( array( 'message' => $result ) );
	}

	/**
	 * Checks and stores a connection.
	 *
	 * @param string $service Service key.
	 * @param array  $values  site_key, secret, url, token.
	 * @param bool   $force   Save even when the service could not be reached to check.
	 * @return string|\WP_Error Message to show, or why it was refused.
	 */
	public static function connect( $service, array $values, $force = false ) {
		$services = self::services();
		$s        = $services[ $service ];
		if ( 'edge' === $s['kind'] ) {
			$message = Cloudflare::connect( $values['token'], $force );
		} else {
			$message = 'captcha' === $s['kind'] ? self::connect_captcha( $service, $values, $force ) : self::connect_chat( $service, $values, $force );
		}
		if ( is_wp_error( $message ) ) {
			return $message;
		}
		$checked             = (array) Network::get_option( self::CHECKED, array() );
		$checked[ $service ] = time();
		Network::update_option( self::CHECKED, $checked, false );
		Events::add(
			'settings',
			/* translators: %s: service name, such as Slack. */
			sprintf( __( 'Connected %s.', 'chaos-shield' ), $s['name'] ),
			Request::ip(),
			array( 'action' => 'settings.connect' )
		);
		return $message;
	}

	/**
	 * Checks CAPTCHA keys with the provider, then saves them and switches the login CAPTCHA on.
	 *
	 * @param string $service turnstile or hcaptcha.
	 * @param array  $values  site_key, secret and an optional token from the preview.
	 * @param bool   $force   Save without a check when the provider is unreachable.
	 * @return string|\WP_Error
	 */
	private static function connect_captcha( $service, array $values, $force ) {
		$d    = Captcha::details( $service );
		$name = $d['name'];
		if ( ! preg_match( $d['key_test'], $values['site_key'] ) ) {
			/* translators: %s: service name. */
			return new \WP_Error( 'cshield_connect', sprintf( __( 'That does not look like a %s site key. Copy it again from the window.', 'chaos-shield' ), $name ) );
		}
		$secret = '' !== $values['secret'] ? $values['secret'] : ( Captcha::provider() === $service ? (string) Totp::open( Network::get_option( $d['secret'] ) ) : '' );
		if ( '' === $secret || strlen( $secret ) < 20 || preg_match( '/\s/', $secret ) ) {
			return new \WP_Error( 'cshield_connect', __( 'Paste the secret key too.', 'chaos-shield' ) );
		}
		$check = Captcha::siteverify( $service, $values['site_key'], $secret, $values['token'] );
		if ( is_wp_error( $check ) && ! $force ) {
			/* translators: 1: service name, 2: error. */
			return new \WP_Error( 'cshield_unreachable', sprintf( __( '%1$s could not be reached to check the keys (%2$s). You can save them anyway and test the login page yourself.', 'chaos-shield' ), $name, $check->get_error_message() ) );
		}
		$full = false;
		if ( ! is_wp_error( $check ) ) {
			$codes = $check['codes'];
			if ( array_intersect( $codes, array( 'invalid-input-secret', 'missing-input-secret', 'invalid-or-already-seen-response-secret' ) ) ) {
				/* translators: %s: service name. */
				return new \WP_Error( 'cshield_connect', sprintf( __( '%s says the secret key is wrong. Copy it again.', 'chaos-shield' ), $name ) );
			}
			if ( array_intersect( $codes, array( 'sitekey-secret-mismatch', 'invalid-sitekey' ) ) ) {
				return new \WP_Error( 'cshield_connect', __( 'The site key and secret key do not belong together. Copy both from the same place.', 'chaos-shield' ) );
			}
			if ( '' !== $values['token'] && ! $check['success'] ) {
				return new \WP_Error( 'cshield_connect', __( 'The keys were accepted, but the test challenge did not pass. Make sure both keys come from the same widget, then try again.', 'chaos-shield' ) );
			}
			$full = '' !== $values['token'] && $check['success'];
		}
		Captcha::save_secret( $secret, $service );
		Settings::save_connection(
			array(
				'captcha'          => true,
				'captcha_provider' => $service,
				$d['key']          => $values['site_key'],
			)
		);
		$done = $full
			/* translators: %s: service name. */
			? __( 'Connected. %s checked both keys and the test challenge, and the login CAPTCHA is on.', 'chaos-shield' )
			/* translators: %s: service name. */
			: __( 'Connected. %s accepted the secret key, and the login CAPTCHA is on. Try logging in from a private window to see it.', 'chaos-shield' );
		return sprintf( $done, $name );
	}

	/**
	 * Checks a chat webhook by sending a message, then saves it.
	 *
	 * @param string $service Chat service.
	 * @param array  $values  url.
	 * @param bool   $force   Save even if the test message could not be sent.
	 * @return string|\WP_Error
	 */
	private static function connect_chat( $service, array $values, $force ) {
		$s   = self::services()[ $service ];
		$url = esc_url_raw( $values['url'], array( 'https' ) );
		if ( '' === $url || ! preg_match( $s['pattern'], $url ) ) {
			/* translators: 1: service name, 2: example address. */
			return new \WP_Error( 'cshield_connect', sprintf( __( 'That is not a %1$s webhook address. It starts like %2$s', 'chaos-shield' ), $s['name'], $s['example'] ) );
		}
		$sent = self::post( $service, $url, self::test_title(), self::test_body() );
		if ( is_wp_error( $sent ) && ! $force ) {
			$unreachable = 'cshield_chat_http' !== $sent->get_error_code();
			return new \WP_Error(
				$unreachable ? 'cshield_unreachable' : 'cshield_connect',
				/* translators: 1: service name, 2: error. */
				sprintf( __( '%1$s did not take the test message: %2$s', 'chaos-shield' ), $s['name'], $sent->get_error_message() )
			);
		}
		Network::update_option( self::CHAT_URL, Totp::seal( $url ), false );
		Network::delete_option( self::CHAT_STATUS );
		Settings::save_connection( array( 'chat_service' => $service ) );
		/* translators: %s: service name. */
		return sprintf( __( 'Connected. A test message is in your %s channel, and alerts will arrive there as well as by email.', 'chaos-shield' ), $s['name'] );
	}

	/**
	 * Removes a connection.
	 *
	 * @param string $service Service key.
	 */
	public static function disconnect( $service ) {
		$services = self::services();
		if ( 'edge' === $services[ $service ]['kind'] ) {
			Cloudflare::disconnect();
		} elseif ( 'captcha' === $services[ $service ]['kind'] ) {
			$d = Captcha::details( $service );
			Network::delete_option( $d['secret'] );
			$changes = array( $d['key'] => '' );
			if ( Captcha::provider() === $service ) {
				$changes['captcha'] = false;
			}
			Settings::save_connection( $changes );
		} elseif ( self::chat() === $service || (string) Settings::get( 'chat_service' ) === $service ) {
			Network::delete_option( self::CHAT_URL );
			Network::delete_option( self::CHAT_STATUS );
			Settings::save_connection( array( 'chat_service' => '' ) );
		}
		$checked = (array) Network::get_option( self::CHECKED, array() );
		unset( $checked[ $service ] );
		Network::update_option( self::CHECKED, $checked, false );
		Events::add(
			'settings',
			/* translators: %s: service name, such as Slack. */
			sprintf( __( 'Disconnected %s.', 'chaos-shield' ), $services[ $service ]['name'] ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'settings.disconnect',
			)
		);
	}

	/**
	 * Test message title.
	 *
	 * @return string
	 */
	private static function test_title() {
		return __( 'Chaos Shield is connected', 'chaos-shield' );
	}

	/**
	 * Test message body.
	 *
	 * @return string
	 */
	private static function test_body() {
		/* translators: %s: site address. */
		return sprintf( __( 'Security alerts from %s will appear here.', 'chaos-shield' ), home_url() );
	}

	/**
	 * Sends an alert to the connected chat, if any.
	 *
	 * @param string $title    Short title.
	 * @param string $body     Plain text.
	 * @return true|\WP_Error
	 */
	public static function send_chat( $title, $body ) {
		$service = self::chat();
		if ( '' === $service ) {
			return new \WP_Error( 'cshield_chat_none', __( 'No chat is connected.', 'chaos-shield' ) );
		}
		$sent = self::post( $service, self::chat_url(), $title, $body );
		Network::update_option(
			self::CHAT_STATUS,
			array(
				'time'  => time(),
				'ok'    => true === $sent,
				'error' => is_wp_error( $sent ) ? $sent->get_error_message() : '',
			),
			false
		);
		return $sent;
	}

	/**
	 * Result of the last chat delivery.
	 *
	 * @return array|null time, ok, error.
	 */
	public static function chat_status() {
		$status = Network::get_option( self::CHAT_STATUS );
		return is_array( $status ) ? $status : null;
	}

	/**
	 * Posts one message to a chat webhook.
	 *
	 * @param string $service Chat service.
	 * @param string $url     Webhook address.
	 * @param string $title   Short title.
	 * @param string $body    Plain text.
	 * @return true|\WP_Error
	 */
	private static function post( $service, $url, $title, $body ) {
		$response = wp_safe_remote_post(
			$url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'headers'     => array( 'Content-Type' => 'application/json; charset=utf-8' ),
				'body'        => wp_json_encode( self::message( $service, $title, $body ) ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code > 299 ) {
			/* translators: %d: HTTP status code. */
			return new \WP_Error( 'cshield_chat_http', sprintf( __( 'it answered HTTP %d. Check the address, or make a new webhook.', 'chaos-shield' ), $code ) );
		}
		return true;
	}

	/**
	 * A message in the format each service expects.
	 *
	 * Text from the log can hold attacker input such as a user name, so it is
	 * escaped and mentions are switched off: an alert can never ping a whole
	 * channel or turn into a link the attacker chose.
	 *
	 * @param string $service Chat service.
	 * @param string $title   Short title.
	 * @param string $body    Plain text.
	 * @return array
	 */
	public static function message( $service, $title, $body ) {
		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$link  = Network::admin_url( 'admin.php?page=' . Admin::SLUG );
		$title = $site . ': ' . $title;
		$body  = mb_substr( trim( (string) $body ), 0, 1500 );
		switch ( $service ) {
			case 'discord':
				$clean = static function ( $text ) {
					return str_replace( array( '@', '<', '>', '[', ']' ), array( "@\u{200B}", '‹', '›', '(', ')' ), $text );
				};
				return array(
					'username'         => 'Chaos Shield',
					'content'          => mb_substr( '**' . $clean( $title ) . "**\n" . $clean( $body ) . "\n" . $link, 0, 1990 ),
					'allowed_mentions' => array( 'parse' => array() ),
				);
			case 'teams':
				return array(
					'type'        => 'message',
					'attachments' => array(
						array(
							'contentType' => 'application/vnd.microsoft.card.adaptive',
							'content'     => array(
								'$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
								'type'    => 'AdaptiveCard',
								'version' => '1.4',
								'body'    => array(
									array(
										'type'   => 'TextBlock',
										'text'   => self::plain( $title ),
										'weight' => 'Bolder',
										'wrap'   => true,
									),
									array(
										'type' => 'TextBlock',
										'text' => self::plain( $body ),
										'wrap' => true,
									),
								),
								'actions' => array(
									array(
										'type'  => 'Action.OpenUrl',
										'title' => __( 'Open Chaos Shield', 'chaos-shield' ),
										'url'   => $link,
									),
								),
							),
						),
					),
				);
			case 'gchat':
				return array( 'text' => '*' . self::plain( $title ) . "*\n" . self::plain( $body ) . "\n" . $link );
			default:
				$escape = static function ( $text ) {
					return str_replace( array( '&', '<', '>' ), array( '&amp;', '&lt;', '&gt;' ), $text );
				};
				return array(
					'text'         => '*' . $escape( $title ) . "*\n" . $escape( $body ) . "\n<" . $link . '|' . $escape( __( 'Open Chaos Shield', 'chaos-shield' ) ) . '>',
					'unfurl_links' => false,
				);
		}
	}

	/**
	 * Text with markup and mention characters made harmless.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private static function plain( $text ) {
		return str_replace( array( '<', '>', '*', '_', '[', ']', '`' ), array( '‹', '›', '∗', '＿', '(', ')', "'" ), (string) $text );
	}
}
