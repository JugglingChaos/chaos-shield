<?php
/**
 * Sends activity log events to a webhook or syslog, for a SIEM or chat channel.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Forwards events as they are logged.
 *
 * Local and UDP syslog are written at once because they never wait. Webhook
 * and TCP syslog deliveries are queued and sent in batches by cron, so a slow
 * or dead receiver never slows a page load.
 */
final class Forwarder {

	const QUEUE  = 'cshield_forward_queue';
	const STATUS = 'cshield_forward_status';
	const HOOK   = 'cshield_forward';
	const MAX    = 1000;
	const BATCH  = 200;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'flush' ) );
		if ( self::webhook() || self::syslog_target() ) {
			add_action( 'cshield_event', array( __CLASS__, 'forward' ) );
		}
	}

	/**
	 * Webhook address, or ''.
	 *
	 * @return string
	 */
	public static function webhook() {
		return (string) Settings::get( 'forward_webhook' );
	}

	/**
	 * Syslog target: '', 'local', or udp:// / tcp:// host:port.
	 *
	 * @return string
	 */
	public static function syslog_target() {
		return (string) Settings::get( 'forward_syslog' );
	}

	/**
	 * Checks a syslog target typed by an admin.
	 *
	 * @param string $target Target.
	 * @return string|false Clean target, '' for off, or false when invalid.
	 */
	public static function clean_syslog( $target ) {
		$target = strtolower( trim( (string) $target ) );
		if ( '' === $target || 'local' === $target ) {
			return $target;
		}
		if ( ! preg_match( '#^(udp|tcp)://([a-z0-9.\-]+|\[[0-9a-f:]+\]):(\d{1,5})$#', $target, $m ) || (int) $m[3] < 1 || (int) $m[3] > 65535 ) {
			return false;
		}
		return $target;
	}

	/**
	 * Handles a new event.
	 *
	 * @param array $event Event row.
	 */
	public static function forward( array $event ) {
		if ( (int) $event['severity'] < (int) Settings::get( 'forward_min_severity' ) ) {
			return;
		}
		$target = self::syslog_target();
		if ( 'local' === $target ) {
			self::syslog_local( $event );
		} elseif ( 0 === strpos( $target, 'udp://' ) ) {
			self::send_socket( $target, self::syslog_line( $event ) );
		}
		if ( self::webhook() || 0 === strpos( $target, 'tcp://' ) ) {
			self::enqueue( $event );
		}
	}

	/**
	 * Adds an event to the delivery queue and makes sure a delivery is scheduled.
	 *
	 * @param array $event Event.
	 */
	private static function enqueue( array $event ) {
		$queue   = (array) Network::get_option( self::QUEUE, array() );
		$queue[] = $event;
		if ( count( $queue ) > self::MAX ) {
			$queue = array_slice( $queue, -self::MAX );
		}
		Network::update_option( self::QUEUE, $queue, false );
		if ( ! Network::next_scheduled( self::HOOK ) ) {
			Network::schedule_single( time() + 30, self::HOOK );
		}
	}

	/**
	 * Sends the queued events. Runs from cron.
	 */
	public static function flush() {
		$queue = (array) Network::get_option( self::QUEUE, array() );
		if ( ! $queue ) {
			return;
		}
		$batch  = array_slice( $queue, 0, self::BATCH );
		$result = self::deliver( $batch );
		if ( true === $result ) {
			// Re-read: events may have arrived while sending.
			$queue = array_slice( (array) Network::get_option( self::QUEUE, array() ), count( $batch ) );
			Network::update_option( self::QUEUE, $queue, false );
			self::status( true, '' );
			if ( $queue ) {
				Network::schedule_single( time() + 30, self::HOOK );
			}
			return;
		}
		self::status( false, $result );
		// Retry later; the queue is capped, so a dead receiver cannot grow it forever.
		Network::schedule_single( time() + 5 * MINUTE_IN_SECONDS, self::HOOK );
	}

	/**
	 * Delivers a batch to the webhook and TCP syslog.
	 *
	 * @param array $events Events.
	 * @return true|string True, or the error.
	 */
	public static function deliver( array $events ) {
		$url = self::webhook();
		if ( $url ) {
			$data = self::payload( $events );
			if ( preg_match( '#^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/#', $url ) ) {
				// Discord reads content, not text, and must not ping anyone.
				$data['content']          = mb_substr( str_replace( '@', "@\u{200B}", $data['text'] ), 0, 1990 );
				$data['allowed_mentions'] = array( 'parse' => array() );
				unset( $data['events'] );
			}
			$body   = wp_json_encode( $data );
			$args   = array(
				'timeout'    => 8,
				'headers'    => array( 'Content-Type' => 'application/json' ),
				'body'       => $body,
				'user-agent' => 'ChaosShield/' . CSHIELD_VERSION . '; ' . home_url( '/' ),
			);
			$secret = (string) Settings::get( 'forward_secret' );
			if ( '' !== $secret ) {
				$args['headers']['X-Chaos-Signature'] = 'sha256=' . hash_hmac( 'sha256', $body, $secret );
			}
			$response = wp_remote_post( $url, $args );
			if ( is_wp_error( $response ) ) {
				return $response->get_error_message();
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( $code < 200 || $code >= 300 ) {
				/* translators: %d: HTTP status code. */
				return sprintf( __( 'The webhook answered HTTP %d.', 'chaos-shield' ), $code );
			}
		}
		$target = self::syslog_target();
		if ( 0 === strpos( $target, 'tcp://' ) ) {
			$lines = '';
			foreach ( $events as $event ) {
				$line   = self::syslog_line( $event );
				$lines .= strlen( $line ) . ' ' . $line; // RFC 6587 octet counting.
			}
			$sent = self::send_socket( $target, $lines );
			if ( true !== $sent ) {
				return $sent;
			}
		}
		return true;
	}

	/**
	 * Webhook body. The text field makes Slack, Mattermost and Discord-style hooks show a readable message.
	 *
	 * @param array $events Events.
	 * @return array
	 */
	public static function payload( array $events ) {
		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$items = array();
		$lines = array();
		foreach ( $events as $event ) {
			$user    = (int) $event['user_id'] ? get_userdata( (int) $event['user_id'] ) : false;
			$items[] = array(
				'time'     => gmdate( 'c', (int) $event['created'] ),
				'type'     => (string) $event['type'],
				'severity' => self::severity_name( (int) $event['severity'] ),
				'user'     => $user ? $user->user_login : '',
				'ip'       => (string) $event['ip'],
				'message'  => (string) $event['message'],
			);
			$lines[] = '[' . self::severity_name( (int) $event['severity'] ) . '] ' . $event['message'] . ( $event['ip'] ? ' (' . $event['ip'] . ')' : '' );
		}
		return array(
			'text'    => $site . ': ' . implode( "\n", array_slice( $lines, 0, 20 ) ) . ( count( $lines ) > 20 ? "\n…" : '' ),
			'site'    => home_url( '/' ),
			'source'  => 'chaos-shield',
			'version' => CSHIELD_VERSION,
			'events'  => $items,
		);
	}

	/**
	 * Severity as a word.
	 *
	 * @param int $severity Severity.
	 * @return string
	 */
	public static function severity_name( $severity ) {
		if ( Events::CRITICAL <= $severity ) {
			return 'critical';
		}
		return Events::NOTICE <= $severity ? 'notice' : 'info';
	}

	/**
	 * RFC 5424 syslog line.
	 *
	 * @param array $event Event.
	 * @return string
	 */
	public static function syslog_line( array $event ) {
		$levels = array(
			Events::INFO     => 6,
			Events::NOTICE   => 5,
			Events::CRITICAL => 2,
		);
		$level  = isset( $levels[ (int) $event['severity'] ] ) ? $levels[ (int) $event['severity'] ] : 6;
		$pri    = 10 * 8 + $level; // Facility 10: security/authorization.
		$host   = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$user   = (int) $event['user_id'] ? get_userdata( (int) $event['user_id'] ) : false;
		$sd     = sprintf(
			'[cshield@32473 type="%s" ip="%s" user="%s"]',
			self::sd_escape( (string) $event['type'] ),
			self::sd_escape( (string) $event['ip'] ),
			self::sd_escape( $user ? $user->user_login : '' )
		);
		return sprintf( '<%d>1 %s %s chaos-shield - %s %s %s', $pri, gmdate( 'Y-m-d\TH:i:s\Z', (int) $event['created'] ), $host ? $host : '-', self::sd_escape( (string) $event['type'] ), $sd, str_replace( array( "\r", "\n" ), ' ', (string) $event['message'] ) );
	}

	/**
	 * Escapes a structured data value.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function sd_escape( $value ) {
		return str_replace( array( '\\', '"', ']' ), array( '\\\\', '\\"', '\\]' ), $value );
	}

	/**
	 * Writes to the server's own syslog.
	 *
	 * @param array $event Event.
	 */
	private static function syslog_local( array $event ) {
		if ( ! function_exists( 'openlog' ) ) {
			return;
		}
		$levels = array(
			Events::INFO     => LOG_INFO,
			Events::NOTICE   => LOG_NOTICE,
			Events::CRITICAL => LOG_CRIT,
		);
		$level  = isset( $levels[ (int) $event['severity'] ] ) ? $levels[ (int) $event['severity'] ] : LOG_INFO;
		openlog( 'chaos-shield', LOG_NDELAY, defined( 'LOG_AUTHPRIV' ) ? LOG_AUTHPRIV : LOG_AUTH ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions -- Log forwarding the admin turned on.
		syslog( $level, '[' . $event['type'] . '] ' . $event['message'] . ( $event['ip'] ? ' ip=' . $event['ip'] : '' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions -- Log forwarding the admin turned on.
		closelog();
	}

	/**
	 * Sends bytes to a UDP or TCP syslog receiver.
	 *
	 * @param string $target udp:// or tcp:// host:port.
	 * @param string $data   Bytes.
	 * @return true|string
	 */
	private static function send_socket( $target, $data ) {
		$errno  = 0;
		$errstr = '';
		$socket = @stream_socket_client( $target, $errno, $errstr, 3 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Failure is reported in the status.
		if ( ! $socket ) {
			/* translators: %s: error message. */
			return sprintf( __( 'Could not reach the syslog server: %s', 'chaos-shield' ), $errstr ? $errstr : (string) $errno );
		}
		stream_set_timeout( $socket, 3 );
		$written = fwrite( $socket, $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Network socket.
		fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Network socket.
		return false === $written ? __( 'Could not write to the syslog server.', 'chaos-shield' ) : true;
	}

	/**
	 * Records the last delivery result.
	 *
	 * @param bool   $ok    Success.
	 * @param string $error Error.
	 */
	private static function status( $ok, $error ) {
		Network::update_option(
			self::STATUS,
			array(
				'time'  => time(),
				'ok'    => (bool) $ok,
				'error' => (string) $error,
			),
			false
		);
	}

	/**
	 * Last delivery result.
	 *
	 * @return array time, ok, error; empty when nothing was sent yet.
	 */
	public static function last_status() {
		$status = Network::get_option( self::STATUS );
		return is_array( $status ) ? $status : array();
	}

	/**
	 * Sends a test event straight away.
	 *
	 * @return true|string
	 */
	public static function test() {
		$event  = array(
			'created'  => time(),
			'type'     => 'system',
			'severity' => Events::NOTICE,
			'user_id'  => get_current_user_id(),
			'ip'       => Request::ip(),
			'message'  => __( 'Test event from Chaos Shield log forwarding.', 'chaos-shield' ),
		);
		$target = self::syslog_target();
		if ( 'local' === $target ) {
			self::syslog_local( $event );
		} elseif ( 0 === strpos( $target, 'udp://' ) ) {
			$sent = self::send_socket( $target, self::syslog_line( $event ) );
			if ( true !== $sent ) {
				return $sent;
			}
		}
		$result = self::deliver( array( $event ) );
		self::status( true === $result, true === $result ? '' : $result );
		return $result;
	}
}
