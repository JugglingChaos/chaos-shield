<?php
/**
 * Uptime and SSL certificate checks for the sites a hub watches.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Checks every connected site's home page and certificate from the hub, and
 * emails when a site goes down, comes back, or its certificate is about to expire.
 */
final class Uptime {

	const OPTION     = 'cshield_uptime';
	const HOOK       = 'cshield_uptime_check';
	const SSL_EVERY  = 12 * HOUR_IN_SECONDS;
	const SSL_WARN   = 14;
	const DOWN_AFTER = 2;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::HOOK, array( __CLASS__, 'check_all' ) );
		add_filter( 'cron_schedules', array( __CLASS__, 'schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval -- Five minute uptime checks.
		add_action( 'init', array( __CLASS__, 'schedule' ) );
	}

	/**
	 * Adds a five minute schedule.
	 *
	 * @param array $schedules Schedules.
	 * @return array
	 */
	public static function schedules( $schedules ) {
		$schedules['cshield_5min'] = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			'display'  => 'Every 5 minutes (Chaos Shield uptime)',
		);
		return $schedules;
	}

	/**
	 * Keeps the check scheduled while sites are connected.
	 */
	public static function schedule() {
		$next = Network::next_scheduled( self::HOOK );
		if ( Hub::sites() && ! $next ) {
			Network::schedule_event( time() + MINUTE_IN_SECONDS, 'cshield_5min', self::HOOK );
		} elseif ( ! Hub::sites() && $next ) {
			Network::clear_scheduled( self::HOOK );
		}
	}

	/**
	 * Stored results.
	 *
	 * @return array Site ID ('' for this site) => state.
	 */
	public static function all() {
		$all = Network::get_option( self::OPTION, array() );
		return is_array( $all ) ? $all : array();
	}

	/**
	 * State of one site.
	 *
	 * @param string $id Site ID, '' for this site.
	 * @return array
	 */
	public static function get( $id ) {
		$all = self::all();
		return isset( $all[ $id ] ) ? $all[ $id ] : array();
	}

	/**
	 * Removes a site's results.
	 *
	 * @param string $id Site ID.
	 */
	public static function forget( $id ) {
		$all = self::all();
		unset( $all[ $id ] );
		Network::update_option( self::OPTION, $all, false );
	}

	/**
	 * Checks every connected site, and this site's certificate.
	 *
	 * @param bool $force Check certificates now instead of twice a day.
	 */
	public static function check_all( $force = false ) {
		$all = self::all();
		foreach ( Hub::sites() as $id => $site ) {
			$state      = isset( $all[ $id ] ) ? $all[ $id ] : array();
			$all[ $id ] = self::check_site( $site, $state, (bool) $force );
		}
		$own     = isset( $all[''] ) ? $all[''] : array();
		$all[''] = self::check_ssl_state(
			array(
				'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				'url'  => home_url( '/' ),
			),
			$own,
			(bool) $force
		);
		$all     = array_intersect_key( $all, array_merge( array( '' => true ), Hub::sites() ) );
		Network::update_option( self::OPTION, $all, false );
	}

	/**
	 * Checks one site's home page, then its certificate when due.
	 *
	 * @param array $site  Site: url, name.
	 * @param array $state Previous state.
	 * @param bool  $force Check the certificate now.
	 * @return array New state.
	 */
	public static function check_site( array $site, array $state, $force ) {
		$start    = microtime( true );
		$response = wp_remote_get(
			$site['url'],
			array(
				'timeout'     => 15,
				'redirection' => 3,
				'user-agent'  => 'ChaosShieldUptime/' . CSHIELD_VERSION . '; ' . home_url( '/' ),
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		$ms       = (int) round( ( microtime( true ) - $start ) * 1000 );
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
		$up       = $code >= 200 && $code < 500 && 429 !== $code;
		$err      = is_wp_error( $response ) ? $response->get_error_message() : ( $up ? '' : sprintf( 'HTTP %d', $code ) );

		$was_down  = ! empty( $state['down'] );
		$fails     = $up ? 0 : ( isset( $state['fails'] ) ? (int) $state['fails'] : 0 ) + 1;
		$history   = isset( $state['history'] ) ? (array) $state['history'] : array();
		$history[] = array( time(), $up ? 1 : 0, $ms );
		$history   = array_slice( $history, -288 ); // One day of five minute checks.

		$state = array_merge(
			$state,
			array(
				'checked' => time(),
				'code'    => $code,
				'ms'      => $ms,
				'error'   => $err,
				'fails'   => $fails,
				'history' => $history,
			)
		);

		if ( ! $was_down && $fails >= self::DOWN_AFTER ) {
			$state['down']  = true;
			$state['since'] = time();
			/* translators: 1: site name, 2: error. */
			Events::add( 'system', sprintf( __( 'Hub: %1$s is down (%2$s).', 'chaos-shield' ), $site['name'], $err ), '', array( 'severity' => Events::CRITICAL ) );
			Alerts::send(
				'alert_uptime',
				/* translators: %s: site name. */
				sprintf( __( '%s is down', 'chaos-shield' ), $site['name'] ),
				sprintf(
					/* translators: 1: site address, 2: number of checks, 3: error. */
					__( "%1\$s did not answer correctly %2\$d checks in a row.\n\nLast error: %3\$s\n\nYou will get another email when it is back.", 'chaos-shield' ),
					$site['url'],
					$fails,
					$err
				),
				'down|' . md5( $site['url'] )
			);
		} elseif ( $was_down && $up ) {
			$minutes        = max( 1, (int) round( ( time() - (int) $state['since'] ) / MINUTE_IN_SECONDS ) );
			$state['down']  = false;
			$state['since'] = time();
			/* translators: 1: site name, 2: minutes. */
			Events::add( 'system', sprintf( __( 'Hub: %1$s is back up after %2$d minutes.', 'chaos-shield' ), $site['name'], $minutes ), '', array( 'severity' => Events::NOTICE ) );
			Alerts::send(
				'alert_uptime',
				/* translators: %s: site name. */
				sprintf( __( '%s is back up', 'chaos-shield' ), $site['name'] ),
				/* translators: 1: site address, 2: minutes. */
				sprintf( __( '%1$s answers again. It was down for about %2$d minutes.', 'chaos-shield' ), $site['url'], $minutes ),
				'up|' . md5( $site['url'] )
			);
		} elseif ( ! isset( $state['since'] ) ) {
			$state['down']  = false;
			$state['since'] = time();
		}

		return self::check_ssl_state( $site, $state, $force );
	}

	/**
	 * Refreshes the certificate details when due and warns before expiry.
	 *
	 * @param array $site  Site: url, name.
	 * @param array $state State.
	 * @param bool  $force Check now.
	 * @return array State.
	 */
	public static function check_ssl_state( array $site, array $state, $force ) {
		if ( 'https' !== wp_parse_url( $site['url'], PHP_URL_SCHEME ) ) {
			$state['ssl'] = array( 'none' => true );
			return $state;
		}
		$last = isset( $state['ssl']['checked'] ) ? (int) $state['ssl']['checked'] : 0;
		if ( ! $force && $last > time() - self::SSL_EVERY ) {
			return $state;
		}
		$state['ssl'] = self::certificate( $site['url'] );
		$days         = isset( $state['ssl']['expires'] ) ? self::days_left( (int) $state['ssl']['expires'] ) : null;
		if ( null !== $days && $days <= self::SSL_WARN ) {
			Alerts::send(
				'alert_uptime',
				$days < 0
					/* translators: %s: site name. */
					? sprintf( __( 'The certificate of %s has expired', 'chaos-shield' ), $site['name'] )
					/* translators: 1: site name, 2: days. */
					: sprintf( _n( 'The certificate of %1$s expires in %2$d day', 'The certificate of %1$s expires in %2$d days', $days, 'chaos-shield' ), $site['name'], $days ),
				sprintf(
					/* translators: 1: site address, 2: expiry date, 3: issuer. */
					__( "The HTTPS certificate of %1\$s expires on %2\$s (issued by %3\$s). Visitors will see a security warning after that.\n\nMost hosts renew certificates automatically; if this one did not renew, ask your host or renew it in your hosting panel.", 'chaos-shield' ),
					$site['url'],
					wp_date( get_option( 'date_format' ), (int) $state['ssl']['expires'] ),
					isset( $state['ssl']['issuer'] ) ? $state['ssl']['issuer'] : '?'
				),
				'ssl|' . md5( $site['url'] ) . '|' . gmdate( 'Y-m-d' )
			);
		}
		return $state;
	}

	/**
	 * Whole days until a time; negative once passed.
	 *
	 * @param int $time Unix time.
	 * @return int
	 */
	public static function days_left( $time ) {
		return (int) floor( ( $time - time() ) / DAY_IN_SECONDS );
	}

	/**
	 * Reads a site's certificate.
	 *
	 * @param string $url Site address.
	 * @return array checked, expires, issuer, subject, trusted, error.
	 */
	public static function certificate( $url ) {
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		$port = (int) wp_parse_url( $url, PHP_URL_PORT );
		$port = $port ? $port : 443;
		$out  = array(
			'checked' => time(),
			'trusted' => false,
			'error'   => '',
		);
		if ( ! function_exists( 'openssl_x509_parse' ) || '' === $host ) {
			$out['error'] = __( 'This server cannot read certificates (OpenSSL is missing).', 'chaos-shield' );
			return $out;
		}
		$cert = self::fetch_cert( $host, $port, true, $error );
		if ( $cert ) {
			$out['trusted'] = true;
		} else {
			// Read the certificate anyway, so the expiry still shows when it is not trusted.
			$out['error'] = $error;
			$cert         = self::fetch_cert( $host, $port, false, $ignored );
		}
		if ( $cert ) {
			$info = openssl_x509_parse( $cert );
			if ( is_array( $info ) ) {
				$out['expires'] = isset( $info['validTo_time_t'] ) ? (int) $info['validTo_time_t'] : 0;
				$out['issuer']  = isset( $info['issuer']['O'] ) ? (string) $info['issuer']['O'] : ( isset( $info['issuer']['CN'] ) ? (string) $info['issuer']['CN'] : '' );
				$out['subject'] = isset( $info['subject']['CN'] ) ? (string) $info['subject']['CN'] : '';
			}
		}
		return $out;
	}

	/**
	 * Opens a TLS connection and returns the peer certificate.
	 *
	 * @param string $host   Host.
	 * @param int    $port   Port.
	 * @param bool   $verify Verify the chain and host name.
	 * @param string $error  Set to the error, if any.
	 * @return resource|\OpenSSLCertificate|false
	 */
	private static function fetch_cert( $host, $port, $verify, &$error ) {
		$error   = '';
		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => $verify,
					'verify_peer_name'  => $verify,
					'allow_self_signed' => ! $verify,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
					'cafile'            => ABSPATH . WPINC . '/certificates/ca-bundle.crt',
				),
			)
		);
		$errno   = 0;
		$errstr  = '';
		$client  = @stream_socket_client( 'ssl://' . $host . ':' . $port, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Failure is reported.
		if ( ! $client ) {
			$error = $errstr ? $errstr : __( 'The certificate could not be verified.', 'chaos-shield' );
			if ( $verify && '' === $errstr ) {
				$error = __( 'The certificate is not trusted, or does not match the site name.', 'chaos-shield' );
			}
			return false;
		}
		$params = stream_context_get_params( $client );
		fclose( $client ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Network socket.
		return isset( $params['options']['ssl']['peer_certificate'] ) ? $params['options']['ssl']['peer_certificate'] : false;
	}

	/**
	 * Share of successful checks in the stored history, as a percentage.
	 *
	 * @param array $state State.
	 * @return float|null
	 */
	public static function uptime_percent( array $state ) {
		if ( empty( $state['history'] ) ) {
			return null;
		}
		$up = 0;
		foreach ( $state['history'] as $item ) {
			$up += (int) $item[1];
		}
		return round( 100 * $up / count( $state['history'] ), 1 );
	}
}
