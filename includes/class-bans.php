<?php
/**
 * Automatic bans for repeat attackers and 404 probing bots.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Counts strikes per IP and bans an IP from the whole site once it crosses a limit.
 */
final class Bans {

	const OPTION      = 'sshield_bans';
	const ALERT_EVENT = 'sshield_ban_alert';

	/**
	 * File types whose 404s come from broken pages, not from scanners.
	 *
	 * @var string[]
	 */
	private static $asset_ext = array( 'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'ico', 'css', 'js', 'map', 'woff', 'woff2', 'ttf', 'eot', 'mp4', 'webm', 'mp3', 'pdf', 'txt', 'xml' );

	/**
	 * Registers hooks.
	 */
	public function register() {
		// Like the block list, a ban needs nothing but the IP, so it runs while the plugin loads.
		$this->enforce();

		add_action( self::ALERT_EVENT, array( __CLASS__, 'send_alert' ) );

		if ( Settings::enabled( 'block_404_probes' ) ) {
			add_action( 'template_redirect', array( $this, 'track_404' ), 99 );
		}
	}

	/**
	 * Refuses every request from a banned IP.
	 */
	private function enforce() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		$ip = Request::ip();
		if ( ! $ip || ! self::until( $ip ) || Firewall::allowlisted() ) {
			return;
		}
		Login_Guard::bump_stat( 'firewall_blocks' );
		Firewall::deny( 'ban' );
	}

	/**
	 * Counts 404s from visitors and bans IPs that probe for files.
	 */
	public function track_404() {
		if ( ! is_404() || current_user_can( 'edit_posts' ) || Firewall::allowlisted() || Page_Check::is_self() || Request::embedded_cross_site() ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$ext  = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, self::$asset_ext, true ) ) {
			return;
		}
		$ip = Request::ip();
		if ( $ip && self::count( $ip, 'probe', 5 * MINUTE_IN_SECONDS ) >= (int) Settings::get( 'probe_404_limit' ) ) {
			self::ban(
				$ip,
				sprintf(
					/* translators: 1: number of missing pages, 2: last path requested. */
					__( 'Requested %1$d missing pages within 5 minutes, last one %2$s', 'sentinel-shield' ),
					(int) Settings::get( 'probe_404_limit' ),
					substr( $uri, 0, 120 )
				)
			);
		}
	}

	/**
	 * Records a strike from a lockout or a firewall block and bans at the limit.
	 *
	 * @param string $ip   IP address.
	 * @param string $kind lockout or firewall.
	 */
	public static function strike( $ip, $kind ) {
		if ( ! $ip || ! Settings::enabled( 'auto_ban' ) || Firewall::allowlisted() || self::until( $ip ) ) {
			return;
		}
		if ( 'lockout' !== $kind && Request::embedded_cross_site() ) {
			// Another site can make a visitor's browser load a bad URL from here, in an
			// image tag for example. Block that request but do not hold it against the visitor.
			return;
		}
		if ( 'lockout' === $kind ) {
			$limit = (int) Settings::get( 'autoban_strikes' );
			if ( self::count( $ip, 'lockout', DAY_IN_SECONDS ) >= $limit ) {
				/* translators: %d: number of lockouts. */
				self::ban( $ip, sprintf( __( 'Locked out %d times within 24 hours', 'sentinel-shield' ), $limit ) );
			}
			return;
		}
		if ( 'ratelimit' === $kind ) {
			// Plain English: rate limits are hit before translations may be loaded.
			if ( self::count( $ip, 'ratelimit', HOUR_IN_SECONDS ) >= 5 ) {
				self::ban( $ip, 'Hit the rate limit 5 times within an hour' );
			}
			return;
		}
		// Firewall rules only catch obvious attacks, so ten blocked requests in an hour is a scanner.
		if ( self::count( $ip, 'firewall', HOUR_IN_SECONDS ) >= 10 ) {
			// Plain English: firewall strikes happen before translations may be loaded.
			self::ban( $ip, 'Tripped the firewall 10 times within an hour' );
		}
	}

	/**
	 * Adds one to an IP's counter and returns the new total within the window.
	 *
	 * @param string $ip     IP address.
	 * @param string $kind   Counter name.
	 * @param int    $window Seconds the counter lives, from the first hit.
	 * @return int
	 */
	private static function count( $ip, $kind, $window ) {
		$key  = 'sshield_strk_' . $kind . '_' . md5( $ip );
		$data = Network::get_transient( $key );
		$now  = time();
		if ( ! is_array( $data ) || $now - (int) $data['since'] > $window ) {
			$data = array(
				'since' => $now,
				'count' => 0,
			);
		}
		++$data['count'];
		Network::set_transient( $key, $data, max( 60, $window - ( $now - $data['since'] ) ) );
		return (int) $data['count'];
	}

	/**
	 * Whether an IP is the server itself.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_server( $ip ) {
		return in_array( $ip, array( '127.0.0.1', '::1', Request::server( 'SERVER_ADDR' ) ), true );
	}

	/**
	 * Bans an IP, unless it is the server, an administrator uses it or it is a verified search engine.
	 *
	 * @param string $ip     IP address.
	 * @param string $reason Why.
	 * @return bool Whether the ban was added.
	 */
	public static function ban( $ip, $reason ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || self::until( $ip ) ) {
			return false;
		}
		// Banning the server itself would stop cron, loopback checks and, behind an unconfigured proxy, every visitor.
		if ( self::is_server( $ip ) ) {
			self::reset_counters( $ip );
			return false;
		}
		$early = ! did_action( 'init' );
		if ( self::admin_ip( $ip ) ) {
			Events::add(
				'ban',
				$early
					? sprintf( 'Did not ban %1$s because an administrator has logged in from it (%2$s).', $ip, $reason )
					/* translators: 1: IP address, 2: reason. */
					: sprintf( __( 'Did not ban %1$s because an administrator has logged in from it (%2$s).', 'sentinel-shield' ), $ip, $reason ),
				$ip,
				array( 'severity' => Events::NOTICE )
			);
			self::reset_counters( $ip );
			return false;
		}
		if ( self::verified_crawler( $ip ) ) {
			self::reset_counters( $ip );
			return false;
		}

		$hours       = (int) Settings::get( 'autoban_hours' );
		$bans        = self::bans();
		$bans[ $ip ] = array(
			'until'  => time() + $hours * HOUR_IN_SECONDS,
			'reason' => $reason,
			'since'  => time(),
		);
		Network::update_option( self::OPTION, $bans, false );
		self::reset_counters( $ip );
		Login_Guard::bump_stat( 'bans' );

		Events::add(
			'ban',
			$early
				? sprintf( 'Banned %1$s for %2$d hours: %3$s.', $ip, $hours, $reason )
				/* translators: 1: IP address, 2: hours, 3: reason. */
				: sprintf( __( 'Banned %1$s for %2$d hours: %3$s.', 'sentinel-shield' ), $ip, $hours, $reason ),
			$ip,
			array(
				'severity' => Events::NOTICE,
				'action'   => 'fw.ban',
				'subject'  => $reason,
			)
		);
		/**
		 * Fires after an IP is banned.
		 *
		 * @param string $ip    IP address.
		 * @param int    $until Unix time the ban ends.
		 */
		do_action( 'sshield_ip_banned', $ip, $bans[ $ip ]['until'] );
		if ( $early ) {
			// Alert emails are translated, so they go out from a later request.
			Network::schedule_single( time(), self::ALERT_EVENT, array( $ip ) );
		} else {
			self::send_alert( $ip );
		}
		return true;
	}

	/**
	 * Emails the ban alert.
	 *
	 * @param string $ip Banned IP address.
	 */
	public static function send_alert( $ip ) {
		$bans = self::bans();
		if ( ! isset( $bans[ $ip ] ) ) {
			return;
		}
		Alerts::send(
			'alert_lockouts',
			/* translators: %s: IP address. */
			sprintf( __( 'IP %s banned', 'sentinel-shield' ), $ip ),
			sprintf(
				/* translators: 1: IP address, 2: date the ban ends, 3: reason. */
				__( '%1$s is banned from the whole site until %2$s. Reason: %3$s.', 'sentinel-shield' ),
				$ip,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $bans[ $ip ]['until'] ),
				$bans[ $ip ]['reason']
			),
			'ban' . $ip
		);
	}

	/**
	 * Active bans as IP => [ until, reason, since ]. Expired bans are pruned.
	 *
	 * @return array
	 */
	public static function bans() {
		$bans   = Network::get_option( self::OPTION, array() );
		$bans   = is_array( $bans ) ? $bans : array();
		$now    = time();
		$active = array_filter(
			$bans,
			static function ( $ban ) use ( $now ) {
				return is_array( $ban ) && (int) $ban['until'] > $now;
			}
		);
		if ( count( $active ) !== count( $bans ) ) {
			Network::update_option( self::OPTION, $active, false );
		}
		return $active;
	}

	/**
	 * Ban expiry for an IP, or 0.
	 *
	 * @param string $ip IP address.
	 * @return int
	 */
	public static function until( $ip ) {
		$bans = Network::get_option( self::OPTION, array() );
		if ( ! is_array( $bans ) || ! isset( $bans[ $ip ]['until'] ) ) {
			return 0;
		}
		return (int) $bans[ $ip ]['until'] > time() ? (int) $bans[ $ip ]['until'] : 0;
	}

	/**
	 * Lifts one ban, or all of them.
	 *
	 * @param string $ip Optional IP address.
	 */
	public static function release( $ip = '' ) {
		if ( '' === $ip ) {
			Network::update_option( self::OPTION, array(), false );
		} else {
			$bans = self::bans();
			unset( $bans[ $ip ] );
			Network::update_option( self::OPTION, $bans, false );
			self::reset_counters( $ip );
		}
		/**
		 * Fires after one ban or every ban is lifted.
		 *
		 * @param string $ip IP address, or '' for all.
		 */
		do_action( 'sshield_ip_released', $ip );
	}

	/**
	 * Clears an IP's strike counters.
	 *
	 * @param string $ip IP address.
	 */
	private static function reset_counters( $ip ) {
		foreach ( array( 'lockout', 'firewall', 'probe', 'ratelimit' ) as $kind ) {
			Network::delete_transient( 'sshield_strk_' . $kind . '_' . md5( $ip ) );
		}
	}

	/**
	 * Whether an administrator has logged in from this IP recently.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private static function admin_ip( $ip ) {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => 50,
			)
		);
		foreach ( $admins as $id ) {
			if ( in_array( $ip, (array) get_user_meta( (int) $id, Monitor::KNOWN_IPS_META, true ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether the request comes from Google or Bing, with the DNS answer kept for a day.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_verified_crawler( $ip ) {
		$agent = strtolower( Request::server( 'HTTP_USER_AGENT' ) );
		if ( ! $ip || ! preg_match( '/googlebot|bingbot|google-inspectiontool|adsbot-google/', $agent ) ) {
			return false;
		}
		// DNS lookups are slow, so each IP's answer is kept for a day.
		$key    = 'sshield_crawler_' . md5( $ip );
		$cached = Network::get_transient( $key );
		if ( false !== $cached ) {
			return 'yes' === $cached;
		}
		$yes = self::verified_crawler( $ip );
		Network::set_transient( $key, $yes ? 'yes' : 'no', DAY_IN_SECONDS );
		return $yes;
	}

	/**
	 * Whether the request comes from Google or Bing, checked by reverse and forward DNS.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private static function verified_crawler( $ip ) {
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) ) : '';
		if ( ! preg_match( '/googlebot|bingbot|google-inspectiontool|adsbot-google/', $agent ) ) {
			return false;
		}
		$host = gethostbyaddr( $ip );
		if ( ! $host || $host === $ip || ! preg_match( '/\.(googlebot\.com|google\.com|googleusercontent\.com|search\.msn\.com)$/i', $host ) ) {
			return false;
		}
		$forward = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? dns_get_record( $host, DNS_AAAA ) : gethostbynamel( $host );
		if ( ! $forward ) {
			return false;
		}
		foreach ( (array) $forward as $record ) {
			$addr = is_array( $record ) ? ( isset( $record['ipv6'] ) ? $record['ipv6'] : '' ) : $record;
			if ( $addr && inet_pton( $addr ) === inet_pton( $ip ) ) {
				return true;
			}
		}
		return false;
	}
}
