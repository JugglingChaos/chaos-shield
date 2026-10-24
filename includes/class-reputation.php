<?php
/**
 * Blocklist and domain expiry checks.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Checks every day that spam blocklists and, with a key, Google Safe
 * Browsing do not list the site, and how long its domain has left.
 * Alerts when a listing appears or the domain is about to lapse.
 */
final class Reputation {

	const OPTION      = 'cshield_reputation';
	const KEY         = 'cshield_gsb_key';
	const EXPIRY_WARN = 30;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'admin_post_cshield_reputation', array( __CLASS__, 'handle' ) );
	}

	/**
	 * The DNS blocklists asked, and how to read their answers.
	 *
	 * @return array Key => label, zone, of (domain or ip), listed (pattern), refused (pattern), url.
	 */
	public static function lists() {
		return array(
			'spamhaus_dbl' => array(
				'label'   => 'Spamhaus DBL',
				'zone'    => 'dbl.spamhaus.org',
				'of'      => 'domain',
				'listed'  => '/^127\.0\.1\.([2-9]|[1-9][0-9])$/',
				'refused' => '/^127\.255\.255\./',
				'url'     => 'https://check.spamhaus.org/',
			),
			'surbl'        => array(
				'label'   => 'SURBL',
				'zone'    => 'multi.surbl.org',
				'of'      => 'domain',
				'listed'  => '/^127\.0\.0\.([2-9]|[1-9][0-9]+)$/',
				'refused' => '/^127\.0\.0\.1$/',
				'url'     => 'https://surbl.org/surbl-analysis',
			),
			'uribl'        => array(
				'label'   => 'URIBL',
				'zone'    => 'multi.uribl.com',
				'of'      => 'domain',
				'listed'  => '/^127\.0\.0\.(2|8|10|14)$/',
				'refused' => '/^127\.0\.0\.1$/',
				'url'     => 'https://admin.uribl.com/',
			),
			'spamhaus_zen' => array(
				'label'   => 'Spamhaus ZEN',
				'zone'    => 'zen.spamhaus.org',
				'of'      => 'ip',
				'listed'  => '/^127\.0\.0\.[2-9]$/',
				'refused' => '/^127\.255\.255\./',
				'url'     => 'https://check.spamhaus.org/',
			),
			'spamcop'      => array(
				'label'   => 'SpamCop',
				'zone'    => 'bl.spamcop.net',
				'of'      => 'ip',
				'listed'  => '/^127\.0\.0\.2$/',
				'refused' => '/^$/',
				'url'     => 'https://www.spamcop.net/bl.shtml',
			),
		);
	}

	/**
	 * Last results.
	 *
	 * @return array checked, domain, ip, lists, expiry.
	 */
	public static function state() {
		$state = Network::get_option( self::OPTION, array() );
		return wp_parse_args(
			is_array( $state ) ? $state : array(),
			array(
				'checked' => 0,
				'domain'  => '',
				'ip'      => '',
				'lists'   => array(),
				'expiry'  => array(),
			)
		);
	}

	/**
	 * Addresses a DNS name points to.
	 *
	 * @param string $name Name.
	 * @return string[]
	 */
	public static function resolve( $name ) {
		/**
		 * Answers a DNS lookup instead of the system resolver.
		 *
		 * @param string[]|null $ips  IPv4 addresses, or null to ask the resolver.
		 * @param string        $name Name looked up.
		 */
		$ips = apply_filters( 'cshield_dns_lookup', null, $name );
		if ( null === $ips ) {
			// The trailing dot keeps the resolver from adding its own search domain.
			$ips = gethostbynamel( rtrim( $name, '.' ) . '.' );
		}
		return is_array( $ips ) ? array_values( array_filter( $ips, 'is_string' ) ) : array();
	}

	/**
	 * The site's host name, without www.
	 *
	 * @return string
	 */
	public static function host() {
		return preg_replace( '/^www\./', '', strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) );
	}

	/**
	 * Whether a host is a real public name that lists and registries know.
	 *
	 * @param string $host Host.
	 * @return bool
	 */
	public static function public_host( $host ) {
		return false !== strpos( $host, '.' ) && ! filter_var( $host, FILTER_VALIDATE_IP ) && ! preg_match( '/\.(test|local|localhost|invalid|example|internal|lan)$/', $host );
	}

	/**
	 * Asks one blocklist about a domain or an IP.
	 *
	 * @param array  $source  One entry of lists().
	 * @param string $subject Domain, or IPv4 address.
	 * @return string clean, listed or refused (the list would not answer this server).
	 */
	public static function ask( array $source, $subject ) {
		$name = 'ip' === $source['of'] ? implode( '.', array_reverse( explode( '.', $subject ) ) ) : $subject;
		foreach ( self::resolve( $name . '.' . $source['zone'] ) as $answer ) {
			if ( preg_match( $source['refused'], $answer ) ) {
				return 'refused';
			}
			if ( preg_match( $source['listed'], $answer ) ) {
				return 'listed';
			}
		}
		return 'clean';
	}

	/**
	 * Asks Google Safe Browsing whether it flags the site.
	 *
	 * @param string $key API key.
	 * @return string clean, listed or error.
	 */
	public static function safe_browsing( $key ) {
		$res = wp_remote_post(
			'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode( $key ),
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'client'     => array(
							'clientId'      => 'chaos-shield',
							'clientVersion' => CSHIELD_VERSION,
						),
						'threatInfo' => array(
							'threatTypes'      => array( 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION' ),
							'platformTypes'    => array( 'ANY_PLATFORM' ),
							'threatEntryTypes' => array( 'URL' ),
							'threatEntries'    => array(
								array( 'url' => home_url( '/' ) ),
								array( 'url' => self::host() ),
							),
						),
					)
				),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return 'error';
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		return is_array( $data ) && ! empty( $data['matches'] ) ? 'listed' : 'clean';
	}

	/**
	 * When a domain expires, from the registry's public RDAP record.
	 *
	 * Tries the full host first, then drops a label at a time, so a
	 * subdomain finds the domain it belongs to.
	 *
	 * @param string $host Host.
	 * @return array domain, expires (0 when unknown), registrar, error.
	 */
	public static function expiry( $host ) {
		$labels = explode( '.', $host );
		$out    = array(
			'domain'    => $host,
			'expires'   => 0,
			'registrar' => '',
			'error'     => '',
		);
		while ( isset( $labels[1] ) ) {
			$domain = implode( '.', $labels );
			$res    = wp_remote_get(
				'https://rdap.org/domain/' . rawurlencode( $domain ),
				array(
					'timeout'     => 15,
					'redirection' => 5,
					'headers'     => array( 'Accept' => 'application/rdap+json' ),
				)
			);
			if ( is_wp_error( $res ) ) {
				$out['error'] = $res->get_error_message();
				return $out;
			}
			$code = (int) wp_remote_retrieve_response_code( $res );
			if ( 404 === $code ) {
				array_shift( $labels );
				continue;
			}
			$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
			if ( 200 !== $code || ! is_array( $data ) ) {
				/* translators: %d: HTTP status code. */
				$out['error'] = sprintf( __( 'The domain registry answered with error %d.', 'chaos-shield' ), $code );
				return $out;
			}
			$out['domain'] = $domain;
			foreach ( isset( $data['events'] ) ? (array) $data['events'] : array() as $event ) {
				if ( isset( $event['eventAction'], $event['eventDate'] ) && 'expiration' === $event['eventAction'] ) {
					$out['expires'] = (int) strtotime( (string) $event['eventDate'] );
				}
			}
			foreach ( isset( $data['entities'] ) ? (array) $data['entities'] : array() as $entity ) {
				if ( in_array( 'registrar', isset( $entity['roles'] ) ? (array) $entity['roles'] : array(), true ) && isset( $entity['vcardArray'][1] ) ) {
					foreach ( (array) $entity['vcardArray'][1] as $field ) {
						if ( isset( $field[0], $field[3] ) && 'fn' === $field[0] ) {
							$out['registrar'] = sanitize_text_field( (string) $field[3] );
						}
					}
				}
			}
			if ( ! $out['expires'] ) {
				$out['error'] = __( 'The registry for this domain does not publish an expiry date.', 'chaos-shield' );
			}
			return $out;
		}
		$out['error'] = __( 'No registry knows this domain.', 'chaos-shield' );
		return $out;
	}

	/**
	 * Runs every check, stores the results and alerts on what changed.
	 *
	 * @return array State.
	 */
	public static function check() {
		$before = self::state();
		$host   = self::host();
		$state  = array(
			'checked' => time(),
			'domain'  => $host,
			'ip'      => '',
			'lists'   => array(),
			'expiry'  => array(),
		);
		$public = self::public_host( $host );
		foreach ( self::resolve( $host ) as $ip ) {
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				$state['ip'] = $ip;
				break;
			}
		}
		foreach ( self::lists() as $id => $list ) {
			$subject               = 'ip' === $list['of'] ? $state['ip'] : ( $public ? $host : '' );
			$state['lists'][ $id ] = array(
				'label'  => $list['label'],
				'status' => '' === $subject ? 'skip' : self::ask( $list, $subject ),
				'url'    => $list['url'],
			);
		}
		$key = (string) Totp::open( (string) Network::get_option( self::KEY, '' ) );
		if ( '' !== $key && $public ) {
			$state['lists']['safe_browsing'] = array(
				'label'  => 'Google Safe Browsing',
				'status' => self::safe_browsing( $key ),
				'url'    => 'https://transparencyreport.google.com/safe-browsing/search?url=' . rawurlencode( $host ),
			);
		}
		if ( $public ) {
			$state['expiry'] = self::expiry( $host );
		}
		Network::update_option( self::OPTION, $state, false );
		self::alert( $before, $state );
		return $state;
	}

	/**
	 * Logs and emails new listings and a domain that is about to lapse.
	 *
	 * @param array $before Previous state.
	 * @param array $state  New state.
	 */
	private static function alert( array $before, array $state ) {
		$new = array();
		foreach ( $state['lists'] as $id => $row ) {
			$was = isset( $before['lists'][ $id ]['status'] ) ? $before['lists'][ $id ]['status'] : '';
			if ( 'listed' === $row['status'] && 'listed' !== $was ) {
				$new[] = $row['label'];
			}
		}
		if ( $new ) {
			$names = implode( ', ', $new );
			Events::add(
				'system',
				/* translators: %s: list of blocklists. */
				sprintf( __( 'This site was found on a blocklist: %s.', 'chaos-shield' ), $names ),
				'',
				array(
					'severity' => Events::CRITICAL,
					'action'   => 'reputation.listed',
					'subject'  => $names,
				)
			);
			Alerts::send(
				'alert_reputation',
				/* translators: %s: list of blocklists. */
				sprintf( __( 'Your site is on a blocklist: %s', 'chaos-shield' ), $names ),
				sprintf(
					/* translators: 1: domain, 2: list of blocklists. */
					__( "%1\$s was found on: %2\$s.\n\nListed sites lose email delivery, get flagged in browsers and search results, or both. Run a malware scan from the Chaos Shield dashboard, remove anything it finds, then ask each list to review the site. The Edge tab links to each list's removal page.", 'chaos-shield' ),
					$state['domain'],
					$names
				),
				'listed|' . md5( $names ) . '|' . gmdate( 'Y-m-d' )
			);
		}
		$expires = isset( $state['expiry']['expires'] ) ? (int) $state['expiry']['expires'] : 0;
		$days    = $expires ? Uptime::days_left( $expires ) : null;
		if ( null !== $days && $days <= self::EXPIRY_WARN && ( $days <= 0 || in_array( $days, array( 30, 14, 7, 3, 1 ), true ) ) ) {
			Alerts::send(
				'alert_reputation',
				$days < 0
					/* translators: %s: domain. */
					? sprintf( __( 'The domain %s has expired', 'chaos-shield' ), $state['expiry']['domain'] )
					/* translators: 1: domain, 2: days. */
					: sprintf( _n( 'The domain %1$s expires in %2$d day', 'The domain %1$s expires in %2$d days', $days, 'chaos-shield' ), $state['expiry']['domain'], $days ),
				sprintf(
					/* translators: 1: domain, 2: date, 3: registrar. */
					__( "The registration of %1\$s ends on %2\$s (registrar: %3\$s). When it lapses the site and its email stop working, and someone else can register the name.\n\nRenew it with your registrar, and switch on automatic renewal if they offer it.", 'chaos-shield' ),
					$state['expiry']['domain'],
					wp_date( get_option( 'date_format' ), $expires ),
					'' !== $state['expiry']['registrar'] ? $state['expiry']['registrar'] : '?'
				),
				'domain|' . gmdate( 'Y-m-d' )
			);
		}
	}

	/**
	 * Handles the buttons on the Reputation card.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to change Chaos Shield settings.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( 'cshield_reputation' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'key' === $op ) {
			$key = isset( $_POST['gsb_key'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['gsb_key'] ) ) ) : '';
			if ( ! empty( $_POST['forget'] ) ) {
				Network::delete_option( self::KEY );
			} elseif ( preg_match( '/^[A-Za-z0-9_-]{20,64}$/', $key ) ) {
				Network::update_option( self::KEY, Totp::seal( $key ), false );
			}
		}
		self::check();
		wp_safe_redirect( Admin::url( 'edge', array( 'cshield_notice' => 'rep_checked' ) ) . '#cshield-reputation' );
		exit;
	}
}
