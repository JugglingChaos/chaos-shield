<?php
/**
 * SIEM detection engine.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Correlation rules that watch the event stream and raise incidents.
 *
 * Every rule names the actions that wake it. When one of those is logged, the
 * rule looks back over the log (a few indexed queries) for the pattern it
 * describes, and raises an incident mapped to a MITRE ATT&CK technique.
 */
final class Detect {

	/**
	 * Re-entry guard: incidents log events too.
	 *
	 * @var bool
	 */
	private static $busy = false;

	/**
	 * Events logged before init, checked once translations can load.
	 *
	 * @var array
	 */
	private static $queue = array();

	/**
	 * Saves events a request could not check because it ended before init.
	 */
	public static function park() {
		if ( ! self::$queue || did_action( 'init' ) ) {
			return;
		}
		$parked = (array) Network::get_option( 'cshield_detect_queue', array() );
		// Autoloaded and kept, even when empty, so checking it costs no query.
		Network::update_option( 'cshield_detect_queue', array_slice( array_merge( $parked, self::$queue ), -200 ), true );
		self::$queue = array();
	}

	/**
	 * Checks the events that arrived before init, here or in an earlier request.
	 */
	public static function drain() {
		$parked = Network::get_option( 'cshield_detect_queue' );
		if ( $parked ) {
			Network::update_option( 'cshield_detect_queue', array(), true );
		}
		$queue       = array_merge( is_array( $parked ) ? $parked : array(), self::$queue );
		self::$queue = array();
		foreach ( $queue as $event ) {
			self::on_event( $event );
		}
	}

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! Settings::enabled( 'siem' ) ) {
			return;
		}
		add_action( 'cshield_event', array( __CLASS__, 'on_event' ), 20 );
		if ( Network::get_option( 'cshield_detect_queue' ) ) {
			add_action( 'init', array( __CLASS__, 'drain' ), 0 );
		}
	}

	/**
	 * The rules.
	 *
	 * @return array Key => [ name, description, technique, tactic, on (actions) ].
	 */
	public static function rules() {
		return array(
			'brute_success'   => array(
				'name'        => __( 'Login after brute force', 'chaos-shield' ),
				'description' => __( 'A login succeeds from an IP that failed or was locked out at least five times in the hour before.', 'chaos-shield' ),
				'technique'   => 'T1110',
				'tactic'      => 'Credential Access',
				'on'          => array( 'auth.login' ),
			),
			'stuffing'        => array(
				'name'        => __( 'Credential stuffing', 'chaos-shield' ),
				'description' => __( 'One IP tries five or more different usernames in 15 minutes.', 'chaos-shield' ),
				'technique'   => 'T1110.004',
				'tactic'      => 'Credential Access',
				'on'          => array( 'auth.failed' ),
			),
			'distributed'     => array(
				'name'        => __( 'Distributed login attack', 'chaos-shield' ),
				'description' => __( 'Thirty or more failed logins from ten or more IPs in 10 minutes: a botnet working around per-IP lockouts.', 'chaos-shield' ),
				'technique'   => 'T1110.003',
				'tactic'      => 'Credential Access',
				'on'          => array( 'auth.failed' ),
			),
			'new_admin'       => array(
				'name'        => __( 'New administrator', 'chaos-shield' ),
				'description' => __( 'An administrator account is created, or a user is promoted to administrator.', 'chaos-shield' ),
				'technique'   => 'T1136.001',
				'tactic'      => 'Persistence',
				'on'          => array( 'user.created', 'user.role' ),
			),
			'risky_session'   => array(
				'name'        => __( 'Risky changes from a new IP', 'chaos-shield' ),
				'description' => __( 'Within two hours of logging in from a new IP, an administrator installs or activates code, adds an administrator, creates an application password, changes key settings or exports data.', 'chaos-shield' ),
				'technique'   => 'T1078',
				'tactic'      => 'Initial Access',
				'on'          => array( 'plugin.installed', 'theme.installed', 'plugin.activated', 'user.created', 'user.role', 'user.app_password', 'option.changed', 'settings.weakened', 'data.export' ),
			),
			'takeover'        => array(
				'name'        => __( 'Account takeover pattern', 'chaos-shield' ),
				'description' => __( 'The email and the password of one account change within an hour of each other.', 'chaos-shield' ),
				'technique'   => 'T1098',
				'tactic'      => 'Persistence',
				'on'          => array( 'user.email_changed', 'user.password_changed' ),
			),
			'site_hijack'     => array(
				'name'        => __( 'Site address or registration changed', 'chaos-shield' ),
				'description' => __( 'The site address, admin email, registration or default role changes. Open registration as administrator is critical.', 'chaos-shield' ),
				'technique'   => 'T1098',
				'tactic'      => 'Persistence',
				'on'          => array( 'option.changed' ),
			),
			'defense_evasion' => array(
				'name'        => __( 'Protection switched off', 'chaos-shield' ),
				'description' => __( 'A Chaos Shield protection, two-factor for an account, or a security plugin is switched off.', 'chaos-shield' ),
				'technique'   => 'T1562.001',
				'tactic'      => 'Defense Evasion',
				'on'          => array( 'settings.weakened', 'auth.2fa_removed', 'plugin.deactivated' ),
			),
			'malware'         => array(
				'name'        => __( 'Malware or tampered files found', 'chaos-shield' ),
				'description' => __( 'A scan finishes with high severity findings: backdoor patterns or official files that were modified.', 'chaos-shield' ),
				'technique'   => 'T1505.003',
				'tactic'      => 'Persistence',
				'on'          => array( 'scan.finished' ),
			),
			'repeat_attacker' => array(
				'name'        => __( 'Repeat attacker', 'chaos-shield' ),
				'description' => __( 'The same IP is banned a second time within a week. Consider blocking it for good.', 'chaos-shield' ),
				'technique'   => 'T1595',
				'tactic'      => 'Reconnaissance',
				'on'          => array( 'fw.ban' ),
			),
			'mass_delete'     => array(
				'name'        => __( 'Mass deletion', 'chaos-shield' ),
				'description' => __( 'One user permanently deletes 20 or more posts, pages or media files in 10 minutes.', 'chaos-shield' ),
				'technique'   => 'T1485',
				'tactic'      => 'Impact',
				'on'          => array( 'content.deleted' ),
			),
			'key_abuse'       => array(
				'name'        => __( 'Suspicious sign-in method', 'chaos-shield' ),
				'description' => __( 'A passkey looks copied, or an administrator signs in with a breached password.', 'chaos-shield' ),
				'technique'   => 'T1556',
				'tactic'      => 'Credential Access',
				'on'          => array( 'auth.passkey_clone', 'auth.breached_password' ),
			),
		);
	}

	/**
	 * Whether a rule is switched on.
	 *
	 * @param string $rule Rule key.
	 * @return bool
	 */
	public static function rule_on( $rule ) {
		return ! in_array( $rule, (array) Settings::get( 'siem_rules_off' ), true );
	}

	/**
	 * Runs the rules woken by a logged event.
	 *
	 * @param array $event Event row.
	 */
	public static function on_event( $event ) {
		if ( self::$busy || empty( $event['action'] ) || 0 === strpos( (string) $event['action'], 'siem.' ) ) {
			return;
		}
		if ( ! did_action( 'init' ) ) {
			// Firewall events fire while the plugin loads; rules translate their text, so wait for init.
			self::$queue[] = $event;
			if ( 1 === count( self::$queue ) ) {
				add_action( 'init', array( __CLASS__, 'drain' ), 0 );
				// Blocked requests stop before init: hand their events to the next request.
				register_shutdown_function( array( __CLASS__, 'park' ) );
			}
			return;
		}
		self::$busy = true;
		try {
			foreach ( self::rules() as $key => $rule ) {
				if ( ! in_array( $event['action'], $rule['on'], true ) || ! self::rule_on( $key ) ) {
					continue;
				}
				$hit = self::evaluate( $key, $event );
				if ( $hit ) {
					Incidents::raise(
						array_merge(
							array(
								'rule'      => $key,
								'technique' => $rule['technique'],
								'ip'        => (string) $event['ip'],
								'user_id'   => (int) $event['user_id'],
								'subject'   => (string) $event['subject'],
								'events'    => array( (int) $event['id'] ),
							),
							$hit
						)
					);
				}
			}
		} finally {
			self::$busy = false;
		}
	}

	/**
	 * Checks one rule against the event that woke it.
	 *
	 * @param string $rule  Rule key.
	 * @param array  $event Event row.
	 * @return array|null Incident fields (severity, title, summary, key, events), or null.
	 */
	public static function evaluate( $rule, array $event ) {
		$ip      = (string) $event['ip'];
		$user_id = (int) $event['user_id'];
		$subject = (string) $event['subject'];
		$now     = (int) $event['created'];

		switch ( $rule ) {
			case 'brute_success':
				if ( ! $ip ) {
					return null;
				}
				$fails = self::ids(
					array(
						'action' => array( 'auth.failed', 'auth.lockout' ),
						'ip'     => $ip,
						'since'  => $now - HOUR_IN_SECONDS,
					)
				);
				if ( count( $fails ) < 5 ) {
					return null;
				}
				$admin = $user_id && user_can( $user_id, 'manage_options' );
				return array(
					'severity' => $admin ? Incidents::CRITICAL : Incidents::HIGH,
					/* translators: 1: username, 2: IP address. */
					'title'    => sprintf( __( '%1$s logged in from %2$s after repeated failures', 'chaos-shield' ), $subject, $ip ),
					/* translators: 1: number of failures, 2: IP address, 3: username. */
					'summary'  => sprintf( __( '%1$d failed logins or lockouts came from %2$s in the hour before %3$s logged in from it. The password may have been guessed. Check the account, end its sessions and reset its password if the login was not expected.', 'chaos-shield' ), count( $fails ), $ip, $subject ),
					'key'      => $ip . '|' . $user_id,
					'events'   => array_merge( $fails, array( (int) $event['id'] ) ),
				);

			case 'stuffing':
				if ( ! $ip ) {
					return null;
				}
				$names = self::distinct(
					'subject',
					array(
						'action' => array( 'auth.failed' ),
						'ip'     => $ip,
						'since'  => $now - 15 * MINUTE_IN_SECONDS,
					)
				);
				if ( count( $names ) < 5 ) {
					return null;
				}
				return array(
					'severity' => Incidents::MEDIUM,
					/* translators: 1: IP address, 2: number of usernames. */
					'title'    => sprintf( __( '%1$s tried %2$d different usernames', 'chaos-shield' ), $ip, count( $names ) ),
					/* translators: 1: IP address, 2: usernames. */
					'summary'  => sprintf( __( '%1$s tried to log in as %2$s within 15 minutes, which looks like a list of stolen credentials being tested.', 'chaos-shield' ), $ip, implode( ', ', array_slice( $names, 0, 10 ) ) ),
					'key'      => $ip,
				);

			case 'distributed':
				$since = $now - 10 * MINUTE_IN_SECONDS;
				$ips   = self::distinct(
					'ip',
					array(
						'action' => array( 'auth.failed' ),
						'since'  => $since,
					)
				);
				$total = self::count(
					array(
						'action' => array( 'auth.failed' ),
						'since'  => $since,
					)
				);
				if ( $total < 30 || count( $ips ) < 10 ) {
					return null;
				}
				return array(
					'severity' => Incidents::MEDIUM,
					/* translators: 1: number of failures, 2: number of IPs. */
					'title'    => sprintf( __( '%1$d failed logins from %2$d IPs in 10 minutes', 'chaos-shield' ), $total, count( $ips ) ),
					'summary'  => __( 'Many IPs are each trying a few passwords, which stays under per-IP lockouts. Consider the login CAPTCHA, a custom login address or country rules for the login page.', 'chaos-shield' ),
					'key'      => 'global|' . gmdate( 'YmdH', $now ),
					'ip'       => '',
					'user_id'  => 0,
					'subject'  => '',
				);

			case 'new_admin':
				if ( Events::CRITICAL !== (int) $event['severity'] ) {
					return null;
				}
				$actor = get_userdata( $user_id );
				return array(
					'severity' => Incidents::HIGH,
					/* translators: %s: username. */
					'title'    => sprintf( __( 'New administrator: %s', 'chaos-shield' ), $subject ),
					/* translators: 1: username, 2: who made the change, 3: IP address. */
					'summary'  => sprintf( __( '%1$s now has full control of the site. The change was made by %2$s from %3$s. If nobody on your team expected this, delete the account and review recent activity.', 'chaos-shield' ), $subject, $actor ? $actor->user_login : __( 'an unknown user or code', 'chaos-shield' ), $ip ? $ip : '-' ),
					'key'      => $subject,
				);

			case 'risky_session':
				if ( ! $user_id || ! $ip ) {
					return null;
				}
				if ( 'option.changed' === $event['action'] && Events::NOTICE > (int) $event['severity'] ) {
					return null;
				}
				if ( in_array( $event['action'], array( 'user.created', 'user.role' ), true ) && Events::CRITICAL !== (int) $event['severity'] ) {
					return null;
				}
				$login = self::ids(
					array(
						'action'  => array( 'auth.new_ip' ),
						'user_id' => $user_id,
						'ip'      => $ip, // The change must come from that new IP, not the owner's usual one.
						'since'   => $now - 2 * HOUR_IN_SECONDS,
					)
				);
				if ( ! $login ) {
					return null;
				}
				$user = get_userdata( $user_id );
				return array(
					'severity' => Incidents::CRITICAL,
					/* translators: %s: username. */
					'title'    => sprintf( __( 'Risky changes by %s soon after a login from a new IP', 'chaos-shield' ), $user ? $user->user_login : '#' . $user_id ),
					/* translators: 1: username, 2: what was done. */
					'summary'  => sprintf( __( '%1$s logged in from an IP never seen before and then: %2$s This is how a stolen administrator login is usually used. Confirm with the person; if it was not them, end their sessions and force a password reset.', 'chaos-shield' ), $user ? $user->user_login : '#' . $user_id, $event['message'] ),
					'key'      => (string) $user_id,
					'events'   => array_merge( $login, array( (int) $event['id'] ) ),
				);

			case 'takeover':
				$other = 'user.email_changed' === $event['action'] ? 'user.password_changed' : 'user.email_changed';
				$pair  = self::ids(
					array(
						'action'  => array( $other ),
						'subject' => $subject,
						'since'   => $now - HOUR_IN_SECONDS,
					)
				);
				if ( ! $pair || '' === $subject ) {
					return null;
				}
				return array(
					'severity' => Incidents::HIGH,
					/* translators: %s: username. */
					'title'    => sprintf( __( 'Email and password of %s changed together', 'chaos-shield' ), $subject ),
					/* translators: %s: username. */
					'summary'  => sprintf( __( 'Changing both the email and the password of %s locks the real owner out. Confirm the change with them.', 'chaos-shield' ), $subject ),
					'key'      => $subject,
					'events'   => array_merge( $pair, array( (int) $event['id'] ) ),
				);

			case 'site_hijack':
				$watched = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role' );
				if ( ! in_array( $subject, $watched, true ) ) {
					return null;
				}
				$open_admin = get_option( 'users_can_register' ) && 'administrator' === get_option( 'default_role' );
				return array(
					'severity' => $open_admin ? Incidents::CRITICAL : Incidents::HIGH,
					'title'    => $open_admin
						? __( 'Anyone can now register as an administrator', 'chaos-shield' )
						/* translators: %s: option name. */
						: sprintf( __( 'Key site setting changed: %s', 'chaos-shield' ), $subject ),
					'summary'  => $open_admin
						? __( 'Registration is open and new users become administrators. Attackers use this to take a site over. Switch off registration or set the default role to Subscriber under Settings > General.', 'chaos-shield' )
						: (string) $event['message'],
					'key'      => $open_admin ? 'open_admin' : $subject,
				);

			case 'defense_evasion':
				if ( 'plugin.deactivated' === $event['action'] && ! preg_match( '/secur|firewall|shield|wordfence|sucuri|ithemes|solid|malcare|defender|two-factor|2fa|login/i', $subject ) ) {
					return null;
				}
				return array(
					'severity' => Incidents::MEDIUM,
					'title'    => __( 'Protection switched off', 'chaos-shield' ),
					/* translators: %s: event message. */
					'summary'  => sprintf( __( '%s Attackers switch protections off before they act. Make sure this was intended.', 'chaos-shield' ), $event['message'] ),
					'key'      => (string) $user_id,
				);

			case 'malware':
				if ( Events::CRITICAL !== (int) $event['severity'] ) {
					return null;
				}
				return array(
					'severity' => Incidents::CRITICAL,
					'title'    => __( 'Malware or tampered files found by the scan', 'chaos-shield' ),
					/* translators: %s: scan summary. */
					'summary'  => sprintf( __( '%s Open the Scan tab to repair or quarantine the files, then change all passwords.', 'chaos-shield' ), $event['message'] ),
					'key'      => 'scan',
				);

			case 'repeat_attacker':
				$bans = self::ids(
					array(
						'action' => array( 'fw.ban' ),
						'ip'     => $ip,
						'since'  => $now - WEEK_IN_SECONDS,
					)
				);
				if ( ! $ip || count( $bans ) < 2 ) {
					return null;
				}
				return array(
					'severity' => Incidents::LOW,
					/* translators: 1: IP address, 2: number of bans. */
					'title'    => sprintf( __( '%1$s banned %2$d times this week', 'chaos-shield' ), $ip, count( $bans ) ),
					'summary'  => __( 'This IP keeps coming back after its bans end. Block it for good from this incident.', 'chaos-shield' ),
					'key'      => $ip,
					'events'   => $bans,
				);

			case 'mass_delete':
				$deleted = self::ids(
					array(
						'action'  => array( 'content.deleted' ),
						'user_id' => $user_id,
						'since'   => $now - 10 * MINUTE_IN_SECONDS,
					)
				);
				if ( ! $user_id || count( $deleted ) < 20 ) {
					return null;
				}
				$user = get_userdata( $user_id );
				return array(
					'severity' => Incidents::HIGH,
					/* translators: 1: username, 2: number of items. */
					'title'    => sprintf( __( '%1$s permanently deleted %2$d items in 10 minutes', 'chaos-shield' ), $user ? $user->user_login : '#' . $user_id, count( $deleted ) ),
					'summary'  => __( 'Deleting content in bulk can be sabotage or a hijacked account. Check with the person and restore from a backup if needed.', 'chaos-shield' ),
					'key'      => (string) $user_id,
					'events'   => $deleted,
				);

			case 'key_abuse':
				return array(
					'severity' => 'auth.passkey_clone' === $event['action'] ? Incidents::HIGH : Incidents::MEDIUM,
					'title'    => 'auth.passkey_clone' === $event['action'] ? __( 'Possible copied passkey', 'chaos-shield' ) : __( 'Administrator signed in with a breached password', 'chaos-shield' ),
					'summary'  => (string) $event['message'],
					'key'      => $event['action'] . '|' . $subject,
				);
		}
		return null;
	}


	/**
	 * Event IDs matching filters.
	 *
	 * @param array $f action (list), ip, user_id, subject, since.
	 * @return int[]
	 */
	private static function ids( array $f ) {
		global $wpdb;
		$table = Events::table();
		$where = self::where( $f );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Own table; $where is prepared.
		return array_map( 'intval', (array) $wpdb->get_col( "SELECT id FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT 200" ) );
	}

	/**
	 * Number of events matching filters.
	 *
	 * @param array $f Filters as for ids().
	 * @return int
	 */
	private static function count( array $f ) {
		global $wpdb;
		$table = Events::table();
		$where = self::where( $f );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Own table; $where is prepared.
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );
	}

	/**
	 * Distinct values of a column among matching events.
	 *
	 * @param string $column ip or subject.
	 * @param array  $f      Filters as for ids().
	 * @return string[]
	 */
	private static function distinct( $column, array $f ) {
		global $wpdb;
		$column = 'ip' === $column ? 'ip' : 'subject';
		$table  = Events::table();
		$where  = self::where( $f );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Own table; $where is prepared, $column is fixed.
		return array_values( array_filter( (array) $wpdb->get_col( "SELECT DISTINCT {$column} FROM {$table} WHERE {$where} LIMIT 500" ), 'strlen' ) );
	}

	/**
	 * WHERE clause for the rule queries.
	 *
	 * @param array $f Filters.
	 * @return string
	 */
	private static function where( array $f ) {
		global $wpdb;
		$parts = array();
		if ( ! empty( $f['action'] ) ) {
			$parts[] = 'action IN (' . implode(
				',',
				array_map(
					static function ( $a ) use ( $wpdb ) {
						return $wpdb->prepare( '%s', $a );
					},
					(array) $f['action']
				)
			) . ')'; // phpcs:ignore Generic.Formatting.MultipleStatementAlignment.NotSameWarning
		}
		if ( isset( $f['ip'] ) ) {
			$parts[] = $wpdb->prepare( 'ip = %s', (string) $f['ip'] );
		}
		if ( isset( $f['user_id'] ) ) {
			$parts[] = $wpdb->prepare( 'user_id = %d', (int) $f['user_id'] );
		}
		if ( isset( $f['subject'] ) ) {
			$parts[] = $wpdb->prepare( 'subject = %s', (string) $f['subject'] );
		}
		$parts[] = $wpdb->prepare( 'created >= %d', isset( $f['since'] ) ? (int) $f['since'] : 0 );
		return implode( ' AND ', $parts );
	}
}
