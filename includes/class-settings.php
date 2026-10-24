<?php
/**
 * Settings storage.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Reads, validates and stores plugin settings in a single option.
 */
final class Settings {

	const OPTION = 'cshield_settings';

	/**
	 * Cached settings for the current request.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Messages for fields the last save could not accept.
	 *
	 * @var string[]
	 */
	public static $errors = array();

	/**
	 * Hardening modules: key => [ label, description, default ].
	 *
	 * @return array
	 */
	public static function modules() {
		$modules  = array(
			'disable_xmlrpc'        => array(
				'label'       => __( 'Disable XML-RPC', 'chaos-shield' ),
				'description' => __( 'Blocks xmlrpc.php and pingbacks, a common brute-force and DDoS amplification target.', 'chaos-shield' ),
			),
			'disable_file_edit'     => array(
				'label'       => __( 'Disable file editor', 'chaos-shield' ),
				'description' => __( 'Removes the theme and plugin code editors from wp-admin so a stolen login cannot inject code.', 'chaos-shield' ),
			),
			'hide_version'          => array(
				'label'       => __( 'Hide WordPress version', 'chaos-shield' ),
				'description' => __( 'Strips the version from page markup, feeds and asset URLs to slow down targeted scans.', 'chaos-shield' ),
			),
			'block_user_enum'       => array(
				'label'       => __( 'Block user enumeration', 'chaos-shield' ),
				'description' => __( 'Stops visitors from listing usernames through ?author= URLs, the REST API and sitemaps.', 'chaos-shield' ),
			),
			'security_headers'      => array(
				'label'       => __( 'Security headers', 'chaos-shield' ),
				'description' => __( 'Sends nosniff, frame, referrer and permissions headers, plus HSTS when the site runs on HTTPS.', 'chaos-shield' ),
			),
			'limit_login'           => array(
				'label'       => __( 'Limit login attempts', 'chaos-shield' ),
				'description' => __( 'Temporarily locks out an IP address after repeated failed logins.', 'chaos-shield' ),
			),
			'generic_login_errors'  => array(
				'label'       => __( 'Generic login errors', 'chaos-shield' ),
				'description' => __( 'Shows one neutral message on failed logins so attackers cannot tell whether a username exists.', 'chaos-shield' ),
			),
			'two_factor'            => array(
				'label'       => __( 'Two-factor login', 'chaos-shield' ),
				'description' => __( 'Lets each user add an authenticator app code to their login from their profile page.', 'chaos-shield' ),
			),
			'firewall'              => array(
				'label'       => __( 'Request firewall', 'chaos-shield' ),
				'description' => __( 'Scores every part of each request, from the address to form fields, JSON, cookies and uploads, for SQL, script, code and command injection, path traversal and attack tools, and blocks clear attacks. Tune it on the Firewall tab.', 'chaos-shield' ),
			),
			'auto_ban'              => array(
				'label'       => __( 'Auto-ban repeat attackers', 'chaos-shield' ),
				'description' => __( 'Bans an IP from the whole site when it keeps getting locked out or keeps tripping the firewall.', 'chaos-shield' ),
			),
			'block_404_probes'      => array(
				'label'       => __( 'Block 404 probing', 'chaos-shield' ),
				'description' => __( 'Bans bots that request many missing pages in a few minutes while hunting for vulnerable files.', 'chaos-shield' ),
			),
			'breached_passwords'    => array(
				'label'       => __( 'Block breached passwords', 'chaos-shield' ),
				'description' => __( 'Refuses new passwords found in public data breaches and warns administrators whose current password is breached. Uses the Have I Been Pwned range API, which never receives the password.', 'chaos-shield' ),
			),
			'password_policy'       => array(
				'label'       => __( 'Password policy', 'chaos-shield' ),
				'description' => __( 'Requires long, varied passwords for the roles you choose, and can make passwords expire. Set the rules below.', 'chaos-shield' ),
			),
			'audit_trail'           => array(
				'label'       => __( 'Detailed audit trail', 'chaos-shield' ),
				'description' => __( 'Also logs content changes, core site settings, profile, email and password changes, logouts, failed logins and privacy requests.', 'chaos-shield' ),
			),
			'passkeys'              => array(
				'label'       => __( 'Passkey login', 'chaos-shield' ),
				'description' => __( 'Lets users add passkeys on their profile and sign in with a fingerprint, face or device PIN. Needs HTTPS.', 'chaos-shield' ),
			),
			'rate_limit'            => array(
				'label'       => __( 'Rate limiting', 'chaos-shield' ),
				'description' => __( 'Answers 429 to an IP that sends too many login, API, AJAX or search requests in a minute, and bans IPs that keep doing it.', 'chaos-shield' ),
			),
			'country_block'         => array(
				'label'       => __( 'Country blocking', 'chaos-shield' ),
				'description' => __( 'Blocks or allows visitors by country, for the whole site or only the login page. Set the countries under Access.', 'chaos-shield' ),
			),
			'captcha'               => array(
				'label'       => __( 'Login CAPTCHA', 'chaos-shield' ),
				'description' => __( 'Adds a Cloudflare Turnstile or hCaptcha check to the login, lost password and registration forms. Connect one under Login page below; both are free.', 'chaos-shield' ),
			),
			'visitor_help'          => array(
				'label'       => __( 'Visitor help', 'chaos-shield' ),
				'description' => __( 'Shows blocked and locked-out visitors a clear page with a help assistant and a way to ask you for access, and adds sign-in help to the login page. Set it up under Visitor help.', 'chaos-shield' ),
			),
			'file_watch'            => array(
				'label'       => __( 'Critical file watch', 'chaos-shield' ),
				'description' => __( 'Fingerprints wp-config.php, .htaccess, drop-ins, must-use plugins and key core files every hour, and alerts you the moment one changes.', 'chaos-shield' ),
			),
			'attack_auto'           => array(
				'label'       => __( 'Automatic under attack mode', 'chaos-shield' ),
				'description' => __( 'When blocked requests pile up, puts a one-second browser check in front of the site until the flood stops, so bots cannot keep the server busy. Set it up on the Edge tab.', 'chaos-shield' ),
			),
			'script_watch'          => array(
				'label'       => __( 'Page script monitor', 'chaos-shield' ),
				'description' => __( 'Lists every script your pages load and alerts you when a new or suspicious one appears, the usual sign of a card skimmer or injected ads.', 'chaos-shield' ),
			),
			'exposure_check'        => array(
				'label'       => __( 'Exposed files and keys check', 'chaos-shield' ),
				'description' => __( 'Checks every day that backups, database dumps, logs, .env and .git cannot be downloaded, and that no secret keys show in your pages.', 'chaos-shield' ),
			),
			'vuln_check'            => array(
				'label'       => __( 'Vulnerability alerts', 'chaos-shield' ),
				'description' => __( 'Checks WordPress, your plugins and your themes every day against the free WPVulnerability database, and flags plugins that were closed or abandoned. No account or key needed.', 'chaos-shield' ),
			),
			'threat_feed'           => array(
				'label'       => __( 'Threat intelligence blocklist', 'chaos-shield' ),
				'description' => __( 'Blocks networks run by criminals and spammers, using the free Spamhaus DROP list, refreshed daily. Can also block Tor exit nodes.', 'chaos-shield' ),
			),
			'live_traffic'          => array(
				'label'       => __( 'Live traffic', 'chaos-shield' ),
				'description' => __( 'Shows who is on the site right now: logins, blocked requests, missing pages and, if you choose, every visit. Kept for 24 hours.', 'chaos-shield' ),
			),
			'geo_db'                => array(
				'label'       => __( 'Built-in country lookup', 'chaos-shield' ),
				'description' => __( 'Finds the country of each visitor for the traffic map and country rules, using a free public domain database downloaded once a week (about 25 MB, no account). Nothing about your visitors leaves the site.', 'chaos-shield' ),
			),
			'siem'                  => array(
				'label'       => __( 'SIEM detections', 'chaos-shield' ),
				'description' => __( 'Correlates the activity log in real time to spot attacks in progress, such as a login after brute force or risky changes from a new IP, and opens incidents you can work through on the SIEM tab.', 'chaos-shield' ),
			),
			'restore_points'        => array(
				'label'       => __( 'Restore points', 'chaos-shield' ),
				'description' => __( 'Saves a copy of a plugin or theme before it updates, of a file before it is repaired and of these settings before they change, so you can put them back from the Backups tab. Kept for 30 days.', 'chaos-shield' ),
			),
			'comment_spam'          => array(
				'label'       => __( 'Block comment spam', 'chaos-shield' ),
				'description' => __( 'Adds a hidden field and a signed time stamp to the comment form, refuses bots that fill it in or post within seconds, bans those that keep trying, and sends comments that skip the form to the spam folder. No CAPTCHA needed.', 'chaos-shield' ),
			),
			'approve_signups'       => array(
				'label'       => __( 'Approve new sign-ups', 'chaos-shield' ),
				'description' => __( 'Accounts that visitors make for themselves cannot log in until an administrator approves them on the Users screen. You get an email for each one.', 'chaos-shield' ),
			),
			'block_blank_ua'        => array(
				'label'       => __( 'Block posts without a user agent', 'chaos-shield' ),
				'description' => __( 'Refuses form posts from visitors whose browser sends no user agent, which only scripts do. Block named bots and tools under Access.', 'chaos-shield' ),
			),
			'rest_private'          => array(
				'label'       => __( 'Close the REST API to visitors', 'chaos-shield' ),
				'description' => __( 'Only logged-in users can use the REST API, apart from the routes you allow below. Embeds, WooCommerce checkout, Contact Form 7, WPForms and Jetpack stay open.', 'chaos-shield' ),
			),
			'disable_feeds'         => array(
				'label'       => __( 'Turn off RSS feeds', 'chaos-shield' ),
				'description' => __( 'Feed addresses answer 410 Gone and the feed links leave your pages, so scrapers cannot copy posts from them. Leave on if you run a podcast or a newsletter from the feed.', 'chaos-shield' ),
			),
			'block_hotlinks'        => array(
				'label'       => __( 'Block image hotlinking', 'chaos-shield' ),
				'description' => __( 'Stops other sites from showing your images and using your bandwidth. Search engines and the sites you allow below can still show them. Needs Apache or LiteSpeed.', 'chaos-shield' ),
			),
			'disable_app_passwords' => array(
				'label'       => __( 'Disable application passwords', 'chaos-shield' ),
				'description' => __( 'Turns off REST API application passwords. Leave off if an app or service signs in with them.', 'chaos-shield' ),
			),
		);
		$defaults = self::defaults();
		foreach ( $modules as $key => $module ) {
			$modules[ $key ]['default'] = $defaults[ $key ];
		}
		return $modules;
	}

	/**
	 * Default settings.
	 *
	 * @return array
	 */
	public static function defaults() {
		// Kept free of translation calls because settings are read while the plugin loads.
		$defaults                         = array(
			'disable_xmlrpc'        => true,
			'disable_file_edit'     => true,
			'hide_version'          => true,
			'block_user_enum'       => true,
			'security_headers'      => true,
			'limit_login'           => true,
			'generic_login_errors'  => true,
			'two_factor'            => true,
			'firewall'              => true,
			'auto_ban'              => true,
			'block_404_probes'      => true,
			'breached_passwords'    => true,
			'password_policy'       => false,
			'audit_trail'           => true,
			'passkeys'              => true,
			'rate_limit'            => true,
			'country_block'         => false,
			'captcha'               => false,
			'vuln_check'            => true,
			'file_watch'            => true,
			'visitor_help'          => true,
			'attack_auto'           => true,
			'script_watch'          => true,
			'exposure_check'        => true,
			'threat_feed'           => true,
			'live_traffic'          => true,
			'geo_db'                => true,
			'siem'                  => true,
			'restore_points'        => true,
			'comment_spam'          => true,
			'approve_signups'       => false,
			'block_blank_ua'        => false,
			'rest_private'          => false,
			'disable_feeds'         => false,
			'block_hotlinks'        => false,
			'disable_app_passwords' => false,
		);
		$defaults['login_max_attempts']   = 5;
		$defaults['login_window']         = 15;
		$defaults['login_lockout']        = 30;
		$defaults['autoban_strikes']      = 3;
		$defaults['autoban_hours']        = 24;
		$defaults['probe_404_limit']      = 20;
		$defaults['login_slug']           = '';
		$defaults['turnstile_site_key']   = '';
		$defaults['captcha_provider']     = 'turnstile';
		$defaults['hcaptcha_site_key']    = '';
		$defaults['captcha_comments']     = false;
		$defaults['captcha_woo']          = false;
		$defaults['captcha_cf7']          = false;
		$defaults['captcha_wpforms']      = false;
		$defaults['chat_service']         = '';
		$defaults['help_bubble']          = false;
		$defaults['help_contact']         = true;
		$defaults['help_title']           = '';
		$defaults['help_greeting']        = '';
		$defaults['help_color']           = '#2563eb';
		$defaults['attack_threshold']     = 100;
		$defaults['csp_mode']             = 'off';
		$defaults['https_upgrade']        = false;
		$defaults['force_https']          = false;
		$defaults['cf_sync_bans']         = true;
		$defaults['cf_attack_sync']       = true;
		$defaults['ban_feed']             = false;
		$defaults['rate_login']           = 20;
		$defaults['rate_api']             = 180;
		$defaults['rate_search']          = 30;
		$defaults['rate_pages']           = 300;
		$defaults['country_source']       = '';
		$defaults['country_mode']         = 'block';
		$defaults['country_scope']        = 'login';
		$defaults['country_list']         = array();
		$defaults['ip_allowlist']         = array();
		$defaults['ip_blocklist']         = array();
		$defaults['ua_blocklist']         = array();
		$defaults['rest_allow']           = array();
		$defaults['hotlink_allow']        = array();
		$defaults['proxy_header']         = '';
		$defaults['fw_mode']              = 'block';
		$defaults['fw_learn_until']       = 0;
		$defaults['fw_sensitivity']       = 'balanced';
		$defaults['fw_rules_off']         = array();
		$defaults['trusted_proxies']      = array();
		$defaults['alert_email']          = '';
		$defaults['scan_schedule']        = 'daily';
		$defaults['log_retention']        = 90;
		$defaults['forward_webhook']      = '';
		$defaults['forward_secret']       = '';
		$defaults['forward_syslog']       = '';
		$defaults['forward_min_severity'] = 1;
		$defaults['pw_min_length']        = 12;
		$defaults['pw_classes']           = 3;
		$defaults['pw_roles']             = 'staff';
		$defaults['pw_max_age']           = 0;
		$defaults['tf_required']          = 'off';
		$defaults['tf_grace_days']        = 7;
		$defaults['tf_trust_days']        = 0;
		$defaults['idle_minutes']         = 0;
		$defaults['idle_roles']           = 'staff';
		$defaults['threat_tor']           = false;
		$defaults['traffic_mode']         = 'security';
		$defaults['siem_rules_off']       = array();
		$defaults['siem_alert_min']       = 3;
		foreach ( self::alert_defaults() as $key => $on ) {
			$defaults[ $key ] = $on;
		}
		return $defaults;
	}

	/**
	 * Email alert switches and their defaults.
	 *
	 * @return array Key => default.
	 */
	private static function alert_defaults() {
		return array(
			'alert_admin_login'    => true,
			'alert_new_admin'      => true,
			'alert_plugin_changes' => true,
			'alert_scan'           => true,
			'alert_lockouts'       => false,
			'alert_weekly_report'  => true,
			'alert_vulns'          => true,
			'alert_uptime'         => true,
			'alert_incidents'      => true,
			'alert_help'           => true,
			'alert_attack'         => true,
			'alert_scripts'        => true,
			'alert_exposure'       => true,
		);
	}

	/**
	 * Email alert labels.
	 *
	 * @return array Key => label.
	 */
	public static function alerts() {
		return array(
			'alert_admin_login'    => __( 'An administrator logs in from a new IP address', 'chaos-shield' ),
			'alert_new_admin'      => __( 'A new administrator account appears, or a user is promoted to administrator', 'chaos-shield' ),
			'alert_plugin_changes' => __( 'A plugin or theme is installed, activated or deleted', 'chaos-shield' ),
			'alert_scan'           => __( 'A scan finds modified core files or suspicious code', 'chaos-shield' ),
			'alert_lockouts'       => __( 'An IP address is locked out or banned (can be noisy)', 'chaos-shield' ),
			'alert_weekly_report'  => __( 'A weekly security report', 'chaos-shield' ),
			'alert_vulns'          => __( 'Installed software has a newly published vulnerability', 'chaos-shield' ),
			'alert_uptime'         => __( 'A site connected to the hub goes down, or a certificate is about to expire', 'chaos-shield' ),
			'alert_incidents'      => __( 'A SIEM detection opens an incident (high and critical by default)', 'chaos-shield' ),
			'alert_help'           => __( 'A blocked visitor asks you for access', 'chaos-shield' ),
			'alert_attack'         => __( 'Under attack mode switches on during a flood', 'chaos-shield' ),
			'alert_scripts'        => __( 'A new or suspicious script appears on your pages', 'chaos-shield' ),
			'alert_exposure'       => __( 'A backup, log, key or other private file can be downloaded', 'chaos-shield' ),
		);
	}

	/**
	 * Address that receives alerts.
	 *
	 * @return string
	 */
	public static function alert_email() {
		$email = (string) self::get( 'alert_email' );
		return is_email( $email ) ? $email : (string) get_option( 'admin_email' );
	}

	/**
	 * Validates and saves the alerts form.
	 *
	 * @param array $input Raw input.
	 * @return array Saved settings.
	 */
	public static function save_alerts( array $input ) {
		$clean = self::all();
		$email = isset( $input['alert_email'] ) ? sanitize_email( (string) $input['alert_email'] ) : '';

		$clean['alert_email'] = is_email( $email ) ? $email : '';
		foreach ( array_keys( self::alert_defaults() ) as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}
		$schedule               = isset( $input['scan_schedule'] ) ? (string) $input['scan_schedule'] : 'daily';
		$clean['scan_schedule'] = in_array( $schedule, array( 'daily', 'weekly', 'off' ), true ) ? $schedule : 'daily';
		$clean['log_retention'] = self::bounded_int( $input, 'log_retention', 7, 730 );

		self::$errors = array();
		$webhook      = isset( $input['forward_webhook'] ) ? trim( (string) $input['forward_webhook'] ) : '';
		if ( '' === $webhook ) {
			$clean['forward_webhook'] = '';
		} elseif ( in_array( wp_parse_url( $webhook, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) && wp_parse_url( $webhook, PHP_URL_HOST ) ) {
			$clean['forward_webhook'] = esc_url_raw( $webhook );
		} else {
			self::$errors[] = __( 'The webhook address must start with https:// or http://. It was not saved.', 'chaos-shield' );
		}
		$clean['forward_secret'] = isset( $input['forward_secret'] ) ? substr( sanitize_text_field( (string) $input['forward_secret'] ), 0, 128 ) : '';
		$syslog                  = Forwarder::clean_syslog( isset( $input['forward_syslog'] ) ? (string) $input['forward_syslog'] : '' );
		if ( false === $syslog ) {
			self::$errors[] = __( 'The syslog server must look like udp://logs.example.com:514 or tcp://10.0.0.5:6514, or be "local". It was not saved.', 'chaos-shield' );
		} else {
			$clean['forward_syslog'] = $syslog;
		}
		$clean['forward_min_severity'] = self::bounded_int( $input, 'forward_min_severity', 1, 3 );
		return self::store( $clean );
	}

	/**
	 * All settings merged over defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored      = Network::get_option( self::OPTION, array() );
			self::$cache = wp_parse_args( is_array( $stored ) ? $stored : array(), self::defaults() );
		}
		return self::$cache;
	}

	/**
	 * Saves settings already cleaned by Backup::clean().
	 *
	 * @param array $settings Settings.
	 * @return array
	 */
	public static function import( array $settings ) {
		return self::store( $settings );
	}

	/**
	 * Drops the cached settings, after they were written directly.
	 */
	public static function forget() {
		self::$cache = null;
	}

	/**
	 * Single setting value.
	 *
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Whether a module is switched on.
	 *
	 * @param string $key Module key.
	 * @return bool
	 */
	public static function enabled( $key ) {
		return (bool) self::get( $key );
	}

	/**
	 * Headers a trusted proxy may use to pass on the visitor IP.
	 *
	 * @return array Header key in $_SERVER => label.
	 */
	public static function proxy_headers() {
		return array(
			''                      => __( 'None, use the direct connection (REMOTE_ADDR)', 'chaos-shield' ),
			'HTTP_CF_CONNECTING_IP' => __( 'Cloudflare (CF-Connecting-IP)', 'chaos-shield' ),
			'HTTP_X_FORWARDED_FOR'  => __( 'Load balancer or proxy (X-Forwarded-For)', 'chaos-shield' ),
			'HTTP_X_REAL_IP'        => __( 'Nginx proxy (X-Real-IP)', 'chaos-shield' ),
		);
	}

	/**
	 * Validates and saves the hardening form: modules and login limits.
	 *
	 * @param array $input Raw input.
	 * @return array Saved settings.
	 */
	public static function save_hardening( array $input ) {
		$clean = self::all();
		foreach ( array_keys( self::modules() ) as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}
		$clean['login_max_attempts'] = self::bounded_int( $input, 'login_max_attempts', 2, 50 );
		$clean['login_window']       = self::bounded_int( $input, 'login_window', 1, 1440 );
		$clean['login_lockout']      = self::bounded_int( $input, 'login_lockout', 1, 10080 );
		$clean['autoban_strikes']    = self::bounded_int( $input, 'autoban_strikes', 2, 20 );
		$clean['autoban_hours']      = self::bounded_int( $input, 'autoban_hours', 1, 720 );
		$clean['probe_404_limit']    = self::bounded_int( $input, 'probe_404_limit', 5, 200 );
		$clean['rate_login']         = self::bounded_int( $input, 'rate_login', 5, 600 );
		$clean['rate_api']           = self::bounded_int( $input, 'rate_api', 20, 6000 );
		$clean['rate_search']        = self::bounded_int( $input, 'rate_search', 5, 600 );
		$clean['rate_pages']         = self::bounded_int( $input, 'rate_pages', 30, 6000 );
		$clean['pw_min_length']      = self::bounded_int( $input, 'pw_min_length', 8, 64 );
		$clean['pw_classes']         = self::bounded_int( $input, 'pw_classes', 1, 4 );
		$clean['pw_max_age']         = self::bounded_int( $input, 'pw_max_age', 0, 730 );
		$roles                       = isset( $input['pw_roles'] ) ? (string) $input['pw_roles'] : 'staff';
		$clean['pw_roles']           = in_array( $roles, array( 'admins', 'staff', 'all' ), true ) ? $roles : 'staff';
		$required                    = isset( $input['tf_required'] ) ? (string) $input['tf_required'] : 'off';
		$clean['tf_required']        = in_array( $required, array( 'off', 'admins', 'staff' ), true ) ? $required : 'off';
		$clean['tf_grace_days']      = self::bounded_int( $input, 'tf_grace_days', 0, 30 );
		$clean['tf_trust_days']      = self::bounded_int( $input, 'tf_trust_days', 0, 90 );
		$clean['idle_minutes']       = self::bounded_int( $input, 'idle_minutes', 0, 1440 );
		$idle                        = isset( $input['idle_roles'] ) ? (string) $input['idle_roles'] : 'staff';
		$clean['idle_roles']         = in_array( $idle, array( 'admins', 'staff', 'all' ), true ) ? $idle : 'staff';
		$clean['threat_tor']         = ! empty( $input['threat_tor'] );
		foreach ( array_keys( Captcha::form_options() ) as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}
		$clean['rest_allow']    = Server::parse_routes( isset( $input['rest_allow'] ) ? (string) $input['rest_allow'] : '' );
		$clean['hotlink_allow'] = Server::parse_hosts( isset( $input['hotlink_allow'] ) ? (string) $input['hotlink_allow'] : '' );
		$mode                   = isset( $input['traffic_mode'] ) ? (string) $input['traffic_mode'] : 'security';
		$clean['traffic_mode']  = 'all' === $mode ? 'all' : 'security';
		return self::store( $clean );
	}

	/**
	 * Saves the firewall mode, sensitivity and rule switches.
	 *
	 * @param string   $mode  block or learn. Learning runs for seven days, then blocking resumes.
	 * @param string   $level relaxed, balanced or strict.
	 * @param string[] $off   Rule keys that are off.
	 * @return array
	 */
	public static function save_firewall( $mode, $level, array $off ) {
		$clean = self::all();
		$was   = 'learn' === $clean['fw_mode'] && (int) $clean['fw_learn_until'] > time();
		if ( 'learn' === $mode ) {
			$clean['fw_mode'] = 'learn';
			if ( ! $was ) {
				$clean['fw_learn_until'] = time() + 7 * DAY_IN_SECONDS;
			}
		} else {
			$clean['fw_mode']        = 'block';
			$clean['fw_learn_until'] = 0;
		}
		$clean['fw_sensitivity'] = array_key_exists( $level, Firewall::thresholds() ) ? $level : 'balanced';
		$clean['fw_rules_off']   = array_values( array_intersect( $off, array_keys( Firewall::rules( true ) ) ) );
		return self::store( $clean );
	}

	/**
	 * Saves the Visitor help switches and wording.
	 *
	 * @param array $input Raw input.
	 * @return array
	 */
	public static function save_help( array $input ) {
		$clean                  = self::all();
		$clean['visitor_help']  = ! empty( $input['visitor_help'] );
		$clean['help_bubble']   = ! empty( $input['help_bubble'] );
		$clean['help_contact']  = ! empty( $input['help_contact'] );
		$clean['help_title']    = isset( $input['help_title'] ) ? mb_substr( sanitize_text_field( (string) $input['help_title'] ), 0, 60 ) : '';
		$clean['help_greeting'] = isset( $input['help_greeting'] ) ? mb_substr( sanitize_text_field( (string) $input['help_greeting'] ), 0, 200 ) : '';
		$color                  = isset( $input['help_color'] ) ? sanitize_hex_color( (string) $input['help_color'] ) : '';
		$clean['help_color']    = $color ? $color : '#2563eb';
		return self::store( $clean );
	}

	/**
	 * Saves the Edge tab: flood detection, the script policy, HTTPS and the Cloudflare switches.
	 *
	 * Each card on the tab is its own form, so only the fields it lists change.
	 *
	 * @param array    $input  Raw input.
	 * @param string[] $fields Fields the form holds.
	 * @return array
	 */
	public static function save_edge( array $input, array $fields ) {
		$clean = self::all();
		$bools = array( 'attack_auto', 'script_watch', 'exposure_check', 'https_upgrade', 'force_https', 'cf_sync_bans', 'cf_attack_sync', 'ban_feed' );
		foreach ( array_intersect( $fields, $bools ) as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}
		if ( in_array( 'attack_threshold', $fields, true ) ) {
			$clean['attack_threshold'] = self::bounded_int( $input, 'attack_threshold', 20, 10000 );
		}
		if ( in_array( 'csp_mode', $fields, true ) ) {
			$mode              = isset( $input['csp_mode'] ) ? (string) $input['csp_mode'] : 'off';
			$clean['csp_mode'] = in_array( $mode, array( 'off', 'report', 'enforce' ), true ) ? $mode : 'off';
		}
		return self::store( $clean );
	}

	/**
	 * Reads visitor IPs from Cloudflare's header, trusting Cloudflare's own ranges.
	 *
	 * @return array
	 */
	public static function use_cloudflare_ip() {
		$clean                 = self::all();
		$clean['proxy_header'] = 'HTTP_CF_CONNECTING_IP';
		return self::store( $clean );
	}

	/**
	 * Saves the settings a connection changes: CAPTCHA provider and keys, and the chat service.
	 *
	 * @param array $changes Key => value, limited to the connection keys.
	 * @return array
	 */
	public static function save_connection( array $changes ) {
		$clean = self::all();
		foreach ( array( 'captcha', 'captcha_provider', 'turnstile_site_key', 'hcaptcha_site_key', 'chat_service' ) as $key ) {
			if ( array_key_exists( $key, $changes ) ) {
				$clean[ $key ] = is_bool( $clean[ $key ] ) ? (bool) $changes[ $key ] : sanitize_text_field( (string) $changes[ $key ] );
			}
		}
		return self::store( $clean );
	}

	/**
	 * Saves the SIEM rule switches and the incident alert threshold.
	 *
	 * @param string[] $off Rule keys that are off.
	 * @param int      $min Lowest incident severity that sends an email.
	 * @return array
	 */
	public static function save_siem( array $off, $min ) {
		$clean                   = self::all();
		$clean['siem_rules_off'] = array_values( array_intersect( $off, array_keys( Detect::rules() ) ) );
		$clean['siem_alert_min'] = max( 1, min( 4, (int) $min ) );
		return self::store( $clean );
	}

	/**
	 * Saves the login page settings: the custom address. CAPTCHA keys are saved by Connections.
	 *
	 * @param array $input Raw input.
	 * @return array|\WP_Error Old and new slug, or an error when the slug was refused.
	 */
	public static function save_login( array $input ) {
		$clean = self::all();
		$old   = (string) $clean['login_slug'];
		$slug  = Login_Url::validate( isset( $input['login_slug'] ) ? (string) $input['login_slug'] : '' );

		if ( isset( $input['turnstile_site_key'] ) ) {
			$clean['turnstile_site_key'] = sanitize_text_field( (string) $input['turnstile_site_key'] );
		}
		if ( ! is_wp_error( $slug ) ) {
			$clean['login_slug'] = $slug;
		}
		self::store( $clean );
		return is_wp_error( $slug ) ? $slug : array(
			'old' => $old,
			'new' => $slug,
		);
	}

	/**
	 * Validates and saves the access form: IP lists and proxy settings.
	 *
	 * Entries that are not valid IPs or CIDR ranges are dropped, and so is any
	 * block entry that matches the IP of the person saving, so nobody can lock
	 * themselves out.
	 *
	 * @param array  $input     Raw input.
	 * @param string $own_ip    IP of the user saving the form.
	 * @return array Rejected entries: 'invalid' and 'self' lists.
	 */
	public static function save_access( array $input, $own_ip ) {
		$clean    = self::all();
		$rejected = array(
			'invalid' => array(),
			'self'    => array(),
		);

		$source                  = isset( $input['country_source'] ) ? (string) $input['country_source'] : '';
		$clean['country_source'] = array_key_exists( $source, Geo::sources() ) ? $source : '';
		$clean['country_mode']   = isset( $input['country_mode'] ) && 'allow' === $input['country_mode'] ? 'allow' : 'block';
		$clean['country_scope']  = isset( $input['country_scope'] ) && 'site' === $input['country_scope'] ? 'site' : 'login';
		$clean['country_list']   = Geo::parse( isset( $input['country_list'] ) ? (string) $input['country_list'] : '' );

		$header                = isset( $input['proxy_header'] ) ? (string) $input['proxy_header'] : '';
		$clean['proxy_header'] = array_key_exists( $header, self::proxy_headers() ) ? $header : '';

		foreach ( array( 'ip_allowlist', 'ip_blocklist', 'trusted_proxies' ) as $key ) {
			$list = Request::parse_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' );

			$rejected['invalid'] = array_merge( $rejected['invalid'], $list['invalid'] );
			$clean[ $key ]       = $list['valid'];
		}

		if ( $own_ip ) {
			foreach ( $clean['ip_blocklist'] as $i => $entry ) {
				if ( Request::ip_matches( $own_ip, array( $entry ) ) ) {
					$rejected['self'][] = $entry;
					unset( $clean['ip_blocklist'][ $i ] );
				}
			}
			$clean['ip_blocklist'] = array_values( $clean['ip_blocklist'] );
		}

		$agents                = Server::parse_agents( isset( $input['ua_blocklist'] ) ? (string) $input['ua_blocklist'] : '', Request::server( 'HTTP_USER_AGENT' ) );
		$clean['ua_blocklist'] = $agents['valid'];
		$rejected['agent']     = $agents['self'];

		self::store( $clean );

		// Never let the person saving block their own country.
		$country = Geo::country();
		if ( $country ) {
			$listed = in_array( $country, $clean['country_list'], true );
			if ( 'allow' === $clean['country_mode'] && ! $listed ) {
				$clean['country_list'][] = $country;
				$rejected['country']     = $country;
			} elseif ( 'block' === $clean['country_mode'] && $listed ) {
				$clean['country_list'] = array_values( array_diff( $clean['country_list'], array( $country ) ) );
				$rejected['country']   = $country;
			}
			if ( isset( $rejected['country'] ) ) {
				self::store( $clean );
			}
		}
		return $rejected;
	}

	/**
	 * Adds one IP to the block list.
	 *
	 * @param string $ip IP address.
	 */
	public static function block_ip( $ip ) {
		$clean = self::all();
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) && ! in_array( $ip, $clean['ip_blocklist'], true ) ) {
			$clean['ip_blocklist'][] = $ip;
			self::store( $clean );
		}
	}

	/**
	 * Takes an exact IP off the block list and, if asked, adds it to the allow list.
	 *
	 * @param string $ip     IP address.
	 * @param bool   $always Also add it to the allow list.
	 */
	public static function unblock_ip( $ip, $always = false ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}
		$clean                 = self::all();
		$clean['ip_blocklist'] = array_values( array_diff( (array) $clean['ip_blocklist'], array( $ip ) ) );
		if ( $always && ! in_array( $ip, (array) $clean['ip_allowlist'], true ) ) {
			$clean['ip_allowlist'][] = $ip;
		}
		self::store( $clean );
	}

	/**
	 * Saves a full settings array.
	 *
	 * @param array $settings Settings.
	 * @return array
	 */
	private static function store( array $settings ) {
		$before = self::all();
		if ( $settings !== $before ) {
			Restore_Points::before_settings_change();
		}
		Network::update_option( self::OPTION, $settings );
		self::$cache = null;
		$after       = self::all();
		$off         = array();
		foreach ( self::modules() as $key => $module ) {
			if ( ! empty( $before[ $key ] ) && empty( $after[ $key ] ) ) {
				$off[] = $module['label'];
			}
		}
		if ( $off ) {
			Events::add(
				'settings',
				/* translators: %s: list of protections. */
				sprintf( __( 'Protection switched off: %s.', 'chaos-shield' ), implode( ', ', $off ) ),
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => 'settings.weakened',
				)
			);
		}
		return $after;
	}

	/**
	 * Clamps an integer input.
	 *
	 * @param array  $input Raw input.
	 * @param string $key   Key.
	 * @param int    $min   Minimum.
	 * @param int    $max   Maximum.
	 * @return int
	 */
	private static function bounded_int( array $input, $key, $min, $max ) {
		$value = isset( $input[ $key ] ) ? absint( $input[ $key ] ) : self::defaults()[ $key ];
		return max( $min, min( $max, $value ) );
	}
}
