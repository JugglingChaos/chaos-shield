<?php
/**
 * Plugin bootstrap.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Wires every module together.
 */
final class Plugin {

	/**
	 * Singleton instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Returns the shared instance.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Registers hooks for all modules.
	 */
	public function boot() {
		Network::migrate();
		// Creates the log table on first run and after updates, where activation hooks do not fire.
		Events::maybe_install();
		Incidents::maybe_install();

		// The firewall and hardening run while the plugin loads so they cover the whole request.
		// Traffic goes first so it also records the requests the others stop.
		( new Traffic() )->register();
		// Detection listens to events, so it is ready before the modules that log them.
		( new Detect() )->register();
		( new Siem() )->register();
		( new Help() )->register();
		( new Firewall() )->register();
		( new Threat_Feed() )->register();
		( new Bans() )->register();
		( new Login_Url() )->register();
		( new Rate_Limit() )->register();
		( new Attack_Mode() )->register();
		( new Https() )->register();
		( new Scripts() )->register();
		( new Page_Check() )->register();
		( new Cloudflare() )->register();
		( new Edge() )->register();
		( new Geo() )->register();
		( new Geo_Db() )->register();
		( new Hardening() )->register();
		( new Server() )->register();
		( new Reputation() )->register();
		( new Login_Guard() )->register();
		( new Two_Factor() )->register();
		( new Passkeys() )->register();
		( new Passwords() )->register();
		( new Password_Policy() )->register();
		( new Accounts() )->register();
		( new Audit() )->register();
		( new Forwarder() )->register();
		( new Export() )->register();
		( new Uptime() )->register();
		( new Captcha() )->register();
		( new Comments() )->register();
		( new Connections() )->register();
		( new Monitor() )->register();
		( new Scanner() )->register();
		( new Integrity() )->register();
		( new Vulns() )->register();
		( new Restore_Points() )->register();
		( new Api() )->register();
		if ( class_exists( __NAMESPACE__ . '\\Updater' ) ) {
			( new Updater() )->register();
		}
		add_action( self::DAILY, array( $this, 'daily' ) );
		add_action( 'init', array( $this, 'schedule' ) );

		if ( is_admin() ) {
			( new Admin() )->register();
		}
	}

	const DAILY = 'cshield_daily';

	/**
	 * Makes sure the daily job is scheduled.
	 */
	public function schedule() {
		if ( ! Network::on_main_site() ) {
			// Before 1.7 each site of a network ran its own jobs. Now the main site runs them once.
			if ( wp_next_scheduled( self::DAILY ) ) {
				self::clear_jobs_here();
			}
			return;
		}
		if ( ! Network::next_scheduled( self::DAILY ) ) {
			Network::schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::DAILY );
		}
	}

	/**
	 * Daily housekeeping: trims the log, sends the weekly report and starts a scheduled scan when one is due.
	 */
	public function daily() {
		Events::prune( (int) Settings::get( 'log_retention' ) );
		Incidents::prune();
		Restore_Points::prune();
		Help::prune();
		Page_Check::schedule();
		Report::maybe_send();
		if ( ! Settings::enabled( 'threat_feed' ) && Network::get_option( Threat_Feed::OPTION ) ) {
			Threat_Feed::forget();
		}
		if ( ! Geo_Db::enabled() && Network::get_option( Geo_Db::STATUS ) ) {
			Geo_Db::forget();
		}
		// Network lookups run in their own cron requests.
		if ( Vulns::enabled() && ! Network::next_scheduled( Vulns::REFRESH_HOOK ) ) {
			Network::schedule_single( time() + 120, Vulns::REFRESH_HOOK );
		}

		$schedule = Settings::get( 'scan_schedule' );
		if ( 'off' === $schedule || Scanner::running() ) {
			return;
		}
		$last = Scanner::results();
		$age  = $last ? time() - (int) $last['finished'] : PHP_INT_MAX;
		if ( 'daily' === $schedule || $age > 6 * DAY_IN_SECONDS ) {
			Scanner::start( 'scheduled' );
		}
	}

	/**
	 * Activation: store defaults without overwriting existing choices.
	 *
	 * @param bool $network_wide Whether the plugin is being network activated.
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() && ! $network_wide ) {
			// One site's firewall and login limits cannot protect a network that shares
			// its users and files, so the plugin runs for the whole network or not at all.
			wp_die(
				esc_html__( 'Chaos Shield protects the whole network, so it has to be network activated. Go to Network Admin, Plugins, and choose Network Activate.', 'chaos-shield' ),
				esc_html__( 'Network activation needed', 'chaos-shield' ),
				array( 'back_link' => true )
			);
		}
		if ( $network_wide ) {
			// WordPress records the network activation only after this runs.
			Network::assume( true );
		}
		if ( false === Network::get_option( Settings::OPTION ) ) {
			Network::add_option( Settings::OPTION, Settings::defaults() );
		}
		Events::install();
		Events::add( 'system', __( 'Chaos Shield activated.', 'chaos-shield' ) );
	}

	/**
	 * Deactivation: stops background jobs. Settings and logs stay until uninstall.
	 */
	public static function deactivate() {
		// Bans stop with the plugin, so they come off Cloudflare too; the connection stays.
		Cloudflare::release_edge();
		self::clear_jobs_here();
		if ( is_multisite() ) {
			Network::on_main( array( __CLASS__, 'clear_jobs_here' ) );
		}
	}

	/**
	 * Removes this site's scheduled jobs.
	 */
	public static function clear_jobs_here() {
		wp_unschedule_hook( self::DAILY );
		wp_unschedule_hook( Scanner::CRON_STEP );
		wp_unschedule_hook( Bans::ALERT_EVENT );
		wp_unschedule_hook( Vulns::REFRESH_HOOK );
		wp_unschedule_hook( Forwarder::HOOK );
		wp_unschedule_hook( Uptime::HOOK );
		wp_unschedule_hook( Threat_Feed::HOOK );
		wp_unschedule_hook( Geo_Db::HOOK );
		wp_unschedule_hook( Integrity::HOOK );
		wp_unschedule_hook( Help::NOTIFY );
		wp_unschedule_hook( Page_Check::HOOK );
		wp_unschedule_hook( Attack_Mode::EVENT );
		wp_unschedule_hook( Cloudflare::HOOK );
	}
}
