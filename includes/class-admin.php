<?php
/**
 * Admin dashboard.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Registers the admin page and handles its form actions.
 */
final class Admin {

	const SLUG = 'chaos-shield';
	const CAP  = 'manage_options';

	/**
	 * Admin page hook suffix.
	 *
	 * @var string
	 */
	private $hook = '';

	/**
	 * Registers hooks.
	 */
	public function register() {
		// Network activated, the screens live in Network Admin and site admins do not see them.
		add_action( Network::active() ? 'network_admin_menu' : 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_cshield_save', array( $this, 'handle_save' ) );
		add_action( 'admin_post_cshield_recommended', array( $this, 'handle_recommended' ) );
		add_action( 'admin_post_cshield_release', array( $this, 'handle_release' ) );
		add_action( 'admin_post_cshield_access', array( $this, 'handle_access' ) );
		add_action( 'admin_post_cshield_block', array( $this, 'handle_block' ) );
		add_action( 'admin_post_cshield_alerts', array( $this, 'handle_alerts' ) );
		add_action( 'admin_post_cshield_ignore', array( $this, 'handle_ignore' ) );
		add_action( 'wp_ajax_cshield_scan', array( $this, 'ajax_scan' ) );
		add_action( 'admin_post_cshield_hub', array( $this, 'handle_hub' ) );
		add_action( 'admin_post_cshield_vulns', array( $this, 'handle_vulns' ) );
		add_action( 'admin_post_cshield_session', array( $this, 'handle_session' ) );
		add_action( 'admin_post_cshield_cleanup', array( $this, 'handle_cleanup' ) );
		add_action( Network::active() ? 'wp_network_dashboard_setup' : 'wp_dashboard_setup', array( $this, 'dashboard_widget' ) );
		if ( is_multisite() && ! Network::active() ) {
			add_action( 'admin_notices', array( $this, 'network_notice' ) );
		}
		add_filter( ( Network::active() ? 'network_admin_' : '' ) . 'plugin_action_links_' . plugin_basename( CSHIELD_FILE ), array( $this, 'action_links' ) );
	}

	/**
	 * Adds the top-level menu.
	 */
	public function menu() {
		$this->hook = add_menu_page(
			__( 'Chaos Shield', 'chaos-shield' ),
			__( 'Chaos Shield', 'chaos-shield' ),
			Network::cap(),
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield',
			80
		);
	}

	/**
	 * Loads CSS and JS on the plugin page only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function assets( $hook ) {
		if ( $hook !== $this->hook ) {
			return;
		}
		wp_enqueue_style( 'cshield-admin', CSHIELD_URL . 'assets/css/admin.css', array(), CSHIELD_VERSION );
		wp_enqueue_script( 'cshield-admin', CSHIELD_URL . 'assets/js/admin.js', array(), CSHIELD_VERSION, true );
		wp_localize_script(
			'cshield-admin',
			'cshieldAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'cshield_scan' ),
				'traffic' => wp_create_nonce( 'cshield_traffic' ),
				'connect' => wp_create_nonce( Connections::AJAX ),
				'i18n'    => array(
					'checking'   => __( 'Checking with the service...', 'chaos-shield' ),
					'back'       => __( 'Welcome back. Paste what you copied, then choose Check and connect.', 'chaos-shield' ),
					'domain'     => __( 'The service does not allow this site yet. Add this hostname to the widget there, then try again.', 'chaos-shield' ),
					'badKey'     => __( 'The service did not recognise that site key.', 'chaos-shield' ),
					'passed'     => __( 'Challenge passed. Both keys will be checked together.', 'chaos-shield' ),
					'failedCall' => __( 'The request did not go through. Check your connection and try again.', 'chaos-shield' ),
					'remove'     => __( 'Disconnect this service? Its keys or address are deleted from this site.', 'chaos-shield' ),
					'sending'    => __( 'Sending...', 'chaos-shield' ),
					'preparing'  => __( 'Preparing file list...', 'chaos-shield' ),
					/* translators: 1: files done, 2: total files. */
					'progress'   => __( 'Checked %1$s of %2$s files', 'chaos-shield' ),
					'failed'     => __( 'The scan stopped unexpectedly. Reload the page to continue it.', 'chaos-shield' ),
				),
			)
		);
	}

	/**
	 * Starts or advances a scan from the dashboard.
	 */
	public function ajax_scan() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_send_json_error( null, 403 );
		}
		check_ajax_referer( 'cshield_scan' );
		$op = isset( $_POST['op'] ) ? sanitize_key( $_POST['op'] ) : 'step';
		if ( 'start' === $op && ! Scanner::running() ) {
			Scanner::start( 'manual' );
			wp_send_json_success( Scanner::progress() );
		}
		wp_send_json_success( Scanner::step( 8 ) );
	}

	/**
	 * Hub actions: create or revoke this site's key, connect, refresh or remove a site.
	 */
	public function handle_hub() {
		$this->require_cap();
		check_admin_referer( 'cshield_hub' );
		$op = isset( $_POST['op'] ) ? sanitize_key( $_POST['op'] ) : '';
		$id = isset( $_POST['site'] ) ? sanitize_key( wp_unslash( $_POST['site'] ) ) : '';

		switch ( $op ) {
			case 'new_key':
				// Shown once on the next page load, then only its hash remains.
				$manage = ! empty( $_POST['manage'] );
				Network::set_transient( 'cshield_new_key_' . get_current_user_id(), Api::new_key( $manage ), 5 * MINUTE_IN_SECONDS );
				Events::add(
					'settings',
					$manage
						? __( 'A new hub key was created that lets the hub run scans, release bans and push settings. Any old key stopped working.', 'chaos-shield' )
						: __( 'A new read-only hub key was created. Any old key stopped working.', 'chaos-shield' ),
					Request::ip(),
					array( 'severity' => Events::NOTICE )
				);
				$this->done( 'hub', 'key_created' );
				break;
			case 'revoke_key':
				Api::revoke_key();
				Events::add( 'settings', __( 'The hub key was revoked.', 'chaos-shield' ), Request::ip() );
				$this->done( 'hub', 'key_revoked' );
				break;
			case 'add':
				$url    = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';
				$key    = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
				$name   = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
				$result = Hub::add( $url, $key, $name );
				if ( is_wp_error( $result ) ) {
					Network::set_transient( 'cshield_hub_error_' . get_current_user_id(), $result->get_error_message(), MINUTE_IN_SECONDS );
					$this->done( 'hub', 'hub_error' );
				}
				/* translators: %s: site address. */
				Events::add( 'settings', sprintf( __( 'Hub site connected: %s', 'chaos-shield' ), $url ), Request::ip() );
				$this->done( 'hub', 'site_added' );
				break;
			case 'refresh':
				foreach ( array_keys( Hub::sites() ) as $site ) {
					Hub::status( $site, true );
				}
				$this->done( 'hub', 'refreshed' );
				break;
			case 'remove':
				Hub::remove( $id );
				Uptime::forget( $id );
				$this->done( 'hub', 'site_removed' );
				break;
			case 'act':
			case 'act_all':
				$action = isset( $_POST['hub_action'] ) ? sanitize_key( wp_unslash( $_POST['hub_action'] ) ) : '';
				if ( ! isset( Hub::actions()[ $action ] ) ) {
					$this->done( 'hub', '' );
				}
				$uid = get_current_user_id();
				if ( 'act' === $op ) {
					$result = Hub::act( $id, $action );
					if ( is_wp_error( $result ) ) {
						Network::set_transient( 'cshield_hub_error_' . $uid, $result->get_error_message(), MINUTE_IN_SECONDS );
						$this->done( 'hub', 'hub_error' );
					}
					$this->done( 'hub', 'hub_done' );
				}
				$summary = Hub::act_all( $action );
				if ( $summary['failed'] ) {
					$lines = array();
					foreach ( $summary['failed'] as $name => $message ) {
						$lines[] = $name . ': ' . $message;
					}
					/* translators: 1: number of sites done, 2: list of failures. */
					Network::set_transient( 'cshield_hub_error_' . $uid, sprintf( __( 'Done on %1$d sites. Failed on: %2$s', 'chaos-shield' ), $summary['ok'], implode( '; ', $lines ) ), MINUTE_IN_SECONDS );
					$this->done( 'hub', 'hub_error' );
				}
				$this->done( 'hub', 'hub_done' );
				break;
			case 'uptime':
				Uptime::check_all( true );
				$this->done( 'hub', 'uptime_checked' );
				break;
		}
		$this->done( 'hub', '' );
	}

	/**
	 * Asks for network activation on a network where the plugin runs on one site,
	 * as it could before 1.7.
	 */
	public function network_notice() {
		$screen = get_current_screen();
		if ( ! current_user_can( 'manage_network_plugins' ) || ! $screen || ! in_array( $screen->id, array( 'plugins', 'toplevel_page_' . self::SLUG ), true ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
			esc_html__( 'Chaos Shield:', 'chaos-shield' ),
			esc_html__( 'This network shares its users, login and files, but Chaos Shield only protects this site. Network activate it to protect every site with one set of settings and one log. Each site keeps its current settings until then.', 'chaos-shield' ),
			esc_url( network_admin_url( 'plugins.php' ) ),
			esc_html__( 'Open network plugins', 'chaos-shield' )
		);
	}

	/**
	 * Adds the security summary to the main WordPress dashboard.
	 */
	public function dashboard_widget() {
		if ( current_user_can( Network::cap() ) ) {
			wp_add_dashboard_widget( 'cshield_widget', __( 'Chaos Shield', 'chaos-shield' ), array( $this, 'render_widget' ) );
		}
	}

	/**
	 * Prints the dashboard widget.
	 */
	public function render_widget() {
		$checks = Posture::checks();
		$score  = Posture::score( $checks );
		$band   = self::band( $score );
		$issues = array_values(
			array_filter(
				$checks,
				static function ( $c ) {
					return Posture::FAIL === $c['status'];
				}
			)
		);
		$stats  = Login_Guard::stats();
		$colors = array(
			'good' => '#0a8f62',
			'fair' => '#b57900',
			'poor' => '#c62828',
		);
		?>
		<div class="cshield-widget" style="display:flex;gap:16px;align-items:center">
			<div style="flex:none;width:64px;height:64px;border-radius:50%;border:6px solid <?php echo esc_attr( $colors[ $band ] ); ?>;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700"><?php echo esc_html( $score ); ?></div>
			<div>
				<p style="margin:0 0 4px"><strong><?php esc_html_e( 'Security score', 'chaos-shield' ); ?></strong></p>
				<p style="margin:0">
					<?php
					printf(
						/* translators: 1: failed logins, 2: firewall blocks. */
						esc_html__( 'Last 24 hours: %1$s failed logins, %2$s firewall blocks.', 'chaos-shield' ),
						esc_html( number_format_i18n( $stats['failed_logins'] ) ),
						esc_html( number_format_i18n( $stats['firewall_blocks'] ) )
					);
					?>
				</p>
			</div>
		</div>
		<?php if ( $issues ) : ?>
			<ul style="margin:12px 0 0;list-style:disc;padding-left:18px">
				<?php foreach ( array_slice( $issues, 0, 3 ) as $issue ) : ?>
					<li><?php echo esc_html( $issue['label'] ); ?></li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>
		<p style="margin:12px 0 0"><a class="button" href="<?php echo esc_url( self::url() ); ?>"><?php esc_html_e( 'Open Chaos Shield', 'chaos-shield' ); ?></a></p>
		<?php
	}

	/**
	 * Saves the alerts form.
	 */
	public function handle_alerts() {
		$this->require_cap();
		check_admin_referer( 'cshield_alerts' );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each field is validated in Settings::save_alerts().
		$input = isset( $_POST['cshield'] ) && is_array( $_POST['cshield'] ) ? wp_unslash( $_POST['cshield'] ) : array();
		Settings::save_alerts( $input );
		Events::add( 'settings', __( 'Alert, log and forwarding settings updated.', 'chaos-shield' ), Request::ip() );
		if ( Settings::$errors ) {
			Network::set_transient( 'cshield_alerts_error_' . get_current_user_id(), implode( ' ', Settings::$errors ), MINUTE_IN_SECONDS );
		}

		if ( ! empty( $_POST['cshield_test_forward'] ) ) {
			$this->done( 'alerts', true === Forwarder::test() ? 'fwd_ok' : 'fwd_failed' );
		}

		if ( ! empty( $_POST['cshield_test_email'] ) ) {
			$sent = wp_mail(
				Settings::alert_email(),
				sprintf( '[%s] %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), __( 'Chaos Shield test alert', 'chaos-shield' ) ),
				__( 'This is a test. Chaos Shield alerts from this site will arrive at this address.', 'chaos-shield' )
			);
			$this->done( 'alerts', $sent ? 'test_sent' : 'test_failed' );
		}
		if ( ! empty( $_POST['cshield_send_report'] ) ) {
			$this->done( 'alerts', Report::send() ? 'report_sent' : 'test_failed' );
		}
		$this->done( 'alerts', 'saved' );
	}

	/**
	 * Quarantine, restore, delete, core repair and the database scan.
	 */
	public function handle_cleanup() {
		$this->require_cap();
		check_admin_referer( 'cshield_cleanup' );
		$op      = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$finding = isset( $_POST['finding'] ) ? sanitize_key( wp_unslash( $_POST['finding'] ) ) : '';
		$qid     = isset( $_POST['qid'] ) ? sanitize_key( wp_unslash( $_POST['qid'] ) ) : '';
		$result  = true;
		$notices = array(
			'quarantine' => 'quarantined',
			'repair'     => 'repaired',
			'restore'    => 'restored',
			'delete'     => 'q_deleted',
			'dbscan'     => 'db_scanned',
		);
		if ( 'quarantine' === $op ) {
			$result = Cleanup::quarantine( $finding );
		} elseif ( 'repair' === $op ) {
			$result = Cleanup::repair_core( $finding );
		} elseif ( 'restore' === $op ) {
			$result = Cleanup::restore( $qid );
		} elseif ( 'delete' === $op ) {
			Cleanup::delete( $qid );
		} elseif ( 'dbscan' === $op ) {
			Cleanup::scan_database();
		}
		if ( is_wp_error( $result ) ) {
			Network::set_transient( 'cshield_error_' . get_current_user_id(), $result->get_error_message(), MINUTE_IN_SECONDS );
			$this->done( 'scan', '' );
		}
		$this->done( 'scan', isset( $notices[ $op ] ) ? $notices[ $op ] : '' );
	}

	/**
	 * Signs out one administrator session.
	 */
	public function handle_session() {
		$this->require_cap();
		check_admin_referer( 'cshield_session' );
		$user    = isset( $_POST['user'] ) ? absint( $_POST['user'] ) : 0;
		$session = isset( $_POST['session'] ) ? sanitize_key( wp_unslash( $_POST['session'] ) ) : '';
		$target  = get_userdata( $user );
		if ( $target && Sessions::end( $user, $session ) ) {
			/* translators: %s: username. */
			Events::add( 'user', sprintf( __( 'A session of %s was signed out from the dashboard.', 'chaos-shield' ), $target->user_login ), Request::ip(), array( 'user_id' => $user ) );
		}
		$this->done( 'activity', 'session_end' );
	}

	/**
	 * Checks for known vulnerabilities now.
	 */
	public function handle_vulns() {
		$this->require_cap();
		check_admin_referer( 'cshield_vulns' );
		if ( ! Vulns::enabled() ) {
			$this->done( 'scan', '' );
		}
		Vulns::clear_cache();
		$result = Vulns::refresh( 20 );
		if ( is_wp_error( $result ) ) {
			Network::set_transient( 'cshield_vuln_error_' . get_current_user_id(), $result->get_error_message(), MINUTE_IN_SECONDS );
			$this->done( 'scan', '' );
		}
		if ( false === $result ) {
			// The rest runs in the background.
			Network::schedule_single( time() + 5, Vulns::REFRESH_HOOK );
			$this->done( 'scan', 'vuln_partial' );
		}
		$this->done( 'scan', 'vuln_checked' );
	}

	/**
	 * Marks a scan finding as reviewed, or clears all reviewed marks.
	 */
	public function handle_ignore() {
		$this->require_cap();
		check_admin_referer( 'cshield_ignore' );
		$id = isset( $_POST['finding'] ) ? sanitize_key( wp_unslash( $_POST['finding'] ) ) : '';
		if ( 'all' === $id ) {
			Scanner::unignore_all();
			$this->done( 'scan', 'unignored' );
		}
		if ( Scanner::ignore( $id ) ) {
			Events::add( 'scan', __( 'A scan finding was marked as reviewed.', 'chaos-shield' ), Request::ip() );
		}
		$this->done( 'scan', 'ignored' );
	}

	/**
	 * Adds a Dashboard link on the Plugins screen.
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function action_links( $links ) {
		array_unshift(
			$links,
			sprintf( '<a href="%s">%s</a>', esc_url( self::url() ), esc_html__( 'Dashboard', 'chaos-shield' ) )
		);
		return $links;
	}

	/**
	 * URL of a dashboard tab.
	 *
	 * @param string $tab  Tab key.
	 * @param array  $args Extra query args.
	 * @return string
	 */
	public static function url( $tab = 'overview', array $args = array() ) {
		return add_query_arg(
			array_merge(
				array(
					'page' => self::SLUG,
					'tab'  => $tab,
				),
				$args
			),
			Network::admin_url( 'admin.php' )
		);
	}

	/**
	 * Saves the hardening form.
	 */
	public function handle_save() {
		$this->require_cap();
		check_admin_referer( 'cshield_save' );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each field is validated in Settings::save_hardening().
		$input = isset( $_POST['cshield'] ) && is_array( $_POST['cshield'] ) ? wp_unslash( $_POST['cshield'] ) : array();
		$tor   = (bool) Settings::get( 'threat_tor' );
		Settings::save_hardening( $input );
		if ( Settings::enabled( 'threat_feed' ) && ( (bool) Settings::get( 'threat_tor' ) !== $tor || ! Network::get_option( Threat_Feed::OPTION ) ) ) {
			// Download the changed lists in the background.
			Network::clear_scheduled( Threat_Feed::HOOK );
			Network::schedule_single( time() + 5, Threat_Feed::HOOK );
		}
		Captcha::save_secret( isset( $input['turnstile_secret'] ) ? (string) $input['turnstile_secret'] : '' );
		$login = Settings::save_login( $input );
		Events::add( 'settings', __( 'Hardening settings updated.', 'chaos-shield' ), Request::ip(), array( 'action' => 'settings.hardening' ) );
		if ( is_wp_error( $login ) ) {
			Network::set_transient( 'cshield_hardening_error_' . get_current_user_id(), $login->get_error_message(), MINUTE_IN_SECONDS );
			$this->done( 'hardening', '' );
		}
		if ( $login['old'] !== $login['new'] ) {
			$url = $login['new'] ? home_url( '/' . $login['new'] ) : site_url( 'wp-login.php' );
			/* translators: %s: login URL. */
			Events::add( 'settings', sprintf( __( 'Login address changed to %s.', 'chaos-shield' ), $url ), Request::ip(), array( 'severity' => Events::NOTICE ) );
			wp_mail(
				Settings::alert_email(),
				sprintf( '[%s] %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), __( 'Your login address changed', 'chaos-shield' ) ),
				sprintf(
					/* translators: 1: login URL, 2: constant name. */
					__( "The login page of this site is now:\n\n%1\$s\n\nBookmark it. wp-login.php and wp-admin now answer 404 to visitors who are not logged in. If you lose the address, add define( '%2\$s', true ); to wp-config.php to switch it off.", 'chaos-shield' ),
					$url,
					'CSHIELD_DISABLE_LOGIN_SLUG'
				)
			);
			$this->done( 'hardening', 'login_moved' );
		}
		$this->done( 'hardening', 'saved' );
	}

	/**
	 * Turns on every recommended module.
	 */
	public function handle_recommended() {
		$this->require_cap();
		check_admin_referer( 'cshield_recommended' );
		$settings = Settings::all();
		foreach ( Settings::modules() as $key => $module ) {
			if ( $module['default'] ) {
				$settings[ $key ] = true;
			}
		}
		Settings::save_hardening( $settings );
		Events::add( 'settings', __( 'Recommended hardening applied.', 'chaos-shield' ), Request::ip() );
		$this->done( 'hardening', 'recommended' );
	}

	/**
	 * Saves IP lists and proxy settings.
	 */
	public function handle_access() {
		$this->require_cap();
		check_admin_referer( 'cshield_access' );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each field is validated in Settings::save_access().
		$input    = isset( $_POST['cshield'] ) && is_array( $_POST['cshield'] ) ? wp_unslash( $_POST['cshield'] ) : array();
		$own_ip   = Request::ip();
		$rejected = Settings::save_access( $input, $own_ip );
		Request::reset();
		Events::add( 'settings', __( 'Access settings updated.', 'chaos-shield' ), Request::ip() );

		// Shown once on the next page load.
		Network::set_transient( 'cshield_access_rejected_' . get_current_user_id(), $rejected, MINUTE_IN_SECONDS );
		$this->done( 'access', 'saved' );
	}

	/**
	 * Moves a locked out IP onto the block list.
	 */
	public function handle_block() {
		$this->require_cap();
		check_admin_referer( 'cshield_block' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) && Request::ip() !== $ip ) {
			Settings::block_ip( $ip );
			Login_Guard::release( $ip );
			Bans::release( $ip );
			/* translators: %s: IP address. */
			Events::add( 'settings', sprintf( __( '%s added to the block list.', 'chaos-shield' ), $ip ), Request::ip() );
		}
		$this->done( isset( $_POST['back'] ) && 'traffic' === $_POST['back'] ? 'traffic' : 'activity', 'blocked' );
	}

	/**
	 * Releases one or all lockouts.
	 */
	public function handle_release() {
		$this->require_cap();
		check_admin_referer( 'cshield_release' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$ip = filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
		Login_Guard::release( $ip );
		Bans::release( $ip );
		Events::add(
			'settings',
			$ip
				/* translators: %s: IP address. */
				? sprintf( __( 'Lockout and ban released for %s.', 'chaos-shield' ), $ip )
				: __( 'All lockouts and bans released.', 'chaos-shield' ),
			Request::ip()
		);
		$this->done( 'activity', 'released' );
	}

	/**
	 * Stops the request unless the user may manage the plugin.
	 */
	private function require_cap() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to change Chaos Shield settings.', 'chaos-shield' ), 403 );
		}
	}

	/**
	 * Redirects back to a tab with a notice.
	 *
	 * @param string $tab    Tab key.
	 * @param string $notice Notice key.
	 */
	private function done( $tab, $notice ) {
		wp_safe_redirect( self::url( $tab, array( 'cshield_notice' => $notice ) ) );
		exit;
	}

	/**
	 * Renders the dashboard.
	 */
	public function render() {
		if ( ! current_user_can( Network::cap() ) ) {
			return;
		}
		$tabs = array(
			'overview'  => __( 'Overview', 'chaos-shield' ),
			'hardening' => __( 'Hardening', 'chaos-shield' ),
			'access'    => __( 'Access', 'chaos-shield' ),
			'firewall'  => __( 'Firewall', 'chaos-shield' ),
			'edge'      => __( 'Edge', 'chaos-shield' ),
			'scan'      => __( 'Scan', 'chaos-shield' ),
			'activity'  => __( 'Activity', 'chaos-shield' ),
			'siem'      => __( 'SIEM', 'chaos-shield' ),
			'traffic'   => __( 'Live traffic', 'chaos-shield' ),
			'alerts'    => __( 'Alerts', 'chaos-shield' ),
			'help'      => __( 'Visitor help', 'chaos-shield' ),
			'backups'   => __( 'Backups', 'chaos-shield' ),
			'hub'       => __( 'Hub', 'chaos-shield' ),
		);
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view state.
		$tab    = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'overview';
		$notice = isset( $_GET['cshield_notice'] ) ? sanitize_key( $_GET['cshield_notice'] ) : '';
		// phpcs:enable
		$tab = isset( $tabs[ $tab ] ) ? $tab : 'overview';

		$checks   = Posture::checks();
		$score    = Posture::score( $checks );
		$stats    = Login_Guard::stats();
		$lockouts = Login_Guard::lockouts();
		$modules  = Settings::modules();
		$on       = count( array_filter( array_keys( $modules ), array( Settings::class, 'enabled' ) ) );

		require CSHIELD_DIR . 'includes/views/dashboard.php';
	}

	/**
	 * Score band used for colours and wording.
	 *
	 * @param int $score Score.
	 * @return string good, fair or poor.
	 */
	public static function band( $score ) {
		if ( $score >= 80 ) {
			return 'good';
		}
		return $score >= 50 ? 'fair' : 'poor';
	}
}
