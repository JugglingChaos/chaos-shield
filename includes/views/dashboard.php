<?php
/**
 * Dashboard view.
 *
 * Variables come from Admin::render(): $tabs, $tab, $notice, $checks, $score,
 * $stats, $lockouts, $modules, $on.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_band    = Admin::band( $score );
$cshield_labels  = array(
	'good' => __( 'Well protected', 'chaos-shield' ),
	'fair' => __( 'Needs attention', 'chaos-shield' ),
	'poor' => __( 'At risk', 'chaos-shield' ),
);
$cshield_notices = array(
	'fw_learning'       => __( 'Learning mode is on for 7 days. Nothing is blocked by the firewall rules until then; check the hits below.', 'chaos-shield' ),
	'fw_allowed'        => __( 'Exception added. That rule no longer fires on that address and field.', 'chaos-shield' ),
	'fw_removed'        => __( 'Exception removed.', 'chaos-shield' ),
	'rp_created'        => __( 'Restore point saved.', 'chaos-shield' ),
	'help_saved'        => __( 'Visitor help saved.', 'chaos-shield' ),
	'edge_saved'        => __( 'Edge settings saved.', 'chaos-shield' ),
	'edge_checked'      => __( 'Pages checked: scripts, HTTPS, exposed files and keys.', 'chaos-shield' ),
	'edge_error'        => '',
	'attack_on'         => __( 'Under attack mode is on. Visitors who are not logged in see a short browser check.', 'chaos-shield' ),
	'attack_off'        => __( 'Under attack mode is off.', 'chaos-shield' ),
	'scripts_approve'   => __( 'Approved.', 'chaos-shield' ),
	'scripts_block'     => __( 'Blocked. With the policy set to Enforce, browsers refuse scripts from that domain.', 'chaos-shield' ),
	'scripts_forget'    => __( 'Removed from the list.', 'chaos-shield' ),
	'file_deleted'      => __( 'File deleted.', 'chaos-shield' ),
	'files_protected'   => __( 'Blocked in .htaccess. The home page still loads.', 'chaos-shield' ),
	'cf_synced'         => __( 'Cloudflare is up to date.', 'chaos-shield' ),
	'cf_purged'         => __( 'Cloudflare\'s cache is cleared.', 'chaos-shield' ),
	'cf_ip'             => __( 'Visitor IPs are now read from Cloudflare.', 'chaos-shield' ),
	'feed_new'          => __( 'New ban list address made. The old one no longer works.', 'chaos-shield' ),
	'help_allowed'      => __( 'Allowed. Their ban and lockout are lifted, and the blocked request will go through next time.', 'chaos-shield' ),
	'help_dismissed'    => __( 'Dismissed.', 'chaos-shield' ),
	'int_checked'       => __( 'Critical files checked.', 'chaos-shield' ),
	'int_accepted'      => __( 'Accepted. The current version is now the fingerprint to compare with.', 'chaos-shield' ),
	'int_restored'      => __( 'Put back. The version it replaced is saved as a restore point.', 'chaos-shield' ),
	'rp_restored'       => __( 'Restored. The state from just before is saved as a new restore point, in case you want it back.', 'chaos-shield' ),
	'rp_deleted'        => __( 'Restore point deleted.', 'chaos-shield' ),
	'settings_imported' => __( 'Settings imported. Your previous settings are saved as a restore point.', 'chaos-shield' ),
	'saved'             => __( 'Settings saved.', 'chaos-shield' ),
	'recommended'       => __( 'Recommended hardening is now on.', 'chaos-shield' ),
	'released'          => __( 'Lockouts and bans released.', 'chaos-shield' ),
	'report_sent'       => __( 'Weekly report sent. Check your inbox.', 'chaos-shield' ),
	'login_moved'       => __( 'Login address changed. It was also emailed to you: bookmark it before you log out.', 'chaos-shield' ),
	'session_end'       => __( 'Session signed out.', 'chaos-shield' ),
	'quarantined'       => __( 'File moved to quarantine. It can no longer run.', 'chaos-shield' ),
	'repaired'          => __( 'File replaced with the official copy from WordPress.org.', 'chaos-shield' ),
	'restored'          => __( 'File restored from quarantine.', 'chaos-shield' ),
	'q_deleted'         => __( 'Quarantined file deleted.', 'chaos-shield' ),
	'db_scanned'        => __( 'Database scan finished.', 'chaos-shield' ),
	'vuln_checked'      => __( 'Everything installed was checked against the vulnerability database.', 'chaos-shield' ),
	'vuln_partial'      => __( 'Vulnerability check started. The rest of your plugins and themes are being checked in the background.', 'chaos-shield' ),
	'blocked'           => __( 'IP added to the block list.', 'chaos-shield' ),
	'ignored'           => __( 'Finding marked as reviewed. It will come back if the file changes.', 'chaos-shield' ),
	'unignored'         => __( 'All reviewed findings are visible again.', 'chaos-shield' ),
	'test_sent'         => __( 'Settings saved and a test email was sent.', 'chaos-shield' ),
	'key_created'       => __( 'New hub key created. Copy it now: it will not be shown again.', 'chaos-shield' ),
	'key_revoked'       => __( 'Hub key revoked. No hub can read this site any more.', 'chaos-shield' ),
	'site_added'        => __( 'Site connected.', 'chaos-shield' ),
	'site_removed'      => __( 'Site removed from the hub.', 'chaos-shield' ),
	'refreshed'         => __( 'All sites refreshed.', 'chaos-shield' ),
	'test_failed'       => __( 'Settings saved, but the test email could not be sent. Check that this site can send email.', 'chaos-shield' ),
	'forced'            => sprintf(
		/* translators: %d: number of users. */
		_n( 'Password reset forced for %d user. They were signed out and will choose a new password at their next login.', 'Password reset forced for %d users. They were signed out and will choose a new password at their next login.', isset( $_GET['forced'] ) ? absint( $_GET['forced'] ) : 0, 'chaos-shield' ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		isset( $_GET['forced'] ) ? absint( $_GET['forced'] ) : 0 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
	),
	'hub_done'          => __( 'Hub action done.', 'chaos-shield' ),
	'incident_saved'    => __( 'Incident updated.', 'chaos-shield' ),
	'incident_acted'    => __( 'Response action done and noted on the incident.', 'chaos-shield' ),
	'incident_skipped'  => __( 'Nothing was done. Chaos Shield never bans an IP an administrator has logged in from, your own IP, or your own account.', 'chaos-shield' ),
	'uptime_checked'    => __( 'Uptime and certificates checked.', 'chaos-shield' ),
	'fwd_ok'            => __( 'Settings saved and a test event was delivered.', 'chaos-shield' ),
	'fwd_failed'        => __( 'Settings saved, but the test event could not be delivered. See the error under Log forwarding.', 'chaos-shield' ),
);
$cshield_issues  = array_values(
	array_filter(
		$checks,
		static function ( $check ) {
			return Posture::PASS !== $check['status'];
		}
	)
);
usort(
	$cshield_issues,
	static function ( $a, $b ) {
		return array( Posture::FAIL === $b['status'], $b['weight'] ) <=> array( Posture::FAIL === $a['status'], $a['weight'] );
	}
);
$cshield_status       = array(
	Posture::PASS => __( 'Pass', 'chaos-shield' ),
	Posture::WARN => __( 'Warning', 'chaos-shield' ),
	Posture::FAIL => __( 'Fail', 'chaos-shield' ),
);
$cshield_event_labels = array(
	'lockout'   => __( 'Lockout', 'chaos-shield' ),
	'settings'  => __( 'Settings', 'chaos-shield' ),
	'system'    => __( 'System', 'chaos-shield' ),
	'blocked'   => __( 'Firewall', 'chaos-shield' ),
	'twofactor' => __( 'Two-factor', 'chaos-shield' ),
	'login'     => __( 'Login', 'chaos-shield' ),
	'user'      => __( 'User', 'chaos-shield' ),
	'plugin'    => __( 'Plugin', 'chaos-shield' ),
	'theme'     => __( 'Theme', 'chaos-shield' ),
	'scan'      => __( 'Scan', 'chaos-shield' ),
	'ban'       => __( 'Ban', 'chaos-shield' ),
	'password'  => __( 'Password', 'chaos-shield' ),
	'vuln'      => __( 'Vulnerability', 'chaos-shield' ),
	'content'   => __( 'Content', 'chaos-shield' ),
	'option'    => __( 'Site setting', 'chaos-shield' ),
	'privacy'   => __( 'Privacy', 'chaos-shield' ),
	'incident'  => __( 'Incident', 'chaos-shield' ),
);
$cshield_date_format  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

/**
 * Prints the event table.
 *
 * @param array $events Events.
 * @param array $labels Type labels.
 * @param string $date_format Date format.
 */
$cshield_events_table = static function ( array $events, array $labels, $date_format ) {
	if ( ! $events ) {
		echo '<p class="cshield-empty">' . esc_html__( 'Nothing recorded yet. Logins, lockouts, scans and changes to users, plugins and settings will show up here.', 'chaos-shield' ) . '</p>';
		return;
	}
	// On a network, each event names the site it happened on.
	$sites = Network::active();
	echo '<table class="cshield-table cshield-table--events"><thead><tr><th>' . esc_html__( 'When', 'chaos-shield' ) . '</th>' . ( $sites ? '<th>' . esc_html__( 'Site', 'chaos-shield' ) . '</th>' : '' ) . '<th>' . esc_html__( 'Type', 'chaos-shield' ) . '</th><th>' . esc_html__( 'Event', 'chaos-shield' ) . '</th><th>' . esc_html__( 'User', 'chaos-shield' ) . '</th><th>' . esc_html__( 'IP', 'chaos-shield' ) . '</th></tr></thead><tbody>';
	$users = array();
	foreach ( $events as $event ) {
		$type = isset( $labels[ $event['type'] ] ) ? $labels[ $event['type'] ] : $event['type'];
		$uid  = isset( $event['user_id'] ) ? (int) $event['user_id'] : 0;
		if ( $uid && ! isset( $users[ $uid ] ) ) {
			$user          = get_userdata( $uid );
			$users[ $uid ] = $user ? $user->user_login : '#' . $uid;
		}
		printf(
			'<tr class="cshield-sev-%d"><td>%s</td>%s<td><span class="cshield-tag cshield-tag--%s">%s</span></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>',
			isset( $event['severity'] ) ? (int) $event['severity'] : 1,
			esc_html( wp_date( $date_format, $event['time'] ) ),
			$sites ? '<td>' . esc_html( ! empty( $event['blog_id'] ) ? Network::site_name( $event['blog_id'] ) : '-' ) . '</td>' : '',
			esc_attr( $event['type'] ),
			esc_html( $type ),
			esc_html( $event['message'] ),
			esc_html( $uid ? $users[ $uid ] : '-' ),
			esc_html( $event['ip'] ? $event['ip'] : '-' )
		);
	}
	echo '</tbody></table>';
};
?>
<div class="wrap cshield">
	<h1 class="screen-reader-text"><?php esc_html_e( 'Chaos Shield', 'chaos-shield' ); ?></h1>

	<header class="cshield-top">
		<div class="cshield-brand">
			<svg class="cshield-logo" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><path d="M16 2 4 6.5v8.2c0 7.3 5 13.4 12 15.3 7-1.9 12-8 12-15.3V6.5L16 2Z" fill="currentColor" opacity=".18"/><path d="M16 2 4 6.5v8.2c0 7.3 5 13.4 12 15.3 7-1.9 12-8 12-15.3V6.5L16 2Zm0 2.1 10 3.8v6.8c0 6.2-4.1 11.5-10 13.2-5.9-1.7-10-7-10-13.2V7.9l10-3.8Z" fill="currentColor"/><path d="m14.4 19.6-4-4 1.5-1.5 2.5 2.5 5.7-5.7 1.5 1.5-7.2 7.2Z" fill="currentColor"/></svg>
			<span class="cshield-name"><?php esc_html_e( 'Chaos Shield', 'chaos-shield' ); ?></span>
			<span class="cshield-pill"><?php echo esc_html( 'v' . CSHIELD_VERSION ); ?></span>
		</div>
		<div class="cshield-state cshield-state--<?php echo esc_attr( $cshield_band ); ?>">
			<span class="cshield-dot"></span><?php echo esc_html( $cshield_labels[ $cshield_band ] ); ?>
		</div>
	</header>

	<?php if ( ! empty( $cshield_notices[ $notice ] ) ) : ?>
		<div class="cshield-notice" role="status"><?php echo esc_html( $cshield_notices[ $notice ] ); ?></div>
	<?php endif; ?>
	<?php
	// A failed action leaves its reason for the next page load.
	$cshield_error = Network::get_transient( 'cshield_error_' . get_current_user_id() );
	if ( $cshield_error ) {
		Network::delete_transient( 'cshield_error_' . get_current_user_id() );
	}
	?>
	<?php if ( $cshield_error ) : ?>
		<div class="cshield-notice cshield-notice--warn" role="alert"><?php echo esc_html( $cshield_error ); ?></div>
	<?php endif; ?>

	<section class="cshield-hero">
		<div class="cshield-score cshield-score--<?php echo esc_attr( $cshield_band ); ?>" data-score="<?php echo esc_attr( $score ); ?>">
			<svg viewBox="0 0 120 120" aria-hidden="true" focusable="false">
				<circle class="cshield-score__track" cx="60" cy="60" r="52"/>
				<circle class="cshield-score__bar" cx="60" cy="60" r="52" pathLength="100" style="stroke-dasharray: <?php echo esc_attr( $score ); ?> 100"/>
			</svg>
			<div class="cshield-score__value"><strong><?php echo esc_html( $score ); ?></strong><span><?php esc_html_e( 'Security score', 'chaos-shield' ); ?></span></div>
		</div>
		<div class="cshield-tiles">
			<div class="cshield-tile">
				<span class="cshield-tile__label"><?php esc_html_e( 'Firewall blocks, 24h', 'chaos-shield' ); ?></span>
				<strong class="cshield-tile__value"><?php echo esc_html( number_format_i18n( $stats['firewall_blocks'] ) ); ?></strong>
			</div>
			<div class="cshield-tile">
				<span class="cshield-tile__label"><?php esc_html_e( 'Hardening on', 'chaos-shield' ); ?></span>
				<strong class="cshield-tile__value"><?php echo esc_html( $on . ' / ' . count( $modules ) ); ?></strong>
			</div>
			<div class="cshield-tile">
				<span class="cshield-tile__label"><?php esc_html_e( 'Failed logins, 24h', 'chaos-shield' ); ?></span>
				<strong class="cshield-tile__value"><?php echo esc_html( number_format_i18n( $stats['failed_logins'] ) ); ?></strong>
			</div>
			<div class="cshield-tile">
				<span class="cshield-tile__label"><?php esc_html_e( 'IPs locked out now', 'chaos-shield' ); ?></span>
				<strong class="cshield-tile__value"><?php echo esc_html( number_format_i18n( count( $lockouts ) ) ); ?></strong>
			</div>
		</div>
	</section>

	<nav class="cshield-tabs" aria-label="<?php esc_attr_e( 'Chaos Shield sections', 'chaos-shield' ); ?>">
		<?php foreach ( $tabs as $cshield_key => $cshield_label ) : ?>
			<a href="<?php echo esc_url( Admin::url( $cshield_key ) ); ?>" class="cshield-tab<?php echo $cshield_key === $tab ? ' is-active' : ''; ?>"<?php echo $cshield_key === $tab ? ' aria-current="page"' : ''; ?>><?php echo esc_html( $cshield_label ); ?></a>
		<?php endforeach; ?>
	</nav>

	<?php if ( 'overview' === $tab ) : ?>
		<?php
		$cshield_inc_sum = Incidents::summary();
		$cshield_urgent  = $cshield_inc_sum['by_severity'][ Incidents::CRITICAL ] + $cshield_inc_sum['by_severity'][ Incidents::HIGH ];
		?>
		<?php if ( $cshield_urgent ) : ?>
			<div class="cshield-notice cshield-notice--warn cshield-notice--incidents" role="status">
				<span>
					<?php
					/* translators: %d: number of incidents. */
					echo esc_html( sprintf( _n( '%d high or critical incident is open.', '%d high or critical incidents are open.', $cshield_urgent, 'chaos-shield' ), $cshield_urgent ) );
					?>
				</span>
				<a class="cshield-btn" href="<?php echo esc_url( Admin::url( 'siem' ) ); ?>"><?php esc_html_e( 'Review incidents', 'chaos-shield' ); ?></a>
			</div>
		<?php endif; ?>
		<div class="cshield-grid">
			<section class="cshield-card cshield-card--wide">
				<h2><?php esc_html_e( 'What to fix', 'chaos-shield' ); ?></h2>
				<?php if ( ! $cshield_issues ) : ?>
					<p class="cshield-empty"><?php esc_html_e( 'Every check passes. Nice work.', 'chaos-shield' ); ?></p>
				<?php else : ?>
					<ul class="cshield-checks">
						<?php foreach ( $cshield_issues as $cshield_check ) : ?>
							<li class="cshield-check cshield-check--<?php echo esc_attr( $cshield_check['status'] ); ?>">
								<span class="cshield-badge"><?php echo esc_html( $cshield_status[ $cshield_check['status'] ] ); ?></span>
								<div><strong><?php echo esc_html( $cshield_check['label'] ); ?></strong><p><?php echo esc_html( $cshield_check['detail'] ); ?></p></div>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			</section>

			<section class="cshield-card">
				<h2><?php esc_html_e( 'Passing', 'chaos-shield' ); ?></h2>
				<ul class="cshield-passlist">
					<?php foreach ( $checks as $cshield_check ) : ?>
						<?php if ( Posture::PASS === $cshield_check['status'] ) : ?>
							<li><?php echo esc_html( $cshield_check['label'] ); ?></li>
						<?php endif; ?>
					<?php endforeach; ?>
				</ul>
			</section>

			<section class="cshield-card cshield-card--full">
				<h2><?php esc_html_e( 'Recent activity', 'chaos-shield' ); ?></h2>
				<?php $cshield_events_table( Events::all( 5 ), $cshield_event_labels, $cshield_date_format ); ?>
			</section>
		</div>

	<?php elseif ( 'hardening' === $tab ) : ?>
		<?php
		$cshield_hard_error = Network::get_transient( 'cshield_hardening_error_' . get_current_user_id() );
		Network::delete_transient( 'cshield_hardening_error_' . get_current_user_id() );
		?>
		<?php if ( $cshield_hard_error ) : ?>
			<div class="cshield-notice cshield-notice--warn" role="alert"><?php echo esc_html( $cshield_hard_error ); ?></div>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form cshield-recommend">
			<input type="hidden" name="action" value="cshield_recommended">
			<?php wp_nonce_field( 'cshield_recommended' ); ?>
			<p><?php esc_html_e( 'Turn on every recommended protection in one click. Optional modules stay as they are.', 'chaos-shield' ); ?></p>
			<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Apply recommended', 'chaos-shield' ); ?></button>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="cshield_save">
			<?php wp_nonce_field( 'cshield_save' ); ?>
			<div class="cshield-modules">
				<?php foreach ( $modules as $cshield_key => $cshield_module ) : ?>
					<?php $cshield_id = 'cshield-' . $cshield_key; ?>
					<div class="cshield-module">
						<div class="cshield-module__text">
							<label for="<?php echo esc_attr( $cshield_id ); ?>"><?php echo esc_html( $cshield_module['label'] ); ?></label>
							<?php if ( ! $cshield_module['default'] ) : ?>
								<span class="cshield-tag"><?php esc_html_e( 'Optional', 'chaos-shield' ); ?></span>
							<?php endif; ?>
							<p><?php echo esc_html( $cshield_module['description'] ); ?></p>
						</div>
						<span class="cshield-switch">
							<input type="checkbox" role="switch" id="<?php echo esc_attr( $cshield_id ); ?>" name="cshield[<?php echo esc_attr( $cshield_key ); ?>]" value="1" <?php checked( Settings::enabled( $cshield_key ) ); ?>>
							<span class="cshield-switch__ui" aria-hidden="true"></span>
						</span>
					</div>
				<?php endforeach; ?>
			</div>

			<section class="cshield-card cshield-login-limits">
				<h2><?php esc_html_e( 'Login limits', 'chaos-shield' ); ?></h2>
				<div class="cshield-fields">
					<label><span><?php esc_html_e( 'Failed attempts allowed', 'chaos-shield' ); ?></span>
						<input type="number" min="2" max="50" name="cshield[login_max_attempts]" value="<?php echo esc_attr( Settings::get( 'login_max_attempts' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Within (minutes)', 'chaos-shield' ); ?></span>
						<input type="number" min="1" max="1440" name="cshield[login_window]" value="<?php echo esc_attr( Settings::get( 'login_window' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Lock out for (minutes)', 'chaos-shield' ); ?></span>
						<input type="number" min="1" max="10080" name="cshield[login_lockout]" value="<?php echo esc_attr( Settings::get( 'login_lockout' ) ); ?>"></label>
				</div>
			</section>

			<section class="cshield-card cshield-login-limits">
				<h2><?php esc_html_e( 'Bans', 'chaos-shield' ); ?></h2>
				<p class="cshield-small"><?php esc_html_e( 'A banned IP gets a 403 on every page. IPs on the allow list, IPs an administrator has logged in from, and verified Google and Bing crawlers are never banned. Ten firewall blocks in an hour also count as a ban.', 'chaos-shield' ); ?></p>
				<div class="cshield-fields">
					<label><span><?php esc_html_e( 'Ban after this many lockouts in 24 hours', 'chaos-shield' ); ?></span>
						<input type="number" min="2" max="20" name="cshield[autoban_strikes]" value="<?php echo esc_attr( Settings::get( 'autoban_strikes' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Missing pages in 5 minutes before a 404 ban', 'chaos-shield' ); ?></span>
						<input type="number" min="5" max="200" name="cshield[probe_404_limit]" value="<?php echo esc_attr( Settings::get( 'probe_404_limit' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Ban for (hours)', 'chaos-shield' ); ?></span>
						<input type="number" min="1" max="720" name="cshield[autoban_hours]" value="<?php echo esc_attr( Settings::get( 'autoban_hours' ) ); ?>"></label>
				</div>
			</section>

			<section class="cshield-card cshield-login-limits">
				<h2><?php esc_html_e( 'Rate limits (requests per minute per IP)', 'chaos-shield' ); ?></h2>
				<div class="cshield-fields cshield-fields--four">
					<label><span><?php esc_html_e( 'Login and XML-RPC', 'chaos-shield' ); ?></span>
						<input type="number" min="5" max="600" name="cshield[rate_login]" value="<?php echo esc_attr( Settings::get( 'rate_login' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'REST API and AJAX', 'chaos-shield' ); ?></span>
						<input type="number" min="20" max="6000" name="cshield[rate_api]" value="<?php echo esc_attr( Settings::get( 'rate_api' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Search', 'chaos-shield' ); ?></span>
						<input type="number" min="5" max="600" name="cshield[rate_search]" value="<?php echo esc_attr( Settings::get( 'rate_search' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'All pages', 'chaos-shield' ); ?></span>
						<input type="number" min="30" max="6000" name="cshield[rate_pages]" value="<?php echo esc_attr( Settings::get( 'rate_pages' ) ); ?>"></label>
				</div>
				<p class="cshield-small">
					<?php
					echo esc_html(
						wp_using_ext_object_cache()
							? __( 'Administrators and the allow list are never limited. An IP that hits a limit 5 times in an hour is banned.', 'chaos-shield' )
							: __( 'Administrators and the allow list are never limited. An IP that hits a limit 5 times in an hour is banned. The all pages limit needs a persistent object cache such as Redis, so it is not active on this site.', 'chaos-shield' )
					);
					?>
				</p>
			</section>

			<section class="cshield-card cshield-card--full cshield-pw-policy">
				<h2><?php esc_html_e( 'Password policy', 'chaos-shield' ); ?></h2>
				<div class="cshield-fields cshield-fields--four">
					<label><span><?php esc_html_e( 'Minimum length', 'chaos-shield' ); ?></span>
						<input type="number" min="8" max="64" name="cshield[pw_min_length]" value="<?php echo esc_attr( Settings::get( 'pw_min_length' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Kinds of characters (1 to 4)', 'chaos-shield' ); ?></span>
						<input type="number" min="1" max="4" name="cshield[pw_classes]" value="<?php echo esc_attr( Settings::get( 'pw_classes' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Applies to', 'chaos-shield' ); ?></span>
						<select name="cshield[pw_roles]">
							<option value="admins" <?php selected( Settings::get( 'pw_roles' ), 'admins' ); ?>><?php esc_html_e( 'Administrators', 'chaos-shield' ); ?></option>
							<option value="staff" <?php selected( Settings::get( 'pw_roles' ), 'staff' ); ?>><?php esc_html_e( 'Everyone who can write posts', 'chaos-shield' ); ?></option>
							<option value="all" <?php selected( Settings::get( 'pw_roles' ), 'all' ); ?>><?php esc_html_e( 'All users', 'chaos-shield' ); ?></option>
						</select></label>
					<label><span><?php esc_html_e( 'Expire after (days, 0 = never)', 'chaos-shield' ); ?></span>
						<input type="number" min="0" max="730" name="cshield[pw_max_age]" value="<?php echo esc_attr( Settings::get( 'pw_max_age' ) ); ?>"></label>
				</div>
				<p class="cshield-small">
					<?php
					echo esc_html(
						Settings::enabled( 'password_policy' )
							? Password_Policy::describe() . ' ' . __( 'Rules apply when a password is set or reset, and a password cannot contain the username or email.', 'chaos-shield' )
							: __( 'Switch on Password policy above for these rules to apply. Current NIST guidance favours length over forced expiry, so leave expiry at 0 unless a policy you follow requires it.', 'chaos-shield' )
					);
					?>
				</p>
				<?php $cshield_pending = Password_Policy::pending_count(); ?>
				<div class="cshield-actions cshield-actions--start">
					<a class="cshield-btn cshield-btn--ghost" href="
					<?php
					echo esc_url(
						wp_nonce_url(
							add_query_arg(
								array(
									'action' => 'cshield_force_reset',
									'group'  => 'admins',
								),
								admin_url( 'admin-post.php' )
							),
							'cshield_force_group'
						)
					);
					?>
																	" onclick="return confirm(<?php echo esc_attr( wp_json_encode( __( 'Sign out every other administrator and make them choose a new password?', 'chaos-shield' ) ) ); ?>)"><?php esc_html_e( 'Force a reset for all other administrators', 'chaos-shield' ); ?></a>
					<a class="cshield-btn cshield-btn--ghost" href="
					<?php
					echo esc_url(
						wp_nonce_url(
							add_query_arg(
								array(
									'action' => 'cshield_force_reset',
									'group'  => 'policy',
								),
								admin_url( 'admin-post.php' )
							),
							'cshield_force_group'
						)
					);
					?>
																	" onclick="return confirm(<?php echo esc_attr( wp_json_encode( __( 'Sign out everyone the policy covers, except you, and make them choose a new password?', 'chaos-shield' ) ) ); ?>)"><?php esc_html_e( 'Force a reset for everyone the policy covers', 'chaos-shield' ); ?></a>
				</div>
				<p class="cshield-small">
					<?php
					echo esc_html(
						$cshield_pending
							/* translators: %d: number of users. */
							? sprintf( _n( '%d user still has to choose a new password.', '%d users still have to choose a new password.', $cshield_pending, 'chaos-shield' ), $cshield_pending )
							: __( 'You can also force a reset for one user from the Users screen.', 'chaos-shield' )
					);
					?>
				</p>
			</section>

			<?php $cshield_tf = Threat_Feed::status(); ?>
			<section class="cshield-card cshield-login-limits">
				<h2><?php esc_html_e( 'Threat intelligence and traffic', 'chaos-shield' ); ?></h2>
				<label class="cshield-check-line"><input type="checkbox" name="cshield[threat_tor]" value="1" <?php checked( Settings::get( 'threat_tor' ) ); ?>> <?php esc_html_e( 'Also block Tor exit nodes', 'chaos-shield' ); ?></label>
				<p class="cshield-small"><?php esc_html_e( 'Tor hides who a visitor is. Most attacks through it are automated, but some real people use it for privacy, so this is off by default.', 'chaos-shield' ); ?></p>
				<p class="cshield-small">
					<?php
					if ( ! Settings::enabled( 'threat_feed' ) ) {
						esc_html_e( 'Switch on Threat intelligence blocklist above to use these lists.', 'chaos-shield' );
					} elseif ( $cshield_tf['updated'] ) {
						printf(
							/* translators: 1: number of networks, 2: date. */
							esc_html__( '%1$s networks blocked, lists updated %2$s.', 'chaos-shield' ),
							esc_html( number_format_i18n( array_sum( $cshield_tf['counts'] ) ) ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cshield_tf['updated'] ) )
						);
						if ( $cshield_tf['error'] ) {
							echo ' ' . esc_html( $cshield_tf['error'] );
						}
					} else {
						esc_html_e( 'The lists download in the background within a minute.', 'chaos-shield' );
					}
					?>
				</p>
				<div class="cshield-fields cshield-fields--one cshield-fields--spaced">
					<label><span><?php esc_html_e( 'Live traffic records', 'chaos-shield' ); ?></span>
						<select name="cshield[traffic_mode]">
							<option value="security" <?php selected( Settings::get( 'traffic_mode' ), 'security' ); ?>><?php esc_html_e( 'Security events only: blocks, logins, missing pages', 'chaos-shield' ); ?></option>
							<option value="all" <?php selected( Settings::get( 'traffic_mode' ), 'all' ); ?>><?php esc_html_e( 'Every visit (more database writes)', 'chaos-shield' ); ?></option>
						</select></label>
				</div>
			</section>

			<section class="cshield-card cshield-login-limits">
				<h2><?php esc_html_e( 'Login page', 'chaos-shield' ); ?></h2>
				<p>
					<?php
					/* translators: %s: login URL. */
					echo esc_html( sprintf( __( 'Your login page is %s', 'chaos-shield' ), Login_Url::url() ) );
					?>
				</p>
				<div class="cshield-fields cshield-fields--two">
					<label><span><?php esc_html_e( 'Custom login address (leave empty for wp-login.php)', 'chaos-shield' ); ?></span>
						<span class="cshield-prefixed"><code><?php echo esc_html( trailingslashit( home_url() ) ); ?></code><input type="text" name="cshield[login_slug]" value="<?php echo esc_attr( Settings::get( 'login_slug' ) ); ?>" placeholder="my-secret-door" pattern="[a-z0-9-]{6,}" spellcheck="false"></span></label>
				</div>
				<p class="cshield-small"><?php esc_html_e( 'With a custom address, wp-login.php and wp-admin answer 404 to anyone not logged in, so bots stop finding your login form. The new address is emailed to you. Forgot it? Add define( \'CSHIELD_DISABLE_LOGIN_SLUG\', true ); to wp-config.php.', 'chaos-shield' ); ?></p>
				<h3 class="cshield-subhead"><?php esc_html_e( 'Login CAPTCHA', 'chaos-shield' ); ?></h3>
				<?php
				$cshield_kind = 'captcha';
				require CSHIELD_DIR . 'includes/views/connections.php';
				?>
				<p class="cshield-small"><?php esc_html_e( 'Connecting checks the keys with the service and switches Login CAPTCHA on. If the service cannot be reached during a login, the login is allowed and the outage is logged, so you are never locked out.', 'chaos-shield' ); ?></p>
			</section>

			<div class="cshield-actions">
				<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save changes', 'chaos-shield' ); ?></button>
			</div>
		</form>

	<?php elseif ( 'access' === $tab ) : ?>
		<?php
		$cshield_rejected = Network::get_transient( 'cshield_access_rejected_' . get_current_user_id() );
		Network::delete_transient( 'cshield_access_rejected_' . get_current_user_id() );
		$cshield_detected = Request::detected_proxy_headers();
		$cshield_header   = (string) Settings::get( 'proxy_header' );
		?>
		<?php if ( ! empty( $cshield_rejected['invalid'] ) ) : ?>
			<div class="cshield-notice cshield-notice--warn" role="alert">
				<?php
				/* translators: %s: list of rejected entries. */
				echo esc_html( sprintf( __( 'These entries are not valid IP addresses or ranges and were skipped: %s', 'chaos-shield' ), implode( ', ', $cshield_rejected['invalid'] ) ) );
				?>
			</div>
		<?php endif; ?>
		<?php if ( ! empty( $cshield_rejected['country'] ) ) : ?>
			<div class="cshield-notice cshield-notice--warn" role="alert">
				<?php
				/* translators: %s: country code. */
				echo esc_html( sprintf( __( 'You are visiting from %s, so the country rule was adjusted to keep you from locking yourself out.', 'chaos-shield' ), $cshield_rejected['country'] ) );
				?>
			</div>
		<?php endif; ?>
		<?php if ( ! empty( $cshield_rejected['self'] ) ) : ?>
			<div class="cshield-notice cshield-notice--warn" role="alert">
				<?php
				/* translators: %s: list of entries. */
				echo esc_html( sprintf( __( 'These block list entries match your own IP, so they were left out to keep you from locking yourself out: %s', 'chaos-shield' ), implode( ', ', $cshield_rejected['self'] ) ) );
				?>
			</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="cshield_access">
			<?php wp_nonce_field( 'cshield_access' ); ?>
			<div class="cshield-grid cshield-grid--even">
				<section class="cshield-card">
					<h2><?php esc_html_e( 'Allow list', 'chaos-shield' ); ?></h2>
					<p><?php esc_html_e( 'These IPs are never locked out or blocked by the firewall. One IP or range per line, for example 203.0.113.7 or 203.0.113.0/24.', 'chaos-shield' ); ?></p>
					<textarea name="cshield[ip_allowlist]" rows="6" class="cshield-textarea" spellcheck="false"><?php echo esc_textarea( implode( "\n", (array) Settings::get( 'ip_allowlist' ) ) ); ?></textarea>
				</section>
				<section class="cshield-card">
					<h2><?php esc_html_e( 'Block list', 'chaos-shield' ); ?></h2>
					<p><?php esc_html_e( 'These IPs get a 403 on every page of the site. Your own IP is never accepted here.', 'chaos-shield' ); ?></p>
					<textarea name="cshield[ip_blocklist]" rows="6" class="cshield-textarea" spellcheck="false"><?php echo esc_textarea( implode( "\n", (array) Settings::get( 'ip_blocklist' ) ) ); ?></textarea>
				</section>
				<section class="cshield-card cshield-card--full">
					<h2><?php esc_html_e( 'Countries', 'chaos-shield' ); ?></h2>
					<p>
						<?php
						$cshield_country = Geo::country();
						echo esc_html(
							$cshield_country
								/* translators: %s: country code. */
								? sprintf( __( 'Switch on Country blocking under Hardening for these rules to apply. Your request comes from %s.', 'chaos-shield' ), $cshield_country )
								: __( 'Switch on Country blocking under Hardening for these rules to apply. No country is detected for your request with the current source.', 'chaos-shield' )
						);
						?>
					</p>
					<div class="cshield-fields cshield-fields--four">
						<label><span><?php esc_html_e( 'Country comes from', 'chaos-shield' ); ?></span>
							<select name="cshield[country_source]">
								<?php foreach ( Geo::sources() as $cshield_value => $cshield_text ) : ?>
									<option value="<?php echo esc_attr( $cshield_value ); ?>" <?php selected( Settings::get( 'country_source' ), $cshield_value ); ?>><?php echo esc_html( $cshield_text ); ?></option>
								<?php endforeach; ?>
							</select></label>
						<label><span><?php esc_html_e( 'Rule', 'chaos-shield' ); ?></span>
							<select name="cshield[country_mode]">
								<option value="block" <?php selected( Settings::get( 'country_mode' ), 'block' ); ?>><?php esc_html_e( 'Block the listed countries', 'chaos-shield' ); ?></option>
								<option value="allow" <?php selected( Settings::get( 'country_mode' ), 'allow' ); ?>><?php esc_html_e( 'Allow only the listed countries', 'chaos-shield' ); ?></option>
							</select></label>
						<label><span><?php esc_html_e( 'Applies to', 'chaos-shield' ); ?></span>
							<select name="cshield[country_scope]">
								<option value="login" <?php selected( Settings::get( 'country_scope' ), 'login' ); ?>><?php esc_html_e( 'Login page and XML-RPC only', 'chaos-shield' ); ?></option>
								<option value="site" <?php selected( Settings::get( 'country_scope' ), 'site' ); ?>><?php esc_html_e( 'The whole site', 'chaos-shield' ); ?></option>
							</select></label>
						<label><span><?php esc_html_e( 'Countries (two-letter codes)', 'chaos-shield' ); ?></span>
							<input type="text" name="cshield[country_list]" value="<?php echo esc_attr( implode( ', ', (array) Settings::get( 'country_list' ) ) ); ?>" placeholder="RU, CN, KP" spellcheck="false"></label>
					</div>
					<p class="cshield-small"><?php esc_html_e( 'Use ISO country codes, such as US, GB or DE. With Cloudflare, T1 means Tor. Logged-in users are not blocked from the site, and you cannot save a rule that blocks your own country.', 'chaos-shield' ); ?></p>
				</section>
				<section class="cshield-card cshield-card--full">
					<h2><?php esc_html_e( 'Visitor IP detection', 'chaos-shield' ); ?></h2>
					<p>
						<?php
						/* translators: %s: IP address. */
						echo esc_html( sprintf( __( 'Chaos Shield currently sees your IP as %s.', 'chaos-shield' ), Request::ip() ? Request::ip() : __( 'unknown', 'chaos-shield' ) ) );
						?>
					</p>
					<?php if ( $cshield_detected && ! $cshield_header ) : ?>
						<p class="cshield-hint">
							<?php
							/* translators: %s: header names. */
							echo esc_html( sprintf( __( 'This request passed through a proxy (%s was sent). If your site is behind Cloudflare or a load balancer, pick it below so lockouts target the real visitor and not the proxy.', 'chaos-shield' ), implode( ', ', array_keys( $cshield_detected ) ) ) );
							?>
						</p>
					<?php endif; ?>
					<div class="cshield-fields cshield-fields--two">
						<label><span><?php esc_html_e( 'Your site sits behind', 'chaos-shield' ); ?></span>
							<select name="cshield[proxy_header]">
								<?php foreach ( Settings::proxy_headers() as $cshield_value => $cshield_text ) : ?>
									<option value="<?php echo esc_attr( $cshield_value ); ?>" <?php selected( $cshield_header, $cshield_value ); ?>><?php echo esc_html( $cshield_text ); ?></option>
								<?php endforeach; ?>
							</select>
						</label>
						<label><span><?php esc_html_e( 'Trusted proxy IPs (optional)', 'chaos-shield' ); ?></span>
							<textarea name="cshield[trusted_proxies]" rows="3" class="cshield-textarea" spellcheck="false"><?php echo esc_textarea( implode( "\n", (array) Settings::get( 'trusted_proxies' ) ) ); ?></textarea>
						</label>
					</div>
					<p class="cshield-small"><?php esc_html_e( 'The proxy header is only believed when the connection comes from a trusted proxy, so a visitor who reaches your server directly cannot fake their address. With no list, private network addresses are trusted, and so are Cloudflare\'s published ranges for the Cloudflare header. List your proxy IPs or ranges if your proxy uses public addresses.', 'chaos-shield' ); ?></p>
					<?php $cshield_untrusted = Request::untrusted(); ?>
					<?php if ( $cshield_untrusted ) : ?>
						<p class="cshield-notice cshield-notice--warn">
							<?php
							/* translators: %s: IP address. */
							echo esc_html( sprintf( __( 'Your own request came from %1$s with the proxy header, but that address is not trusted, so the header was ignored and lockouts see the proxy instead of visitors. If %2$s is your proxy, add it to the trusted list.', 'chaos-shield' ), $cshield_untrusted, $cshield_untrusted ) );
							?>
						</p>
					<?php endif; ?>
				</section>
			</div>
			<div class="cshield-actions">
				<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save changes', 'chaos-shield' ); ?></button>
			</div>
		</form>

	<?php elseif ( 'scan' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-scan.php'; ?>

	<?php elseif ( 'alerts' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-alerts.php'; ?>

	<?php elseif ( 'siem' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-siem.php'; ?>
	<?php elseif ( 'traffic' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-traffic.php'; ?>

	<?php elseif ( 'firewall' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-firewall.php'; ?>
	<?php elseif ( 'edge' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-edge.php'; ?>
	<?php elseif ( 'help' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-help.php'; ?>
	<?php elseif ( 'backups' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-backups.php'; ?>
	<?php elseif ( 'hub' === $tab ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/tab-hub.php'; ?>

	<?php else : ?>
		<div class="cshield-grid">
			<section class="cshield-card cshield-card--full">
				<div class="cshield-card__head">
					<h2><?php esc_html_e( 'Locked out IPs', 'chaos-shield' ); ?></h2>

					<?php if ( $lockouts ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
							<input type="hidden" name="action" value="cshield_release">
							<?php wp_nonce_field( 'cshield_release' ); ?>
							<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Release all', 'chaos-shield' ); ?></button>
						</form>
					<?php endif; ?>
				</div>
				<?php if ( ! $lockouts ) : ?>
					<p class="cshield-empty"><?php esc_html_e( 'No IP addresses are locked out.', 'chaos-shield' ); ?></p>
				<?php else : ?>
					<table class="cshield-table">
						<thead><tr><th><?php esc_html_e( 'IP', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Locked until', 'chaos-shield' ); ?></th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $lockouts as $cshield_ip => $cshield_until ) : ?>
							<tr>
								<td><code><?php echo esc_html( $cshield_ip ); ?></code></td>
								<td><?php echo esc_html( wp_date( $cshield_date_format, $cshield_until ) ); ?></td>
								<td class="cshield-right">
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
										<input type="hidden" name="action" value="cshield_release">
										<input type="hidden" name="ip" value="<?php echo esc_attr( $cshield_ip ); ?>">
										<?php wp_nonce_field( 'cshield_release' ); ?>
										<button type="submit" class="cshield-link"><?php esc_html_e( 'Release', 'chaos-shield' ); ?></button>
									</form>
									<?php if ( Request::ip() !== $cshield_ip ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
											<input type="hidden" name="action" value="cshield_block">
											<input type="hidden" name="ip" value="<?php echo esc_attr( $cshield_ip ); ?>">
											<?php wp_nonce_field( 'cshield_block' ); ?>
											<button type="submit" class="cshield-link cshield-link--danger"><?php esc_html_e( 'Block permanently', 'chaos-shield' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</section>

			<?php $cshield_sessions = Sessions::admins(); ?>
			<section class="cshield-card cshield-card--full">
				<div class="cshield-card__head">
					<h2><?php esc_html_e( 'Signed-in administrators', 'chaos-shield' ); ?></h2>
				</div>
				<?php if ( ! $cshield_sessions ) : ?>
					<p class="cshield-empty"><?php esc_html_e( 'No administrator sessions.', 'chaos-shield' ); ?></p>
				<?php else : ?>
					<table class="cshield-table">
						<thead><tr><th><?php esc_html_e( 'User', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'IP', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Browser', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Signed in', 'chaos-shield' ); ?></th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $cshield_sessions as $cshield_s ) : ?>
							<tr>
								<td><?php echo esc_html( $cshield_s['login'] ); ?></td>
								<td><code><?php echo esc_html( $cshield_s['ip'] ); ?></code></td>
								<td><?php echo esc_html( $cshield_s['agent'] ); ?></td>
								<td><?php echo esc_html( $cshield_s['login_time'] ? wp_date( $cshield_date_format, $cshield_s['login_time'] ) : '-' ); ?></td>
								<td class="cshield-right">
									<?php if ( $cshield_s['current'] ) : ?>
										<span class="cshield-small"><?php esc_html_e( 'This session', 'chaos-shield' ); ?></span>
									<?php else : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
											<input type="hidden" name="action" value="cshield_session">
											<input type="hidden" name="user" value="<?php echo esc_attr( $cshield_s['user_id'] ); ?>">
											<input type="hidden" name="session" value="<?php echo esc_attr( $cshield_s['verifier'] ); ?>">
											<?php wp_nonce_field( 'cshield_session' ); ?>
											<button type="submit" class="cshield-link cshield-link--danger"><?php esc_html_e( 'Sign out', 'chaos-shield' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</section>

			<?php $cshield_bans = Bans::bans(); ?>
			<section class="cshield-card cshield-card--full">
				<div class="cshield-card__head">
					<h2><?php esc_html_e( 'Banned IPs', 'chaos-shield' ); ?></h2>
				</div>
				<?php if ( ! $cshield_bans ) : ?>
					<p class="cshield-empty"><?php esc_html_e( 'No IP addresses are banned. Repeat attackers and 404 probing bots will show up here.', 'chaos-shield' ); ?></p>
				<?php else : ?>
					<table class="cshield-table">
						<thead><tr><th><?php esc_html_e( 'IP', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Why', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Banned until', 'chaos-shield' ); ?></th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $cshield_bans as $cshield_ip => $cshield_ban ) : ?>
							<tr>
								<td><code><?php echo esc_html( $cshield_ip ); ?></code></td>
								<td><?php echo esc_html( $cshield_ban['reason'] ); ?></td>
								<td><?php echo esc_html( wp_date( $cshield_date_format, $cshield_ban['until'] ) ); ?></td>
								<td class="cshield-right">
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
										<input type="hidden" name="action" value="cshield_release">
										<input type="hidden" name="ip" value="<?php echo esc_attr( $cshield_ip ); ?>">
										<?php wp_nonce_field( 'cshield_release' ); ?>
										<button type="submit" class="cshield-link"><?php esc_html_e( 'Lift ban', 'chaos-shield' ); ?></button>
									</form>
									<?php if ( Request::ip() !== $cshield_ip ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
											<input type="hidden" name="action" value="cshield_block">
											<input type="hidden" name="ip" value="<?php echo esc_attr( $cshield_ip ); ?>">
											<?php wp_nonce_field( 'cshield_block' ); ?>
											<button type="submit" class="cshield-link cshield-link--danger"><?php esc_html_e( 'Block permanently', 'chaos-shield' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</section>

			<section class="cshield-card cshield-card--full">
				<?php
				// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filters.
				$cshield_f    = Export::filters( $_GET );
				$cshield_page = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
				// phpcs:enable
				$cshield_type  = $cshield_f['type'];
				$cshield_args  = array_intersect_key( $cshield_f, array_flip( array( 'type', 'search', 'user_id', 'since', 'until', 'blog_id' ) ) );
				$cshield_per   = 50;
				$cshield_total = Events::count( $cshield_args );
				$cshield_pages = max( 1, (int) ceil( $cshield_total / $cshield_per ) );
				$cshield_rows  = Events::query(
					array_merge(
						$cshield_args,
						array(
							'limit'  => $cshield_per,
							'offset' => ( $cshield_page - 1 ) * $cshield_per,
						)
					)
				);
				$cshield_form  = $cshield_f['form'];
				?>
				<div class="cshield-card__head">
					<h2>
						<?php esc_html_e( 'Activity log', 'chaos-shield' ); ?>
						<span class="cshield-count">
							<?php
							/* translators: %s: number of events. */
							echo esc_html( sprintf( _n( '%s event', '%s events', $cshield_total, 'chaos-shield' ), number_format_i18n( $cshield_total ) ) );
							?>
						</span>
					</h2>
					<div class="cshield-inline-form">
						<a class="cshield-btn cshield-btn--ghost" href="<?php echo esc_url( wp_nonce_url( add_query_arg( array_merge( array( 'action' => 'cshield_export' ), $cshield_form ), admin_url( 'admin-post.php' ) ), 'cshield_export' ) ); ?>"><?php esc_html_e( 'Export CSV', 'chaos-shield' ); ?></a>
						<form method="get" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form" target="_blank">
							<input type="hidden" name="action" value="cshield_compliance">
							<?php wp_nonce_field( 'cshield_compliance', '_wpnonce', false ); ?>
							<label class="screen-reader-text" for="cshield-days"><?php esc_html_e( 'Report period', 'chaos-shield' ); ?></label>
							<select id="cshield-days" name="days">
								<option value="7"><?php esc_html_e( 'Last 7 days', 'chaos-shield' ); ?></option>
								<option value="30" selected><?php esc_html_e( 'Last 30 days', 'chaos-shield' ); ?></option>
								<option value="90"><?php esc_html_e( 'Last 90 days', 'chaos-shield' ); ?></option>
								<option value="365"><?php esc_html_e( 'Last 12 months', 'chaos-shield' ); ?></option>
							</select>
							<button type="submit" class="cshield-btn"><?php esc_html_e( 'Compliance report', 'chaos-shield' ); ?></button>
						</form>
					</div>
				</div>
				<form method="get" class="cshield-filter cshield-filter--log">
					<input type="hidden" name="page" value="<?php echo esc_attr( Admin::SLUG ); ?>">
					<input type="hidden" name="tab" value="activity">
					<label><span><?php esc_html_e( 'Type', 'chaos-shield' ); ?></span>
						<select name="type">
							<option value=""><?php esc_html_e( 'All events', 'chaos-shield' ); ?></option>
							<?php foreach ( Events::types() as $cshield_t ) : ?>
								<option value="<?php echo esc_attr( $cshield_t ); ?>" <?php selected( $cshield_type, $cshield_t ); ?>><?php echo esc_html( isset( $cshield_event_labels[ $cshield_t ] ) ? $cshield_event_labels[ $cshield_t ] : $cshield_t ); ?></option>
							<?php endforeach; ?>
						</select></label>
					<?php if ( Network::active() ) : ?>
						<label><span><?php esc_html_e( 'Site', 'chaos-shield' ); ?></span>
							<select name="site">
								<option value=""><?php esc_html_e( 'All sites', 'chaos-shield' ); ?></option>
								<?php foreach ( get_sites( array( 'number' => 200 ) ) as $cshield_site ) : ?>
									<option value="<?php echo esc_attr( $cshield_site->blog_id ); ?>" <?php selected( isset( $cshield_form['site'] ) ? (int) $cshield_form['site'] : 0, (int) $cshield_site->blog_id ); ?>><?php echo esc_html( Network::site_name( $cshield_site->blog_id ) ); ?></option>
								<?php endforeach; ?>
							</select></label>
					<?php endif; ?>
					<label><span><?php esc_html_e( 'Username', 'chaos-shield' ); ?></span>
						<input type="text" name="user" value="<?php echo esc_attr( isset( $cshield_form['user'] ) ? $cshield_form['user'] : '' ); ?>" spellcheck="false"></label>
					<label><span><?php esc_html_e( 'Contains', 'chaos-shield' ); ?></span>
						<input type="search" name="s" value="<?php echo esc_attr( isset( $cshield_form['s'] ) ? $cshield_form['s'] : '' ); ?>" placeholder="<?php esc_attr_e( 'Text or IP', 'chaos-shield' ); ?>"></label>
					<label><span><?php esc_html_e( 'From', 'chaos-shield' ); ?></span>
						<input type="date" name="from" value="<?php echo esc_attr( isset( $cshield_form['from'] ) ? $cshield_form['from'] : '' ); ?>"></label>
					<label><span><?php esc_html_e( 'To', 'chaos-shield' ); ?></span>
						<input type="date" name="to" value="<?php echo esc_attr( isset( $cshield_form['to'] ) ? $cshield_form['to'] : '' ); ?>"></label>
					<div class="cshield-filter__buttons">
						<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Filter', 'chaos-shield' ); ?></button>
						<?php if ( $cshield_form ) : ?>
							<a href="<?php echo esc_url( Admin::url( 'activity' ) ); ?>"><?php esc_html_e( 'Clear', 'chaos-shield' ); ?></a>
						<?php endif; ?>
					</div>
				</form>
				<?php $cshield_events_table( $cshield_rows, $cshield_event_labels, $cshield_date_format ); ?>
				<?php if ( $cshield_pages > 1 ) : ?>
					<nav class="cshield-pager" aria-label="<?php esc_attr_e( 'Activity pages', 'chaos-shield' ); ?>">
						<?php if ( $cshield_page > 1 ) : ?>
							<a href="
							<?php
							echo esc_url(
								Admin::url(
									'activity',
									array_filter(
										array_merge(
											$cshield_form,
											array( 'paged' => $cshield_page - 1 )
										)
									)
								)
							);
							?>
										"><?php esc_html_e( 'Newer', 'chaos-shield' ); ?></a>
						<?php endif; ?>
						<span>
							<?php
							/* translators: 1: page number, 2: page count. */
							echo esc_html( sprintf( __( 'Page %1$d of %2$d', 'chaos-shield' ), $cshield_page, $cshield_pages ) );
							?>
						</span>
						<?php if ( $cshield_page < $cshield_pages ) : ?>
							<a href="
							<?php
							echo esc_url(
								Admin::url(
									'activity',
									array_filter(
										array_merge(
											$cshield_form,
											array( 'paged' => $cshield_page + 1 )
										)
									)
								)
							);
							?>
										"><?php esc_html_e( 'Older', 'chaos-shield' ); ?></a>
						<?php endif; ?>
					</nav>
				<?php endif; ?>
			</section>
		</div>
	<?php endif; ?>
	<?php
	$cshield_kinds = array_filter(
		array(
			'hardening' === $tab ? 'captcha' : '',
			'alerts' === $tab ? 'chat' : '',
			'edge' === $tab ? 'edge' : '',
		)
	);
	if ( $cshield_kinds ) {
		require CSHIELD_DIR . 'includes/views/connect-dialogs.php';
	}
	?>
</div>
