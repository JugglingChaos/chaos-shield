<?php
/**
 * Dashboard view.
 *
 * Variables come from Admin::render(): $tabs, $tab, $notice, $checks, $score,
 * $stats, $lockouts, $modules, $on.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_band    = Admin::band( $score );
$sshield_labels  = array(
	'good' => __( 'Well protected', 'sentinel-shield' ),
	'fair' => __( 'Needs attention', 'sentinel-shield' ),
	'poor' => __( 'At risk', 'sentinel-shield' ),
);
$sshield_notices = array(
	'fw_learning'       => __( 'Learning mode is on for 7 days. Nothing is blocked by the firewall rules until then; check the hits below.', 'sentinel-shield' ),
	'fw_allowed'        => __( 'Exception added. That rule no longer fires on that address and field.', 'sentinel-shield' ),
	'fw_removed'        => __( 'Exception removed.', 'sentinel-shield' ),
	'rp_created'        => __( 'Restore point saved.', 'sentinel-shield' ),
	'help_saved'        => __( 'Visitor help saved.', 'sentinel-shield' ),
	'edge_saved'        => __( 'Edge settings saved.', 'sentinel-shield' ),
	'edge_checked'      => __( 'Pages checked: scripts, HTTPS, exposed files and keys.', 'sentinel-shield' ),
	'edge_error'        => '',
	'attack_on'         => __( 'Under attack mode is on. Visitors who are not logged in see a short browser check.', 'sentinel-shield' ),
	'attack_off'        => __( 'Under attack mode is off.', 'sentinel-shield' ),
	'scripts_approve'   => __( 'Approved.', 'sentinel-shield' ),
	'scripts_block'     => __( 'Blocked. With the policy set to Enforce, browsers refuse scripts from that domain.', 'sentinel-shield' ),
	'scripts_forget'    => __( 'Removed from the list.', 'sentinel-shield' ),
	'file_deleted'      => __( 'File deleted.', 'sentinel-shield' ),
	'files_protected'   => __( 'Blocked in .htaccess. The home page still loads.', 'sentinel-shield' ),
	'cf_synced'         => __( 'Cloudflare is up to date.', 'sentinel-shield' ),
	'cf_purged'         => __( 'Cloudflare\'s cache is cleared.', 'sentinel-shield' ),
	'cf_ip'             => __( 'Visitor IPs are now read from Cloudflare.', 'sentinel-shield' ),
	'feed_new'          => __( 'New ban list address made. The old one no longer works.', 'sentinel-shield' ),
	'help_allowed'      => __( 'Allowed. Their ban and lockout are lifted, and the blocked request will go through next time.', 'sentinel-shield' ),
	'help_dismissed'    => __( 'Dismissed.', 'sentinel-shield' ),
	'int_checked'       => __( 'Critical files checked.', 'sentinel-shield' ),
	'int_accepted'      => __( 'Accepted. The current version is now the fingerprint to compare with.', 'sentinel-shield' ),
	'int_restored'      => __( 'Put back. The version it replaced is saved as a restore point.', 'sentinel-shield' ),
	'rp_restored'       => __( 'Restored. The state from just before is saved as a new restore point, in case you want it back.', 'sentinel-shield' ),
	'rp_deleted'        => __( 'Restore point deleted.', 'sentinel-shield' ),
	'settings_imported' => __( 'Settings imported. Your previous settings are saved as a restore point.', 'sentinel-shield' ),
	'saved'             => __( 'Settings saved.', 'sentinel-shield' ),
	'recommended'       => __( 'Recommended hardening is now on.', 'sentinel-shield' ),
	'released'          => __( 'Lockouts and bans released.', 'sentinel-shield' ),
	'report_sent'       => __( 'Weekly report sent. Check your inbox.', 'sentinel-shield' ),
	'login_moved'       => __( 'Login address changed. It was also emailed to you: bookmark it before you log out.', 'sentinel-shield' ),
	'session_end'       => __( 'Session signed out.', 'sentinel-shield' ),
	'quarantined'       => __( 'File moved to quarantine. It can no longer run.', 'sentinel-shield' ),
	'repaired'          => __( 'File replaced with the official copy from WordPress.org.', 'sentinel-shield' ),
	'restored'          => __( 'File restored from quarantine.', 'sentinel-shield' ),
	'q_deleted'         => __( 'Quarantined file deleted.', 'sentinel-shield' ),
	'db_scanned'        => __( 'Database scan finished.', 'sentinel-shield' ),
	'vuln_checked'      => __( 'Everything installed was checked against the vulnerability database.', 'sentinel-shield' ),
	'vuln_partial'      => __( 'Vulnerability check started. The rest of your plugins and themes are being checked in the background.', 'sentinel-shield' ),
	'blocked'           => __( 'IP added to the block list.', 'sentinel-shield' ),
	'ignored'           => __( 'Finding marked as reviewed. It will come back if the file changes.', 'sentinel-shield' ),
	'unignored'         => __( 'All reviewed findings are visible again.', 'sentinel-shield' ),
	'test_sent'         => __( 'Settings saved and a test email was sent.', 'sentinel-shield' ),
	'key_created'       => __( 'New hub key created. Copy it now: it will not be shown again.', 'sentinel-shield' ),
	'key_revoked'       => __( 'Hub key revoked. No hub can read this site any more.', 'sentinel-shield' ),
	'site_added'        => __( 'Site connected.', 'sentinel-shield' ),
	'site_removed'      => __( 'Site removed from the hub.', 'sentinel-shield' ),
	'refreshed'         => __( 'All sites refreshed.', 'sentinel-shield' ),
	'test_failed'       => __( 'Settings saved, but the test email could not be sent. Check that this site can send email.', 'sentinel-shield' ),
	'forced'            => sprintf(
		/* translators: %d: number of users. */
		_n( 'Password reset forced for %d user. They were signed out and will choose a new password at their next login.', 'Password reset forced for %d users. They were signed out and will choose a new password at their next login.', isset( $_GET['forced'] ) ? absint( $_GET['forced'] ) : 0, 'sentinel-shield' ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		isset( $_GET['forced'] ) ? absint( $_GET['forced'] ) : 0 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
	),
	'hub_done'          => __( 'Hub action done.', 'sentinel-shield' ),
	'incident_saved'    => __( 'Incident updated.', 'sentinel-shield' ),
	'incident_acted'    => __( 'Response action done and noted on the incident.', 'sentinel-shield' ),
	'incident_skipped'  => __( 'Nothing was done. Sentinel Shield never bans an IP an administrator has logged in from, your own IP, or your own account.', 'sentinel-shield' ),
	'uptime_checked'    => __( 'Uptime and certificates checked.', 'sentinel-shield' ),
	'fwd_ok'            => __( 'Settings saved and a test event was delivered.', 'sentinel-shield' ),
	'fwd_failed'        => __( 'Settings saved, but the test event could not be delivered. See the error under Log forwarding.', 'sentinel-shield' ),
);
$sshield_issues  = array_values(
	array_filter(
		$checks,
		static function ( $check ) {
			return Posture::PASS !== $check['status'];
		}
	)
);
usort(
	$sshield_issues,
	static function ( $a, $b ) {
		return array( Posture::FAIL === $b['status'], $b['weight'] ) <=> array( Posture::FAIL === $a['status'], $a['weight'] );
	}
);
$sshield_status       = array(
	Posture::PASS => __( 'Pass', 'sentinel-shield' ),
	Posture::WARN => __( 'Warning', 'sentinel-shield' ),
	Posture::FAIL => __( 'Fail', 'sentinel-shield' ),
);
$sshield_event_labels = array(
	'lockout'   => __( 'Lockout', 'sentinel-shield' ),
	'settings'  => __( 'Settings', 'sentinel-shield' ),
	'system'    => __( 'System', 'sentinel-shield' ),
	'blocked'   => __( 'Firewall', 'sentinel-shield' ),
	'twofactor' => __( 'Two-factor', 'sentinel-shield' ),
	'login'     => __( 'Login', 'sentinel-shield' ),
	'user'      => __( 'User', 'sentinel-shield' ),
	'plugin'    => __( 'Plugin', 'sentinel-shield' ),
	'theme'     => __( 'Theme', 'sentinel-shield' ),
	'scan'      => __( 'Scan', 'sentinel-shield' ),
	'ban'       => __( 'Ban', 'sentinel-shield' ),
	'password'  => __( 'Password', 'sentinel-shield' ),
	'vuln'      => __( 'Vulnerability', 'sentinel-shield' ),
	'content'   => __( 'Content', 'sentinel-shield' ),
	'option'    => __( 'Site setting', 'sentinel-shield' ),
	'privacy'   => __( 'Privacy', 'sentinel-shield' ),
	'incident'  => __( 'Incident', 'sentinel-shield' ),
);
$sshield_date_format  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

/**
 * Prints the event table.
 *
 * @param array $events Events.
 * @param array $labels Type labels.
 * @param string $date_format Date format.
 */
$sshield_events_table = static function ( array $events, array $labels, $date_format ) {
	if ( ! $events ) {
		echo '<p class="sshield-empty">' . esc_html__( 'Nothing recorded yet. Logins, lockouts, scans and changes to users, plugins and settings will show up here.', 'sentinel-shield' ) . '</p>';
		return;
	}
	// On a network, each event names the site it happened on.
	$sites = Network::active();
	echo '<table class="sshield-table sshield-table--events"><thead><tr><th>' . esc_html__( 'When', 'sentinel-shield' ) . '</th>' . ( $sites ? '<th>' . esc_html__( 'Site', 'sentinel-shield' ) . '</th>' : '' ) . '<th>' . esc_html__( 'Type', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Event', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'User', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'IP', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
	$users = array();
	foreach ( $events as $event ) {
		$type = isset( $labels[ $event['type'] ] ) ? $labels[ $event['type'] ] : $event['type'];
		$uid  = isset( $event['user_id'] ) ? (int) $event['user_id'] : 0;
		if ( $uid && ! isset( $users[ $uid ] ) ) {
			$user          = get_userdata( $uid );
			$users[ $uid ] = $user ? $user->user_login : '#' . $uid;
		}
		printf(
			'<tr class="sshield-sev-%d"><td>%s</td>%s<td><span class="sshield-tag sshield-tag--%s">%s</span></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>',
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
<div class="wrap sshield">
	<h1 class="screen-reader-text"><?php esc_html_e( 'Sentinel Shield', 'sentinel-shield' ); ?></h1>

	<header class="sshield-top">
		<div class="sshield-brand">
			<svg class="sshield-logo" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><path d="M16 2 4 6.5v8.2c0 7.3 5 13.4 12 15.3 7-1.9 12-8 12-15.3V6.5L16 2Z" fill="currentColor" opacity=".18"/><path d="M16 2 4 6.5v8.2c0 7.3 5 13.4 12 15.3 7-1.9 12-8 12-15.3V6.5L16 2Zm0 2.1 10 3.8v6.8c0 6.2-4.1 11.5-10 13.2-5.9-1.7-10-7-10-13.2V7.9l10-3.8Z" fill="currentColor"/><path d="m14.4 19.6-4-4 1.5-1.5 2.5 2.5 5.7-5.7 1.5 1.5-7.2 7.2Z" fill="currentColor"/></svg>
			<span class="sshield-name"><?php esc_html_e( 'Sentinel Shield', 'sentinel-shield' ); ?></span>
			<span class="sshield-pill"><?php echo esc_html( 'v' . SSHIELD_VERSION ); ?></span>
		</div>
		<div class="sshield-state sshield-state--<?php echo esc_attr( $sshield_band ); ?>">
			<span class="sshield-dot"></span><?php echo esc_html( $sshield_labels[ $sshield_band ] ); ?>
		</div>
	</header>

	<?php if ( ! empty( $sshield_notices[ $notice ] ) ) : ?>
		<div class="sshield-notice" role="status"><?php echo esc_html( $sshield_notices[ $notice ] ); ?></div>
	<?php endif; ?>
	<?php
	// A failed action leaves its reason for the next page load.
	$sshield_error = Network::get_transient( 'sshield_error_' . get_current_user_id() );
	if ( $sshield_error ) {
		Network::delete_transient( 'sshield_error_' . get_current_user_id() );
	}
	?>
	<?php if ( $sshield_error ) : ?>
		<div class="sshield-notice sshield-notice--warn" role="alert"><?php echo esc_html( $sshield_error ); ?></div>
	<?php endif; ?>

	<section class="sshield-hero">
		<div class="sshield-score sshield-score--<?php echo esc_attr( $sshield_band ); ?>" data-score="<?php echo esc_attr( $score ); ?>">
			<svg viewBox="0 0 120 120" aria-hidden="true" focusable="false">
				<circle class="sshield-score__track" cx="60" cy="60" r="52"/>
				<circle class="sshield-score__bar" cx="60" cy="60" r="52" pathLength="100" style="stroke-dasharray: <?php echo esc_attr( $score ); ?> 100"/>
			</svg>
			<div class="sshield-score__value"><strong><?php echo esc_html( $score ); ?></strong><span><?php esc_html_e( 'Security score', 'sentinel-shield' ); ?></span></div>
		</div>
		<div class="sshield-tiles">
			<div class="sshield-tile">
				<span class="sshield-tile__label"><?php esc_html_e( 'Firewall blocks, 24h', 'sentinel-shield' ); ?></span>
				<strong class="sshield-tile__value"><?php echo esc_html( number_format_i18n( $stats['firewall_blocks'] ) ); ?></strong>
			</div>
			<div class="sshield-tile">
				<span class="sshield-tile__label"><?php esc_html_e( 'Hardening on', 'sentinel-shield' ); ?></span>
				<strong class="sshield-tile__value"><?php echo esc_html( $on . ' / ' . count( $modules ) ); ?></strong>
			</div>
			<div class="sshield-tile">
				<span class="sshield-tile__label"><?php esc_html_e( 'Failed logins, 24h', 'sentinel-shield' ); ?></span>
				<strong class="sshield-tile__value"><?php echo esc_html( number_format_i18n( $stats['failed_logins'] ) ); ?></strong>
			</div>
			<div class="sshield-tile">
				<span class="sshield-tile__label"><?php esc_html_e( 'IPs locked out now', 'sentinel-shield' ); ?></span>
				<strong class="sshield-tile__value"><?php echo esc_html( number_format_i18n( count( $lockouts ) ) ); ?></strong>
			</div>
		</div>
	</section>

	<nav class="sshield-tabs" aria-label="<?php esc_attr_e( 'Sentinel Shield sections', 'sentinel-shield' ); ?>">
		<?php foreach ( $tabs as $sshield_key => $sshield_label ) : ?>
			<a href="<?php echo esc_url( Admin::url( $sshield_key ) ); ?>" class="sshield-tab<?php echo $sshield_key === $tab ? ' is-active' : ''; ?>"<?php echo $sshield_key === $tab ? ' aria-current="page"' : ''; ?>><?php echo esc_html( $sshield_label ); ?></a>
		<?php endforeach; ?>
	</nav>

	<?php if ( 'overview' === $tab ) : ?>
		<?php
		$sshield_inc_sum = Incidents::summary();
		$sshield_urgent  = $sshield_inc_sum['by_severity'][ Incidents::CRITICAL ] + $sshield_inc_sum['by_severity'][ Incidents::HIGH ];
		?>
		<?php if ( $sshield_urgent ) : ?>
			<div class="sshield-notice sshield-notice--warn sshield-notice--incidents" role="status">
				<span>
					<?php
					/* translators: %d: number of incidents. */
					echo esc_html( sprintf( _n( '%d high or critical incident is open.', '%d high or critical incidents are open.', $sshield_urgent, 'sentinel-shield' ), $sshield_urgent ) );
					?>
				</span>
				<a class="sshield-btn" href="<?php echo esc_url( Admin::url( 'siem' ) ); ?>"><?php esc_html_e( 'Review incidents', 'sentinel-shield' ); ?></a>
			</div>
		<?php endif; ?>
		<div class="sshield-grid">
			<section class="sshield-card sshield-card--wide">
				<h2><?php esc_html_e( 'What to fix', 'sentinel-shield' ); ?></h2>
				<?php if ( ! $sshield_issues ) : ?>
					<p class="sshield-empty"><?php esc_html_e( 'Every check passes. Nice work.', 'sentinel-shield' ); ?></p>
				<?php else : ?>
					<ul class="sshield-checks">
						<?php foreach ( $sshield_issues as $sshield_check ) : ?>
							<li class="sshield-check sshield-check--<?php echo esc_attr( $sshield_check['status'] ); ?>">
								<span class="sshield-badge"><?php echo esc_html( $sshield_status[ $sshield_check['status'] ] ); ?></span>
								<div><strong><?php echo esc_html( $sshield_check['label'] ); ?></strong><p><?php echo esc_html( $sshield_check['detail'] ); ?></p></div>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			</section>

			<section class="sshield-card">
				<h2><?php esc_html_e( 'Passing', 'sentinel-shield' ); ?></h2>
				<ul class="sshield-passlist">
					<?php foreach ( $checks as $sshield_check ) : ?>
						<?php if ( Posture::PASS === $sshield_check['status'] ) : ?>
							<li><?php echo esc_html( $sshield_check['label'] ); ?></li>
						<?php endif; ?>
					<?php endforeach; ?>
				</ul>
			</section>

			<section class="sshield-card sshield-card--full">
				<h2><?php esc_html_e( 'Recent activity', 'sentinel-shield' ); ?></h2>
				<?php $sshield_events_table( Events::all( 5 ), $sshield_event_labels, $sshield_date_format ); ?>
			</section>
		</div>

	<?php elseif ( 'hardening' === $tab ) : ?>
		<?php
		$sshield_hard_error = Network::get_transient( 'sshield_hardening_error_' . get_current_user_id() );
		Network::delete_transient( 'sshield_hardening_error_' . get_current_user_id() );
		?>
		<?php if ( $sshield_hard_error ) : ?>
			<div class="sshield-notice sshield-notice--warn" role="alert"><?php echo esc_html( $sshield_hard_error ); ?></div>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form sshield-recommend">
			<input type="hidden" name="action" value="sshield_recommended">
			<?php wp_nonce_field( 'sshield_recommended' ); ?>
			<p><?php esc_html_e( 'Turn on every recommended protection in one click. Optional modules stay as they are.', 'sentinel-shield' ); ?></p>
			<button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Apply recommended', 'sentinel-shield' ); ?></button>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="sshield_save">
			<?php wp_nonce_field( 'sshield_save' ); ?>
			<div class="sshield-modules">
				<?php foreach ( $modules as $sshield_key => $sshield_module ) : ?>
					<?php $sshield_id = 'sshield-' . $sshield_key; ?>
					<div class="sshield-module">
						<div class="sshield-module__text">
							<label for="<?php echo esc_attr( $sshield_id ); ?>"><?php echo esc_html( $sshield_module['label'] ); ?></label>
							<?php if ( ! $sshield_module['default'] ) : ?>
								<span class="sshield-tag"><?php esc_html_e( 'Optional', 'sentinel-shield' ); ?></span>
							<?php endif; ?>
							<p><?php echo esc_html( $sshield_module['description'] ); ?></p>
						</div>
						<span class="sshield-switch">
							<input type="checkbox" role="switch" id="<?php echo esc_attr( $sshield_id ); ?>" name="sshield[<?php echo esc_attr( $sshield_key ); ?>]" value="1" <?php checked( Settings::enabled( $sshield_key ) ); ?>>
							<span class="sshield-switch__ui" aria-hidden="true"></span>
						</span>
					</div>
				<?php endforeach; ?>
			</div>

			<section class="sshield-card sshield-login-limits">
				<h2><?php esc_html_e( 'Login limits', 'sentinel-shield' ); ?></h2>
				<div class="sshield-fields">
					<label><span><?php esc_html_e( 'Failed attempts allowed', 'sentinel-shield' ); ?></span>
						<input type="number" min="2" max="50" name="sshield[login_max_attempts]" value="<?php echo esc_attr( Settings::get( 'login_max_attempts' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Within (minutes)', 'sentinel-shield' ); ?></span>
						<input type="number" min="1" max="1440" name="sshield[login_window]" value="<?php echo esc_attr( Settings::get( 'login_window' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Lock out for (minutes)', 'sentinel-shield' ); ?></span>
						<input type="number" min="1" max="10080" name="sshield[login_lockout]" value="<?php echo esc_attr( Settings::get( 'login_lockout' ) ); ?>"></label>
				</div>
			</section>

			<section class="sshield-card sshield-login-limits">
				<h2><?php esc_html_e( 'Bans', 'sentinel-shield' ); ?></h2>
				<p class="sshield-small"><?php esc_html_e( 'A banned IP gets a 403 on every page. IPs on the allow list, IPs an administrator has logged in from, and verified Google and Bing crawlers are never banned. Ten firewall blocks in an hour also count as a ban.', 'sentinel-shield' ); ?></p>
				<div class="sshield-fields">
					<label><span><?php esc_html_e( 'Ban after this many lockouts in 24 hours', 'sentinel-shield' ); ?></span>
						<input type="number" min="2" max="20" name="sshield[autoban_strikes]" value="<?php echo esc_attr( Settings::get( 'autoban_strikes' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Missing pages in 5 minutes before a 404 ban', 'sentinel-shield' ); ?></span>
						<input type="number" min="5" max="200" name="sshield[probe_404_limit]" value="<?php echo esc_attr( Settings::get( 'probe_404_limit' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Ban for (hours)', 'sentinel-shield' ); ?></span>
						<input type="number" min="1" max="720" name="sshield[autoban_hours]" value="<?php echo esc_attr( Settings::get( 'autoban_hours' ) ); ?>"></label>
				</div>
			</section>

			<section class="sshield-card sshield-login-limits">
				<h2><?php esc_html_e( 'Rate limits (requests per minute per IP)', 'sentinel-shield' ); ?></h2>
				<div class="sshield-fields sshield-fields--four">
					<label><span><?php esc_html_e( 'Login and XML-RPC', 'sentinel-shield' ); ?></span>
						<input type="number" min="5" max="600" name="sshield[rate_login]" value="<?php echo esc_attr( Settings::get( 'rate_login' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'REST API and AJAX', 'sentinel-shield' ); ?></span>
						<input type="number" min="20" max="6000" name="sshield[rate_api]" value="<?php echo esc_attr( Settings::get( 'rate_api' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Search', 'sentinel-shield' ); ?></span>
						<input type="number" min="5" max="600" name="sshield[rate_search]" value="<?php echo esc_attr( Settings::get( 'rate_search' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'All pages', 'sentinel-shield' ); ?></span>
						<input type="number" min="30" max="6000" name="sshield[rate_pages]" value="<?php echo esc_attr( Settings::get( 'rate_pages' ) ); ?>"></label>
				</div>
				<p class="sshield-small">
					<?php
					echo esc_html(
						wp_using_ext_object_cache()
							? __( 'Administrators and the allow list are never limited. An IP that hits a limit 5 times in an hour is banned.', 'sentinel-shield' )
							: __( 'Administrators and the allow list are never limited. An IP that hits a limit 5 times in an hour is banned. The all pages limit needs a persistent object cache such as Redis, so it is not active on this site.', 'sentinel-shield' )
					);
					?>
				</p>
			</section>

			<section class="sshield-card sshield-card--full sshield-pw-policy">
				<h2><?php esc_html_e( 'Password policy', 'sentinel-shield' ); ?></h2>
				<div class="sshield-fields sshield-fields--four">
					<label><span><?php esc_html_e( 'Minimum length', 'sentinel-shield' ); ?></span>
						<input type="number" min="8" max="64" name="sshield[pw_min_length]" value="<?php echo esc_attr( Settings::get( 'pw_min_length' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Kinds of characters (1 to 4)', 'sentinel-shield' ); ?></span>
						<input type="number" min="1" max="4" name="sshield[pw_classes]" value="<?php echo esc_attr( Settings::get( 'pw_classes' ) ); ?>"></label>
					<label><span><?php esc_html_e( 'Applies to', 'sentinel-shield' ); ?></span>
						<select name="sshield[pw_roles]">
							<option value="admins" <?php selected( Settings::get( 'pw_roles' ), 'admins' ); ?>><?php esc_html_e( 'Administrators', 'sentinel-shield' ); ?></option>
							<option value="staff" <?php selected( Settings::get( 'pw_roles' ), 'staff' ); ?>><?php esc_html_e( 'Everyone who can write posts', 'sentinel-shield' ); ?></option>
							<option value="all" <?php selected( Settings::get( 'pw_roles' ), 'all' ); ?>><?php esc_html_e( 'All users', 'sentinel-shield' ); ?></option>
						</select></label>
					<label><span><?php esc_html_e( 'Expire after (days, 0 = never)', 'sentinel-shield' ); ?></span>
						<input type="number" min="0" max="730" name="sshield[pw_max_age]" value="<?php echo esc_attr( Settings::get( 'pw_max_age' ) ); ?>"></label>
				</div>
				<p class="sshield-small">
					<?php
					echo esc_html(
						Settings::enabled( 'password_policy' )
							? Password_Policy::describe() . ' ' . __( 'Rules apply when a password is set or reset, and a password cannot contain the username or email.', 'sentinel-shield' )
							: __( 'Switch on Password policy above for these rules to apply. Current NIST guidance favours length over forced expiry, so leave expiry at 0 unless a policy you follow requires it.', 'sentinel-shield' )
					);
					?>
				</p>
				<?php $sshield_pending = Password_Policy::pending_count(); ?>
				<div class="sshield-actions sshield-actions--start">
					<a class="sshield-btn sshield-btn--ghost" href="
					<?php
					echo esc_url(
						wp_nonce_url(
							add_query_arg(
								array(
									'action' => 'sshield_force_reset',
									'group'  => 'admins',
								),
								admin_url( 'admin-post.php' )
							),
							'sshield_force_group'
						)
					);
					?>
																	" onclick="return confirm(<?php echo esc_attr( wp_json_encode( __( 'Sign out every other administrator and make them choose a new password?', 'sentinel-shield' ) ) ); ?>)"><?php esc_html_e( 'Force a reset for all other administrators', 'sentinel-shield' ); ?></a>
					<a class="sshield-btn sshield-btn--ghost" href="
					<?php
					echo esc_url(
						wp_nonce_url(
							add_query_arg(
								array(
									'action' => 'sshield_force_reset',
									'group'  => 'policy',
								),
								admin_url( 'admin-post.php' )
							),
							'sshield_force_group'
						)
					);
					?>
																	" onclick="return confirm(<?php echo esc_attr( wp_json_encode( __( 'Sign out everyone the policy covers, except you, and make them choose a new password?', 'sentinel-shield' ) ) ); ?>)"><?php esc_html_e( 'Force a reset for everyone the policy covers', 'sentinel-shield' ); ?></a>
				</div>
				<p class="sshield-small">
					<?php
					echo esc_html(
						$sshield_pending
							/* translators: %d: number of users. */
							? sprintf( _n( '%d user still has to choose a new password.', '%d users still have to choose a new password.', $sshield_pending, 'sentinel-shield' ), $sshield_pending )
							: __( 'You can also force a reset for one user from the Users screen.', 'sentinel-shield' )
					);
					?>
				</p>
			</section>

			<?php $sshield_tf = Threat_Feed::status(); ?>
			<section class="sshield-card sshield-login-limits">
				<h2><?php esc_html_e( 'Threat intelligence and traffic', 'sentinel-shield' ); ?></h2>
				<label class="sshield-check-line"><input type="checkbox" name="sshield[threat_tor]" value="1" <?php checked( Settings::get( 'threat_tor' ) ); ?>> <?php esc_html_e( 'Also block Tor exit nodes', 'sentinel-shield' ); ?></label>
				<p class="sshield-small"><?php esc_html_e( 'Tor hides who a visitor is. Most attacks through it are automated, but some real people use it for privacy, so this is off by default.', 'sentinel-shield' ); ?></p>
				<p class="sshield-small">
					<?php
					if ( ! Settings::enabled( 'threat_feed' ) ) {
						esc_html_e( 'Switch on Threat intelligence blocklist above to use these lists.', 'sentinel-shield' );
					} elseif ( $sshield_tf['updated'] ) {
						printf(
							/* translators: 1: number of networks, 2: date. */
							esc_html__( '%1$s networks blocked, lists updated %2$s.', 'sentinel-shield' ),
							esc_html( number_format_i18n( array_sum( $sshield_tf['counts'] ) ) ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $sshield_tf['updated'] ) )
						);
						if ( $sshield_tf['error'] ) {
							echo ' ' . esc_html( $sshield_tf['error'] );
						}
					} else {
						esc_html_e( 'The lists download in the background within a minute.', 'sentinel-shield' );
					}
					?>
				</p>
				<div class="sshield-fields sshield-fields--one sshield-fields--spaced">
					<label><span><?php esc_html_e( 'Live traffic records', 'sentinel-shield' ); ?></span>
						<select name="sshield[traffic_mode]">
							<option value="security" <?php selected( Settings::get( 'traffic_mode' ), 'security' ); ?>><?php esc_html_e( 'Security events only: blocks, logins, missing pages', 'sentinel-shield' ); ?></option>
							<option value="all" <?php selected( Settings::get( 'traffic_mode' ), 'all' ); ?>><?php esc_html_e( 'Every visit (more database writes)', 'sentinel-shield' ); ?></option>
						</select></label>
				</div>
			</section>

			<section class="sshield-card sshield-login-limits">
				<h2><?php esc_html_e( 'Login page', 'sentinel-shield' ); ?></h2>
				<p>
					<?php
					/* translators: %s: login URL. */
					echo esc_html( sprintf( __( 'Your login page is %s', 'sentinel-shield' ), Login_Url::url() ) );
					?>
				</p>
				<div class="sshield-fields sshield-fields--two">
					<label><span><?php esc_html_e( 'Custom login address (leave empty for wp-login.php)', 'sentinel-shield' ); ?></span>
						<span class="sshield-prefixed"><code><?php echo esc_html( trailingslashit( home_url() ) ); ?></code><input type="text" name="sshield[login_slug]" value="<?php echo esc_attr( Settings::get( 'login_slug' ) ); ?>" placeholder="my-secret-door" pattern="[a-z0-9-]{6,}" spellcheck="false"></span></label>
				</div>
				<p class="sshield-small"><?php esc_html_e( 'With a custom address, wp-login.php and wp-admin answer 404 to anyone not logged in, so bots stop finding your login form. The new address is emailed to you. Forgot it? Add define( \'SSHIELD_DISABLE_LOGIN_SLUG\', true ); to wp-config.php.', 'sentinel-shield' ); ?></p>
				<h3 class="sshield-subhead"><?php esc_html_e( 'Login CAPTCHA', 'sentinel-shield' ); ?></h3>
				<?php
				$sshield_kind = 'captcha';
				require SSHIELD_DIR . 'includes/views/connections.php';
				?>
				<p class="sshield-small"><?php esc_html_e( 'Connecting checks the keys with the service and switches Login CAPTCHA on. If the service cannot be reached during a login, the login is allowed and the outage is logged, so you are never locked out.', 'sentinel-shield' ); ?></p>
			</section>

			<div class="sshield-actions">
				<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save changes', 'sentinel-shield' ); ?></button>
			</div>
		</form>

	<?php elseif ( 'access' === $tab ) : ?>
		<?php
		$sshield_rejected = Network::get_transient( 'sshield_access_rejected_' . get_current_user_id() );
		Network::delete_transient( 'sshield_access_rejected_' . get_current_user_id() );
		$sshield_detected = Request::detected_proxy_headers();
		$sshield_header   = (string) Settings::get( 'proxy_header' );
		?>
		<?php if ( ! empty( $sshield_rejected['invalid'] ) ) : ?>
			<div class="sshield-notice sshield-notice--warn" role="alert">
				<?php
				/* translators: %s: list of rejected entries. */
				echo esc_html( sprintf( __( 'These entries are not valid IP addresses or ranges and were skipped: %s', 'sentinel-shield' ), implode( ', ', $sshield_rejected['invalid'] ) ) );
				?>
			</div>
		<?php endif; ?>
		<?php if ( ! empty( $sshield_rejected['country'] ) ) : ?>
			<div class="sshield-notice sshield-notice--warn" role="alert">
				<?php
				/* translators: %s: country code. */
				echo esc_html( sprintf( __( 'You are visiting from %s, so the country rule was adjusted to keep you from locking yourself out.', 'sentinel-shield' ), $sshield_rejected['country'] ) );
				?>
			</div>
		<?php endif; ?>
		<?php if ( ! empty( $sshield_rejected['self'] ) ) : ?>
			<div class="sshield-notice sshield-notice--warn" role="alert">
				<?php
				/* translators: %s: list of entries. */
				echo esc_html( sprintf( __( 'These block list entries match your own IP, so they were left out to keep you from locking yourself out: %s', 'sentinel-shield' ), implode( ', ', $sshield_rejected['self'] ) ) );
				?>
			</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="sshield_access">
			<?php wp_nonce_field( 'sshield_access' ); ?>
			<div class="sshield-grid sshield-grid--even">
				<section class="sshield-card">
					<h2><?php esc_html_e( 'Allow list', 'sentinel-shield' ); ?></h2>
					<p><?php esc_html_e( 'These IPs are never locked out or blocked by the firewall. One IP or range per line, for example 203.0.113.7 or 203.0.113.0/24.', 'sentinel-shield' ); ?></p>
					<textarea name="sshield[ip_allowlist]" rows="6" class="sshield-textarea" spellcheck="false"><?php echo esc_textarea( implode( "\n", (array) Settings::get( 'ip_allowlist' ) ) ); ?></textarea>
				</section>
				<section class="sshield-card">
					<h2><?php esc_html_e( 'Block list', 'sentinel-shield' ); ?></h2>
					<p><?php esc_html_e( 'These IPs get a 403 on every page of the site. Your own IP is never accepted here.', 'sentinel-shield' ); ?></p>
					<textarea name="sshield[ip_blocklist]" rows="6" class="sshield-textarea" spellcheck="false"><?php echo esc_textarea( implode( "\n", (array) Settings::get( 'ip_blocklist' ) ) ); ?></textarea>
				</section>
				<section class="sshield-card sshield-card--full">
					<h2><?php esc_html_e( 'Countries', 'sentinel-shield' ); ?></h2>
					<p>
						<?php
						$sshield_country = Geo::country();
						echo esc_html(
							$sshield_country
								/* translators: %s: country code. */
								? sprintf( __( 'Switch on Country blocking under Hardening for these rules to apply. Your request comes from %s.', 'sentinel-shield' ), $sshield_country )
								: __( 'Switch on Country blocking under Hardening for these rules to apply. No country is detected for your request with the current source.', 'sentinel-shield' )
						);
						?>
					</p>
					<div class="sshield-fields sshield-fields--four">
						<label><span><?php esc_html_e( 'Country comes from', 'sentinel-shield' ); ?></span>
							<select name="sshield[country_source]">
								<?php foreach ( Geo::sources() as $sshield_value => $sshield_text ) : ?>
									<option value="<?php echo esc_attr( $sshield_value ); ?>" <?php selected( Settings::get( 'country_source' ), $sshield_value ); ?>><?php echo esc_html( $sshield_text ); ?></option>
								<?php endforeach; ?>
							</select></label>
						<label><span><?php esc_html_e( 'Rule', 'sentinel-shield' ); ?></span>
							<select name="sshield[country_mode]">
								<option value="block" <?php selected( Settings::get( 'country_mode' ), 'block' ); ?>><?php esc_html_e( 'Block the listed countries', 'sentinel-shield' ); ?></option>
								<option value="allow" <?php selected( Settings::get( 'country_mode' ), 'allow' ); ?>><?php esc_html_e( 'Allow only the listed countries', 'sentinel-shield' ); ?></option>
							</select></label>
						<label><span><?php esc_html_e( 'Applies to', 'sentinel-shield' ); ?></span>
							<select name="sshield[country_scope]">
								<option value="login" <?php selected( Settings::get( 'country_scope' ), 'login' ); ?>><?php esc_html_e( 'Login page and XML-RPC only', 'sentinel-shield' ); ?></option>
								<option value="site" <?php selected( Settings::get( 'country_scope' ), 'site' ); ?>><?php esc_html_e( 'The whole site', 'sentinel-shield' ); ?></option>
							</select></label>
						<label><span><?php esc_html_e( 'Countries (two-letter codes)', 'sentinel-shield' ); ?></span>
							<input type="text" name="sshield[country_list]" value="<?php echo esc_attr( implode( ', ', (array) Settings::get( 'country_list' ) ) ); ?>" placeholder="RU, CN, KP" spellcheck="false"></label>
					</div>
					<p class="sshield-small"><?php esc_html_e( 'Use ISO country codes, such as US, GB or DE. With Cloudflare, T1 means Tor. Logged-in users are not blocked from the site, and you cannot save a rule that blocks your own country.', 'sentinel-shield' ); ?></p>
				</section>
				<section class="sshield-card sshield-card--full">
					<h2><?php esc_html_e( 'Visitor IP detection', 'sentinel-shield' ); ?></h2>
					<p>
						<?php
						/* translators: %s: IP address. */
						echo esc_html( sprintf( __( 'Sentinel Shield currently sees your IP as %s.', 'sentinel-shield' ), Request::ip() ? Request::ip() : __( 'unknown', 'sentinel-shield' ) ) );
						?>
					</p>
					<?php if ( $sshield_detected && ! $sshield_header ) : ?>
						<p class="sshield-hint">
							<?php
							/* translators: %s: header names. */
							echo esc_html( sprintf( __( 'This request passed through a proxy (%s was sent). If your site is behind Cloudflare or a load balancer, pick it below so lockouts target the real visitor and not the proxy.', 'sentinel-shield' ), implode( ', ', array_keys( $sshield_detected ) ) ) );
							?>
						</p>
					<?php endif; ?>
					<div class="sshield-fields sshield-fields--two">
						<label><span><?php esc_html_e( 'Your site sits behind', 'sentinel-shield' ); ?></span>
							<select name="sshield[proxy_header]">
								<?php foreach ( Settings::proxy_headers() as $sshield_value => $sshield_text ) : ?>
									<option value="<?php echo esc_attr( $sshield_value ); ?>" <?php selected( $sshield_header, $sshield_value ); ?>><?php echo esc_html( $sshield_text ); ?></option>
								<?php endforeach; ?>
							</select>
						</label>
						<label><span><?php esc_html_e( 'Trusted proxy IPs (optional)', 'sentinel-shield' ); ?></span>
							<textarea name="sshield[trusted_proxies]" rows="3" class="sshield-textarea" spellcheck="false"><?php echo esc_textarea( implode( "\n", (array) Settings::get( 'trusted_proxies' ) ) ); ?></textarea>
						</label>
					</div>
					<p class="sshield-small"><?php esc_html_e( 'The proxy header is only believed when the connection comes from a trusted proxy, so a visitor who reaches your server directly cannot fake their address. With no list, private network addresses are trusted, and so are Cloudflare\'s published ranges for the Cloudflare header. List your proxy IPs or ranges if your proxy uses public addresses.', 'sentinel-shield' ); ?></p>
					<?php $sshield_untrusted = Request::untrusted(); ?>
					<?php if ( $sshield_untrusted ) : ?>
						<p class="sshield-notice sshield-notice--warn">
							<?php
							/* translators: %s: IP address. */
							echo esc_html( sprintf( __( 'Your own request came from %1$s with the proxy header, but that address is not trusted, so the header was ignored and lockouts see the proxy instead of visitors. If %2$s is your proxy, add it to the trusted list.', 'sentinel-shield' ), $sshield_untrusted, $sshield_untrusted ) );
							?>
						</p>
					<?php endif; ?>
				</section>
			</div>
			<div class="sshield-actions">
				<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save changes', 'sentinel-shield' ); ?></button>
			</div>
		</form>

	<?php elseif ( 'scan' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-scan.php'; ?>

	<?php elseif ( 'alerts' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-alerts.php'; ?>

	<?php elseif ( 'siem' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-siem.php'; ?>
	<?php elseif ( 'traffic' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-traffic.php'; ?>

	<?php elseif ( 'firewall' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-firewall.php'; ?>
	<?php elseif ( 'edge' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-edge.php'; ?>
	<?php elseif ( 'help' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-help.php'; ?>
	<?php elseif ( 'backups' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-backups.php'; ?>
	<?php elseif ( 'hub' === $tab ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/tab-hub.php'; ?>

	<?php else : ?>
		<div class="sshield-grid">
			<section class="sshield-card sshield-card--full">
				<div class="sshield-card__head">
					<h2><?php esc_html_e( 'Locked out IPs', 'sentinel-shield' ); ?></h2>

					<?php if ( $lockouts ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
							<input type="hidden" name="action" value="sshield_release">
							<?php wp_nonce_field( 'sshield_release' ); ?>
							<button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Release all', 'sentinel-shield' ); ?></button>
						</form>
					<?php endif; ?>
				</div>
				<?php if ( ! $lockouts ) : ?>
					<p class="sshield-empty"><?php esc_html_e( 'No IP addresses are locked out.', 'sentinel-shield' ); ?></p>
				<?php else : ?>
					<table class="sshield-table">
						<thead><tr><th><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Locked until', 'sentinel-shield' ); ?></th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $lockouts as $sshield_ip => $sshield_until ) : ?>
							<tr>
								<td><code><?php echo esc_html( $sshield_ip ); ?></code></td>
								<td><?php echo esc_html( wp_date( $sshield_date_format, $sshield_until ) ); ?></td>
								<td class="sshield-right">
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
										<input type="hidden" name="action" value="sshield_release">
										<input type="hidden" name="ip" value="<?php echo esc_attr( $sshield_ip ); ?>">
										<?php wp_nonce_field( 'sshield_release' ); ?>
										<button type="submit" class="sshield-link"><?php esc_html_e( 'Release', 'sentinel-shield' ); ?></button>
									</form>
									<?php if ( Request::ip() !== $sshield_ip ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
											<input type="hidden" name="action" value="sshield_block">
											<input type="hidden" name="ip" value="<?php echo esc_attr( $sshield_ip ); ?>">
											<?php wp_nonce_field( 'sshield_block' ); ?>
											<button type="submit" class="sshield-link sshield-link--danger"><?php esc_html_e( 'Block permanently', 'sentinel-shield' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</section>

			<?php $sshield_sessions = Sessions::admins(); ?>
			<section class="sshield-card sshield-card--full">
				<div class="sshield-card__head">
					<h2><?php esc_html_e( 'Signed-in administrators', 'sentinel-shield' ); ?></h2>
				</div>
				<?php if ( ! $sshield_sessions ) : ?>
					<p class="sshield-empty"><?php esc_html_e( 'No administrator sessions.', 'sentinel-shield' ); ?></p>
				<?php else : ?>
					<table class="sshield-table">
						<thead><tr><th><?php esc_html_e( 'User', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Browser', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Signed in', 'sentinel-shield' ); ?></th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $sshield_sessions as $sshield_s ) : ?>
							<tr>
								<td><?php echo esc_html( $sshield_s['login'] ); ?></td>
								<td><code><?php echo esc_html( $sshield_s['ip'] ); ?></code></td>
								<td><?php echo esc_html( $sshield_s['agent'] ); ?></td>
								<td><?php echo esc_html( $sshield_s['login_time'] ? wp_date( $sshield_date_format, $sshield_s['login_time'] ) : '-' ); ?></td>
								<td class="sshield-right">
									<?php if ( $sshield_s['current'] ) : ?>
										<span class="sshield-small"><?php esc_html_e( 'This session', 'sentinel-shield' ); ?></span>
									<?php else : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
											<input type="hidden" name="action" value="sshield_session">
											<input type="hidden" name="user" value="<?php echo esc_attr( $sshield_s['user_id'] ); ?>">
											<input type="hidden" name="session" value="<?php echo esc_attr( $sshield_s['verifier'] ); ?>">
											<?php wp_nonce_field( 'sshield_session' ); ?>
											<button type="submit" class="sshield-link sshield-link--danger"><?php esc_html_e( 'Sign out', 'sentinel-shield' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</section>

			<?php $sshield_bans = Bans::bans(); ?>
			<section class="sshield-card sshield-card--full">
				<div class="sshield-card__head">
					<h2><?php esc_html_e( 'Banned IPs', 'sentinel-shield' ); ?></h2>
				</div>
				<?php if ( ! $sshield_bans ) : ?>
					<p class="sshield-empty"><?php esc_html_e( 'No IP addresses are banned. Repeat attackers and 404 probing bots will show up here.', 'sentinel-shield' ); ?></p>
				<?php else : ?>
					<table class="sshield-table">
						<thead><tr><th><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Why', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Banned until', 'sentinel-shield' ); ?></th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $sshield_bans as $sshield_ip => $sshield_ban ) : ?>
							<tr>
								<td><code><?php echo esc_html( $sshield_ip ); ?></code></td>
								<td><?php echo esc_html( $sshield_ban['reason'] ); ?></td>
								<td><?php echo esc_html( wp_date( $sshield_date_format, $sshield_ban['until'] ) ); ?></td>
								<td class="sshield-right">
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
										<input type="hidden" name="action" value="sshield_release">
										<input type="hidden" name="ip" value="<?php echo esc_attr( $sshield_ip ); ?>">
										<?php wp_nonce_field( 'sshield_release' ); ?>
										<button type="submit" class="sshield-link"><?php esc_html_e( 'Lift ban', 'sentinel-shield' ); ?></button>
									</form>
									<?php if ( Request::ip() !== $sshield_ip ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
											<input type="hidden" name="action" value="sshield_block">
											<input type="hidden" name="ip" value="<?php echo esc_attr( $sshield_ip ); ?>">
											<?php wp_nonce_field( 'sshield_block' ); ?>
											<button type="submit" class="sshield-link sshield-link--danger"><?php esc_html_e( 'Block permanently', 'sentinel-shield' ); ?></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</section>

			<section class="sshield-card sshield-card--full">
				<?php
				// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filters.
				$sshield_f    = Export::filters( $_GET );
				$sshield_page = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
				// phpcs:enable
				$sshield_type  = $sshield_f['type'];
				$sshield_args  = array_intersect_key( $sshield_f, array_flip( array( 'type', 'search', 'user_id', 'since', 'until', 'blog_id' ) ) );
				$sshield_per   = 50;
				$sshield_total = Events::count( $sshield_args );
				$sshield_pages = max( 1, (int) ceil( $sshield_total / $sshield_per ) );
				$sshield_rows  = Events::query(
					array_merge(
						$sshield_args,
						array(
							'limit'  => $sshield_per,
							'offset' => ( $sshield_page - 1 ) * $sshield_per,
						)
					)
				);
				$sshield_form  = $sshield_f['form'];
				?>
				<div class="sshield-card__head">
					<h2>
						<?php esc_html_e( 'Activity log', 'sentinel-shield' ); ?>
						<span class="sshield-count">
							<?php
							/* translators: %s: number of events. */
							echo esc_html( sprintf( _n( '%s event', '%s events', $sshield_total, 'sentinel-shield' ), number_format_i18n( $sshield_total ) ) );
							?>
						</span>
					</h2>
					<div class="sshield-inline-form">
						<a class="sshield-btn sshield-btn--ghost" href="<?php echo esc_url( wp_nonce_url( add_query_arg( array_merge( array( 'action' => 'sshield_export' ), $sshield_form ), admin_url( 'admin-post.php' ) ), 'sshield_export' ) ); ?>"><?php esc_html_e( 'Export CSV', 'sentinel-shield' ); ?></a>
						<form method="get" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form" target="_blank">
							<input type="hidden" name="action" value="sshield_compliance">
							<?php wp_nonce_field( 'sshield_compliance', '_wpnonce', false ); ?>
							<label class="screen-reader-text" for="sshield-days"><?php esc_html_e( 'Report period', 'sentinel-shield' ); ?></label>
							<select id="sshield-days" name="days">
								<option value="7"><?php esc_html_e( 'Last 7 days', 'sentinel-shield' ); ?></option>
								<option value="30" selected><?php esc_html_e( 'Last 30 days', 'sentinel-shield' ); ?></option>
								<option value="90"><?php esc_html_e( 'Last 90 days', 'sentinel-shield' ); ?></option>
								<option value="365"><?php esc_html_e( 'Last 12 months', 'sentinel-shield' ); ?></option>
							</select>
							<button type="submit" class="sshield-btn"><?php esc_html_e( 'Compliance report', 'sentinel-shield' ); ?></button>
						</form>
					</div>
				</div>
				<form method="get" class="sshield-filter sshield-filter--log">
					<input type="hidden" name="page" value="<?php echo esc_attr( Admin::SLUG ); ?>">
					<input type="hidden" name="tab" value="activity">
					<label><span><?php esc_html_e( 'Type', 'sentinel-shield' ); ?></span>
						<select name="type">
							<option value=""><?php esc_html_e( 'All events', 'sentinel-shield' ); ?></option>
							<?php foreach ( Events::types() as $sshield_t ) : ?>
								<option value="<?php echo esc_attr( $sshield_t ); ?>" <?php selected( $sshield_type, $sshield_t ); ?>><?php echo esc_html( isset( $sshield_event_labels[ $sshield_t ] ) ? $sshield_event_labels[ $sshield_t ] : $sshield_t ); ?></option>
							<?php endforeach; ?>
						</select></label>
					<?php if ( Network::active() ) : ?>
						<label><span><?php esc_html_e( 'Site', 'sentinel-shield' ); ?></span>
							<select name="site">
								<option value=""><?php esc_html_e( 'All sites', 'sentinel-shield' ); ?></option>
								<?php foreach ( get_sites( array( 'number' => 200 ) ) as $sshield_site ) : ?>
									<option value="<?php echo esc_attr( $sshield_site->blog_id ); ?>" <?php selected( isset( $sshield_form['site'] ) ? (int) $sshield_form['site'] : 0, (int) $sshield_site->blog_id ); ?>><?php echo esc_html( Network::site_name( $sshield_site->blog_id ) ); ?></option>
								<?php endforeach; ?>
							</select></label>
					<?php endif; ?>
					<label><span><?php esc_html_e( 'Username', 'sentinel-shield' ); ?></span>
						<input type="text" name="user" value="<?php echo esc_attr( isset( $sshield_form['user'] ) ? $sshield_form['user'] : '' ); ?>" spellcheck="false"></label>
					<label><span><?php esc_html_e( 'Contains', 'sentinel-shield' ); ?></span>
						<input type="search" name="s" value="<?php echo esc_attr( isset( $sshield_form['s'] ) ? $sshield_form['s'] : '' ); ?>" placeholder="<?php esc_attr_e( 'Text or IP', 'sentinel-shield' ); ?>"></label>
					<label><span><?php esc_html_e( 'From', 'sentinel-shield' ); ?></span>
						<input type="date" name="from" value="<?php echo esc_attr( isset( $sshield_form['from'] ) ? $sshield_form['from'] : '' ); ?>"></label>
					<label><span><?php esc_html_e( 'To', 'sentinel-shield' ); ?></span>
						<input type="date" name="to" value="<?php echo esc_attr( isset( $sshield_form['to'] ) ? $sshield_form['to'] : '' ); ?>"></label>
					<div class="sshield-filter__buttons">
						<button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Filter', 'sentinel-shield' ); ?></button>
						<?php if ( $sshield_form ) : ?>
							<a href="<?php echo esc_url( Admin::url( 'activity' ) ); ?>"><?php esc_html_e( 'Clear', 'sentinel-shield' ); ?></a>
						<?php endif; ?>
					</div>
				</form>
				<?php $sshield_events_table( $sshield_rows, $sshield_event_labels, $sshield_date_format ); ?>
				<?php if ( $sshield_pages > 1 ) : ?>
					<nav class="sshield-pager" aria-label="<?php esc_attr_e( 'Activity pages', 'sentinel-shield' ); ?>">
						<?php if ( $sshield_page > 1 ) : ?>
							<a href="
							<?php
							echo esc_url(
								Admin::url(
									'activity',
									array_filter(
										array_merge(
											$sshield_form,
											array( 'paged' => $sshield_page - 1 )
										)
									)
								)
							);
							?>
										"><?php esc_html_e( 'Newer', 'sentinel-shield' ); ?></a>
						<?php endif; ?>
						<span>
							<?php
							/* translators: 1: page number, 2: page count. */
							echo esc_html( sprintf( __( 'Page %1$d of %2$d', 'sentinel-shield' ), $sshield_page, $sshield_pages ) );
							?>
						</span>
						<?php if ( $sshield_page < $sshield_pages ) : ?>
							<a href="
							<?php
							echo esc_url(
								Admin::url(
									'activity',
									array_filter(
										array_merge(
											$sshield_form,
											array( 'paged' => $sshield_page + 1 )
										)
									)
								)
							);
							?>
										"><?php esc_html_e( 'Older', 'sentinel-shield' ); ?></a>
						<?php endif; ?>
					</nav>
				<?php endif; ?>
			</section>
		</div>
	<?php endif; ?>
	<?php
	$sshield_kinds = array_filter(
		array(
			'hardening' === $tab ? 'captcha' : '',
			'alerts' === $tab ? 'chat' : '',
			'edge' === $tab ? 'edge' : '',
		)
	);
	if ( $sshield_kinds ) {
		require SSHIELD_DIR . 'includes/views/connect-dialogs.php';
	}
	?>
</div>
