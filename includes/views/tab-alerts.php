<?php
/**
 * Alerts tab: email and chat alerts, scan schedule, log retention and forwarding.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_fwd_error = Network::get_transient( 'sshield_alerts_error_' . get_current_user_id() );
Network::delete_transient( 'sshield_alerts_error_' . get_current_user_id() );
$sshield_fwd_state = Forwarder::last_status();
$sshield_fwd_queue = count( (array) Network::get_option( Forwarder::QUEUE, array() ) );
$sshield_schedules = array(
	'daily'  => __( 'Every day', 'sentinel-shield' ),
	'weekly' => __( 'Every week', 'sentinel-shield' ),
	'off'    => __( 'Only when I click Scan now', 'sentinel-shield' ),
);
?>
<?php if ( $sshield_fwd_error ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="alert"><?php echo esc_html( $sshield_fwd_error ); ?></div>
<?php endif; ?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="sshield_alerts">
	<?php wp_nonce_field( 'sshield_alerts' ); ?>
	<div class="sshield-grid sshield-grid--even">
		<section class="sshield-card">
			<h2><?php esc_html_e( 'Email alerts', 'sentinel-shield' ); ?></h2>
			<div class="sshield-fields sshield-fields--one">
				<label><span><?php esc_html_e( 'Send alerts to', 'sentinel-shield' ); ?></span>
					<input type="email" name="sshield[alert_email]" value="<?php echo esc_attr( Settings::get( 'alert_email' ) ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>">
				</label>
			</div>
			<p class="sshield-small"><?php esc_html_e( 'Leave empty to use the site admin email. Each alert is sent at most once every 15 minutes.', 'sentinel-shield' ); ?></p>
			<ul class="sshield-optlist">
				<?php foreach ( Settings::alerts() as $sshield_key => $sshield_label ) : ?>
					<li><label><input type="checkbox" name="sshield[<?php echo esc_attr( $sshield_key ); ?>]" value="1" <?php checked( Settings::enabled( $sshield_key ) ); ?>> <?php echo esc_html( $sshield_label ); ?></label></li>
				<?php endforeach; ?>
			</ul>
		</section>
		<section class="sshield-card">
			<h2><?php esc_html_e( 'Scans and log', 'sentinel-shield' ); ?></h2>
			<div class="sshield-fields sshield-fields--one">
				<label><span><?php esc_html_e( 'Scan automatically', 'sentinel-shield' ); ?></span>
					<select name="sshield[scan_schedule]">
						<?php foreach ( $sshield_schedules as $sshield_value => $sshield_text ) : ?>
							<option value="<?php echo esc_attr( $sshield_value ); ?>" <?php selected( Settings::get( 'scan_schedule' ), $sshield_value ); ?>><?php echo esc_html( $sshield_text ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label><span><?php esc_html_e( 'Keep the activity log for (days)', 'sentinel-shield' ); ?></span>
					<input type="number" min="7" max="730" name="sshield[log_retention]" value="<?php echo esc_attr( Settings::get( 'log_retention' ) ); ?>">
				</label>
			</div>
			<p class="sshield-small"><?php esc_html_e( 'Scheduled scans run in the background through WP-Cron, in small steps, so visitors do not notice them. Many audit policies ask for a year of logs: set 365 days, or forward the log below.', 'sentinel-shield' ); ?></p>
		</section>
		<section class="sshield-card sshield-card--full">
			<h2><?php esc_html_e( 'Team chat', 'sentinel-shield' ); ?></h2>
			<p class="sshield-small"><?php esc_html_e( 'Send the alerts switched on above to a chat channel too, so the whole team sees them. Connect one service.', 'sentinel-shield' ); ?></p>
			<?php
			$sshield_kind = 'chat';
			require SSHIELD_DIR . 'includes/views/connections.php';
			$sshield_chat_state = Connections::chat() ? Connections::chat_status() : null;
			?>
			<?php if ( $sshield_chat_state && ! $sshield_chat_state['ok'] ) : ?>
				<p class="sshield-small sshield-text-warn">
					<?php
					/* translators: 1: date and time, 2: error. */
					echo esc_html( sprintf( __( 'The last chat alert failed %1$s: %2$s', 'sentinel-shield' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $sshield_chat_state['time'] ), $sshield_chat_state['error'] ) );
					?>
				</p>
			<?php endif; ?>
		</section>
		<section class="sshield-card sshield-card--full">
			<h2><?php esc_html_e( 'Log forwarding', 'sentinel-shield' ); ?></h2>
			<p class="sshield-small"><?php esc_html_e( 'Send every activity log event to your SIEM, log service or team chat as it happens. A copy outside this site survives even if the site is compromised.', 'sentinel-shield' ); ?></p>
			<div class="sshield-fields sshield-fields--two">
				<label><span><?php esc_html_e( 'Webhook address for a SIEM or log service (JSON POST of every event)', 'sentinel-shield' ); ?></span>
					<input type="url" name="sshield[forward_webhook]" value="<?php echo esc_attr( Settings::get( 'forward_webhook' ) ); ?>" placeholder="https://hooks.example.com/..." spellcheck="false"></label>
				<label><span><?php esc_html_e( 'Signing secret (optional, adds an X-Sentinel-Signature header)', 'sentinel-shield' ); ?></span>
					<input type="text" name="sshield[forward_secret]" value="<?php echo esc_attr( Settings::get( 'forward_secret' ) ); ?>" spellcheck="false" autocomplete="off"></label>
				<label><span><?php esc_html_e( 'Syslog (local, or udp:// or tcp:// host:port)', 'sentinel-shield' ); ?></span>
					<input type="text" name="sshield[forward_syslog]" value="<?php echo esc_attr( Settings::get( 'forward_syslog' ) ); ?>" placeholder="udp://logs.example.com:514" spellcheck="false"></label>
				<label><span><?php esc_html_e( 'Forward', 'sentinel-shield' ); ?></span>
					<select name="sshield[forward_min_severity]">
						<option value="1" <?php selected( (int) Settings::get( 'forward_min_severity' ), 1 ); ?>><?php esc_html_e( 'Every event', 'sentinel-shield' ); ?></option>
						<option value="2" <?php selected( (int) Settings::get( 'forward_min_severity' ), 2 ); ?>><?php esc_html_e( 'Notices and critical events', 'sentinel-shield' ); ?></option>
						<option value="3" <?php selected( (int) Settings::get( 'forward_min_severity' ), 3 ); ?>><?php esc_html_e( 'Critical events only', 'sentinel-shield' ); ?></option>
					</select></label>
			</div>
			<p class="sshield-small">
				<?php
				if ( $sshield_fwd_state ) {
					echo esc_html(
						$sshield_fwd_state['ok']
							/* translators: %s: date and time. */
							? sprintf( __( 'Last delivery succeeded %s.', 'sentinel-shield' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $sshield_fwd_state['time'] ) )
							/* translators: 1: date and time, 2: error. */
							: sprintf( __( 'Last delivery failed %1$s: %2$s', 'sentinel-shield' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $sshield_fwd_state['time'] ), $sshield_fwd_state['error'] )
					);
					echo ' ';
				}
				if ( $sshield_fwd_queue ) {
					/* translators: %d: number of events. */
					echo esc_html( sprintf( _n( '%d event waiting to be sent.', '%d events waiting to be sent.', $sshield_fwd_queue, 'sentinel-shield' ), $sshield_fwd_queue ) ) . ' ';
				}
				esc_html_e( 'Webhook and TCP deliveries go out in batches within a minute; local and UDP syslog are written at once. Syslog uses RFC 5424 with the security facility.', 'sentinel-shield' );
				?>
			</p>
		</section>
	</div>
	<div class="sshield-actions">
		<button type="submit" name="sshield_send_report" value="1" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Save and send the weekly report now', 'sentinel-shield' ); ?></button>
		<button type="submit" name="sshield_test_forward" value="1" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Save and send a test event', 'sentinel-shield' ); ?></button>
		<button type="submit" name="sshield_test_email" value="1" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Save and send a test email', 'sentinel-shield' ); ?></button>
		<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save changes', 'sentinel-shield' ); ?></button>
	</div>
</form>
