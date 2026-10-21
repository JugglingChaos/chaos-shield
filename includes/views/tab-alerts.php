<?php
/**
 * Alerts tab: email and chat alerts, scan schedule, log retention and forwarding.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_fwd_error = Network::get_transient( 'cshield_alerts_error_' . get_current_user_id() );
Network::delete_transient( 'cshield_alerts_error_' . get_current_user_id() );
$cshield_fwd_state = Forwarder::last_status();
$cshield_fwd_queue = count( (array) Network::get_option( Forwarder::QUEUE, array() ) );
$cshield_schedules = array(
	'daily'  => __( 'Every day', 'chaos-shield' ),
	'weekly' => __( 'Every week', 'chaos-shield' ),
	'off'    => __( 'Only when I click Scan now', 'chaos-shield' ),
);
?>
<?php if ( $cshield_fwd_error ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="alert"><?php echo esc_html( $cshield_fwd_error ); ?></div>
<?php endif; ?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="cshield_alerts">
	<?php wp_nonce_field( 'cshield_alerts' ); ?>
	<div class="cshield-grid cshield-grid--even">
		<section class="cshield-card">
			<h2><?php esc_html_e( 'Email alerts', 'chaos-shield' ); ?></h2>
			<div class="cshield-fields cshield-fields--one">
				<label><span><?php esc_html_e( 'Send alerts to', 'chaos-shield' ); ?></span>
					<input type="email" name="cshield[alert_email]" value="<?php echo esc_attr( Settings::get( 'alert_email' ) ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>">
				</label>
			</div>
			<p class="cshield-small"><?php esc_html_e( 'Leave empty to use the site admin email. Each alert is sent at most once every 15 minutes.', 'chaos-shield' ); ?></p>
			<ul class="cshield-optlist">
				<?php foreach ( Settings::alerts() as $cshield_key => $cshield_label ) : ?>
					<li><label><input type="checkbox" name="cshield[<?php echo esc_attr( $cshield_key ); ?>]" value="1" <?php checked( Settings::enabled( $cshield_key ) ); ?>> <?php echo esc_html( $cshield_label ); ?></label></li>
				<?php endforeach; ?>
			</ul>
		</section>
		<section class="cshield-card">
			<h2><?php esc_html_e( 'Scans and log', 'chaos-shield' ); ?></h2>
			<div class="cshield-fields cshield-fields--one">
				<label><span><?php esc_html_e( 'Scan automatically', 'chaos-shield' ); ?></span>
					<select name="cshield[scan_schedule]">
						<?php foreach ( $cshield_schedules as $cshield_value => $cshield_text ) : ?>
							<option value="<?php echo esc_attr( $cshield_value ); ?>" <?php selected( Settings::get( 'scan_schedule' ), $cshield_value ); ?>><?php echo esc_html( $cshield_text ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label><span><?php esc_html_e( 'Keep the activity log for (days)', 'chaos-shield' ); ?></span>
					<input type="number" min="7" max="730" name="cshield[log_retention]" value="<?php echo esc_attr( Settings::get( 'log_retention' ) ); ?>">
				</label>
			</div>
			<p class="cshield-small"><?php esc_html_e( 'Scheduled scans run in the background through WP-Cron, in small steps, so visitors do not notice them. Many audit policies ask for a year of logs: set 365 days, or forward the log below.', 'chaos-shield' ); ?></p>
		</section>
		<section class="cshield-card cshield-card--full">
			<h2><?php esc_html_e( 'Team chat', 'chaos-shield' ); ?></h2>
			<p class="cshield-small"><?php esc_html_e( 'Send the alerts switched on above to a chat channel too, so the whole team sees them. Connect one service.', 'chaos-shield' ); ?></p>
			<?php
			$cshield_kind = 'chat';
			require CSHIELD_DIR . 'includes/views/connections.php';
			$cshield_chat_state = Connections::chat() ? Connections::chat_status() : null;
			?>
			<?php if ( $cshield_chat_state && ! $cshield_chat_state['ok'] ) : ?>
				<p class="cshield-small cshield-text-warn">
					<?php
					/* translators: 1: date and time, 2: error. */
					echo esc_html( sprintf( __( 'The last chat alert failed %1$s: %2$s', 'chaos-shield' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $cshield_chat_state['time'] ), $cshield_chat_state['error'] ) );
					?>
				</p>
			<?php endif; ?>
		</section>
		<section class="cshield-card cshield-card--full">
			<h2><?php esc_html_e( 'Log forwarding', 'chaos-shield' ); ?></h2>
			<p class="cshield-small"><?php esc_html_e( 'Send every activity log event to your SIEM, log service or team chat as it happens. A copy outside this site survives even if the site is compromised.', 'chaos-shield' ); ?></p>
			<div class="cshield-fields cshield-fields--two">
				<label><span><?php esc_html_e( 'Webhook address for a SIEM or log service (JSON POST of every event)', 'chaos-shield' ); ?></span>
					<input type="url" name="cshield[forward_webhook]" value="<?php echo esc_attr( Settings::get( 'forward_webhook' ) ); ?>" placeholder="https://hooks.example.com/..." spellcheck="false"></label>
				<label><span><?php esc_html_e( 'Signing secret (optional, adds an X-Chaos-Signature header)', 'chaos-shield' ); ?></span>
					<input type="text" name="cshield[forward_secret]" value="<?php echo esc_attr( Settings::get( 'forward_secret' ) ); ?>" spellcheck="false" autocomplete="off"></label>
				<label><span><?php esc_html_e( 'Syslog (local, or udp:// or tcp:// host:port)', 'chaos-shield' ); ?></span>
					<input type="text" name="cshield[forward_syslog]" value="<?php echo esc_attr( Settings::get( 'forward_syslog' ) ); ?>" placeholder="udp://logs.example.com:514" spellcheck="false"></label>
				<label><span><?php esc_html_e( 'Forward', 'chaos-shield' ); ?></span>
					<select name="cshield[forward_min_severity]">
						<option value="1" <?php selected( (int) Settings::get( 'forward_min_severity' ), 1 ); ?>><?php esc_html_e( 'Every event', 'chaos-shield' ); ?></option>
						<option value="2" <?php selected( (int) Settings::get( 'forward_min_severity' ), 2 ); ?>><?php esc_html_e( 'Notices and critical events', 'chaos-shield' ); ?></option>
						<option value="3" <?php selected( (int) Settings::get( 'forward_min_severity' ), 3 ); ?>><?php esc_html_e( 'Critical events only', 'chaos-shield' ); ?></option>
					</select></label>
			</div>
			<p class="cshield-small">
				<?php
				if ( $cshield_fwd_state ) {
					echo esc_html(
						$cshield_fwd_state['ok']
							/* translators: %s: date and time. */
							? sprintf( __( 'Last delivery succeeded %s.', 'chaos-shield' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $cshield_fwd_state['time'] ) )
							/* translators: 1: date and time, 2: error. */
							: sprintf( __( 'Last delivery failed %1$s: %2$s', 'chaos-shield' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $cshield_fwd_state['time'] ), $cshield_fwd_state['error'] )
					);
					echo ' ';
				}
				if ( $cshield_fwd_queue ) {
					/* translators: %d: number of events. */
					echo esc_html( sprintf( _n( '%d event waiting to be sent.', '%d events waiting to be sent.', $cshield_fwd_queue, 'chaos-shield' ), $cshield_fwd_queue ) ) . ' ';
				}
				esc_html_e( 'Webhook and TCP deliveries go out in batches within a minute; local and UDP syslog are written at once. Syslog uses RFC 5424 with the security facility.', 'chaos-shield' );
				?>
			</p>
		</section>
	</div>
	<div class="cshield-actions">
		<button type="submit" name="cshield_send_report" value="1" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Save and send the weekly report now', 'chaos-shield' ); ?></button>
		<button type="submit" name="cshield_test_forward" value="1" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Save and send a test event', 'chaos-shield' ); ?></button>
		<button type="submit" name="cshield_test_email" value="1" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Save and send a test email', 'chaos-shield' ); ?></button>
		<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save changes', 'chaos-shield' ); ?></button>
	</div>
</form>
