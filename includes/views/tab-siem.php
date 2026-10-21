<?php
/**
 * SIEM tab: incidents, search, timelines, rules.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view state.
$sshield_incident_id = isset( $_GET['incident'] ) ? absint( $_GET['incident'] ) : 0;
$sshield_tl_ip       = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
$sshield_tl_user     = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
$sshield_q           = isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : '';
$sshield_status_f    = isset( $_GET['status'] ) ? sanitize_key( $_GET['status'] ) : 'active';
// phpcs:enable

$sshield_sev_labels = Incidents::severities();
$sshield_statuses   = Incidents::statuses();
$sshield_rules      = Detect::rules();
$sshield_fmt        = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$sshield_sev_class  = array(
	1 => 'low',
	2 => 'medium',
	3 => 'high',
	4 => 'critical',
);
$sshield_mitre      = static function ( $technique ) {
	if ( ! $technique ) {
		return '';
	}
	$path = str_replace( '.', '/', $technique );
	return '<a class="sshield-tag" href="' . esc_url( 'https://attack.mitre.org/techniques/' . $path . '/' ) . '" target="_blank" rel="noopener noreferrer" title="MITRE ATT&amp;CK">' . esc_html( $technique ) . '</a>';
};
$sshield_ip_link    = static function ( $ip ) {
	return $ip ? '<a class="sshield-link" href="' . esc_url( Admin::url( 'siem', array( 'ip' => $ip ) ) ) . '"><code>' . esc_html( $ip ) . '</code></a>' : '';
};
$sshield_user_link  = static function ( $user_id ) {
	$user = $user_id ? get_userdata( $user_id ) : null;
	return $user ? '<a class="sshield-link" href="' . esc_url( Admin::url( 'siem', array( 'user' => $user->ID ) ) ) . '">' . esc_html( $user->user_login ) . '</a>' : '';
};
$sshield_post       = static function ( $op, $incident, $label, $css = 'sshield-btn sshield-btn--ghost', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form"<?php echo $confirm ? ' onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ')"' : ''; ?>>
		<input type="hidden" name="action" value="sshield_incident">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<input type="hidden" name="incident" value="<?php echo esc_attr( $incident ); ?>">
		<?php wp_nonce_field( 'sshield_incident' ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>

<?php if ( ! Settings::enabled( 'siem' ) ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="status"><?php esc_html_e( 'SIEM detections are switched off under Hardening, so no new incidents are opened. Search and timelines still work.', 'sentinel-shield' ); ?></div>
<?php endif; ?>

<?php
if ( $sshield_incident_id ) :
	$sshield_i = Incidents::get( $sshield_incident_id );
	if ( ! $sshield_i ) :
		?>
		<p class="sshield-empty"><?php esc_html_e( 'That incident no longer exists.', 'sentinel-shield' ); ?></p>
		<?php
	else :
		$sshield_rule   = isset( $sshield_rules[ $sshield_i['rule'] ] ) ? $sshield_rules[ $sshield_i['rule'] ] : null;
		$sshield_evts   = $sshield_i['events'] ? Events::query(
			array(
				'ids'   => $sshield_i['events'],
				'limit' => 200,
			)
		) : array();
		$sshield_user   = $sshield_i['user_id'] ? get_userdata( $sshield_i['user_id'] ) : get_user_by( 'login', $sshield_i['subject'] );
		$sshield_admins = get_users(
			array(
				'role__in' => array( 'administrator' ),
				'fields'   => array( 'ID', 'user_login' ),
			)
		);
		?>
		<p><a class="sshield-link" href="<?php echo esc_url( Admin::url( 'siem' ) ); ?>">&larr; <?php esc_html_e( 'All incidents', 'sentinel-shield' ); ?></a></p>
		<div class="sshield-grid">
			<section class="sshield-card sshield-card--wide sshield-incident sshield-incident--<?php echo esc_attr( $sshield_sev_class[ $sshield_i['severity'] ] ); ?>">
				<div class="sshield-incident__meta">
					<span class="sshield-sev sshield-sev--<?php echo esc_attr( $sshield_sev_class[ $sshield_i['severity'] ] ); ?>"><?php echo esc_html( $sshield_sev_labels[ $sshield_i['severity'] ] ); ?></span>
					<span class="sshield-pill"><?php echo esc_html( $sshield_statuses[ $sshield_i['status'] ] ); ?></span>
					<?php echo $sshield_mitre( $sshield_i['technique'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
					<?php if ( $sshield_rule ) : ?>
						<span class="sshield-small"><?php echo esc_html( $sshield_rule['tactic'] . ' · ' . $sshield_rule['name'] ); ?></span>
					<?php endif; ?>
				</div>
				<h2 class="sshield-incident__title">#<?php echo esc_html( $sshield_i['id'] . ' ' . $sshield_i['title'] ); ?></h2>
				<p><?php echo esc_html( $sshield_i['summary'] ); ?></p>
				<p class="sshield-small">
					<?php
					printf(
						/* translators: 1: first seen, 2: last seen, 3: number of hits. */
						esc_html( _n( 'First seen %1$s, last seen %2$s, %3$d hit.', 'First seen %1$s, last seen %2$s, %3$d hits.', (int) $sshield_i['hits'], 'sentinel-shield' ) ),
						esc_html( wp_date( $sshield_fmt, $sshield_i['created'] ) ),
						esc_html( wp_date( $sshield_fmt, $sshield_i['updated'] ) ),
						(int) $sshield_i['hits']
					);
					?>
				</p>
				<p class="sshield-incident__entities">
					<?php if ( $sshield_i['ip'] ) : ?>
						<span><?php esc_html_e( 'IP', 'sentinel-shield' ); ?> <?php echo $sshield_ip_link( $sshield_i['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></span>
					<?php endif; ?>
					<?php if ( $sshield_user ) : ?>
						<span><?php esc_html_e( 'User', 'sentinel-shield' ); ?> <?php echo $sshield_user_link( $sshield_user->ID ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></span>
					<?php endif; ?>
				</p>
			</section>

			<section class="sshield-card">
				<h2><?php esc_html_e( 'Respond', 'sentinel-shield' ); ?></h2>
				<div class="sshield-respond">
					<?php
					if ( $sshield_i['ip'] && Request::ip() !== $sshield_i['ip'] ) {
						$sshield_post( 'ban', $sshield_i['id'], __( 'Ban this IP', 'sentinel-shield' ) );
						$sshield_post( 'block', $sshield_i['id'], __( 'Block this IP for good', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', __( 'Add this IP to the permanent block list?', 'sentinel-shield' ) );
					}
					if ( $sshield_user && get_current_user_id() !== $sshield_user->ID ) {
						$sshield_post( 'sessions', $sshield_i['id'], __( 'End this user’s sessions', 'sentinel-shield' ) );
						$sshield_post( 'reset', $sshield_i['id'], __( 'Force a password reset', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', __( 'Sign this user out and make them choose a new password?', 'sentinel-shield' ) );
					}
					?>
				</div>
				<?php if ( ( ! $sshield_i['ip'] || Request::ip() === $sshield_i['ip'] ) && ( ! $sshield_user || get_current_user_id() === $sshield_user->ID ) ) : ?>
					<p class="sshield-small"><?php esc_html_e( 'No response actions apply here: the incident names no other IP or user.', 'sentinel-shield' ); ?></p>
				<?php endif; ?>
			</section>

			<section class="sshield-card sshield-card--wide">
				<h2><?php esc_html_e( 'Evidence', 'sentinel-shield' ); ?></h2>
				<?php if ( ! $sshield_evts ) : ?>
					<p class="sshield-empty"><?php esc_html_e( 'The events behind this incident are no longer in the log.', 'sentinel-shield' ); ?></p>
				<?php else : ?>
					<div class="sshield-table-wrap">
						<table class="sshield-table sshield-table--evidence">
							<thead><tr><th><?php esc_html_e( 'Time', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Action', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Event', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></th></tr></thead>
							<tbody>
							<?php foreach ( $sshield_evts as $sshield_e ) : ?>
								<tr class="sshield-sev-<?php echo esc_attr( $sshield_e['severity'] ); ?>">
									<td><?php echo esc_html( wp_date( $sshield_fmt, (int) $sshield_e['time'] ) ); ?></td>
									<td><code><?php echo esc_html( $sshield_e['action'] ? $sshield_e['action'] : $sshield_e['type'] ); ?></code></td>
									<td><?php echo esc_html( $sshield_e['message'] ); ?></td>
									<td><?php echo $sshield_ip_link( $sshield_e['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>
			</section>

			<section class="sshield-card">
				<h2><?php esc_html_e( 'Case', 'sentinel-shield' ); ?></h2>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="sshield_incident">
					<input type="hidden" name="op" value="update">
					<input type="hidden" name="incident" value="<?php echo esc_attr( $sshield_i['id'] ); ?>">
					<?php wp_nonce_field( 'sshield_incident' ); ?>
					<div class="sshield-fields sshield-fields--one">
						<label><span><?php esc_html_e( 'Status', 'sentinel-shield' ); ?></span>
							<select name="status">
								<?php foreach ( $sshield_statuses as $sshield_k => $sshield_l ) : ?>
									<option value="<?php echo esc_attr( $sshield_k ); ?>" <?php selected( $sshield_i['status'], $sshield_k ); ?>><?php echo esc_html( $sshield_l ); ?></option>
								<?php endforeach; ?>
							</select></label>
						<label><span><?php esc_html_e( 'Assigned to', 'sentinel-shield' ); ?></span>
							<select name="assignee">
								<option value="0"><?php esc_html_e( 'Nobody', 'sentinel-shield' ); ?></option>
								<?php foreach ( $sshield_admins as $sshield_a ) : ?>
									<option value="<?php echo esc_attr( $sshield_a->ID ); ?>" <?php selected( $sshield_i['assignee'], (int) $sshield_a->ID ); ?>><?php echo esc_html( $sshield_a->user_login ); ?></option>
								<?php endforeach; ?>
							</select></label>
						<label><span><?php esc_html_e( 'Add a note', 'sentinel-shield' ); ?></span>
							<textarea name="note" rows="3" placeholder="<?php esc_attr_e( 'What you found, what you did', 'sentinel-shield' ); ?>"></textarea></label>
					</div>
					<div class="sshield-actions sshield-actions--start">
						<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save', 'sentinel-shield' ); ?></button>
					</div>
				</form>
				<?php if ( $sshield_i['notes'] ) : ?>
					<ol class="sshield-notes">
						<?php foreach ( array_reverse( $sshield_i['notes'] ) as $sshield_n ) : ?>
							<?php $sshield_nu = get_userdata( (int) $sshield_n['user'] ); ?>
							<li>
								<span class="sshield-small"><?php echo esc_html( wp_date( $sshield_fmt, (int) $sshield_n['time'] ) . ' · ' . ( $sshield_nu ? $sshield_nu->user_login : __( 'system', 'sentinel-shield' ) ) ); ?></span>
								<?php if ( ! empty( $sshield_n['change'] ) ) : ?>
									<p><em><?php echo esc_html( $sshield_n['change'] ); ?></em></p>
								<?php endif; ?>
								<?php if ( ! empty( $sshield_n['text'] ) ) : ?>
									<p><?php echo nl2br( esc_html( $sshield_n['text'] ) ); ?></p>
								<?php endif; ?>
							</li>
						<?php endforeach; ?>
					</ol>
				<?php endif; ?>
			</section>
		</div>
	<?php endif; ?>

	<?php
elseif ( $sshield_tl_ip || $sshield_tl_user ) :
	$sshield_is_ip = '' !== $sshield_tl_ip;
	$sshield_items = Siem::timeline( $sshield_is_ip ? 'ip' : 'user', $sshield_is_ip ? $sshield_tl_ip : $sshield_tl_user );
	$sshield_tu    = $sshield_tl_user ? get_userdata( $sshield_tl_user ) : null;
	$sshield_until = $sshield_is_ip ? Bans::until( $sshield_tl_ip ) : 0;
	$sshield_src   = array(
		'event'    => __( 'Log', 'sentinel-shield' ),
		'traffic'  => __( 'Traffic', 'sentinel-shield' ),
		'incident' => __( 'Incident', 'sentinel-shield' ),
	);
	?>
	<p><a class="sshield-link" href="<?php echo esc_url( Admin::url( 'siem' ) ); ?>">&larr; <?php esc_html_e( 'All incidents', 'sentinel-shield' ); ?></a></p>
	<section class="sshield-card sshield-card--full">
		<div class="sshield-card__head">
			<div>
				<h2>
					<?php
					echo esc_html(
						$sshield_is_ip
							/* translators: %s: IP address or username. */
							? sprintf( __( 'Timeline for %s', 'sentinel-shield' ), $sshield_tl_ip )
							/* translators: %s: IP address or username. */
							: sprintf( __( 'Timeline for %s', 'sentinel-shield' ), $sshield_tu ? $sshield_tu->user_login : '#' . $sshield_tl_user )
					);
					?>
				</h2>
				<p>
					<?php
					/* translators: %d: number of entries. */
					echo esc_html( sprintf( _n( '%d entry from the log, live traffic and incidents.', '%d entries from the log, live traffic and incidents.', count( $sshield_items ), 'sentinel-shield' ), count( $sshield_items ) ) );
					if ( $sshield_until ) {
						echo ' ';
						/* translators: %s: date. */
						echo esc_html( sprintf( __( 'Banned until %s.', 'sentinel-shield' ), wp_date( $sshield_fmt, $sshield_until ) ) );
					}
					?>
				</p>
			</div>
			<?php if ( $sshield_is_ip && Request::ip() !== $sshield_tl_ip && filter_var( $sshield_tl_ip, FILTER_VALIDATE_IP ) ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
					<input type="hidden" name="action" value="sshield_block">
					<input type="hidden" name="ip" value="<?php echo esc_attr( $sshield_tl_ip ); ?>">
					<?php wp_nonce_field( 'sshield_block' ); ?>
					<button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Block IP', 'sentinel-shield' ); ?></button>
				</form>
			<?php endif; ?>
		</div>
		<?php if ( ! $sshield_items ) : ?>
			<p class="sshield-empty"><?php esc_html_e( 'Nothing recorded.', 'sentinel-shield' ); ?></p>
		<?php else : ?>
			<ol class="sshield-timeline">
				<?php foreach ( $sshield_items as $sshield_it ) : ?>
					<li class="sshield-timeline__item sshield-timeline__item--<?php echo esc_attr( $sshield_it['source'] ); ?> sshield-sev-<?php echo esc_attr( $sshield_it['severity'] ); ?>">
						<span class="sshield-timeline__time"><?php echo esc_html( wp_date( $sshield_fmt, $sshield_it['time'] ) ); ?></span>
						<span class="sshield-pill"><?php echo esc_html( $sshield_src[ $sshield_it['source'] ] ); ?></span>
						<?php if ( 'incident' === $sshield_it['source'] ) : ?>
							<a class="sshield-link" href="<?php echo esc_url( Admin::url( 'siem', array( 'incident' => $sshield_it['id'] ) ) ); ?>"><?php echo esc_html( $sshield_it['text'] ); ?></a>
						<?php else : ?>
							<span class="sshield-timeline__text"><?php echo esc_html( $sshield_it['text'] ); ?></span>
						<?php endif; ?>
						<code class="sshield-timeline__meta"><?php echo esc_html( $sshield_it['meta'] ); ?></code>
						<?php if ( ! $sshield_is_ip && $sshield_it['ip'] ) : ?>
							<?php echo $sshield_ip_link( $sshield_it['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ol>
		<?php endif; ?>
	</section>

	<?php
else :
	$sshield_sum    = Incidents::summary();
	$sshield_list   = Incidents::query(
		array(
			'status' => $sshield_status_f,
			'limit'  => 50,
		)
	);
	$sshield_hourly = Siem::hourly();
	$sshield_events = Events::count( array( 'since' => time() - DAY_IN_SECONDS ) );
	$sshield_closed = Incidents::count(
		array(
			'status' => 'resolved',
			'since'  => time() - 30 * DAY_IN_SECONDS,
		)
	);
	?>
	<div class="sshield-tiles">
		<?php foreach ( array( Incidents::CRITICAL, Incidents::HIGH, Incidents::MEDIUM, Incidents::LOW ) as $sshield_sv ) : ?>
			<a class="sshield-tile sshield-tile--<?php echo esc_attr( $sshield_sev_class[ $sshield_sv ] ); ?><?php echo $sshield_sum['by_severity'][ $sshield_sv ] ? ' is-hot' : ''; ?>" href="<?php echo esc_url( Admin::url( 'siem' ) . '#sshield-incidents' ); ?>">
				<span class="sshield-tile__label">
					<?php
					/* translators: %s: severity. */
					echo esc_html( sprintf( __( '%s, open', 'sentinel-shield' ), $sshield_sev_labels[ $sshield_sv ] ) );
					?>
				</span>
				<span class="sshield-tile__value"><?php echo esc_html( number_format_i18n( $sshield_sum['by_severity'][ $sshield_sv ] ) ); ?></span>
			</a>
		<?php endforeach; ?>
	</div>

	<div class="sshield-grid">
		<?php
		$sshield_max = 1;
		foreach ( $sshield_hourly as $sshield_b ) {
			$sshield_max = max( $sshield_max, $sshield_b[1] + $sshield_b[2] + $sshield_b[3] );
		}
		$sshield_cw = 720;
		$sshield_ch = 150;
		$sshield_bw = $sshield_cw / 24;
		?>
		<section class="sshield-card sshield-card--full">
			<div class="sshield-card__head">
				<div>
					<h2><?php esc_html_e( 'Events in the last 24 hours', 'sentinel-shield' ); ?></h2>
					<p>
						<?php
						/* translators: 1: number of events, 2: busiest hour, 3: number of incidents resolved. */
						echo esc_html( sprintf( _n( '%1$s events logged, at most %2$s in one hour. %3$s incident resolved in the last 30 days.', '%1$s events logged, at most %2$s in one hour. %3$s incidents resolved in the last 30 days.', $sshield_closed, 'sentinel-shield' ), number_format_i18n( $sshield_events ), number_format_i18n( $sshield_max ), number_format_i18n( $sshield_closed ) ) );
						?>
					</p>
				</div>
				<ul class="sshield-legend" aria-label="<?php esc_attr_e( 'Severity', 'sentinel-shield' ); ?>">
					<li><span class="sshield-legend__swatch sshield-legend__swatch--1"></span><?php esc_html_e( 'Info', 'sentinel-shield' ); ?></li>
					<li><span class="sshield-legend__swatch sshield-legend__swatch--2"></span><?php esc_html_e( 'Notice', 'sentinel-shield' ); ?></li>
					<li><span class="sshield-legend__swatch sshield-legend__swatch--3"></span><?php esc_html_e( 'Critical', 'sentinel-shield' ); ?></li>
				</ul>
			</div>
			<svg class="sshield-chart" viewBox="0 0 <?php echo esc_attr( $sshield_cw ); ?> <?php echo esc_attr( $sshield_ch + 22 ); ?>" role="img" aria-label="<?php esc_attr_e( 'Events per hour for the last 24 hours, by severity', 'sentinel-shield' ); ?>">
				<line class="sshield-chart__base" x1="0" x2="<?php echo esc_attr( $sshield_cw ); ?>" y1="<?php echo esc_attr( $sshield_ch ); ?>" y2="<?php echo esc_attr( $sshield_ch ); ?>"></line>
				<?php foreach ( $sshield_hourly as $sshield_h => $sshield_b ) : ?>
					<?php
					$sshield_x     = $sshield_h * $sshield_bw + 3;
					$sshield_y     = $sshield_ch;
					$sshield_total = $sshield_b[1] + $sshield_b[2] + $sshield_b[3];
					?>
					<g class="sshield-chart__col">
						<title>
						<?php
						/* translators: 1: hour, 2: total, 3: info, 4: notice, 5: critical. */
						echo esc_html( sprintf( __( '%1$s: %2$d events (%3$d info, %4$d notice, %5$d critical)', 'sentinel-shield' ), wp_date( get_option( 'time_format' ), $sshield_b['start'] ), $sshield_total, $sshield_b[1], $sshield_b[2], $sshield_b[3] ) );
						?>
						</title>
						<rect class="sshield-chart__hit" x="<?php echo esc_attr( $sshield_h * $sshield_bw ); ?>" y="0" width="<?php echo esc_attr( $sshield_bw ); ?>" height="<?php echo esc_attr( $sshield_ch ); ?>"></rect>
						<?php foreach ( array( 1, 2, 3 ) as $sshield_s ) : ?>
							<?php
							if ( ! $sshield_b[ $sshield_s ] ) {
								continue;
							}
							$sshield_hgt = max( 2, ( $sshield_ch - 6 ) * $sshield_b[ $sshield_s ] / $sshield_max );
							$sshield_y  -= $sshield_hgt;
							?>
							<rect class="sshield-chart__bar sshield-chart__bar--<?php echo esc_attr( $sshield_s ); ?>" x="<?php echo esc_attr( $sshield_x ); ?>" y="<?php echo esc_attr( $sshield_y ); ?>" width="<?php echo esc_attr( $sshield_bw - 6 ); ?>" height="<?php echo esc_attr( max( 1, $sshield_hgt - 2 ) ); ?>" rx="2"></rect>
						<?php endforeach; ?>
						<?php if ( 0 === $sshield_h % 6 ) : ?>
							<text class="sshield-chart__label" x="<?php echo esc_attr( $sshield_x ); ?>" y="<?php echo esc_attr( $sshield_ch + 16 ); ?>"><?php echo esc_html( wp_date( 'H:i', $sshield_b['start'] ) ); ?></text>
						<?php endif; ?>
					</g>
				<?php endforeach; ?>
			</svg>
		</section>

		<section class="sshield-card sshield-card--full" id="sshield-incidents">
			<div class="sshield-card__head">
				<h2><?php esc_html_e( 'Incidents', 'sentinel-shield' ); ?></h2>
				<nav class="sshield-chips" aria-label="<?php esc_attr_e( 'Filter incidents', 'sentinel-shield' ); ?>">
					<?php
					foreach ( array(
						'active'         => __( 'Open', 'sentinel-shield' ),
						'resolved'       => $sshield_statuses['resolved'],
						'false_positive' => $sshield_statuses['false_positive'],
						'all'            => __( 'All', 'sentinel-shield' ),
					) as $sshield_k => $sshield_l ) :
						?>
						<a class="sshield-chip<?php echo $sshield_k === $sshield_status_f ? ' is-active' : ''; ?>" href="<?php echo esc_url( Admin::url( 'siem', array( 'status' => $sshield_k ) ) . '#sshield-incidents' ); ?>"><?php echo esc_html( $sshield_l ); ?></a>
					<?php endforeach; ?>
				</nav>
			</div>
			<?php if ( ! $sshield_list ) : ?>
				<p class="sshield-empty"><?php echo esc_html( 'active' === $sshield_status_f ? __( 'No open incidents. The rules below are watching.', 'sentinel-shield' ) : __( 'No incidents here.', 'sentinel-shield' ) ); ?></p>
			<?php else : ?>
				<ul class="sshield-incidents">
					<?php foreach ( $sshield_list as $sshield_i ) : ?>
						<li class="sshield-incident-row sshield-incident-row--<?php echo esc_attr( $sshield_sev_class[ $sshield_i['severity'] ] ); ?>">
							<span class="sshield-sev sshield-sev--<?php echo esc_attr( $sshield_sev_class[ $sshield_i['severity'] ] ); ?>"><?php echo esc_html( $sshield_sev_labels[ $sshield_i['severity'] ] ); ?></span>
							<div class="sshield-incident-row__body">
								<a class="sshield-incident-row__title" href="<?php echo esc_url( Admin::url( 'siem', array( 'incident' => $sshield_i['id'] ) ) ); ?>">#<?php echo esc_html( $sshield_i['id'] . ' ' . $sshield_i['title'] ); ?></a>
								<p class="sshield-small">
									<?php
									$sshield_bits = array( wp_date( $sshield_fmt, $sshield_i['updated'] ) );
									if ( $sshield_i['hits'] > 1 ) {
										/* translators: %d: number of hits. */
										$sshield_bits[] = sprintf( __( '%d hits', 'sentinel-shield' ), $sshield_i['hits'] );
									}
									$sshield_bits[] = $sshield_statuses[ $sshield_i['status'] ];
									if ( $sshield_i['assignee'] ) {
										$sshield_as = get_userdata( $sshield_i['assignee'] );
										if ( $sshield_as ) {
											/* translators: %s: username. */
											$sshield_bits[] = sprintf( __( 'assigned to %s', 'sentinel-shield' ), $sshield_as->user_login );
										}
									}
									echo esc_html( implode( ' · ', $sshield_bits ) );
									?>
								</p>
							</div>
							<?php echo $sshield_mitre( $sshield_i['technique'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</section>

		<section class="sshield-card sshield-card--full" id="sshield-search">
			<h2><?php esc_html_e( 'Search the log', 'sentinel-shield' ); ?></h2>
			<form method="get" action="<?php echo esc_url( Network::admin_url( 'admin.php' ) ); ?>" class="sshield-search">
				<input type="hidden" name="page" value="<?php echo esc_attr( Admin::SLUG ); ?>">
				<input type="hidden" name="tab" value="siem">
				<input type="search" name="q" value="<?php echo esc_attr( $sshield_q ); ?>" placeholder="action:auth.failed since:24h" spellcheck="false" aria-label="<?php esc_attr_e( 'Search', 'sentinel-shield' ); ?>">
				<button type="submit" class="sshield-btn"><?php esc_html_e( 'Search', 'sentinel-shield' ); ?></button>
			</form>
			<p class="sshield-small"><?php esc_html_e( 'Fields: ip:, user:, action: (end with * for a family, such as auth.*), type:, sev: (1 to 3), since: (30m, 24h, 7d), site: (on a network). Other words search the message.', 'sentinel-shield' ); ?></p>
			<?php if ( '' !== $sshield_q ) : ?>
				<?php
				$sshield_sargs = Siem::parse( $sshield_q );
				$sshield_found = Events::query( $sshield_sargs + array( 'limit' => 200 ) );
				$sshield_total = Events::count( $sshield_sargs );
				?>
				<p>
					<?php
					/* translators: 1: shown, 2: total matches. */
					echo esc_html( sprintf( __( 'Showing %1$s of %2$s matching events.', 'sentinel-shield' ), number_format_i18n( count( $sshield_found ) ), number_format_i18n( $sshield_total ) ) );
					?>
				</p>
				<?php if ( $sshield_found ) : ?>
					<div class="sshield-table-wrap">
						<table class="sshield-table sshield-table--evidence">
							<thead><tr><th><?php esc_html_e( 'Time', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Action', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Event', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></th></tr></thead>
							<tbody>
							<?php foreach ( $sshield_found as $sshield_e ) : ?>
								<tr class="sshield-sev-<?php echo esc_attr( $sshield_e['severity'] ); ?>">
									<td><?php echo esc_html( wp_date( $sshield_fmt, (int) $sshield_e['time'] ) ); ?></td>
									<td><code><?php echo esc_html( $sshield_e['action'] ? $sshield_e['action'] : $sshield_e['type'] ); ?></code></td>
									<td><?php echo esc_html( $sshield_e['message'] ); ?> <?php echo $sshield_user_link( (int) $sshield_e['user_id'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></td>
									<td><?php echo $sshield_ip_link( $sshield_e['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>
			<?php endif; ?>
		</section>

		<section class="sshield-card sshield-card--full" id="sshield-rules">
			<h2><?php esc_html_e( 'Detection rules', 'sentinel-shield' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="sshield_rules">
				<?php wp_nonce_field( 'sshield_rules' ); ?>
				<ul class="sshield-rules">
					<?php foreach ( $sshield_rules as $sshield_rk => $sshield_r ) : ?>
						<?php
						$sshield_hits = Incidents::count(
							array(
								'status' => 'all',
								'rule'   => $sshield_rk,
								'since'  => time() - 30 * DAY_IN_SECONDS,
							)
						);
						?>
						<li>
							<label class="sshield-rule">
								<input type="checkbox" name="rules[]" value="<?php echo esc_attr( $sshield_rk ); ?>" <?php checked( Detect::rule_on( $sshield_rk ) ); ?>>
								<span class="sshield-rule__body">
									<strong><?php echo esc_html( $sshield_r['name'] ); ?></strong>
									<span class="sshield-small"><?php echo esc_html( $sshield_r['description'] ); ?></span>
								</span>
								<span class="sshield-rule__meta">
									<?php echo $sshield_mitre( $sshield_r['technique'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
									<span class="sshield-small">
										<?php
										/* translators: %d: number of incidents. */
										echo esc_html( sprintf( _n( '%d incident in 30 days', '%d incidents in 30 days', $sshield_hits, 'sentinel-shield' ), $sshield_hits ) );
										?>
									</span>
								</span>
							</label>
						</li>
					<?php endforeach; ?>
				</ul>
				<div class="sshield-fields sshield-fields--two sshield-fields--spaced">
					<label><span><?php esc_html_e( 'Email me about incidents rated', 'sentinel-shield' ); ?></span>
						<select name="alert_min">
							<?php foreach ( array_reverse( $sshield_sev_labels, true ) as $sshield_sv => $sshield_sl ) : ?>
								<option value="<?php echo esc_attr( $sshield_sv ); ?>" <?php selected( (int) Settings::get( 'siem_alert_min' ), $sshield_sv ); ?>>
									<?php
									echo esc_html(
										Incidents::CRITICAL === $sshield_sv
											? $sshield_sl
											/* translators: %s: severity. */
											: sprintf( __( '%s and above', 'sentinel-shield' ), $sshield_sl )
									);
									?>
								</option>
							<?php endforeach; ?>
						</select></label>
				</div>
				<div class="sshield-actions sshield-actions--start">
					<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save rules', 'sentinel-shield' ); ?></button>
				</div>
			</form>
		</section>
	</div>
<?php endif; ?>
