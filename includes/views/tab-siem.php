<?php
/**
 * SIEM tab: incidents, search, timelines, rules.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view state.
$cshield_incident_id = isset( $_GET['incident'] ) ? absint( $_GET['incident'] ) : 0;
$cshield_tl_ip       = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
$cshield_tl_user     = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
$cshield_q           = isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : '';
$cshield_status_f    = isset( $_GET['status'] ) ? sanitize_key( $_GET['status'] ) : 'active';
// phpcs:enable

$cshield_sev_labels = Incidents::severities();
$cshield_statuses   = Incidents::statuses();
$cshield_rules      = Detect::rules();
$cshield_fmt        = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$cshield_sev_class  = array(
	1 => 'low',
	2 => 'medium',
	3 => 'high',
	4 => 'critical',
);
$cshield_mitre      = static function ( $technique ) {
	if ( ! $technique ) {
		return '';
	}
	$path = str_replace( '.', '/', $technique );
	return '<a class="cshield-tag" href="' . esc_url( 'https://attack.mitre.org/techniques/' . $path . '/' ) . '" target="_blank" rel="noopener noreferrer" title="MITRE ATT&amp;CK">' . esc_html( $technique ) . '</a>';
};
$cshield_ip_link    = static function ( $ip ) {
	return $ip ? '<a class="cshield-link" href="' . esc_url( Admin::url( 'siem', array( 'ip' => $ip ) ) ) . '"><code>' . esc_html( $ip ) . '</code></a>' : '';
};
$cshield_user_link  = static function ( $user_id ) {
	$user = $user_id ? get_userdata( $user_id ) : null;
	return $user ? '<a class="cshield-link" href="' . esc_url( Admin::url( 'siem', array( 'user' => $user->ID ) ) ) . '">' . esc_html( $user->user_login ) . '</a>' : '';
};
$cshield_post       = static function ( $op, $incident, $label, $css = 'cshield-btn cshield-btn--ghost', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form"<?php echo $confirm ? ' onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ')"' : ''; ?>>
		<input type="hidden" name="action" value="cshield_incident">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<input type="hidden" name="incident" value="<?php echo esc_attr( $incident ); ?>">
		<?php wp_nonce_field( 'cshield_incident' ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>

<?php if ( ! Settings::enabled( 'siem' ) ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="status"><?php esc_html_e( 'SIEM detections are switched off under Hardening, so no new incidents are opened. Search and timelines still work.', 'chaos-shield' ); ?></div>
<?php endif; ?>

<?php
if ( $cshield_incident_id ) :
	$cshield_i = Incidents::get( $cshield_incident_id );
	if ( ! $cshield_i ) :
		?>
		<p class="cshield-empty"><?php esc_html_e( 'That incident no longer exists.', 'chaos-shield' ); ?></p>
		<?php
	else :
		$cshield_rule   = isset( $cshield_rules[ $cshield_i['rule'] ] ) ? $cshield_rules[ $cshield_i['rule'] ] : null;
		$cshield_evts   = $cshield_i['events'] ? Events::query(
			array(
				'ids'   => $cshield_i['events'],
				'limit' => 200,
			)
		) : array();
		$cshield_user   = $cshield_i['user_id'] ? get_userdata( $cshield_i['user_id'] ) : get_user_by( 'login', $cshield_i['subject'] );
		$cshield_admins = get_users(
			array(
				'role__in' => array( 'administrator' ),
				'fields'   => array( 'ID', 'user_login' ),
			)
		);
		?>
		<p><a class="cshield-link" href="<?php echo esc_url( Admin::url( 'siem' ) ); ?>">&larr; <?php esc_html_e( 'All incidents', 'chaos-shield' ); ?></a></p>
		<div class="cshield-grid">
			<section class="cshield-card cshield-card--wide cshield-incident cshield-incident--<?php echo esc_attr( $cshield_sev_class[ $cshield_i['severity'] ] ); ?>">
				<div class="cshield-incident__meta">
					<span class="cshield-sev cshield-sev--<?php echo esc_attr( $cshield_sev_class[ $cshield_i['severity'] ] ); ?>"><?php echo esc_html( $cshield_sev_labels[ $cshield_i['severity'] ] ); ?></span>
					<span class="cshield-pill"><?php echo esc_html( $cshield_statuses[ $cshield_i['status'] ] ); ?></span>
					<?php echo $cshield_mitre( $cshield_i['technique'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
					<?php if ( $cshield_rule ) : ?>
						<span class="cshield-small"><?php echo esc_html( $cshield_rule['tactic'] . ' · ' . $cshield_rule['name'] ); ?></span>
					<?php endif; ?>
				</div>
				<h2 class="cshield-incident__title">#<?php echo esc_html( $cshield_i['id'] . ' ' . $cshield_i['title'] ); ?></h2>
				<p><?php echo esc_html( $cshield_i['summary'] ); ?></p>
				<p class="cshield-small">
					<?php
					printf(
						/* translators: 1: first seen, 2: last seen, 3: number of hits. */
						esc_html( _n( 'First seen %1$s, last seen %2$s, %3$d hit.', 'First seen %1$s, last seen %2$s, %3$d hits.', (int) $cshield_i['hits'], 'chaos-shield' ) ),
						esc_html( wp_date( $cshield_fmt, $cshield_i['created'] ) ),
						esc_html( wp_date( $cshield_fmt, $cshield_i['updated'] ) ),
						(int) $cshield_i['hits']
					);
					?>
				</p>
				<p class="cshield-incident__entities">
					<?php if ( $cshield_i['ip'] ) : ?>
						<span><?php esc_html_e( 'IP', 'chaos-shield' ); ?> <?php echo $cshield_ip_link( $cshield_i['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></span>
					<?php endif; ?>
					<?php if ( $cshield_user ) : ?>
						<span><?php esc_html_e( 'User', 'chaos-shield' ); ?> <?php echo $cshield_user_link( $cshield_user->ID ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></span>
					<?php endif; ?>
				</p>
			</section>

			<section class="cshield-card">
				<h2><?php esc_html_e( 'Respond', 'chaos-shield' ); ?></h2>
				<div class="cshield-respond">
					<?php
					if ( $cshield_i['ip'] && Request::ip() !== $cshield_i['ip'] ) {
						$cshield_post( 'ban', $cshield_i['id'], __( 'Ban this IP', 'chaos-shield' ) );
						$cshield_post( 'block', $cshield_i['id'], __( 'Block this IP for good', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', __( 'Add this IP to the permanent block list?', 'chaos-shield' ) );
					}
					if ( $cshield_user && get_current_user_id() !== $cshield_user->ID ) {
						$cshield_post( 'sessions', $cshield_i['id'], __( 'End this user’s sessions', 'chaos-shield' ) );
						$cshield_post( 'reset', $cshield_i['id'], __( 'Force a password reset', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', __( 'Sign this user out and make them choose a new password?', 'chaos-shield' ) );
					}
					?>
				</div>
				<?php if ( ( ! $cshield_i['ip'] || Request::ip() === $cshield_i['ip'] ) && ( ! $cshield_user || get_current_user_id() === $cshield_user->ID ) ) : ?>
					<p class="cshield-small"><?php esc_html_e( 'No response actions apply here: the incident names no other IP or user.', 'chaos-shield' ); ?></p>
				<?php endif; ?>
			</section>

			<section class="cshield-card cshield-card--wide">
				<h2><?php esc_html_e( 'Evidence', 'chaos-shield' ); ?></h2>
				<?php if ( ! $cshield_evts ) : ?>
					<p class="cshield-empty"><?php esc_html_e( 'The events behind this incident are no longer in the log.', 'chaos-shield' ); ?></p>
				<?php else : ?>
					<div class="cshield-table-wrap">
						<table class="cshield-table cshield-table--evidence">
							<thead><tr><th><?php esc_html_e( 'Time', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Action', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Event', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'IP', 'chaos-shield' ); ?></th></tr></thead>
							<tbody>
							<?php foreach ( $cshield_evts as $cshield_e ) : ?>
								<tr class="cshield-sev-<?php echo esc_attr( $cshield_e['severity'] ); ?>">
									<td><?php echo esc_html( wp_date( $cshield_fmt, (int) $cshield_e['time'] ) ); ?></td>
									<td><code><?php echo esc_html( $cshield_e['action'] ? $cshield_e['action'] : $cshield_e['type'] ); ?></code></td>
									<td><?php echo esc_html( $cshield_e['message'] ); ?></td>
									<td><?php echo $cshield_ip_link( $cshield_e['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>
			</section>

			<section class="cshield-card">
				<h2><?php esc_html_e( 'Case', 'chaos-shield' ); ?></h2>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="cshield_incident">
					<input type="hidden" name="op" value="update">
					<input type="hidden" name="incident" value="<?php echo esc_attr( $cshield_i['id'] ); ?>">
					<?php wp_nonce_field( 'cshield_incident' ); ?>
					<div class="cshield-fields cshield-fields--one">
						<label><span><?php esc_html_e( 'Status', 'chaos-shield' ); ?></span>
							<select name="status">
								<?php foreach ( $cshield_statuses as $cshield_k => $cshield_l ) : ?>
									<option value="<?php echo esc_attr( $cshield_k ); ?>" <?php selected( $cshield_i['status'], $cshield_k ); ?>><?php echo esc_html( $cshield_l ); ?></option>
								<?php endforeach; ?>
							</select></label>
						<label><span><?php esc_html_e( 'Assigned to', 'chaos-shield' ); ?></span>
							<select name="assignee">
								<option value="0"><?php esc_html_e( 'Nobody', 'chaos-shield' ); ?></option>
								<?php foreach ( $cshield_admins as $cshield_a ) : ?>
									<option value="<?php echo esc_attr( $cshield_a->ID ); ?>" <?php selected( $cshield_i['assignee'], (int) $cshield_a->ID ); ?>><?php echo esc_html( $cshield_a->user_login ); ?></option>
								<?php endforeach; ?>
							</select></label>
						<label><span><?php esc_html_e( 'Add a note', 'chaos-shield' ); ?></span>
							<textarea name="note" rows="3" placeholder="<?php esc_attr_e( 'What you found, what you did', 'chaos-shield' ); ?>"></textarea></label>
					</div>
					<div class="cshield-actions cshield-actions--start">
						<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save', 'chaos-shield' ); ?></button>
					</div>
				</form>
				<?php if ( $cshield_i['notes'] ) : ?>
					<ol class="cshield-notes">
						<?php foreach ( array_reverse( $cshield_i['notes'] ) as $cshield_n ) : ?>
							<?php $cshield_nu = get_userdata( (int) $cshield_n['user'] ); ?>
							<li>
								<span class="cshield-small"><?php echo esc_html( wp_date( $cshield_fmt, (int) $cshield_n['time'] ) . ' · ' . ( $cshield_nu ? $cshield_nu->user_login : __( 'system', 'chaos-shield' ) ) ); ?></span>
								<?php if ( ! empty( $cshield_n['change'] ) ) : ?>
									<p><em><?php echo esc_html( $cshield_n['change'] ); ?></em></p>
								<?php endif; ?>
								<?php if ( ! empty( $cshield_n['text'] ) ) : ?>
									<p><?php echo nl2br( esc_html( $cshield_n['text'] ) ); ?></p>
								<?php endif; ?>
							</li>
						<?php endforeach; ?>
					</ol>
				<?php endif; ?>
			</section>
		</div>
	<?php endif; ?>

	<?php
elseif ( $cshield_tl_ip || $cshield_tl_user ) :
	$cshield_is_ip = '' !== $cshield_tl_ip;
	$cshield_items = Siem::timeline( $cshield_is_ip ? 'ip' : 'user', $cshield_is_ip ? $cshield_tl_ip : $cshield_tl_user );
	$cshield_tu    = $cshield_tl_user ? get_userdata( $cshield_tl_user ) : null;
	$cshield_until = $cshield_is_ip ? Bans::until( $cshield_tl_ip ) : 0;
	$cshield_src   = array(
		'event'    => __( 'Log', 'chaos-shield' ),
		'traffic'  => __( 'Traffic', 'chaos-shield' ),
		'incident' => __( 'Incident', 'chaos-shield' ),
	);
	?>
	<p><a class="cshield-link" href="<?php echo esc_url( Admin::url( 'siem' ) ); ?>">&larr; <?php esc_html_e( 'All incidents', 'chaos-shield' ); ?></a></p>
	<section class="cshield-card cshield-card--full">
		<div class="cshield-card__head">
			<div>
				<h2>
					<?php
					echo esc_html(
						$cshield_is_ip
							/* translators: %s: IP address or username. */
							? sprintf( __( 'Timeline for %s', 'chaos-shield' ), $cshield_tl_ip )
							/* translators: %s: IP address or username. */
							: sprintf( __( 'Timeline for %s', 'chaos-shield' ), $cshield_tu ? $cshield_tu->user_login : '#' . $cshield_tl_user )
					);
					?>
				</h2>
				<p>
					<?php
					/* translators: %d: number of entries. */
					echo esc_html( sprintf( _n( '%d entry from the log, live traffic and incidents.', '%d entries from the log, live traffic and incidents.', count( $cshield_items ), 'chaos-shield' ), count( $cshield_items ) ) );
					if ( $cshield_until ) {
						echo ' ';
						/* translators: %s: date. */
						echo esc_html( sprintf( __( 'Banned until %s.', 'chaos-shield' ), wp_date( $cshield_fmt, $cshield_until ) ) );
					}
					?>
				</p>
			</div>
			<?php if ( $cshield_is_ip && Request::ip() !== $cshield_tl_ip && filter_var( $cshield_tl_ip, FILTER_VALIDATE_IP ) ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
					<input type="hidden" name="action" value="cshield_block">
					<input type="hidden" name="ip" value="<?php echo esc_attr( $cshield_tl_ip ); ?>">
					<?php wp_nonce_field( 'cshield_block' ); ?>
					<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Block IP', 'chaos-shield' ); ?></button>
				</form>
			<?php endif; ?>
		</div>
		<?php if ( ! $cshield_items ) : ?>
			<p class="cshield-empty"><?php esc_html_e( 'Nothing recorded.', 'chaos-shield' ); ?></p>
		<?php else : ?>
			<ol class="cshield-timeline">
				<?php foreach ( $cshield_items as $cshield_it ) : ?>
					<li class="cshield-timeline__item cshield-timeline__item--<?php echo esc_attr( $cshield_it['source'] ); ?> cshield-sev-<?php echo esc_attr( $cshield_it['severity'] ); ?>">
						<span class="cshield-timeline__time"><?php echo esc_html( wp_date( $cshield_fmt, $cshield_it['time'] ) ); ?></span>
						<span class="cshield-pill"><?php echo esc_html( $cshield_src[ $cshield_it['source'] ] ); ?></span>
						<?php if ( 'incident' === $cshield_it['source'] ) : ?>
							<a class="cshield-link" href="<?php echo esc_url( Admin::url( 'siem', array( 'incident' => $cshield_it['id'] ) ) ); ?>"><?php echo esc_html( $cshield_it['text'] ); ?></a>
						<?php else : ?>
							<span class="cshield-timeline__text"><?php echo esc_html( $cshield_it['text'] ); ?></span>
						<?php endif; ?>
						<code class="cshield-timeline__meta"><?php echo esc_html( $cshield_it['meta'] ); ?></code>
						<?php if ( ! $cshield_is_ip && $cshield_it['ip'] ) : ?>
							<?php echo $cshield_ip_link( $cshield_it['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ol>
		<?php endif; ?>
	</section>

	<?php
else :
	$cshield_sum    = Incidents::summary();
	$cshield_list   = Incidents::query(
		array(
			'status' => $cshield_status_f,
			'limit'  => 50,
		)
	);
	$cshield_hourly = Siem::hourly();
	$cshield_events = Events::count( array( 'since' => time() - DAY_IN_SECONDS ) );
	$cshield_closed = Incidents::count(
		array(
			'status' => 'resolved',
			'since'  => time() - 30 * DAY_IN_SECONDS,
		)
	);
	?>
	<div class="cshield-tiles">
		<?php foreach ( array( Incidents::CRITICAL, Incidents::HIGH, Incidents::MEDIUM, Incidents::LOW ) as $cshield_sv ) : ?>
			<a class="cshield-tile cshield-tile--<?php echo esc_attr( $cshield_sev_class[ $cshield_sv ] ); ?><?php echo $cshield_sum['by_severity'][ $cshield_sv ] ? ' is-hot' : ''; ?>" href="<?php echo esc_url( Admin::url( 'siem' ) . '#cshield-incidents' ); ?>">
				<span class="cshield-tile__label">
					<?php
					/* translators: %s: severity. */
					echo esc_html( sprintf( __( '%s, open', 'chaos-shield' ), $cshield_sev_labels[ $cshield_sv ] ) );
					?>
				</span>
				<span class="cshield-tile__value"><?php echo esc_html( number_format_i18n( $cshield_sum['by_severity'][ $cshield_sv ] ) ); ?></span>
			</a>
		<?php endforeach; ?>
	</div>

	<div class="cshield-grid">
		<?php
		$cshield_max = 1;
		foreach ( $cshield_hourly as $cshield_b ) {
			$cshield_max = max( $cshield_max, $cshield_b[1] + $cshield_b[2] + $cshield_b[3] );
		}
		$cshield_cw = 720;
		$cshield_ch = 150;
		$cshield_bw = $cshield_cw / 24;
		?>
		<section class="cshield-card cshield-card--full">
			<div class="cshield-card__head">
				<div>
					<h2><?php esc_html_e( 'Events in the last 24 hours', 'chaos-shield' ); ?></h2>
					<p>
						<?php
						/* translators: 1: number of events, 2: busiest hour, 3: number of incidents resolved. */
						echo esc_html( sprintf( _n( '%1$s events logged, at most %2$s in one hour. %3$s incident resolved in the last 30 days.', '%1$s events logged, at most %2$s in one hour. %3$s incidents resolved in the last 30 days.', $cshield_closed, 'chaos-shield' ), number_format_i18n( $cshield_events ), number_format_i18n( $cshield_max ), number_format_i18n( $cshield_closed ) ) );
						?>
					</p>
				</div>
				<ul class="cshield-legend" aria-label="<?php esc_attr_e( 'Severity', 'chaos-shield' ); ?>">
					<li><span class="cshield-legend__swatch cshield-legend__swatch--1"></span><?php esc_html_e( 'Info', 'chaos-shield' ); ?></li>
					<li><span class="cshield-legend__swatch cshield-legend__swatch--2"></span><?php esc_html_e( 'Notice', 'chaos-shield' ); ?></li>
					<li><span class="cshield-legend__swatch cshield-legend__swatch--3"></span><?php esc_html_e( 'Critical', 'chaos-shield' ); ?></li>
				</ul>
			</div>
			<svg class="cshield-chart" viewBox="0 0 <?php echo esc_attr( $cshield_cw ); ?> <?php echo esc_attr( $cshield_ch + 22 ); ?>" role="img" aria-label="<?php esc_attr_e( 'Events per hour for the last 24 hours, by severity', 'chaos-shield' ); ?>">
				<line class="cshield-chart__base" x1="0" x2="<?php echo esc_attr( $cshield_cw ); ?>" y1="<?php echo esc_attr( $cshield_ch ); ?>" y2="<?php echo esc_attr( $cshield_ch ); ?>"></line>
				<?php foreach ( $cshield_hourly as $cshield_h => $cshield_b ) : ?>
					<?php
					$cshield_x     = $cshield_h * $cshield_bw + 3;
					$cshield_y     = $cshield_ch;
					$cshield_total = $cshield_b[1] + $cshield_b[2] + $cshield_b[3];
					?>
					<g class="cshield-chart__col">
						<title>
						<?php
						/* translators: 1: hour, 2: total, 3: info, 4: notice, 5: critical. */
						echo esc_html( sprintf( __( '%1$s: %2$d events (%3$d info, %4$d notice, %5$d critical)', 'chaos-shield' ), wp_date( get_option( 'time_format' ), $cshield_b['start'] ), $cshield_total, $cshield_b[1], $cshield_b[2], $cshield_b[3] ) );
						?>
						</title>
						<rect class="cshield-chart__hit" x="<?php echo esc_attr( $cshield_h * $cshield_bw ); ?>" y="0" width="<?php echo esc_attr( $cshield_bw ); ?>" height="<?php echo esc_attr( $cshield_ch ); ?>"></rect>
						<?php foreach ( array( 1, 2, 3 ) as $cshield_s ) : ?>
							<?php
							if ( ! $cshield_b[ $cshield_s ] ) {
								continue;
							}
							$cshield_hgt = max( 2, ( $cshield_ch - 6 ) * $cshield_b[ $cshield_s ] / $cshield_max );
							$cshield_y  -= $cshield_hgt;
							?>
							<rect class="cshield-chart__bar cshield-chart__bar--<?php echo esc_attr( $cshield_s ); ?>" x="<?php echo esc_attr( $cshield_x ); ?>" y="<?php echo esc_attr( $cshield_y ); ?>" width="<?php echo esc_attr( $cshield_bw - 6 ); ?>" height="<?php echo esc_attr( max( 1, $cshield_hgt - 2 ) ); ?>" rx="2"></rect>
						<?php endforeach; ?>
						<?php if ( 0 === $cshield_h % 6 ) : ?>
							<text class="cshield-chart__label" x="<?php echo esc_attr( $cshield_x ); ?>" y="<?php echo esc_attr( $cshield_ch + 16 ); ?>"><?php echo esc_html( wp_date( 'H:i', $cshield_b['start'] ) ); ?></text>
						<?php endif; ?>
					</g>
				<?php endforeach; ?>
			</svg>
		</section>

		<section class="cshield-card cshield-card--full" id="cshield-incidents">
			<div class="cshield-card__head">
				<h2><?php esc_html_e( 'Incidents', 'chaos-shield' ); ?></h2>
				<nav class="cshield-chips" aria-label="<?php esc_attr_e( 'Filter incidents', 'chaos-shield' ); ?>">
					<?php
					foreach ( array(
						'active'         => __( 'Open', 'chaos-shield' ),
						'resolved'       => $cshield_statuses['resolved'],
						'false_positive' => $cshield_statuses['false_positive'],
						'all'            => __( 'All', 'chaos-shield' ),
					) as $cshield_k => $cshield_l ) :
						?>
						<a class="cshield-chip<?php echo $cshield_k === $cshield_status_f ? ' is-active' : ''; ?>" href="<?php echo esc_url( Admin::url( 'siem', array( 'status' => $cshield_k ) ) . '#cshield-incidents' ); ?>"><?php echo esc_html( $cshield_l ); ?></a>
					<?php endforeach; ?>
				</nav>
			</div>
			<?php if ( ! $cshield_list ) : ?>
				<p class="cshield-empty"><?php echo esc_html( 'active' === $cshield_status_f ? __( 'No open incidents. The rules below are watching.', 'chaos-shield' ) : __( 'No incidents here.', 'chaos-shield' ) ); ?></p>
			<?php else : ?>
				<ul class="cshield-incidents">
					<?php foreach ( $cshield_list as $cshield_i ) : ?>
						<li class="cshield-incident-row cshield-incident-row--<?php echo esc_attr( $cshield_sev_class[ $cshield_i['severity'] ] ); ?>">
							<span class="cshield-sev cshield-sev--<?php echo esc_attr( $cshield_sev_class[ $cshield_i['severity'] ] ); ?>"><?php echo esc_html( $cshield_sev_labels[ $cshield_i['severity'] ] ); ?></span>
							<div class="cshield-incident-row__body">
								<a class="cshield-incident-row__title" href="<?php echo esc_url( Admin::url( 'siem', array( 'incident' => $cshield_i['id'] ) ) ); ?>">#<?php echo esc_html( $cshield_i['id'] . ' ' . $cshield_i['title'] ); ?></a>
								<p class="cshield-small">
									<?php
									$cshield_bits = array( wp_date( $cshield_fmt, $cshield_i['updated'] ) );
									if ( $cshield_i['hits'] > 1 ) {
										/* translators: %d: number of hits. */
										$cshield_bits[] = sprintf( __( '%d hits', 'chaos-shield' ), $cshield_i['hits'] );
									}
									$cshield_bits[] = $cshield_statuses[ $cshield_i['status'] ];
									if ( $cshield_i['assignee'] ) {
										$cshield_as = get_userdata( $cshield_i['assignee'] );
										if ( $cshield_as ) {
											/* translators: %s: username. */
											$cshield_bits[] = sprintf( __( 'assigned to %s', 'chaos-shield' ), $cshield_as->user_login );
										}
									}
									echo esc_html( implode( ' · ', $cshield_bits ) );
									?>
								</p>
							</div>
							<?php echo $cshield_mitre( $cshield_i['technique'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</section>

		<section class="cshield-card cshield-card--full" id="cshield-search">
			<h2><?php esc_html_e( 'Search the log', 'chaos-shield' ); ?></h2>
			<form method="get" action="<?php echo esc_url( Network::admin_url( 'admin.php' ) ); ?>" class="cshield-search">
				<input type="hidden" name="page" value="<?php echo esc_attr( Admin::SLUG ); ?>">
				<input type="hidden" name="tab" value="siem">
				<input type="search" name="q" value="<?php echo esc_attr( $cshield_q ); ?>" placeholder="action:auth.failed since:24h" spellcheck="false" aria-label="<?php esc_attr_e( 'Search', 'chaos-shield' ); ?>">
				<button type="submit" class="cshield-btn"><?php esc_html_e( 'Search', 'chaos-shield' ); ?></button>
			</form>
			<p class="cshield-small"><?php esc_html_e( 'Fields: ip:, user:, action: (end with * for a family, such as auth.*), type:, sev: (1 to 3), since: (30m, 24h, 7d), site: (on a network). Other words search the message.', 'chaos-shield' ); ?></p>
			<?php if ( '' !== $cshield_q ) : ?>
				<?php
				$cshield_sargs = Siem::parse( $cshield_q );
				$cshield_found = Events::query( $cshield_sargs + array( 'limit' => 200 ) );
				$cshield_total = Events::count( $cshield_sargs );
				?>
				<p>
					<?php
					/* translators: 1: shown, 2: total matches. */
					echo esc_html( sprintf( __( 'Showing %1$s of %2$s matching events.', 'chaos-shield' ), number_format_i18n( count( $cshield_found ) ), number_format_i18n( $cshield_total ) ) );
					?>
				</p>
				<?php if ( $cshield_found ) : ?>
					<div class="cshield-table-wrap">
						<table class="cshield-table cshield-table--evidence">
							<thead><tr><th><?php esc_html_e( 'Time', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Action', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Event', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'IP', 'chaos-shield' ); ?></th></tr></thead>
							<tbody>
							<?php foreach ( $cshield_found as $cshield_e ) : ?>
								<tr class="cshield-sev-<?php echo esc_attr( $cshield_e['severity'] ); ?>">
									<td><?php echo esc_html( wp_date( $cshield_fmt, (int) $cshield_e['time'] ) ); ?></td>
									<td><code><?php echo esc_html( $cshield_e['action'] ? $cshield_e['action'] : $cshield_e['type'] ); ?></code></td>
									<td><?php echo esc_html( $cshield_e['message'] ); ?> <?php echo $cshield_user_link( (int) $cshield_e['user_id'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></td>
									<td><?php echo $cshield_ip_link( $cshield_e['ip'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>
			<?php endif; ?>
		</section>

		<section class="cshield-card cshield-card--full" id="cshield-rules">
			<h2><?php esc_html_e( 'Detection rules', 'chaos-shield' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="cshield_rules">
				<?php wp_nonce_field( 'cshield_rules' ); ?>
				<ul class="cshield-rules">
					<?php foreach ( $cshield_rules as $cshield_rk => $cshield_r ) : ?>
						<?php
						$cshield_hits = Incidents::count(
							array(
								'status' => 'all',
								'rule'   => $cshield_rk,
								'since'  => time() - 30 * DAY_IN_SECONDS,
							)
						);
						?>
						<li>
							<label class="cshield-rule">
								<input type="checkbox" name="rules[]" value="<?php echo esc_attr( $cshield_rk ); ?>" <?php checked( Detect::rule_on( $cshield_rk ) ); ?>>
								<span class="cshield-rule__body">
									<strong><?php echo esc_html( $cshield_r['name'] ); ?></strong>
									<span class="cshield-small"><?php echo esc_html( $cshield_r['description'] ); ?></span>
								</span>
								<span class="cshield-rule__meta">
									<?php echo $cshield_mitre( $cshield_r['technique'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the closure. ?>
									<span class="cshield-small">
										<?php
										/* translators: %d: number of incidents. */
										echo esc_html( sprintf( _n( '%d incident in 30 days', '%d incidents in 30 days', $cshield_hits, 'chaos-shield' ), $cshield_hits ) );
										?>
									</span>
								</span>
							</label>
						</li>
					<?php endforeach; ?>
				</ul>
				<div class="cshield-fields cshield-fields--two cshield-fields--spaced">
					<label><span><?php esc_html_e( 'Email me about incidents rated', 'chaos-shield' ); ?></span>
						<select name="alert_min">
							<?php foreach ( array_reverse( $cshield_sev_labels, true ) as $cshield_sv => $cshield_sl ) : ?>
								<option value="<?php echo esc_attr( $cshield_sv ); ?>" <?php selected( (int) Settings::get( 'siem_alert_min' ), $cshield_sv ); ?>>
									<?php
									echo esc_html(
										Incidents::CRITICAL === $cshield_sv
											? $cshield_sl
											/* translators: %s: severity. */
											: sprintf( __( '%s and above', 'chaos-shield' ), $cshield_sl )
									);
									?>
								</option>
							<?php endforeach; ?>
						</select></label>
				</div>
				<div class="cshield-actions cshield-actions--start">
					<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save rules', 'chaos-shield' ); ?></button>
				</div>
			</form>
		</section>
	</div>
<?php endif; ?>
