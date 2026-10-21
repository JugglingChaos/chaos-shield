<?php
/**
 * Hub tab: this site's hub key and the sites this site watches.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_uid     = get_current_user_id();
$cshield_new_key = Network::get_transient( 'cshield_new_key_' . $cshield_uid );
$cshield_error   = Network::get_transient( 'cshield_hub_error_' . $cshield_uid );
Network::delete_transient( 'cshield_new_key_' . $cshield_uid );
Network::delete_transient( 'cshield_hub_error_' . $cshield_uid );

$cshield_rows = array(
	array(
		'id'     => '',
		'name'   => __( 'This site', 'chaos-shield' ),
		'url'    => home_url( '/' ),
		'status' => Api::status(),
	),
);
foreach ( Hub::sites() as $cshield_id => $cshield_site ) {
	$cshield_rows[] = array(
		'id'     => $cshield_id,
		'name'   => $cshield_site['name'],
		'url'    => $cshield_site['url'],
		'status' => Hub::status( $cshield_id ),
	);
}
$cshield_uptime  = Uptime::all();
$cshield_actable = 0;
foreach ( $cshield_rows as $cshield_r ) {
	if ( $cshield_r['id'] && is_array( $cshield_r['status'] ) && ! empty( $cshield_r['status']['actions'] ) ) {
		++$cshield_actable;
	}
}
// Open incidents across the fleet, worst first. Sites on versions before 1.6 send none.
$cshield_fleet = array();
foreach ( $cshield_rows as $cshield_r ) {
	if ( ! is_array( $cshield_r['status'] ) || empty( $cshield_r['status']['incidents']['latest'] ) ) {
		continue;
	}
	foreach ( $cshield_r['status']['incidents']['latest'] as $cshield_inc ) {
		$cshield_fleet[] = $cshield_inc + array(
			'site'     => $cshield_r['name'],
			'link'     => $cshield_r['id']
				? $cshield_r['url'] . 'wp-admin/admin.php?page=chaos-shield&tab=siem&incident=' . absint( $cshield_inc['id'] )
				: Admin::url( 'siem', array( 'incident' => absint( $cshield_inc['id'] ) ) ),
			'external' => '' !== $cshield_r['id'],
		);
	}
}
usort(
	$cshield_fleet,
	static function ( $a, $b ) {
		return array( (int) $b['severity'], (int) $b['updated'] ) <=> array( (int) $a['severity'], (int) $a['updated'] );
	}
);
$cshield_fleet        = array_slice( $cshield_fleet, 0, 12 );
$cshield_sev_names    = Incidents::severities();
$cshield_sev_css      = array(
	1 => 'low',
	2 => 'medium',
	3 => 'high',
	4 => 'critical',
);
$cshield_push_confirm = __( 'Copy this site\'s hardening switches, login limits, rate limits and password policy to the sites that allow actions? Login addresses, IP lists and email settings stay as they are.', 'chaos-shield' );
/**
 * Prints the uptime and certificate line for a row.
 *
 * @param array $state Uptime state.
 * @param bool  $local Whether this is the hub site itself.
 */
$cshield_uptime_line = static function ( $state, $local ) {
	if ( ! $state ) {
		if ( ! $local ) {
			echo '<div class="cshield-uptime"><span>' . esc_html__( 'Uptime: not checked yet.', 'chaos-shield' ) . '</span></div>';
		}
		return;
	}
	echo '<div class="cshield-uptime">';
	if ( ! $local && isset( $state['checked'] ) ) {
		$down = ! empty( $state['down'] );
		$pct  = Uptime::uptime_percent( $state );
		printf(
			'<span class="%1$s">%2$s <b>%3$s</b></span>',
			$down ? 'is-bad' : 'is-ok',
			esc_html__( 'Status', 'chaos-shield' ),
			$down
				/* translators: %s: error. */
				? esc_html( sprintf( __( 'Down (%s)', 'chaos-shield' ), $state['error'] ) )
				/* translators: %d: milliseconds. */
				: esc_html( sprintf( __( 'Up, %d ms', 'chaos-shield' ), (int) $state['ms'] ) )
		);
		if ( null !== $pct ) {
			/* translators: %s: percentage. */
			printf( '<span>%1$s <b>%2$s</b></span>', esc_html__( 'Last 24 hours', 'chaos-shield' ), esc_html( sprintf( __( '%s%% up', 'chaos-shield' ), number_format_i18n( $pct, 1 ) ) ) );
		}
	}
	if ( isset( $state['ssl'] ) ) {
		$ssl = $state['ssl'];
		if ( ! empty( $ssl['none'] ) ) {
			printf( '<span class="is-warn">%1$s <b>%2$s</b></span>', esc_html__( 'Certificate', 'chaos-shield' ), esc_html__( 'No HTTPS', 'chaos-shield' ) );
		} elseif ( ! empty( $ssl['expires'] ) ) {
			$days  = Uptime::days_left( (int) $ssl['expires'] );
			$class = ( $days < Uptime::SSL_WARN || empty( $ssl['trusted'] ) ) ? ( $days < 0 || empty( $ssl['trusted'] ) ? 'is-bad' : 'is-warn' ) : 'is-ok';
			$text  = $days < 0
				? __( 'Expired', 'chaos-shield' )
				/* translators: %d: days. */
				: sprintf( _n( 'Expires in %d day', 'Expires in %d days', $days, 'chaos-shield' ), $days );
			if ( empty( $ssl['trusted'] ) ) {
				$text .= ', ' . __( 'not trusted', 'chaos-shield' );
			}
			printf( '<span class="%1$s">%2$s <b>%3$s</b></span>', esc_attr( $class ), esc_html__( 'Certificate', 'chaos-shield' ), esc_html( $text ) );
		} elseif ( ! empty( $ssl['error'] ) ) {
			printf( '<span class="is-bad">%1$s <b>%2$s</b></span>', esc_html__( 'Certificate', 'chaos-shield' ), esc_html( $ssl['error'] ) );
		}
	}
	echo '</div>';
};
$cshield_band_text   = array(
	'good' => __( 'Well protected', 'chaos-shield' ),
	'fair' => __( 'Needs attention', 'chaos-shield' ),
	'poor' => __( 'At risk', 'chaos-shield' ),
);
$cshield_hub_form    = static function ( $op, $label, $css, $site = '', $hub_action = '', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form"<?php echo $confirm ? ' onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ')"' : ''; ?>>
		<input type="hidden" name="action" value="cshield_hub">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php if ( $site ) : ?>
			<input type="hidden" name="site" value="<?php echo esc_attr( $site ); ?>">
		<?php endif; ?>
		<?php if ( $hub_action ) : ?>
			<input type="hidden" name="hub_action" value="<?php echo esc_attr( $hub_action ); ?>">
		<?php endif; ?>
		<?php wp_nonce_field( 'cshield_hub' ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<?php if ( $cshield_error ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="alert"><?php echo esc_html( $cshield_error ); ?></div>
<?php endif; ?>

<div class="cshield-grid">
	<section class="cshield-card cshield-card--full">
		<div class="cshield-card__head">
			<h2><?php esc_html_e( 'Your sites', 'chaos-shield' ); ?></h2>
			<?php if ( count( $cshield_rows ) > 1 ) : ?>
				<div class="cshield-bulk">
					<?php
					if ( $cshield_actable ) {
						$cshield_hub_form( 'act_all', __( 'Scan all', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', '', 'scan' );
						$cshield_hub_form( 'act_all', __( 'Release all bans', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', '', 'release', __( 'End every lockout and ban on all sites that allow actions?', 'chaos-shield' ) );
						$cshield_hub_form( 'act_all', __( 'Push my settings', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', '', 'settings', $cshield_push_confirm );
					}
					$cshield_hub_form( 'uptime', __( 'Check uptime now', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' );
					$cshield_hub_form( 'refresh', __( 'Refresh all', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' );
					?>
				</div>
			<?php endif; ?>
		</div>
		<div class="cshield-sites">
			<?php foreach ( $cshield_rows as $cshield_row ) : ?>
				<?php $cshield_st = $cshield_row['status']; ?>
				<article class="cshield-site<?php echo is_wp_error( $cshield_st ) ? ' cshield-site--down' : ' cshield-site--' . esc_attr( $cshield_st['band'] ); ?>">
					<?php if ( is_wp_error( $cshield_st ) ) : ?>
						<div class="cshield-site__score">!</div>
						<div class="cshield-site__body">
							<strong><?php echo esc_html( $cshield_row['name'] ); ?></strong>
							<a href="<?php echo esc_url( $cshield_row['url'] ); ?>" class="cshield-site__url" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $cshield_row['url'] ); ?></a>
							<p class="cshield-hint"><?php echo esc_html( $cshield_st->get_error_message() ); ?></p>
							<?php $cshield_uptime_line( isset( $cshield_uptime[ $cshield_row['id'] ] ) ? $cshield_uptime[ $cshield_row['id'] ] : array(), '' === $cshield_row['id'] ); ?>
						</div>
					<?php else : ?>
						<div class="cshield-site__score"><?php echo esc_html( $cshield_st['score'] ); ?></div>
						<div class="cshield-site__body">
							<strong><?php echo esc_html( $cshield_row['name'] ); ?></strong>
							<a href="<?php echo esc_url( $cshield_row['url'] ); ?>" class="cshield-site__url" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $cshield_row['url'] ); ?></a>
							<p>
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: status wording, 2: open issues, 3: scan findings, 4: lockouts. */
										__( '%1$s. %2$d checks to fix, %3$d scan findings, %4$d IPs locked out.', 'chaos-shield' ),
										$cshield_band_text[ $cshield_st['band'] ],
										count( $cshield_st['issues'] ),
										(int) $cshield_st['scan']['findings'],
										(int) $cshield_st['lockouts']
									)
								);
								?>
							</p>
							<p class="cshield-small">
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: plugin version, 2: WordPress version, 3: PHP version. */
										__( 'Chaos Shield %1$s, WordPress %2$s, PHP %3$s', 'chaos-shield' ),
										$cshield_st['plugin'],
										$cshield_st['wordpress'],
										$cshield_st['php']
									)
								);
								?>
							</p>
							<?php if ( isset( $cshield_st['incidents']['open'] ) ) : ?>
								<p class="cshield-site__incidents">
									<?php
									$cshield_crit = (int) $cshield_st['incidents']['by_severity'][ Incidents::CRITICAL ] + (int) $cshield_st['incidents']['by_severity'][ Incidents::HIGH ];
									echo esc_html(
										$cshield_st['incidents']['open']
											? sprintf(
												/* translators: 1: open incidents, 2: of which high or critical. */
												_n( '%1$d open incident, %2$d high or critical.', '%1$d open incidents, %2$d high or critical.', (int) $cshield_st['incidents']['open'], 'chaos-shield' ),
												(int) $cshield_st['incidents']['open'],
												$cshield_crit
											)
											: __( 'No open incidents.', 'chaos-shield' )
									);
									?>
								</p>
							<?php endif; ?>
							<?php $cshield_uptime_line( isset( $cshield_uptime[ $cshield_row['id'] ] ) ? $cshield_uptime[ $cshield_row['id'] ] : array(), '' === $cshield_row['id'] ); ?>
						</div>
					<?php endif; ?>
					<div class="cshield-site__actions">
						<?php if ( $cshield_row['id'] && is_array( $cshield_st ) && ! empty( $cshield_st['actions'] ) ) : ?>
							<?php
							$cshield_hub_form( 'act', __( 'Scan', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', $cshield_row['id'], 'scan' );
							$cshield_hub_form( 'act', __( 'Release bans', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', $cshield_row['id'], 'release', __( 'End every lockout and ban on this site?', 'chaos-shield' ) );
							$cshield_hub_form( 'act', __( 'Push my settings', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', $cshield_row['id'], 'settings', $cshield_push_confirm );
							?>
						<?php elseif ( $cshield_row['id'] && is_array( $cshield_st ) ) : ?>
							<span class="cshield-small"><?php esc_html_e( 'Read-only key: create a key that allows actions on that site to run scans and push settings from here.', 'chaos-shield' ); ?></span>
						<?php endif; ?>
						<?php if ( $cshield_row['id'] ) : ?>
							<a class="cshield-link" href="<?php echo esc_url( $cshield_row['url'] . 'wp-admin/admin.php?page=chaos-shield' ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open', 'chaos-shield' ); ?></a>
							<?php $cshield_hub_form( 'remove', __( 'Remove', 'chaos-shield' ), 'cshield-link cshield-link--danger', $cshield_row['id'] ); ?>
						<?php endif; ?>
					</div>
				</article>
			<?php endforeach; ?>
		</div>
	</section>

	<section class="cshield-card cshield-card--full">
		<h2><?php esc_html_e( 'Fleet incidents', 'chaos-shield' ); ?></h2>
		<?php if ( ! $cshield_fleet ) : ?>
			<p class="cshield-empty"><?php esc_html_e( 'No open incidents on any site.', 'chaos-shield' ); ?></p>
		<?php else : ?>
			<ul class="cshield-incidents">
				<?php foreach ( $cshield_fleet as $cshield_inc ) : ?>
					<?php $cshield_sv = max( 1, min( 4, (int) $cshield_inc['severity'] ) ); ?>
					<li class="cshield-incident-row cshield-incident-row--<?php echo esc_attr( $cshield_sev_css[ $cshield_sv ] ); ?>">
						<span class="cshield-sev cshield-sev--<?php echo esc_attr( $cshield_sev_css[ $cshield_sv ] ); ?>"><?php echo esc_html( $cshield_sev_names[ $cshield_sv ] ); ?></span>
						<div class="cshield-incident-row__body">
							<a class="cshield-incident-row__title" href="<?php echo esc_url( $cshield_inc['link'] ); ?>"<?php echo $cshield_inc['external'] ? ' target="_blank" rel="noopener noreferrer"' : ''; ?>><?php echo esc_html( $cshield_inc['title'] ); ?></a>
							<p class="cshield-small"><?php echo esc_html( $cshield_inc['site'] . ' · ' . wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $cshield_inc['updated'] ) ); ?></p>
						</div>
						<span class="cshield-tag"><?php echo esc_html( $cshield_inc['technique'] ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>
	</section>

	<section class="cshield-card">
		<h2><?php esc_html_e( 'Connect a site', 'chaos-shield' ); ?></h2>
		<p><?php esc_html_e( 'Install Chaos Shield on the other site, create a hub key on its Hub tab, then paste the address and key here. The hub then watches its score, uptime and certificate, and, if the key allows actions, can run scans, release bans and push settings.', 'chaos-shield' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="cshield_hub">
			<input type="hidden" name="op" value="add">
			<?php wp_nonce_field( 'cshield_hub' ); ?>
			<div class="cshield-fields cshield-fields--one">
				<label><span><?php esc_html_e( 'Site address', 'chaos-shield' ); ?></span>
					<input type="url" name="url" required placeholder="https://example.com"></label>
				<label><span><?php esc_html_e( 'Hub key', 'chaos-shield' ); ?></span>
					<input type="password" name="key" required autocomplete="off" placeholder="ssk_..."></label>
				<label><span><?php esc_html_e( 'Name (optional)', 'chaos-shield' ); ?></span>
					<input type="text" name="name"></label>
			</div>
			<div class="cshield-actions">
				<button type="submit" class="cshield-btn"><?php esc_html_e( 'Connect site', 'chaos-shield' ); ?></button>
			</div>
		</form>
	</section>

	<section class="cshield-card">
		<h2><?php esc_html_e( 'This site\'s hub key', 'chaos-shield' ); ?></h2>
		<?php if ( $cshield_new_key ) : ?>
			<p><?php esc_html_e( 'Copy this key now and paste it into your hub site. It will not be shown again.', 'chaos-shield' ); ?></p>
			<input type="text" class="cshield-keybox" readonly value="<?php echo esc_attr( $cshield_new_key ); ?>" onclick="this.select()">
		<?php elseif ( 'manage' === Api::key_scope() ) : ?>
			<p><?php esc_html_e( 'A hub key that allows actions is active. The hub can read this site\'s status, start scans, release lockouts and bans, and push hardening settings. Actions are signed and can only be used once.', 'chaos-shield' ); ?></p>
		<?php elseif ( Api::has_key() ) : ?>
			<p><?php esc_html_e( 'A read-only hub key is active. Another site holding it can read this site\'s security status, but cannot change anything.', 'chaos-shield' ); ?></p>
		<?php else : ?>
			<p><?php esc_html_e( 'No hub key yet. Create one to let another Chaos Shield site watch this one.', 'chaos-shield' ); ?></p>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="cshield_hub">
			<input type="hidden" name="op" value="new_key">
			<?php wp_nonce_field( 'cshield_hub' ); ?>
			<label class="cshield-keyopt"><input type="checkbox" name="manage" value="1" <?php checked( 'manage' === Api::key_scope() ); ?>> <span><?php esc_html_e( 'Let the hub run actions: scans, releasing lockouts and bans, and pushing hardening settings.', 'chaos-shield' ); ?></span></label>
			<button type="submit" class="cshield-btn"><?php echo Api::has_key() ? esc_html__( 'Replace key', 'chaos-shield' ) : esc_html__( 'Create hub key', 'chaos-shield' ); ?></button>
		</form>
		<div class="cshield-actions cshield-actions--start">
			<?php if ( Api::has_key() ) : ?>
				<?php $cshield_hub_form( 'revoke_key', __( 'Revoke', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' ); ?>
			<?php endif; ?>
		</div>
		<p class="cshield-small">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: REST API base URL. */
					__( 'Developers: the REST API lives at %s. Read routes accept the hub key in the X-Chaos-Key header; routes that change settings need an administrator application password.', 'chaos-shield' ),
					rest_url( Api::NS )
				)
			);
			?>
		</p>
	</section>
</div>
