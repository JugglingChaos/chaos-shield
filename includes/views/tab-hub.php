<?php
/**
 * Hub tab: this site's hub key and the sites this site watches.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_uid     = get_current_user_id();
$sshield_new_key = Network::get_transient( 'sshield_new_key_' . $sshield_uid );
$sshield_error   = Network::get_transient( 'sshield_hub_error_' . $sshield_uid );
Network::delete_transient( 'sshield_new_key_' . $sshield_uid );
Network::delete_transient( 'sshield_hub_error_' . $sshield_uid );

$sshield_rows = array(
	array(
		'id'     => '',
		'name'   => __( 'This site', 'sentinel-shield' ),
		'url'    => home_url( '/' ),
		'status' => Api::status(),
	),
);
foreach ( Hub::sites() as $sshield_id => $sshield_site ) {
	$sshield_rows[] = array(
		'id'     => $sshield_id,
		'name'   => $sshield_site['name'],
		'url'    => $sshield_site['url'],
		'status' => Hub::status( $sshield_id ),
	);
}
$sshield_uptime  = Uptime::all();
$sshield_actable = 0;
foreach ( $sshield_rows as $sshield_r ) {
	if ( $sshield_r['id'] && is_array( $sshield_r['status'] ) && ! empty( $sshield_r['status']['actions'] ) ) {
		++$sshield_actable;
	}
}
// Open incidents across the fleet, worst first. Sites on versions before 1.6 send none.
$sshield_fleet = array();
foreach ( $sshield_rows as $sshield_r ) {
	if ( ! is_array( $sshield_r['status'] ) || empty( $sshield_r['status']['incidents']['latest'] ) ) {
		continue;
	}
	foreach ( $sshield_r['status']['incidents']['latest'] as $sshield_inc ) {
		$sshield_fleet[] = $sshield_inc + array(
			'site'     => $sshield_r['name'],
			'link'     => $sshield_r['id']
				? $sshield_r['url'] . 'wp-admin/admin.php?page=sentinel-shield&tab=siem&incident=' . absint( $sshield_inc['id'] )
				: Admin::url( 'siem', array( 'incident' => absint( $sshield_inc['id'] ) ) ),
			'external' => '' !== $sshield_r['id'],
		);
	}
}
usort(
	$sshield_fleet,
	static function ( $a, $b ) {
		return array( (int) $b['severity'], (int) $b['updated'] ) <=> array( (int) $a['severity'], (int) $a['updated'] );
	}
);
$sshield_fleet        = array_slice( $sshield_fleet, 0, 12 );
$sshield_sev_names    = Incidents::severities();
$sshield_sev_css      = array(
	1 => 'low',
	2 => 'medium',
	3 => 'high',
	4 => 'critical',
);
$sshield_push_confirm = __( 'Copy this site\'s hardening switches, login limits, rate limits and password policy to the sites that allow actions? Login addresses, IP lists and email settings stay as they are.', 'sentinel-shield' );
/**
 * Prints the uptime and certificate line for a row.
 *
 * @param array $state Uptime state.
 * @param bool  $local Whether this is the hub site itself.
 */
$sshield_uptime_line = static function ( $state, $local ) {
	if ( ! $state ) {
		if ( ! $local ) {
			echo '<div class="sshield-uptime"><span>' . esc_html__( 'Uptime: not checked yet.', 'sentinel-shield' ) . '</span></div>';
		}
		return;
	}
	echo '<div class="sshield-uptime">';
	if ( ! $local && isset( $state['checked'] ) ) {
		$down = ! empty( $state['down'] );
		$pct  = Uptime::uptime_percent( $state );
		printf(
			'<span class="%1$s">%2$s <b>%3$s</b></span>',
			$down ? 'is-bad' : 'is-ok',
			esc_html__( 'Status', 'sentinel-shield' ),
			$down
				/* translators: %s: error. */
				? esc_html( sprintf( __( 'Down (%s)', 'sentinel-shield' ), $state['error'] ) )
				/* translators: %d: milliseconds. */
				: esc_html( sprintf( __( 'Up, %d ms', 'sentinel-shield' ), (int) $state['ms'] ) )
		);
		if ( null !== $pct ) {
			/* translators: %s: percentage. */
			printf( '<span>%1$s <b>%2$s</b></span>', esc_html__( 'Last 24 hours', 'sentinel-shield' ), esc_html( sprintf( __( '%s%% up', 'sentinel-shield' ), number_format_i18n( $pct, 1 ) ) ) );
		}
	}
	if ( isset( $state['ssl'] ) ) {
		$ssl = $state['ssl'];
		if ( ! empty( $ssl['none'] ) ) {
			printf( '<span class="is-warn">%1$s <b>%2$s</b></span>', esc_html__( 'Certificate', 'sentinel-shield' ), esc_html__( 'No HTTPS', 'sentinel-shield' ) );
		} elseif ( ! empty( $ssl['expires'] ) ) {
			$days  = Uptime::days_left( (int) $ssl['expires'] );
			$class = ( $days < Uptime::SSL_WARN || empty( $ssl['trusted'] ) ) ? ( $days < 0 || empty( $ssl['trusted'] ) ? 'is-bad' : 'is-warn' ) : 'is-ok';
			$text  = $days < 0
				? __( 'Expired', 'sentinel-shield' )
				/* translators: %d: days. */
				: sprintf( _n( 'Expires in %d day', 'Expires in %d days', $days, 'sentinel-shield' ), $days );
			if ( empty( $ssl['trusted'] ) ) {
				$text .= ', ' . __( 'not trusted', 'sentinel-shield' );
			}
			printf( '<span class="%1$s">%2$s <b>%3$s</b></span>', esc_attr( $class ), esc_html__( 'Certificate', 'sentinel-shield' ), esc_html( $text ) );
		} elseif ( ! empty( $ssl['error'] ) ) {
			printf( '<span class="is-bad">%1$s <b>%2$s</b></span>', esc_html__( 'Certificate', 'sentinel-shield' ), esc_html( $ssl['error'] ) );
		}
	}
	echo '</div>';
};
$sshield_band_text   = array(
	'good' => __( 'Well protected', 'sentinel-shield' ),
	'fair' => __( 'Needs attention', 'sentinel-shield' ),
	'poor' => __( 'At risk', 'sentinel-shield' ),
);
$sshield_hub_form    = static function ( $op, $label, $css, $site = '', $hub_action = '', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form"<?php echo $confirm ? ' onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ')"' : ''; ?>>
		<input type="hidden" name="action" value="sshield_hub">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php if ( $site ) : ?>
			<input type="hidden" name="site" value="<?php echo esc_attr( $site ); ?>">
		<?php endif; ?>
		<?php if ( $hub_action ) : ?>
			<input type="hidden" name="hub_action" value="<?php echo esc_attr( $hub_action ); ?>">
		<?php endif; ?>
		<?php wp_nonce_field( 'sshield_hub' ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<?php if ( $sshield_error ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="alert"><?php echo esc_html( $sshield_error ); ?></div>
<?php endif; ?>

<div class="sshield-grid">
	<section class="sshield-card sshield-card--full">
		<div class="sshield-card__head">
			<h2><?php esc_html_e( 'Your sites', 'sentinel-shield' ); ?></h2>
			<?php if ( count( $sshield_rows ) > 1 ) : ?>
				<div class="sshield-bulk">
					<?php
					if ( $sshield_actable ) {
						$sshield_hub_form( 'act_all', __( 'Scan all', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', '', 'scan' );
						$sshield_hub_form( 'act_all', __( 'Release all bans', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', '', 'release', __( 'End every lockout and ban on all sites that allow actions?', 'sentinel-shield' ) );
						$sshield_hub_form( 'act_all', __( 'Push my settings', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', '', 'settings', $sshield_push_confirm );
					}
					$sshield_hub_form( 'uptime', __( 'Check uptime now', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' );
					$sshield_hub_form( 'refresh', __( 'Refresh all', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' );
					?>
				</div>
			<?php endif; ?>
		</div>
		<div class="sshield-sites">
			<?php foreach ( $sshield_rows as $sshield_row ) : ?>
				<?php $sshield_st = $sshield_row['status']; ?>
				<article class="sshield-site<?php echo is_wp_error( $sshield_st ) ? ' sshield-site--down' : ' sshield-site--' . esc_attr( $sshield_st['band'] ); ?>">
					<?php if ( is_wp_error( $sshield_st ) ) : ?>
						<div class="sshield-site__score">!</div>
						<div class="sshield-site__body">
							<strong><?php echo esc_html( $sshield_row['name'] ); ?></strong>
							<a href="<?php echo esc_url( $sshield_row['url'] ); ?>" class="sshield-site__url" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $sshield_row['url'] ); ?></a>
							<p class="sshield-hint"><?php echo esc_html( $sshield_st->get_error_message() ); ?></p>
							<?php $sshield_uptime_line( isset( $sshield_uptime[ $sshield_row['id'] ] ) ? $sshield_uptime[ $sshield_row['id'] ] : array(), '' === $sshield_row['id'] ); ?>
						</div>
					<?php else : ?>
						<div class="sshield-site__score"><?php echo esc_html( $sshield_st['score'] ); ?></div>
						<div class="sshield-site__body">
							<strong><?php echo esc_html( $sshield_row['name'] ); ?></strong>
							<a href="<?php echo esc_url( $sshield_row['url'] ); ?>" class="sshield-site__url" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $sshield_row['url'] ); ?></a>
							<p>
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: status wording, 2: open issues, 3: scan findings, 4: lockouts. */
										__( '%1$s. %2$d checks to fix, %3$d scan findings, %4$d IPs locked out.', 'sentinel-shield' ),
										$sshield_band_text[ $sshield_st['band'] ],
										count( $sshield_st['issues'] ),
										(int) $sshield_st['scan']['findings'],
										(int) $sshield_st['lockouts']
									)
								);
								?>
							</p>
							<p class="sshield-small">
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: plugin version, 2: WordPress version, 3: PHP version. */
										__( 'Sentinel Shield %1$s, WordPress %2$s, PHP %3$s', 'sentinel-shield' ),
										$sshield_st['plugin'],
										$sshield_st['wordpress'],
										$sshield_st['php']
									)
								);
								?>
							</p>
							<?php if ( isset( $sshield_st['incidents']['open'] ) ) : ?>
								<p class="sshield-site__incidents">
									<?php
									$sshield_crit = (int) $sshield_st['incidents']['by_severity'][ Incidents::CRITICAL ] + (int) $sshield_st['incidents']['by_severity'][ Incidents::HIGH ];
									echo esc_html(
										$sshield_st['incidents']['open']
											? sprintf(
												/* translators: 1: open incidents, 2: of which high or critical. */
												_n( '%1$d open incident, %2$d high or critical.', '%1$d open incidents, %2$d high or critical.', (int) $sshield_st['incidents']['open'], 'sentinel-shield' ),
												(int) $sshield_st['incidents']['open'],
												$sshield_crit
											)
											: __( 'No open incidents.', 'sentinel-shield' )
									);
									?>
								</p>
							<?php endif; ?>
							<?php $sshield_uptime_line( isset( $sshield_uptime[ $sshield_row['id'] ] ) ? $sshield_uptime[ $sshield_row['id'] ] : array(), '' === $sshield_row['id'] ); ?>
						</div>
					<?php endif; ?>
					<div class="sshield-site__actions">
						<?php if ( $sshield_row['id'] && is_array( $sshield_st ) && ! empty( $sshield_st['actions'] ) ) : ?>
							<?php
							$sshield_hub_form( 'act', __( 'Scan', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', $sshield_row['id'], 'scan' );
							$sshield_hub_form( 'act', __( 'Release bans', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', $sshield_row['id'], 'release', __( 'End every lockout and ban on this site?', 'sentinel-shield' ) );
							$sshield_hub_form( 'act', __( 'Push my settings', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', $sshield_row['id'], 'settings', $sshield_push_confirm );
							?>
						<?php elseif ( $sshield_row['id'] && is_array( $sshield_st ) ) : ?>
							<span class="sshield-small"><?php esc_html_e( 'Read-only key: create a key that allows actions on that site to run scans and push settings from here.', 'sentinel-shield' ); ?></span>
						<?php endif; ?>
						<?php if ( $sshield_row['id'] ) : ?>
							<a class="sshield-link" href="<?php echo esc_url( $sshield_row['url'] . 'wp-admin/admin.php?page=sentinel-shield' ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open', 'sentinel-shield' ); ?></a>
							<?php $sshield_hub_form( 'remove', __( 'Remove', 'sentinel-shield' ), 'sshield-link sshield-link--danger', $sshield_row['id'] ); ?>
						<?php endif; ?>
					</div>
				</article>
			<?php endforeach; ?>
		</div>
	</section>

	<section class="sshield-card sshield-card--full">
		<h2><?php esc_html_e( 'Fleet incidents', 'sentinel-shield' ); ?></h2>
		<?php if ( ! $sshield_fleet ) : ?>
			<p class="sshield-empty"><?php esc_html_e( 'No open incidents on any site.', 'sentinel-shield' ); ?></p>
		<?php else : ?>
			<ul class="sshield-incidents">
				<?php foreach ( $sshield_fleet as $sshield_inc ) : ?>
					<?php $sshield_sv = max( 1, min( 4, (int) $sshield_inc['severity'] ) ); ?>
					<li class="sshield-incident-row sshield-incident-row--<?php echo esc_attr( $sshield_sev_css[ $sshield_sv ] ); ?>">
						<span class="sshield-sev sshield-sev--<?php echo esc_attr( $sshield_sev_css[ $sshield_sv ] ); ?>"><?php echo esc_html( $sshield_sev_names[ $sshield_sv ] ); ?></span>
						<div class="sshield-incident-row__body">
							<a class="sshield-incident-row__title" href="<?php echo esc_url( $sshield_inc['link'] ); ?>"<?php echo $sshield_inc['external'] ? ' target="_blank" rel="noopener noreferrer"' : ''; ?>><?php echo esc_html( $sshield_inc['title'] ); ?></a>
							<p class="sshield-small"><?php echo esc_html( $sshield_inc['site'] . ' · ' . wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $sshield_inc['updated'] ) ); ?></p>
						</div>
						<span class="sshield-tag"><?php echo esc_html( $sshield_inc['technique'] ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>
	</section>

	<section class="sshield-card">
		<h2><?php esc_html_e( 'Connect a site', 'sentinel-shield' ); ?></h2>
		<p><?php esc_html_e( 'Install Sentinel Shield on the other site, create a hub key on its Hub tab, then paste the address and key here. The hub then watches its score, uptime and certificate, and, if the key allows actions, can run scans, release bans and push settings.', 'sentinel-shield' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="sshield_hub">
			<input type="hidden" name="op" value="add">
			<?php wp_nonce_field( 'sshield_hub' ); ?>
			<div class="sshield-fields sshield-fields--one">
				<label><span><?php esc_html_e( 'Site address', 'sentinel-shield' ); ?></span>
					<input type="url" name="url" required placeholder="https://example.com"></label>
				<label><span><?php esc_html_e( 'Hub key', 'sentinel-shield' ); ?></span>
					<input type="password" name="key" required autocomplete="off" placeholder="ssk_..."></label>
				<label><span><?php esc_html_e( 'Name (optional)', 'sentinel-shield' ); ?></span>
					<input type="text" name="name"></label>
			</div>
			<div class="sshield-actions">
				<button type="submit" class="sshield-btn"><?php esc_html_e( 'Connect site', 'sentinel-shield' ); ?></button>
			</div>
		</form>
	</section>

	<section class="sshield-card">
		<h2><?php esc_html_e( 'This site\'s hub key', 'sentinel-shield' ); ?></h2>
		<?php if ( $sshield_new_key ) : ?>
			<p><?php esc_html_e( 'Copy this key now and paste it into your hub site. It will not be shown again.', 'sentinel-shield' ); ?></p>
			<input type="text" class="sshield-keybox" readonly value="<?php echo esc_attr( $sshield_new_key ); ?>" onclick="this.select()">
		<?php elseif ( 'manage' === Api::key_scope() ) : ?>
			<p><?php esc_html_e( 'A hub key that allows actions is active. The hub can read this site\'s status, start scans, release lockouts and bans, and push hardening settings. Actions are signed and can only be used once.', 'sentinel-shield' ); ?></p>
		<?php elseif ( Api::has_key() ) : ?>
			<p><?php esc_html_e( 'A read-only hub key is active. Another site holding it can read this site\'s security status, but cannot change anything.', 'sentinel-shield' ); ?></p>
		<?php else : ?>
			<p><?php esc_html_e( 'No hub key yet. Create one to let another Sentinel Shield site watch this one.', 'sentinel-shield' ); ?></p>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="sshield_hub">
			<input type="hidden" name="op" value="new_key">
			<?php wp_nonce_field( 'sshield_hub' ); ?>
			<label class="sshield-keyopt"><input type="checkbox" name="manage" value="1" <?php checked( 'manage' === Api::key_scope() ); ?>> <span><?php esc_html_e( 'Let the hub run actions: scans, releasing lockouts and bans, and pushing hardening settings.', 'sentinel-shield' ); ?></span></label>
			<button type="submit" class="sshield-btn"><?php echo Api::has_key() ? esc_html__( 'Replace key', 'sentinel-shield' ) : esc_html__( 'Create hub key', 'sentinel-shield' ); ?></button>
		</form>
		<div class="sshield-actions sshield-actions--start">
			<?php if ( Api::has_key() ) : ?>
				<?php $sshield_hub_form( 'revoke_key', __( 'Revoke', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' ); ?>
			<?php endif; ?>
		</div>
		<p class="sshield-small">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: REST API base URL. */
					__( 'Developers: the REST API lives at %s. Read routes accept the hub key in the X-Sentinel-Key header; routes that change settings need an administrator application password.', 'sentinel-shield' ),
					rest_url( Api::NS )
				)
			);
			?>
		</p>
	</section>
</div>
