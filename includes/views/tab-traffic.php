<?php
/**
 * Live traffic tab.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view state.
$sshield_kind    = isset( $_GET['kind'] ) ? sanitize_key( $_GET['kind'] ) : 'all';
$sshield_country = isset( $_GET['country'] ) ? strtoupper( sanitize_key( $_GET['country'] ) ) : '';
// phpcs:enable
$sshield_country = preg_match( '/^[A-Z]{2}$/', $sshield_country ) ? $sshield_country : '';
$sshield_kind    = in_array( $sshield_kind, Traffic::kinds(), true ) ? $sshield_kind : 'all';
$sshield_on      = Settings::enabled( 'live_traffic' );
$sshield_rows    = $sshield_on ? Traffic::rows( $sshield_kind, 0, 100, $sshield_country ) : array();
$sshield_counts  = $sshield_on ? Traffic::counts() : array();
$sshield_labels  = Traffic::labels();
$sshield_tf      = Threat_Feed::status();
$sshield_stats   = Login_Guard::stats();
$sshield_world   = Traffic::world();
$sshield_geo     = $sshield_on ? Traffic::by_country() : array();
?>
<div class="sshield-grid">
	<?php if ( $sshield_on ) : ?>
		<?php require SSHIELD_DIR . 'includes/views/traffic-map.php'; ?>
	<?php endif; ?>
	<section id="sshield-traffic" class="sshield-card sshield-card--full sshield-traffic" data-kind="<?php echo esc_attr( $sshield_kind ); ?>" data-country="<?php echo esc_attr( $sshield_country ); ?>" data-last="<?php echo esc_attr( $sshield_rows ? $sshield_rows[0]['id'] : 0 ); ?>">
		<div class="sshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Live traffic', 'sentinel-shield' ); ?></h2>
				<p>
					<?php
					if ( ! $sshield_on ) {
						esc_html_e( 'Live traffic is switched off under Hardening.', 'sentinel-shield' );
					} elseif ( 'all' === Settings::get( 'traffic_mode' ) ) {
						esc_html_e( 'Every visit from the last 24 hours. New requests appear on their own.', 'sentinel-shield' );
					} else {
						esc_html_e( 'Blocked requests, logins and missing pages from the last 24 hours. New requests appear on their own. To see every visit, change the mode under Hardening.', 'sentinel-shield' );
					}
					?>
				</p>
			</div>
			<?php if ( $sshield_on ) : ?>
				<label class="sshield-live"><input type="checkbox" class="sshield-live__toggle" checked> <span class="sshield-live__dot" aria-hidden="true"></span><?php esc_html_e( 'Live', 'sentinel-shield' ); ?></label>
			<?php endif; ?>
		</div>

		<?php if ( $sshield_on ) : ?>
			<nav class="sshield-chips" aria-label="<?php esc_attr_e( 'Filter traffic', 'sentinel-shield' ); ?>">
				<a href="<?php echo esc_url( Admin::url( 'traffic', $sshield_country ? array( 'country' => $sshield_country ) : array() ) ); ?>" class="sshield-chip<?php echo 'all' === $sshield_kind ? ' is-active' : ''; ?>"><?php esc_html_e( 'All', 'sentinel-shield' ); ?> <span data-count="all"><?php echo esc_html( number_format_i18n( array_sum( $sshield_counts ) ) ); ?></span></a>
				<?php foreach ( $sshield_labels as $sshield_k => $sshield_label ) : ?>
					<a href="
					<?php
					echo esc_url(
						Admin::url(
							'traffic',
							array_filter(
								array(
									'kind'    => $sshield_k,
									'country' => $sshield_country,
								)
							)
						)
					);
					?>
								" class="sshield-chip<?php echo $sshield_k === $sshield_kind ? ' is-active' : ''; ?>"><?php echo esc_html( $sshield_label ); ?> <span data-count="<?php echo esc_attr( $sshield_k ); ?>"><?php echo esc_html( number_format_i18n( $sshield_counts[ $sshield_k ] ) ); ?></span></a>
				<?php endforeach; ?>
			</nav>
			<?php if ( $sshield_country ) : ?>
				<p class="sshield-filter-note">
					<?php
					/* translators: %s: country name. */
					echo esc_html( sprintf( __( 'Only traffic from %s.', 'sentinel-shield' ), Geo_Db::name( $sshield_country, isset( $sshield_world['shapes'][ $sshield_country ] ) ? $sshield_world['shapes'][ $sshield_country ]['n'] : ( isset( $sshield_world['dots'][ $sshield_country ] ) ? $sshield_world['dots'][ $sshield_country ]['n'] : $sshield_country ) ) ) );
					?>
					<a class="sshield-link" href="<?php echo esc_url( Admin::url( 'traffic', 'all' !== $sshield_kind ? array( 'kind' => $sshield_kind ) : array() ) ); ?>"><?php esc_html_e( 'Show every country', 'sentinel-shield' ); ?></a>
				</p>
			<?php endif; ?>
			<div class="sshield-table-wrap">
				<table class="sshield-table sshield-table--traffic">
					<thead><tr><th><?php esc_html_e( 'Type', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Time', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Visitor', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Request', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Status', 'sentinel-shield' ); ?></th><th></th></tr></thead>
					<tbody>
						<?php
						foreach ( $sshield_rows as $sshield_row ) {
							echo Traffic::row_html( $sshield_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in row_html().
						}
						?>
					</tbody>
				</table>
			</div>
			<p class="sshield-empty"<?php echo $sshield_rows ? ' hidden' : ''; ?>><?php esc_html_e( 'Nothing recorded yet. Requests show up here as they happen.', 'sentinel-shield' ); ?></p>
		<?php endif; ?>
	</section>

	<section class="sshield-card">
		<h2><?php esc_html_e( 'Threat blocklist', 'sentinel-shield' ); ?></h2>
		<p class="sshield-stat"><?php echo esc_html( number_format_i18n( isset( $sshield_stats['threat_blocks'] ) ? $sshield_stats['threat_blocks'] : 0 ) ); ?></p>
		<p class="sshield-small">
			<?php
			if ( ! Settings::enabled( 'threat_feed' ) ) {
				esc_html_e( 'Requests stopped by the threat blocklist in the last day. It is switched off under Hardening.', 'sentinel-shield' );
			} else {
				$sshield_names = array();
				foreach ( Threat_Feed::sources() as $sshield_sk => $sshield_src ) {
					if ( $sshield_src['on'] && ! empty( $sshield_tf['counts'][ $sshield_sk ] ) ) {
						/* translators: 1: list name, 2: number of networks. */
						$sshield_names[] = sprintf( __( '%1$s (%2$s networks)', 'sentinel-shield' ), $sshield_src['label'], number_format_i18n( $sshield_tf['counts'][ $sshield_sk ] ) );
					}
				}
				echo esc_html(
					$sshield_names
						/* translators: %s: list names. */
						? sprintf( __( 'Requests stopped by the threat blocklist in the last day. Lists in use: %s.', 'sentinel-shield' ), implode( ', ', $sshield_names ) )
						: __( 'Requests stopped by the threat blocklist in the last day. The lists have not been downloaded yet.', 'sentinel-shield' )
				);
			}
			?>
		</p>
	</section>
	<section class="sshield-card">
		<h2><?php esc_html_e( 'Firewall', 'sentinel-shield' ); ?></h2>
		<p class="sshield-stat"><?php echo esc_html( number_format_i18n( isset( $sshield_stats['firewall_blocks'] ) ? $sshield_stats['firewall_blocks'] : 0 ) ); ?></p>
		<p class="sshield-small"><?php esc_html_e( 'Requests stopped in the last day by the firewall rules, bans and the block list.', 'sentinel-shield' ); ?></p>
	</section>
</div>
