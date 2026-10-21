<?php
/**
 * Live traffic tab.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view state.
$cshield_kind    = isset( $_GET['kind'] ) ? sanitize_key( $_GET['kind'] ) : 'all';
$cshield_country = isset( $_GET['country'] ) ? strtoupper( sanitize_key( $_GET['country'] ) ) : '';
// phpcs:enable
$cshield_country = preg_match( '/^[A-Z]{2}$/', $cshield_country ) ? $cshield_country : '';
$cshield_kind    = in_array( $cshield_kind, Traffic::kinds(), true ) ? $cshield_kind : 'all';
$cshield_on      = Settings::enabled( 'live_traffic' );
$cshield_rows    = $cshield_on ? Traffic::rows( $cshield_kind, 0, 100, $cshield_country ) : array();
$cshield_counts  = $cshield_on ? Traffic::counts() : array();
$cshield_labels  = Traffic::labels();
$cshield_tf      = Threat_Feed::status();
$cshield_stats   = Login_Guard::stats();
$cshield_world   = Traffic::world();
$cshield_geo     = $cshield_on ? Traffic::by_country() : array();
?>
<div class="cshield-grid">
	<?php if ( $cshield_on ) : ?>
		<?php require CSHIELD_DIR . 'includes/views/traffic-map.php'; ?>
	<?php endif; ?>
	<section id="cshield-traffic" class="cshield-card cshield-card--full cshield-traffic" data-kind="<?php echo esc_attr( $cshield_kind ); ?>" data-country="<?php echo esc_attr( $cshield_country ); ?>" data-last="<?php echo esc_attr( $cshield_rows ? $cshield_rows[0]['id'] : 0 ); ?>">
		<div class="cshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Live traffic', 'chaos-shield' ); ?></h2>
				<p>
					<?php
					if ( ! $cshield_on ) {
						esc_html_e( 'Live traffic is switched off under Hardening.', 'chaos-shield' );
					} elseif ( 'all' === Settings::get( 'traffic_mode' ) ) {
						esc_html_e( 'Every visit from the last 24 hours. New requests appear on their own.', 'chaos-shield' );
					} else {
						esc_html_e( 'Blocked requests, logins and missing pages from the last 24 hours. New requests appear on their own. To see every visit, change the mode under Hardening.', 'chaos-shield' );
					}
					?>
				</p>
			</div>
			<?php if ( $cshield_on ) : ?>
				<label class="cshield-live"><input type="checkbox" class="cshield-live__toggle" checked> <span class="cshield-live__dot" aria-hidden="true"></span><?php esc_html_e( 'Live', 'chaos-shield' ); ?></label>
			<?php endif; ?>
		</div>

		<?php if ( $cshield_on ) : ?>
			<nav class="cshield-chips" aria-label="<?php esc_attr_e( 'Filter traffic', 'chaos-shield' ); ?>">
				<a href="<?php echo esc_url( Admin::url( 'traffic', $cshield_country ? array( 'country' => $cshield_country ) : array() ) ); ?>" class="cshield-chip<?php echo 'all' === $cshield_kind ? ' is-active' : ''; ?>"><?php esc_html_e( 'All', 'chaos-shield' ); ?> <span data-count="all"><?php echo esc_html( number_format_i18n( array_sum( $cshield_counts ) ) ); ?></span></a>
				<?php foreach ( $cshield_labels as $cshield_k => $cshield_label ) : ?>
					<a href="
					<?php
					echo esc_url(
						Admin::url(
							'traffic',
							array_filter(
								array(
									'kind'    => $cshield_k,
									'country' => $cshield_country,
								)
							)
						)
					);
					?>
								" class="cshield-chip<?php echo $cshield_k === $cshield_kind ? ' is-active' : ''; ?>"><?php echo esc_html( $cshield_label ); ?> <span data-count="<?php echo esc_attr( $cshield_k ); ?>"><?php echo esc_html( number_format_i18n( $cshield_counts[ $cshield_k ] ) ); ?></span></a>
				<?php endforeach; ?>
			</nav>
			<?php if ( $cshield_country ) : ?>
				<p class="cshield-filter-note">
					<?php
					/* translators: %s: country name. */
					echo esc_html( sprintf( __( 'Only traffic from %s.', 'chaos-shield' ), Geo_Db::name( $cshield_country, isset( $cshield_world['shapes'][ $cshield_country ] ) ? $cshield_world['shapes'][ $cshield_country ]['n'] : ( isset( $cshield_world['dots'][ $cshield_country ] ) ? $cshield_world['dots'][ $cshield_country ]['n'] : $cshield_country ) ) ) );
					?>
					<a class="cshield-link" href="<?php echo esc_url( Admin::url( 'traffic', 'all' !== $cshield_kind ? array( 'kind' => $cshield_kind ) : array() ) ); ?>"><?php esc_html_e( 'Show every country', 'chaos-shield' ); ?></a>
				</p>
			<?php endif; ?>
			<div class="cshield-table-wrap">
				<table class="cshield-table cshield-table--traffic">
					<thead><tr><th><?php esc_html_e( 'Type', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Time', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Visitor', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Request', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Status', 'chaos-shield' ); ?></th><th></th></tr></thead>
					<tbody>
						<?php
						foreach ( $cshield_rows as $cshield_row ) {
							echo Traffic::row_html( $cshield_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in row_html().
						}
						?>
					</tbody>
				</table>
			</div>
			<p class="cshield-empty"<?php echo $cshield_rows ? ' hidden' : ''; ?>><?php esc_html_e( 'Nothing recorded yet. Requests show up here as they happen.', 'chaos-shield' ); ?></p>
		<?php endif; ?>
	</section>

	<section class="cshield-card">
		<h2><?php esc_html_e( 'Threat blocklist', 'chaos-shield' ); ?></h2>
		<p class="cshield-stat"><?php echo esc_html( number_format_i18n( isset( $cshield_stats['threat_blocks'] ) ? $cshield_stats['threat_blocks'] : 0 ) ); ?></p>
		<p class="cshield-small">
			<?php
			if ( ! Settings::enabled( 'threat_feed' ) ) {
				esc_html_e( 'Requests stopped by the threat blocklist in the last day. It is switched off under Hardening.', 'chaos-shield' );
			} else {
				$cshield_names = array();
				foreach ( Threat_Feed::sources() as $cshield_sk => $cshield_src ) {
					if ( $cshield_src['on'] && ! empty( $cshield_tf['counts'][ $cshield_sk ] ) ) {
						/* translators: 1: list name, 2: number of networks. */
						$cshield_names[] = sprintf( __( '%1$s (%2$s networks)', 'chaos-shield' ), $cshield_src['label'], number_format_i18n( $cshield_tf['counts'][ $cshield_sk ] ) );
					}
				}
				echo esc_html(
					$cshield_names
						/* translators: %s: list names. */
						? sprintf( __( 'Requests stopped by the threat blocklist in the last day. Lists in use: %s.', 'chaos-shield' ), implode( ', ', $cshield_names ) )
						: __( 'Requests stopped by the threat blocklist in the last day. The lists have not been downloaded yet.', 'chaos-shield' )
				);
			}
			?>
		</p>
	</section>
	<section class="cshield-card">
		<h2><?php esc_html_e( 'Firewall', 'chaos-shield' ); ?></h2>
		<p class="cshield-stat"><?php echo esc_html( number_format_i18n( isset( $cshield_stats['firewall_blocks'] ) ? $cshield_stats['firewall_blocks'] : 0 ) ); ?></p>
		<p class="cshield-small"><?php esc_html_e( 'Requests stopped in the last day by the firewall rules, bans and the block list.', 'chaos-shield' ); ?></p>
	</section>
</div>
