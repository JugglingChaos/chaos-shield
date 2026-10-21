<?php
/**
 * Live traffic: where requests come from, as a world heatmap and a top countries table.
 *
 * Expects $cshield_world and $cshield_geo from tab-traffic.php.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_geo_status = Geo_Db::status();
$cshield_geo_max    = 0;
$cshield_geo_names  = array();
foreach ( $cshield_geo as $cshield_cc => $cshield_g ) {
	$cshield_geo_max                  = max( $cshield_geo_max, $cshield_g['all'] );
	$cshield_en                       = isset( $cshield_world['shapes'][ $cshield_cc ] ) ? $cshield_world['shapes'][ $cshield_cc ]['n'] : ( isset( $cshield_world['dots'][ $cshield_cc ] ) ? $cshield_world['dots'][ $cshield_cc ]['n'] : $cshield_cc );
	$cshield_geo_names[ $cshield_cc ] = Geo_Db::name( $cshield_cc, $cshield_en );
}
$cshield_geo_total = array_sum( wp_list_pluck( $cshield_geo, 'all' ) );
$cshield_geo_none  = Traffic::unlocated();
$cshield_geo_data  = array(
	'counts' => $cshield_geo,
	'names'  => $cshield_geo_names,
	'i18n'   => array(
		/* translators: 1: requests, 2: blocked, 3: logins, 4: distinct IPs. */
		'tip'  => __( '%1$s requests · %2$s blocked · %3$s logins · %4$s IPs', 'chaos-shield' ),
		'none' => __( 'No traffic in the last 24 hours', 'chaos-shield' ),
	),
);
?>
<section class="cshield-card cshield-card--full cshield-geo" data-geo="<?php echo esc_attr( wp_json_encode( $cshield_geo_data ) ); ?>">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Where traffic comes from', 'chaos-shield' ); ?></h2>
			<p>
				<?php
				if ( Geo_Db::enabled() && Geo_Db::ready() ) {
					printf(
						/* translators: 1: number of countries, 2: date. */
						esc_html( _n( '%1$s country in the last 24 hours. Country data from the built-in database, updated %2$s.', '%1$s countries in the last 24 hours. Country data from the built-in database, updated %2$s.', count( $cshield_geo ), 'chaos-shield' ) ),
						esc_html( number_format_i18n( count( $cshield_geo ) ) ),
						esc_html( wp_date( get_option( 'date_format' ), $cshield_geo_status['updated'] ) )
					);
				} elseif ( Geo_Db::enabled() ) {
					esc_html_e( 'The country database is downloading in the background. The map fills in as new requests arrive.', 'chaos-shield' );
				} elseif ( Settings::get( 'country_source' ) ) {
					esc_html_e( 'Countries come from the header your proxy or host sends.', 'chaos-shield' );
				} else {
					esc_html_e( 'Switch on Built-in country lookup under Hardening to see where traffic comes from.', 'chaos-shield' );
				}
				if ( Geo_Db::enabled() && $cshield_geo_status['error'] ) {
					echo ' ' . esc_html( $cshield_geo_status['error'] );
				}
				?>
			</p>
		</div>
		<div class="cshield-chips cshield-geo__metric" role="group" aria-label="<?php esc_attr_e( 'Show on the map', 'chaos-shield' ); ?>">
			<button type="button" class="cshield-chip is-active" data-metric="all" aria-pressed="true"><?php esc_html_e( 'All requests', 'chaos-shield' ); ?></button>
			<button type="button" class="cshield-chip" data-metric="blocked" aria-pressed="false"><?php esc_html_e( 'Blocked', 'chaos-shield' ); ?></button>
			<button type="button" class="cshield-chip" data-metric="login" aria-pressed="false"><?php esc_html_e( 'Logins', 'chaos-shield' ); ?></button>
		</div>
	</div>

	<div class="cshield-geo__map">
		<svg viewBox="0 0 <?php echo esc_attr( $cshield_world['w'] . ' ' . $cshield_world['h'] ); ?>" role="img" aria-label="<?php esc_attr_e( 'World map shaded by requests per country in the last 24 hours. The table below lists the same numbers.', 'chaos-shield' ); ?>">
			<?php foreach ( $cshield_world['shapes'] as $cshield_cc => $cshield_shape ) : ?>
				<?php $cshield_n = isset( $cshield_geo[ $cshield_cc ] ) ? $cshield_geo[ $cshield_cc ]['all'] : 0; ?>
				<path class="cshield-geo__c cshield-geo--<?php echo esc_attr( Traffic::shade( $cshield_n, $cshield_geo_max ) ); ?>" data-cc="<?php echo esc_attr( $cshield_cc ); ?>" data-name="<?php echo esc_attr( isset( $cshield_geo_names[ $cshield_cc ] ) ? $cshield_geo_names[ $cshield_cc ] : $cshield_shape['n'] ); ?>" d="<?php echo esc_attr( $cshield_shape['d'] ); ?>"></path>
			<?php endforeach; ?>
			<?php
			// Countries too small for the map's scale show as a dot, but only when they sent traffic.
			foreach ( $cshield_world['dots'] as $cshield_cc => $cshield_dot ) :
				if ( empty( $cshield_geo[ $cshield_cc ] ) ) {
					continue;
				}
				?>
				<circle class="cshield-geo__c cshield-geo__dot cshield-geo--<?php echo esc_attr( Traffic::shade( $cshield_geo[ $cshield_cc ]['all'], $cshield_geo_max ) ); ?>" data-cc="<?php echo esc_attr( $cshield_cc ); ?>" data-name="<?php echo esc_attr( $cshield_geo_names[ $cshield_cc ] ); ?>" cx="<?php echo esc_attr( $cshield_dot['x'] ); ?>" cy="<?php echo esc_attr( $cshield_dot['y'] ); ?>" r="5"></circle>
			<?php endforeach; ?>
		</svg>
		<div class="cshield-geo__tip" role="status" hidden></div>
	</div>

	<div class="cshield-geo__legend" aria-hidden="true">
		<span class="cshield-geo__key"><span class="cshield-geo__swatch cshield-geo--0"></span><?php esc_html_e( 'None', 'chaos-shield' ); ?></span>
		<span class="cshield-geo__key"><?php esc_html_e( 'Fewer', 'chaos-shield' ); ?></span>
		<?php for ( $cshield_s = 1; $cshield_s <= 5; $cshield_s++ ) : ?>
			<span class="cshield-geo__swatch cshield-geo--<?php echo esc_attr( $cshield_s ); ?>"></span>
		<?php endfor; ?>
		<span class="cshield-geo__key">
			<?php
			/* translators: %s: highest count. */
			echo '<span class="cshield-geo__max">' . esc_html( sprintf( __( 'More (up to %s)', 'chaos-shield' ), number_format_i18n( $cshield_geo_max ) ) ) . '</span>';
			?>
		</span>
	</div>

	<?php if ( $cshield_geo ) : ?>
		<div class="cshield-table-wrap">
			<table class="cshield-table cshield-table--geo">
				<thead><tr><th><?php esc_html_e( 'Country', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Requests', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Blocked', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Logins', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'IPs', 'chaos-shield' ); ?></th></tr></thead>
				<tbody>
					<?php foreach ( array_slice( $cshield_geo, 0, 10, true ) as $cshield_cc => $cshield_g ) : ?>
						<tr data-cc="<?php echo esc_attr( $cshield_cc ); ?>">
							<td>
								<a class="cshield-link" href="<?php echo esc_url( Admin::url( 'traffic', array( 'country' => $cshield_cc ) ) . '#cshield-traffic' ); ?>"><?php echo esc_html( $cshield_geo_names[ $cshield_cc ] ); ?></a>
								<span class="cshield-geo__share" style="--share: <?php echo esc_attr( round( 100 * $cshield_g['all'] / max( 1, $cshield_geo_total ), 1 ) ); ?>%"></span>
							</td>
							<td><?php echo esc_html( number_format_i18n( $cshield_g['all'] ) ); ?> <span class="cshield-small"><?php echo esc_html( round( 100 * $cshield_g['all'] / max( 1, $cshield_geo_total ) ) . '%' ); ?></span></td>
							<td><?php echo esc_html( number_format_i18n( $cshield_g['blocked'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $cshield_g['login'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $cshield_g['ips'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
	<p class="cshield-small">
		<?php
		if ( $cshield_geo_none ) {
			/* translators: %s: number of requests. */
			echo esc_html( sprintf( _n( '%s request has no known country (private network or recorded before the lookup was ready).', '%s requests have no known country (private networks or recorded before the lookup was ready).', $cshield_geo_none, 'chaos-shield' ), number_format_i18n( $cshield_geo_none ) ) ) . ' ';
		}
		esc_html_e( 'Click a country to filter the live traffic below. Country data: ip-location-db (public domain). Map: Natural Earth.', 'chaos-shield' );
		?>
	</p>
</section>
