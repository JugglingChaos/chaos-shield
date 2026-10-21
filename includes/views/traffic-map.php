<?php
/**
 * Live traffic: where requests come from, as a world heatmap and a top countries table.
 *
 * Expects $sshield_world and $sshield_geo from tab-traffic.php.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_geo_status = Geo_Db::status();
$sshield_geo_max    = 0;
$sshield_geo_names  = array();
foreach ( $sshield_geo as $sshield_cc => $sshield_g ) {
	$sshield_geo_max                  = max( $sshield_geo_max, $sshield_g['all'] );
	$sshield_en                       = isset( $sshield_world['shapes'][ $sshield_cc ] ) ? $sshield_world['shapes'][ $sshield_cc ]['n'] : ( isset( $sshield_world['dots'][ $sshield_cc ] ) ? $sshield_world['dots'][ $sshield_cc ]['n'] : $sshield_cc );
	$sshield_geo_names[ $sshield_cc ] = Geo_Db::name( $sshield_cc, $sshield_en );
}
$sshield_geo_total = array_sum( wp_list_pluck( $sshield_geo, 'all' ) );
$sshield_geo_none  = Traffic::unlocated();
$sshield_geo_data  = array(
	'counts' => $sshield_geo,
	'names'  => $sshield_geo_names,
	'i18n'   => array(
		/* translators: 1: requests, 2: blocked, 3: logins, 4: distinct IPs. */
		'tip'  => __( '%1$s requests · %2$s blocked · %3$s logins · %4$s IPs', 'sentinel-shield' ),
		'none' => __( 'No traffic in the last 24 hours', 'sentinel-shield' ),
	),
);
?>
<section class="sshield-card sshield-card--full sshield-geo" data-geo="<?php echo esc_attr( wp_json_encode( $sshield_geo_data ) ); ?>">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Where traffic comes from', 'sentinel-shield' ); ?></h2>
			<p>
				<?php
				if ( Geo_Db::enabled() && Geo_Db::ready() ) {
					printf(
						/* translators: 1: number of countries, 2: date. */
						esc_html( _n( '%1$s country in the last 24 hours. Country data from the built-in database, updated %2$s.', '%1$s countries in the last 24 hours. Country data from the built-in database, updated %2$s.', count( $sshield_geo ), 'sentinel-shield' ) ),
						esc_html( number_format_i18n( count( $sshield_geo ) ) ),
						esc_html( wp_date( get_option( 'date_format' ), $sshield_geo_status['updated'] ) )
					);
				} elseif ( Geo_Db::enabled() ) {
					esc_html_e( 'The country database is downloading in the background. The map fills in as new requests arrive.', 'sentinel-shield' );
				} elseif ( Settings::get( 'country_source' ) ) {
					esc_html_e( 'Countries come from the header your proxy or host sends.', 'sentinel-shield' );
				} else {
					esc_html_e( 'Switch on Built-in country lookup under Hardening to see where traffic comes from.', 'sentinel-shield' );
				}
				if ( Geo_Db::enabled() && $sshield_geo_status['error'] ) {
					echo ' ' . esc_html( $sshield_geo_status['error'] );
				}
				?>
			</p>
		</div>
		<div class="sshield-chips sshield-geo__metric" role="group" aria-label="<?php esc_attr_e( 'Show on the map', 'sentinel-shield' ); ?>">
			<button type="button" class="sshield-chip is-active" data-metric="all" aria-pressed="true"><?php esc_html_e( 'All requests', 'sentinel-shield' ); ?></button>
			<button type="button" class="sshield-chip" data-metric="blocked" aria-pressed="false"><?php esc_html_e( 'Blocked', 'sentinel-shield' ); ?></button>
			<button type="button" class="sshield-chip" data-metric="login" aria-pressed="false"><?php esc_html_e( 'Logins', 'sentinel-shield' ); ?></button>
		</div>
	</div>

	<div class="sshield-geo__map">
		<svg viewBox="0 0 <?php echo esc_attr( $sshield_world['w'] . ' ' . $sshield_world['h'] ); ?>" role="img" aria-label="<?php esc_attr_e( 'World map shaded by requests per country in the last 24 hours. The table below lists the same numbers.', 'sentinel-shield' ); ?>">
			<?php foreach ( $sshield_world['shapes'] as $sshield_cc => $sshield_shape ) : ?>
				<?php $sshield_n = isset( $sshield_geo[ $sshield_cc ] ) ? $sshield_geo[ $sshield_cc ]['all'] : 0; ?>
				<path class="sshield-geo__c sshield-geo--<?php echo esc_attr( Traffic::shade( $sshield_n, $sshield_geo_max ) ); ?>" data-cc="<?php echo esc_attr( $sshield_cc ); ?>" data-name="<?php echo esc_attr( isset( $sshield_geo_names[ $sshield_cc ] ) ? $sshield_geo_names[ $sshield_cc ] : $sshield_shape['n'] ); ?>" d="<?php echo esc_attr( $sshield_shape['d'] ); ?>"></path>
			<?php endforeach; ?>
			<?php
			// Countries too small for the map's scale show as a dot, but only when they sent traffic.
			foreach ( $sshield_world['dots'] as $sshield_cc => $sshield_dot ) :
				if ( empty( $sshield_geo[ $sshield_cc ] ) ) {
					continue;
				}
				?>
				<circle class="sshield-geo__c sshield-geo__dot sshield-geo--<?php echo esc_attr( Traffic::shade( $sshield_geo[ $sshield_cc ]['all'], $sshield_geo_max ) ); ?>" data-cc="<?php echo esc_attr( $sshield_cc ); ?>" data-name="<?php echo esc_attr( $sshield_geo_names[ $sshield_cc ] ); ?>" cx="<?php echo esc_attr( $sshield_dot['x'] ); ?>" cy="<?php echo esc_attr( $sshield_dot['y'] ); ?>" r="5"></circle>
			<?php endforeach; ?>
		</svg>
		<div class="sshield-geo__tip" role="status" hidden></div>
	</div>

	<div class="sshield-geo__legend" aria-hidden="true">
		<span class="sshield-geo__key"><span class="sshield-geo__swatch sshield-geo--0"></span><?php esc_html_e( 'None', 'sentinel-shield' ); ?></span>
		<span class="sshield-geo__key"><?php esc_html_e( 'Fewer', 'sentinel-shield' ); ?></span>
		<?php for ( $sshield_s = 1; $sshield_s <= 5; $sshield_s++ ) : ?>
			<span class="sshield-geo__swatch sshield-geo--<?php echo esc_attr( $sshield_s ); ?>"></span>
		<?php endfor; ?>
		<span class="sshield-geo__key">
			<?php
			/* translators: %s: highest count. */
			echo '<span class="sshield-geo__max">' . esc_html( sprintf( __( 'More (up to %s)', 'sentinel-shield' ), number_format_i18n( $sshield_geo_max ) ) ) . '</span>';
			?>
		</span>
	</div>

	<?php if ( $sshield_geo ) : ?>
		<div class="sshield-table-wrap">
			<table class="sshield-table sshield-table--geo">
				<thead><tr><th><?php esc_html_e( 'Country', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Requests', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Blocked', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Logins', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'IPs', 'sentinel-shield' ); ?></th></tr></thead>
				<tbody>
					<?php foreach ( array_slice( $sshield_geo, 0, 10, true ) as $sshield_cc => $sshield_g ) : ?>
						<tr data-cc="<?php echo esc_attr( $sshield_cc ); ?>">
							<td>
								<a class="sshield-link" href="<?php echo esc_url( Admin::url( 'traffic', array( 'country' => $sshield_cc ) ) . '#sshield-traffic' ); ?>"><?php echo esc_html( $sshield_geo_names[ $sshield_cc ] ); ?></a>
								<span class="sshield-geo__share" style="--share: <?php echo esc_attr( round( 100 * $sshield_g['all'] / max( 1, $sshield_geo_total ), 1 ) ); ?>%"></span>
							</td>
							<td><?php echo esc_html( number_format_i18n( $sshield_g['all'] ) ); ?> <span class="sshield-small"><?php echo esc_html( round( 100 * $sshield_g['all'] / max( 1, $sshield_geo_total ) ) . '%' ); ?></span></td>
							<td><?php echo esc_html( number_format_i18n( $sshield_g['blocked'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $sshield_g['login'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $sshield_g['ips'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
	<p class="sshield-small">
		<?php
		if ( $sshield_geo_none ) {
			/* translators: %s: number of requests. */
			echo esc_html( sprintf( _n( '%s request has no known country (private network or recorded before the lookup was ready).', '%s requests have no known country (private networks or recorded before the lookup was ready).', $sshield_geo_none, 'sentinel-shield' ), number_format_i18n( $sshield_geo_none ) ) ) . ' ';
		}
		esc_html_e( 'Click a country to filter the live traffic below. Country data: ip-location-db (public domain). Map: Natural Earth.', 'sentinel-shield' );
		?>
	</p>
</section>
