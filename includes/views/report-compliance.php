<?php
/**
 * Printable security and compliance report.
 *
 * @package ChaosShield
 *
 * @var array $report days, since, checks, controls, admins, score, counts, notable.
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_site   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
$cshield_format = get_option( 'date_format' );
$cshield_full   = $cshield_format . ' ' . get_option( 'time_format' );
$cshield_passed = count(
	array_filter(
		$report['controls'],
		static function ( $c ) {
			return $c['ok'];
		}
	)
);
$cshield_names  = array(
	'login'     => __( 'Logins and logouts', 'chaos-shield' ),
	'lockout'   => __( 'Lockouts', 'chaos-shield' ),
	'ban'       => __( 'Bans', 'chaos-shield' ),
	'blocked'   => __( 'Firewall blocks', 'chaos-shield' ),
	'user'      => __( 'User changes', 'chaos-shield' ),
	'password'  => __( 'Password events', 'chaos-shield' ),
	'content'   => __( 'Content changes', 'chaos-shield' ),
	'option'    => __( 'Site setting changes', 'chaos-shield' ),
	'settings'  => __( 'Security setting changes', 'chaos-shield' ),
	'plugin'    => __( 'Plugin changes', 'chaos-shield' ),
	'theme'     => __( 'Theme changes', 'chaos-shield' ),
	'scan'      => __( 'Scans', 'chaos-shield' ),
	'vuln'      => __( 'Vulnerabilities', 'chaos-shield' ),
	'privacy'   => __( 'Privacy requests', 'chaos-shield' ),
	'twofactor' => __( 'Two-factor events', 'chaos-shield' ),
	'system'    => __( 'System', 'chaos-shield' ),
);
?><!doctype html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>
<?php
/* translators: %s: site name. */
echo esc_html( sprintf( __( 'Security and compliance report: %s', 'chaos-shield' ), $cshield_site ) );
?>
</title>
<style>
	:root { --ink:#1d2327; --muted:#50575e; --line:#dcdcde; --ok:#00875a; --bad:#b32d2e; --accent:#0b7a5b; }
	* { box-sizing: border-box; }
	body { margin: 0; background: #f6f7f7; color: var(--ink); font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
	main { max-width: 960px; margin: 24px auto; padding: 40px 48px; background: #fff; border: 1px solid var(--line); }
	h1 { margin: 0 0 4px; font-size: 24px; }
	h2 { margin: 32px 0 10px; font-size: 17px; border-bottom: 2px solid var(--ink); padding-bottom: 6px; }
	.meta { color: var(--muted); margin: 0 0 20px; }
	.summary { display: flex; gap: 16px; flex-wrap: wrap; }
	.tile { flex: 1; min-width: 160px; border: 1px solid var(--line); padding: 12px 16px; }
	.tile b { display: block; font-size: 26px; }
	.tile span { color: var(--muted); font-size: 12px; }
	table { width: 100%; border-collapse: collapse; margin-top: 6px; }
	th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
	th { font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: var(--muted); }
	.ok { color: var(--ok); font-weight: 600; white-space: nowrap; }
	.bad { color: var(--bad); font-weight: 600; white-space: nowrap; }
	.refs { color: var(--muted); font-size: 12px; white-space: nowrap; }
	.small { color: var(--muted); font-size: 12px; }
	.toolbar { max-width: 960px; margin: 16px auto 0; display: flex; gap: 8px; justify-content: flex-end; }
	.toolbar a, .toolbar button { font: inherit; padding: 6px 14px; border: 1px solid var(--ink); background: #fff; color: var(--ink); cursor: pointer; text-decoration: none; }
	.toolbar button { background: var(--ink); color: #fff; }
	@media print {
		body { background: #fff; }
		main { border: 0; margin: 0; padding: 0; max-width: none; }
		.toolbar { display: none; }
		tr { break-inside: avoid; }
	}
	@media (max-width: 700px) { main { padding: 20px 16px; margin: 0; } .refs { white-space: normal; } }
</style>
</head>
<body>
<div class="toolbar">
	<a href="<?php echo esc_url( Admin::url( 'activity' ) ); ?>"><?php esc_html_e( 'Back to Chaos Shield', 'chaos-shield' ); ?></a>
	<button type="button" onclick="window.print()"><?php esc_html_e( 'Print or save as PDF', 'chaos-shield' ); ?></button>
</div>
<main>
	<h1><?php esc_html_e( 'Security and compliance report', 'chaos-shield' ); ?></h1>
	<p class="meta">
		<?php
		echo esc_html(
			sprintf(
				/* translators: 1: site name, 2: site address, 3: start date, 4: end date, 5: generated date and time. */
				__( '%1$s (%2$s). Period %3$s to %4$s. Generated %5$s.', 'chaos-shield' ),
				$cshield_site,
				home_url( '/' ),
				wp_date( $cshield_format, $report['since'] ),
				wp_date( $cshield_format ),
				wp_date( $cshield_full )
			)
		);
		?>
	</p>

	<div class="summary">
		<div class="tile"><b><?php echo esc_html( $report['score'] ); ?>/100</b><span><?php esc_html_e( 'Security score', 'chaos-shield' ); ?></span></div>
		<div class="tile"><b><?php echo esc_html( $cshield_passed . ' / ' . count( $report['controls'] ) ); ?></b><span><?php esc_html_e( 'Controls in place', 'chaos-shield' ); ?></span></div>
		<div class="tile"><b><?php echo esc_html( number_format_i18n( array_sum( $report['counts'] ) ) ); ?></b><span><?php esc_html_e( 'Events logged in the period', 'chaos-shield' ); ?></span></div>
		<div class="tile"><b><?php echo esc_html( count( $report['admins'] ) ); ?></b><span><?php esc_html_e( 'Administrator accounts', 'chaos-shield' ); ?></span></div>
	</div>

	<h2><?php esc_html_e( 'Controls', 'chaos-shield' ); ?></h2>
	<table>
		<thead><tr><th><?php esc_html_e( 'Control', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Status', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Evidence', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Helps with', 'chaos-shield' ); ?></th></tr></thead>
		<tbody>
		<?php foreach ( $report['controls'] as $cshield_c ) : ?>
			<tr>
				<td><strong><?php echo esc_html( $cshield_c['label'] ); ?></strong><br><span class="small"><?php echo esc_html( $cshield_c['area'] ); ?></span></td>
				<td class="<?php echo $cshield_c['ok'] ? 'ok' : 'bad'; ?>"><?php echo $cshield_c['ok'] ? esc_html__( 'In place', 'chaos-shield' ) : esc_html__( 'Gap', 'chaos-shield' ); ?></td>
				<td><?php echo esc_html( $cshield_c['evidence'] ); ?></td>
				<td class="refs"><?php echo esc_html( $cshield_c['refs'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<p class="small"><?php esc_html_e( 'References name the SOC 2 (2017 Trust Services Criteria) and ISO/IEC 27001:2022 Annex A controls this evidence supports. This report is evidence for an assessment, not a certification.', 'chaos-shield' ); ?></p>

	<h2><?php esc_html_e( 'Administrator accounts', 'chaos-shield' ); ?></h2>
	<table>
		<thead><tr><th><?php esc_html_e( 'User', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Second factor', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Last login', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Password changed', 'chaos-shield' ); ?></th></tr></thead>
		<tbody>
		<?php foreach ( $report['admins'] as $cshield_a ) : ?>
			<?php
			$cshield_factors = array();
			if ( $cshield_a['twofactor'] ) {
				$cshield_factors[] = __( 'Authenticator app', 'chaos-shield' );
			}
			if ( $cshield_a['passkeys'] ) {
				/* translators: %d: number of passkeys. */
				$cshield_factors[] = sprintf( _n( '%d passkey', '%d passkeys', $cshield_a['passkeys'], 'chaos-shield' ), $cshield_a['passkeys'] );
			}
			?>
			<tr>
				<td><strong><?php echo esc_html( $cshield_a['login'] ); ?></strong><br><span class="small"><?php echo esc_html( $cshield_a['email'] ); ?></span></td>
				<td class="<?php echo $cshield_factors ? 'ok' : 'bad'; ?>"><?php echo $cshield_factors ? esc_html( implode( ', ', $cshield_factors ) ) : esc_html__( 'None', 'chaos-shield' ); ?></td>
				<td><?php echo $cshield_a['last_login'] ? esc_html( wp_date( $cshield_full, $cshield_a['last_login'] ) ) : esc_html__( 'Not in the log', 'chaos-shield' ); ?></td>
				<td>
					<?php
					echo $cshield_a['pw_changed'] ? esc_html( wp_date( $cshield_format, $cshield_a['pw_changed'] ) ) : esc_html__( 'Unknown', 'chaos-shield' );
					if ( $cshield_a['reset_pending'] ) {
						echo '<br><span class="bad">' . esc_html__( 'Reset pending', 'chaos-shield' ) . '</span>';
					}
					?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Activity in the period', 'chaos-shield' ); ?></h2>
	<?php if ( $report['counts'] ) : ?>
		<table>
			<thead><tr><th><?php esc_html_e( 'Kind of event', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Count', 'chaos-shield' ); ?></th></tr></thead>
			<tbody>
			<?php
			arsort( $report['counts'] );
			foreach ( $report['counts'] as $cshield_type => $cshield_n ) :
				?>
				<tr><td><?php echo esc_html( isset( $cshield_names[ $cshield_type ] ) ? $cshield_names[ $cshield_type ] : $cshield_type ); ?></td><td><?php echo esc_html( number_format_i18n( $cshield_n ) ); ?></td></tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php else : ?>
		<p><?php esc_html_e( 'No events were logged in this period.', 'chaos-shield' ); ?></p>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Notable events', 'chaos-shield' ); ?></h2>
	<?php if ( $report['notable'] ) : ?>
		<table>
			<thead><tr><th><?php esc_html_e( 'When', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Event', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'IP', 'chaos-shield' ); ?></th></tr></thead>
			<tbody>
			<?php foreach ( $report['notable'] as $cshield_e ) : ?>
				<tr>
					<td style="white-space:nowrap"><?php echo esc_html( wp_date( $cshield_full, (int) $cshield_e['time'] ) ); ?></td>
					<td><?php echo ( Events::CRITICAL <= (int) $cshield_e['severity'] ? '<span class="bad">' . esc_html__( 'Critical', 'chaos-shield' ) . '</span> ' : '' ) . esc_html( $cshield_e['message'] ); ?></td>
					<td><?php echo esc_html( $cshield_e['ip'] ? $cshield_e['ip'] : '-' ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p class="small"><?php esc_html_e( 'Events marked notice or critical. The full log can be exported to CSV from the Activity tab.', 'chaos-shield' ); ?></p>
	<?php else : ?>
		<p><?php esc_html_e( 'No notable events in this period.', 'chaos-shield' ); ?></p>
	<?php endif; ?>

	<p class="small" style="margin-top:32px">
		<?php
		/* translators: %s: plugin version. */
		echo esc_html( sprintf( __( 'Generated by Chaos Shield %s.', 'chaos-shield' ), CSHIELD_VERSION ) );
		?>
	</p>
</main>
</body>
</html>
