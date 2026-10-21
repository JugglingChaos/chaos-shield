<?php
/**
 * Printable security and compliance report.
 *
 * @package SentinelShield
 *
 * @var array $report days, since, checks, controls, admins, score, counts, notable.
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_site   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
$sshield_format = get_option( 'date_format' );
$sshield_full   = $sshield_format . ' ' . get_option( 'time_format' );
$sshield_passed = count(
	array_filter(
		$report['controls'],
		static function ( $c ) {
			return $c['ok'];
		}
	)
);
$sshield_names  = array(
	'login'     => __( 'Logins and logouts', 'sentinel-shield' ),
	'lockout'   => __( 'Lockouts', 'sentinel-shield' ),
	'ban'       => __( 'Bans', 'sentinel-shield' ),
	'blocked'   => __( 'Firewall blocks', 'sentinel-shield' ),
	'user'      => __( 'User changes', 'sentinel-shield' ),
	'password'  => __( 'Password events', 'sentinel-shield' ),
	'content'   => __( 'Content changes', 'sentinel-shield' ),
	'option'    => __( 'Site setting changes', 'sentinel-shield' ),
	'settings'  => __( 'Security setting changes', 'sentinel-shield' ),
	'plugin'    => __( 'Plugin changes', 'sentinel-shield' ),
	'theme'     => __( 'Theme changes', 'sentinel-shield' ),
	'scan'      => __( 'Scans', 'sentinel-shield' ),
	'vuln'      => __( 'Vulnerabilities', 'sentinel-shield' ),
	'privacy'   => __( 'Privacy requests', 'sentinel-shield' ),
	'twofactor' => __( 'Two-factor events', 'sentinel-shield' ),
	'system'    => __( 'System', 'sentinel-shield' ),
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
echo esc_html( sprintf( __( 'Security and compliance report: %s', 'sentinel-shield' ), $sshield_site ) );
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
	<a href="<?php echo esc_url( Admin::url( 'activity' ) ); ?>"><?php esc_html_e( 'Back to Sentinel Shield', 'sentinel-shield' ); ?></a>
	<button type="button" onclick="window.print()"><?php esc_html_e( 'Print or save as PDF', 'sentinel-shield' ); ?></button>
</div>
<main>
	<h1><?php esc_html_e( 'Security and compliance report', 'sentinel-shield' ); ?></h1>
	<p class="meta">
		<?php
		echo esc_html(
			sprintf(
				/* translators: 1: site name, 2: site address, 3: start date, 4: end date, 5: generated date and time. */
				__( '%1$s (%2$s). Period %3$s to %4$s. Generated %5$s.', 'sentinel-shield' ),
				$sshield_site,
				home_url( '/' ),
				wp_date( $sshield_format, $report['since'] ),
				wp_date( $sshield_format ),
				wp_date( $sshield_full )
			)
		);
		?>
	</p>

	<div class="summary">
		<div class="tile"><b><?php echo esc_html( $report['score'] ); ?>/100</b><span><?php esc_html_e( 'Security score', 'sentinel-shield' ); ?></span></div>
		<div class="tile"><b><?php echo esc_html( $sshield_passed . ' / ' . count( $report['controls'] ) ); ?></b><span><?php esc_html_e( 'Controls in place', 'sentinel-shield' ); ?></span></div>
		<div class="tile"><b><?php echo esc_html( number_format_i18n( array_sum( $report['counts'] ) ) ); ?></b><span><?php esc_html_e( 'Events logged in the period', 'sentinel-shield' ); ?></span></div>
		<div class="tile"><b><?php echo esc_html( count( $report['admins'] ) ); ?></b><span><?php esc_html_e( 'Administrator accounts', 'sentinel-shield' ); ?></span></div>
	</div>

	<h2><?php esc_html_e( 'Controls', 'sentinel-shield' ); ?></h2>
	<table>
		<thead><tr><th><?php esc_html_e( 'Control', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Status', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Evidence', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Helps with', 'sentinel-shield' ); ?></th></tr></thead>
		<tbody>
		<?php foreach ( $report['controls'] as $sshield_c ) : ?>
			<tr>
				<td><strong><?php echo esc_html( $sshield_c['label'] ); ?></strong><br><span class="small"><?php echo esc_html( $sshield_c['area'] ); ?></span></td>
				<td class="<?php echo $sshield_c['ok'] ? 'ok' : 'bad'; ?>"><?php echo $sshield_c['ok'] ? esc_html__( 'In place', 'sentinel-shield' ) : esc_html__( 'Gap', 'sentinel-shield' ); ?></td>
				<td><?php echo esc_html( $sshield_c['evidence'] ); ?></td>
				<td class="refs"><?php echo esc_html( $sshield_c['refs'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<p class="small"><?php esc_html_e( 'References name the SOC 2 (2017 Trust Services Criteria) and ISO/IEC 27001:2022 Annex A controls this evidence supports. This report is evidence for an assessment, not a certification.', 'sentinel-shield' ); ?></p>

	<h2><?php esc_html_e( 'Administrator accounts', 'sentinel-shield' ); ?></h2>
	<table>
		<thead><tr><th><?php esc_html_e( 'User', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Second factor', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Last login', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Password changed', 'sentinel-shield' ); ?></th></tr></thead>
		<tbody>
		<?php foreach ( $report['admins'] as $sshield_a ) : ?>
			<?php
			$sshield_factors = array();
			if ( $sshield_a['twofactor'] ) {
				$sshield_factors[] = __( 'Authenticator app', 'sentinel-shield' );
			}
			if ( $sshield_a['passkeys'] ) {
				/* translators: %d: number of passkeys. */
				$sshield_factors[] = sprintf( _n( '%d passkey', '%d passkeys', $sshield_a['passkeys'], 'sentinel-shield' ), $sshield_a['passkeys'] );
			}
			?>
			<tr>
				<td><strong><?php echo esc_html( $sshield_a['login'] ); ?></strong><br><span class="small"><?php echo esc_html( $sshield_a['email'] ); ?></span></td>
				<td class="<?php echo $sshield_factors ? 'ok' : 'bad'; ?>"><?php echo $sshield_factors ? esc_html( implode( ', ', $sshield_factors ) ) : esc_html__( 'None', 'sentinel-shield' ); ?></td>
				<td><?php echo $sshield_a['last_login'] ? esc_html( wp_date( $sshield_full, $sshield_a['last_login'] ) ) : esc_html__( 'Not in the log', 'sentinel-shield' ); ?></td>
				<td>
					<?php
					echo $sshield_a['pw_changed'] ? esc_html( wp_date( $sshield_format, $sshield_a['pw_changed'] ) ) : esc_html__( 'Unknown', 'sentinel-shield' );
					if ( $sshield_a['reset_pending'] ) {
						echo '<br><span class="bad">' . esc_html__( 'Reset pending', 'sentinel-shield' ) . '</span>';
					}
					?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Activity in the period', 'sentinel-shield' ); ?></h2>
	<?php if ( $report['counts'] ) : ?>
		<table>
			<thead><tr><th><?php esc_html_e( 'Kind of event', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Count', 'sentinel-shield' ); ?></th></tr></thead>
			<tbody>
			<?php
			arsort( $report['counts'] );
			foreach ( $report['counts'] as $sshield_type => $sshield_n ) :
				?>
				<tr><td><?php echo esc_html( isset( $sshield_names[ $sshield_type ] ) ? $sshield_names[ $sshield_type ] : $sshield_type ); ?></td><td><?php echo esc_html( number_format_i18n( $sshield_n ) ); ?></td></tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php else : ?>
		<p><?php esc_html_e( 'No events were logged in this period.', 'sentinel-shield' ); ?></p>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Notable events', 'sentinel-shield' ); ?></h2>
	<?php if ( $report['notable'] ) : ?>
		<table>
			<thead><tr><th><?php esc_html_e( 'When', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Event', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></th></tr></thead>
			<tbody>
			<?php foreach ( $report['notable'] as $sshield_e ) : ?>
				<tr>
					<td style="white-space:nowrap"><?php echo esc_html( wp_date( $sshield_full, (int) $sshield_e['time'] ) ); ?></td>
					<td><?php echo ( Events::CRITICAL <= (int) $sshield_e['severity'] ? '<span class="bad">' . esc_html__( 'Critical', 'sentinel-shield' ) . '</span> ' : '' ) . esc_html( $sshield_e['message'] ); ?></td>
					<td><?php echo esc_html( $sshield_e['ip'] ? $sshield_e['ip'] : '-' ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p class="small"><?php esc_html_e( 'Events marked notice or critical. The full log can be exported to CSV from the Activity tab.', 'sentinel-shield' ); ?></p>
	<?php else : ?>
		<p><?php esc_html_e( 'No notable events in this period.', 'sentinel-shield' ); ?></p>
	<?php endif; ?>

	<p class="small" style="margin-top:32px">
		<?php
		/* translators: %s: plugin version. */
		echo esc_html( sprintf( __( 'Generated by Sentinel Shield %s.', 'sentinel-shield' ), SSHIELD_VERSION ) );
		?>
	</p>
</main>
</body>
</html>
