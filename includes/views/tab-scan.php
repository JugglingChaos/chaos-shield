<?php
/**
 * Scan tab.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_results  = Scanner::results();
$sshield_open     = Scanner::open_findings( $sshield_results );
$sshield_running  = Scanner::running();
$sshield_progress = Scanner::progress();
$sshield_reviewed = $sshield_results ? count( $sshield_results['findings'] ) - count( $sshield_open ) : 0;
$sshield_sev      = array(
	'high'   => __( 'High', 'sentinel-shield' ),
	'medium' => __( 'Medium', 'sentinel-shield' ),
);
usort(
	$sshield_open,
	static function ( $a, $b ) {
		return array( 'high' === $b['severity'], $a['file'] ) <=> array( 'high' === $a['severity'], $b['file'] );
	}
);
$sshield_vuln_error = Network::get_transient( 'sshield_vuln_error_' . get_current_user_id() );
Network::delete_transient( 'sshield_vuln_error_' . get_current_user_id() );
$sshield_vulns  = Vulns::open();
$sshield_stale  = Vulns::stale();
$sshield_vuln_r = Vulns::result();
?>
<?php if ( $sshield_vuln_error ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="alert"><?php echo esc_html( $sshield_vuln_error ); ?></div>
<?php endif; ?>
<div class="sshield-grid">
	<section class="sshield-card sshield-card--full">
		<div class="sshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Known vulnerabilities', 'sentinel-shield' ); ?></h2>
				<p>
					<?php
					if ( ! Vulns::enabled() ) {
						esc_html_e( 'Vulnerability alerts are switched off under Hardening.', 'sentinel-shield' );
					} elseif ( $sshield_vuln_r && $sshield_vuln_r['checked'] ) {
						printf(
							/* translators: %s: date. */
							esc_html__( 'Last checked %s.', 'sentinel-shield' ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $sshield_vuln_r['checked'] ) )
						);
					} else {
						esc_html_e( 'The first check runs in the background within a few minutes.', 'sentinel-shield' );
					}
					?>
				</p>
			</div>
			<?php if ( Vulns::enabled() ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
					<input type="hidden" name="action" value="sshield_vulns">
					<?php wp_nonce_field( 'sshield_vulns' ); ?>
					<button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Check now', 'sentinel-shield' ); ?></button>
				</form>
			<?php endif; ?>
		</div>

		<?php if ( Vulns::enabled() ) : ?>
			<?php if ( $sshield_vuln_r && $sshield_vuln_r['error'] ) : ?>
				<p class="sshield-hint"><?php echo esc_html( $sshield_vuln_r['error'] ); ?></p>
			<?php endif; ?>
			<?php if ( $sshield_vuln_r && ! empty( $sshield_vuln_r['pending'] ) ) : ?>
				<p class="sshield-hint">
					<?php
					/* translators: %d: number of items. */
					echo esc_html( sprintf( _n( '%d more item is being checked in the background.', '%d more items are being checked in the background.', (int) $sshield_vuln_r['pending'], 'sentinel-shield' ), (int) $sshield_vuln_r['pending'] ) );
					?>
				</p>
			<?php endif; ?>
			<?php if ( ! $sshield_vulns && $sshield_vuln_r && $sshield_vuln_r['checked'] ) : ?>
				<p class="sshield-empty"><?php esc_html_e( 'No installed version has a known vulnerability.', 'sentinel-shield' ); ?></p>
			<?php elseif ( $sshield_vulns ) : ?>
				<ul class="sshield-checks sshield-findings">
					<?php foreach ( $sshield_vulns as $sshield_v ) : ?>
						<?php $sshield_update = Vulns::update_url( $sshield_v ); ?>
						<li class="sshield-check sshield-check--<?php echo in_array( $sshield_v['severity'], array( 'l', 'n' ), true ) ? 'warn' : 'fail'; ?>">
							<span class="sshield-badge"><?php echo esc_html( Vulns::severity_label( $sshield_v['severity'] ) ); ?></span>
							<div class="sshield-finding">
								<strong><?php echo esc_html( $sshield_v['name'] . ' ' . $sshield_v['version'] ); ?></strong>
								<p>
									<?php echo esc_html( $sshield_v['title'] ); ?>
									<?php if ( $sshield_v['link'] ) : ?>
										<a class="sshield-link" href="<?php echo esc_url( $sshield_v['link'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Details', 'sentinel-shield' ); ?></a>
									<?php endif; ?>
								</p>
								<p class="sshield-small">
									<?php
									$sshield_meta = array();
									if ( $sshield_v['cve'] ) {
										$sshield_meta[] = $sshield_v['cve'];
									}
									if ( $sshield_v['score'] ) {
										/* translators: %s: CVSS score. */
										$sshield_meta[] = sprintf( __( 'CVSS %s', 'sentinel-shield' ), number_format_i18n( $sshield_v['score'], 1 ) );
									}
									$sshield_meta[] = $sshield_v['unfixed']
										? __( 'No fix has been released. Consider removing it or replacing it.', 'sentinel-shield' )
										: ucfirst( Vulns::fix_text( $sshield_v ) ) . '.';
									echo esc_html( implode( ' · ', $sshield_meta ) );
									?>
								</p>
							</div>
							<?php if ( $sshield_update && ! $sshield_v['unfixed'] ) : ?>
								<a class="sshield-btn sshield-finding__action" href="<?php echo esc_url( $sshield_update ); ?>"><?php esc_html_e( 'Update now', 'sentinel-shield' ); ?></a>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<?php if ( $sshield_stale ) : ?>
				<h3 class="sshield-subhead"><?php esc_html_e( 'Closed or abandoned', 'sentinel-shield' ); ?></h3>
				<ul class="sshield-checks sshield-findings">
					<?php foreach ( $sshield_stale as $sshield_s ) : ?>
						<li class="sshield-check sshield-check--<?php echo $sshield_s['closed'] ? 'fail' : 'warn'; ?>">
							<span class="sshield-badge"><?php echo esc_html( $sshield_s['closed'] ? __( 'Closed', 'sentinel-shield' ) : __( 'Abandoned', 'sentinel-shield' ) ); ?></span>
							<div class="sshield-finding">
								<strong><?php echo esc_html( $sshield_s['name'] ); ?></strong>
								<p>
									<?php
									if ( $sshield_s['closed'] ) {
										esc_html_e( 'Removed from the WordPress.org directory. It gets no more updates, often because of an unfixed security problem. Replace it.', 'sentinel-shield' );
									} else {
										printf(
											/* translators: %s: time ago, such as 3 years. */
											esc_html__( 'Last updated %s ago. Security problems found now may never be fixed, so consider a maintained alternative.', 'sentinel-shield' ),
											esc_html( human_time_diff( $sshield_s['updated'] ) )
										);
									}
									?>
								</p>
							</div>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
			<p class="sshield-small sshield-attrib">
				<?php esc_html_e( 'Vulnerability data from WPVulnerability.net, a free and open database. Only the names of your plugins and themes and your WordPress version are sent, never your site address.', 'sentinel-shield' ); ?>
			</p>
		<?php endif; ?>
	</section>

	<?php require SSHIELD_DIR . 'includes/views/integrity.php'; ?>

	<section class="sshield-card sshield-card--full sshield-scanbox" data-running="<?php echo $sshield_running ? '1' : '0'; ?>">
		<div class="sshield-card__head">
			<div>
				<h2><?php esc_html_e( 'File scan', 'sentinel-shield' ); ?></h2>
				<p>
					<?php
					if ( $sshield_results ) {
						printf(
							/* translators: 1: date, 2: files checked. */
							esc_html__( 'Last scan %1$s, %2$s files checked.', 'sentinel-shield' ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $sshield_results['finished'] ) ),
							esc_html( number_format_i18n( $sshield_results['files_scanned'] ) )
						);
					} else {
						esc_html_e( 'No scan has run yet. The first one takes a minute or two on most sites.', 'sentinel-shield' );
					}
					?>
				</p>
			</div>
			<button type="button" class="sshield-btn sshield-scan-start" <?php disabled( $sshield_running ); ?>><?php esc_html_e( 'Scan now', 'sentinel-shield' ); ?></button>
		</div>
		<div class="sshield-progress" <?php echo $sshield_running ? '' : 'hidden'; ?>>
			<div class="sshield-progress__bar"><span style="width: <?php echo esc_attr( $sshield_progress['percent'] ); ?>%"></span></div>
			<p class="sshield-progress__text" aria-live="polite"></p>
		</div>
		<p class="sshield-small">
			<?php esc_html_e( 'Compares WordPress core and every plugin and theme from WordPress.org with the official release, flags PHP files that do not belong, searches everything for malware and backdoor patterns, finds backups and logs that anyone could download, and reports files that changed since the last scan without an update.', 'sentinel-shield' ); ?>
		</p>
		<?php if ( $sshield_results && ! empty( $sshield_results['org_checked'] ) ) : ?>
			<p class="sshield-small">
				<?php
				/* translators: %d: number of plugins and themes. */
				echo esc_html( sprintf( _n( '%d plugin or theme was compared with its official release.', '%d plugins and themes were compared with their official release.', (int) $sshield_results['org_checked'], 'sentinel-shield' ), (int) $sshield_results['org_checked'] ) );
				?>
			</p>
		<?php endif; ?>
		<?php if ( $sshield_results && ! $sshield_results['core_checked'] ) : ?>
			<p class="sshield-hint"><?php esc_html_e( 'WordPress.org could not be reached for core checksums, so core files were only searched for malware patterns this time.', 'sentinel-shield' ); ?></p>
		<?php endif; ?>
	</section>

	<?php if ( $sshield_results ) : ?>
		<section class="sshield-card sshield-card--full">
			<div class="sshield-card__head">
				<h2>
					<?php
					/* translators: %d: number of findings. */
					echo esc_html( sprintf( _n( '%d finding', '%d findings', count( $sshield_open ), 'sentinel-shield' ), count( $sshield_open ) ) );
					?>
				</h2>
				<?php if ( $sshield_reviewed ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
						<input type="hidden" name="action" value="sshield_ignore">
						<input type="hidden" name="finding" value="all">
						<?php wp_nonce_field( 'sshield_ignore' ); ?>
						<button type="submit" class="sshield-link">
							<?php
							/* translators: %d: number of reviewed findings. */
							echo esc_html( sprintf( __( 'Show %d reviewed', 'sentinel-shield' ), $sshield_reviewed ) );
							?>
						</button>
					</form>
				<?php endif; ?>
			</div>
			<?php if ( ! $sshield_open ) : ?>
				<p class="sshield-empty"><?php esc_html_e( 'Nothing suspicious found. Official files match WordPress.org.', 'sentinel-shield' ); ?></p>
			<?php else : ?>
				<ul class="sshield-checks sshield-findings">
					<?php foreach ( $sshield_open as $sshield_f ) : ?>
						<li class="sshield-check sshield-check--<?php echo 'high' === $sshield_f['severity'] ? 'fail' : 'warn'; ?>">
							<span class="sshield-badge"><?php echo esc_html( $sshield_sev[ $sshield_f['severity'] ] ); ?></span>
							<div class="sshield-finding">
								<strong><?php echo esc_html( $sshield_f['label'] ); ?></strong>
								<p><code><?php echo esc_html( $sshield_f['file'] . ( $sshield_f['line'] ? ':' . $sshield_f['line'] : '' ) ); ?></code></p>
								<?php if ( $sshield_f['snippet'] ) : ?>
									<pre class="sshield-snippet"><?php echo esc_html( $sshield_f['snippet'] ); ?></pre>
								<?php endif; ?>
							</div>
							<div class="sshield-finding__action">
								<?php if ( in_array( $sshield_f['rule'], Cleanup::REPAIRABLE, true ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
									<input type="hidden" name="action" value="sshield_cleanup">
									<input type="hidden" name="op" value="repair">
									<input type="hidden" name="finding" value="<?php echo esc_attr( $sshield_f['id'] ); ?>">
									<?php wp_nonce_field( 'sshield_cleanup' ); ?>
									<button type="submit" class="sshield-link"><?php esc_html_e( 'Repair from WordPress.org', 'sentinel-shield' ); ?></button>
								</form>
								<?php else : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
									<input type="hidden" name="action" value="sshield_cleanup">
									<input type="hidden" name="op" value="quarantine">
									<input type="hidden" name="finding" value="<?php echo esc_attr( $sshield_f['id'] ); ?>">
									<?php wp_nonce_field( 'sshield_cleanup' ); ?>
									<button type="submit" class="sshield-link sshield-link--danger"><?php esc_html_e( 'Quarantine', 'sentinel-shield' ); ?></button>
								</form>
								<?php endif; ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
								<input type="hidden" name="action" value="sshield_ignore">
								<input type="hidden" name="finding" value="<?php echo esc_attr( $sshield_f['id'] ); ?>">
								<?php wp_nonce_field( 'sshield_ignore' ); ?>
								<button type="submit" class="sshield-link"><?php esc_html_e( 'Mark reviewed', 'sentinel-shield' ); ?></button>
							</form>
							</div>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="sshield-small"><?php esc_html_e( 'A finding is not proof of a hack: some premium plugins hide their code on purpose. Compare the file with a fresh download of the plugin or theme. Repair puts back the official copy of a modified core, plugin or theme file. Quarantine moves any other file to a locked folder where it cannot run.', 'sentinel-shield' ); ?></p>
			<?php endif; ?>
		</section>
	<?php endif; ?>

	<?php $sshield_q = Cleanup::quarantined(); ?>
	<?php if ( $sshield_q ) : ?>
		<section class="sshield-card sshield-card--full">
			<h2><?php esc_html_e( 'Quarantine', 'sentinel-shield' ); ?></h2>
			<p class="sshield-small"><?php esc_html_e( 'Quarantined files are moved to a locked folder where they cannot run. Restore one if a plugin breaks, or delete it for good.', 'sentinel-shield' ); ?></p>
			<table class="sshield-table">
				<thead><tr><th><?php esc_html_e( 'File', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Why', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Quarantined', 'sentinel-shield' ); ?></th><th></th></tr></thead>
				<tbody>
				<?php foreach ( $sshield_q as $sshield_qid => $sshield_item ) : ?>
					<tr>
						<td><code><?php echo esc_html( $sshield_item['file'] ); ?></code></td>
						<td><?php echo esc_html( $sshield_item['label'] ); ?></td>
						<td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $sshield_item['time'] ) ); ?></td>
						<td class="sshield-right">
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
									<input type="hidden" name="action" value="sshield_cleanup">
									<input type="hidden" name="op" value="restore">
									<input type="hidden" name="qid" value="<?php echo esc_attr( $sshield_qid ); ?>">
									<?php wp_nonce_field( 'sshield_cleanup' ); ?>
									<button type="submit" class="sshield-link"><?php esc_html_e( 'Restore', 'sentinel-shield' ); ?></button>
								</form>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
									<input type="hidden" name="action" value="sshield_cleanup">
									<input type="hidden" name="op" value="delete">
									<input type="hidden" name="qid" value="<?php echo esc_attr( $sshield_qid ); ?>">
									<?php wp_nonce_field( 'sshield_cleanup' ); ?>
									<button type="submit" class="sshield-link sshield-link--danger"><?php esc_html_e( 'Delete for good', 'sentinel-shield' ); ?></button>
								</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</section>
	<?php endif; ?>

	<?php $sshield_db = Cleanup::db_results(); ?>
	<section class="sshield-card sshield-card--full">
		<div class="sshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Database scan', 'sentinel-shield' ); ?></h2>
				<p>
					<?php
					if ( $sshield_db ) {
						printf(
							/* translators: %s: date. */
							esc_html__( 'Last checked %s.', 'sentinel-shield' ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $sshield_db['checked'] ) )
						);
					} else {
						esc_html_e( 'Looks for scripts from other sites, obfuscated code and hidden iframes injected into posts, pages and settings.', 'sentinel-shield' );
					}
					?>
				</p>
			</div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
									<input type="hidden" name="action" value="sshield_cleanup">
									<input type="hidden" name="op" value="dbscan">
									<input type="hidden" name="scope" value="<?php echo esc_attr( 'all' ); ?>">
									<?php wp_nonce_field( 'sshield_cleanup' ); ?>
									<button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Scan database', 'sentinel-shield' ); ?></button>
								</form>
		</div>
		<?php if ( $sshield_db ) : ?>
			<?php if ( ! $sshield_db['findings'] ) : ?>
				<p class="sshield-empty"><?php esc_html_e( 'No injected code found in posts, pages or settings.', 'sentinel-shield' ); ?></p>
			<?php else : ?>
				<ul class="sshield-checks sshield-findings">
					<?php foreach ( $sshield_db['findings'] as $sshield_d ) : ?>
						<li class="sshield-check sshield-check--warn">
							<span class="sshield-badge"><?php esc_html_e( 'Review', 'sentinel-shield' ); ?></span>
							<div class="sshield-finding">
								<strong><?php echo esc_html( $sshield_d['label'] ); ?></strong>
								<p><?php echo esc_html( $sshield_d['title'] ); ?></p>
								<pre class="sshield-snippet"><?php echo esc_html( $sshield_d['snippet'] ); ?></pre>
							</div>
							<?php if ( $sshield_d['edit'] ) : ?>
								<a class="sshield-link sshield-finding__action" href="<?php echo esc_url( $sshield_d['edit'] ); ?>"><?php esc_html_e( 'Edit', 'sentinel-shield' ); ?></a>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="sshield-small"><?php esc_html_e( 'Analytics, chat and ad scripts you added yourself can show up here. Remove anything you do not recognise, then change all passwords.', 'sentinel-shield' ); ?></p>
			<?php endif; ?>
		<?php endif; ?>
	</section>
</div>
