<?php
/**
 * Scan tab.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_results  = Scanner::results();
$cshield_open     = Scanner::open_findings( $cshield_results );
$cshield_running  = Scanner::running();
$cshield_progress = Scanner::progress();
$cshield_reviewed = $cshield_results ? count( $cshield_results['findings'] ) - count( $cshield_open ) : 0;
$cshield_sev      = array(
	'high'   => __( 'High', 'chaos-shield' ),
	'medium' => __( 'Medium', 'chaos-shield' ),
);
usort(
	$cshield_open,
	static function ( $a, $b ) {
		return array( 'high' === $b['severity'], $a['file'] ) <=> array( 'high' === $a['severity'], $b['file'] );
	}
);
$cshield_vuln_error = Network::get_transient( 'cshield_vuln_error_' . get_current_user_id() );
Network::delete_transient( 'cshield_vuln_error_' . get_current_user_id() );
$cshield_vulns  = Vulns::open();
$cshield_stale  = Vulns::stale();
$cshield_vuln_r = Vulns::result();
?>
<?php if ( $cshield_vuln_error ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="alert"><?php echo esc_html( $cshield_vuln_error ); ?></div>
<?php endif; ?>
<div class="cshield-grid">
	<section class="cshield-card cshield-card--full">
		<div class="cshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Known vulnerabilities', 'chaos-shield' ); ?></h2>
				<p>
					<?php
					if ( ! Vulns::enabled() ) {
						esc_html_e( 'Vulnerability alerts are switched off under Hardening.', 'chaos-shield' );
					} elseif ( $cshield_vuln_r && $cshield_vuln_r['checked'] ) {
						printf(
							/* translators: %s: date. */
							esc_html__( 'Last checked %s.', 'chaos-shield' ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cshield_vuln_r['checked'] ) )
						);
					} else {
						esc_html_e( 'The first check runs in the background within a few minutes.', 'chaos-shield' );
					}
					?>
				</p>
			</div>
			<?php if ( Vulns::enabled() ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
					<input type="hidden" name="action" value="cshield_vulns">
					<?php wp_nonce_field( 'cshield_vulns' ); ?>
					<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Check now', 'chaos-shield' ); ?></button>
				</form>
			<?php endif; ?>
		</div>

		<?php if ( Vulns::enabled() ) : ?>
			<?php if ( $cshield_vuln_r && $cshield_vuln_r['error'] ) : ?>
				<p class="cshield-hint"><?php echo esc_html( $cshield_vuln_r['error'] ); ?></p>
			<?php endif; ?>
			<?php if ( $cshield_vuln_r && ! empty( $cshield_vuln_r['pending'] ) ) : ?>
				<p class="cshield-hint">
					<?php
					/* translators: %d: number of items. */
					echo esc_html( sprintf( _n( '%d more item is being checked in the background.', '%d more items are being checked in the background.', (int) $cshield_vuln_r['pending'], 'chaos-shield' ), (int) $cshield_vuln_r['pending'] ) );
					?>
				</p>
			<?php endif; ?>
			<?php if ( ! $cshield_vulns && $cshield_vuln_r && $cshield_vuln_r['checked'] ) : ?>
				<p class="cshield-empty"><?php esc_html_e( 'No installed version has a known vulnerability.', 'chaos-shield' ); ?></p>
			<?php elseif ( $cshield_vulns ) : ?>
				<ul class="cshield-checks cshield-findings">
					<?php foreach ( $cshield_vulns as $cshield_v ) : ?>
						<?php $cshield_update = Vulns::update_url( $cshield_v ); ?>
						<li class="cshield-check cshield-check--<?php echo in_array( $cshield_v['severity'], array( 'l', 'n' ), true ) ? 'warn' : 'fail'; ?>">
							<span class="cshield-badge"><?php echo esc_html( Vulns::severity_label( $cshield_v['severity'] ) ); ?></span>
							<div class="cshield-finding">
								<strong><?php echo esc_html( $cshield_v['name'] . ' ' . $cshield_v['version'] ); ?></strong>
								<p>
									<?php echo esc_html( $cshield_v['title'] ); ?>
									<?php if ( $cshield_v['link'] ) : ?>
										<a class="cshield-link" href="<?php echo esc_url( $cshield_v['link'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Details', 'chaos-shield' ); ?></a>
									<?php endif; ?>
								</p>
								<p class="cshield-small">
									<?php
									$cshield_meta = array();
									if ( $cshield_v['cve'] ) {
										$cshield_meta[] = $cshield_v['cve'];
									}
									if ( $cshield_v['score'] ) {
										/* translators: %s: CVSS score. */
										$cshield_meta[] = sprintf( __( 'CVSS %s', 'chaos-shield' ), number_format_i18n( $cshield_v['score'], 1 ) );
									}
									$cshield_meta[] = $cshield_v['unfixed']
										? __( 'No fix has been released. Consider removing it or replacing it.', 'chaos-shield' )
										: ucfirst( Vulns::fix_text( $cshield_v ) ) . '.';
									echo esc_html( implode( ' · ', $cshield_meta ) );
									?>
								</p>
							</div>
							<?php if ( $cshield_update && ! $cshield_v['unfixed'] ) : ?>
								<a class="cshield-btn cshield-finding__action" href="<?php echo esc_url( $cshield_update ); ?>"><?php esc_html_e( 'Update now', 'chaos-shield' ); ?></a>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<?php if ( $cshield_stale ) : ?>
				<h3 class="cshield-subhead"><?php esc_html_e( 'Closed or abandoned', 'chaos-shield' ); ?></h3>
				<ul class="cshield-checks cshield-findings">
					<?php foreach ( $cshield_stale as $cshield_s ) : ?>
						<li class="cshield-check cshield-check--<?php echo $cshield_s['closed'] ? 'fail' : 'warn'; ?>">
							<span class="cshield-badge"><?php echo esc_html( $cshield_s['closed'] ? __( 'Closed', 'chaos-shield' ) : __( 'Abandoned', 'chaos-shield' ) ); ?></span>
							<div class="cshield-finding">
								<strong><?php echo esc_html( $cshield_s['name'] ); ?></strong>
								<p>
									<?php
									if ( $cshield_s['closed'] ) {
										esc_html_e( 'Removed from the WordPress.org directory. It gets no more updates, often because of an unfixed security problem. Replace it.', 'chaos-shield' );
									} else {
										printf(
											/* translators: %s: time ago, such as 3 years. */
											esc_html__( 'Last updated %s ago. Security problems found now may never be fixed, so consider a maintained alternative.', 'chaos-shield' ),
											esc_html( human_time_diff( $cshield_s['updated'] ) )
										);
									}
									?>
								</p>
							</div>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
			<p class="cshield-small cshield-attrib">
				<?php esc_html_e( 'Vulnerability data from WPVulnerability.net, a free and open database. Only the names of your plugins and themes and your WordPress version are sent, never your site address.', 'chaos-shield' ); ?>
			</p>
		<?php endif; ?>
	</section>

	<?php require CSHIELD_DIR . 'includes/views/integrity.php'; ?>

	<section class="cshield-card cshield-card--full cshield-scanbox" data-running="<?php echo $cshield_running ? '1' : '0'; ?>">
		<div class="cshield-card__head">
			<div>
				<h2><?php esc_html_e( 'File scan', 'chaos-shield' ); ?></h2>
				<p>
					<?php
					if ( $cshield_results ) {
						printf(
							/* translators: 1: date, 2: files checked. */
							esc_html__( 'Last scan %1$s, %2$s files checked.', 'chaos-shield' ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cshield_results['finished'] ) ),
							esc_html( number_format_i18n( $cshield_results['files_scanned'] ) )
						);
					} else {
						esc_html_e( 'No scan has run yet. The first one takes a minute or two on most sites.', 'chaos-shield' );
					}
					?>
				</p>
			</div>
			<button type="button" class="cshield-btn cshield-scan-start" <?php disabled( $cshield_running ); ?>><?php esc_html_e( 'Scan now', 'chaos-shield' ); ?></button>
		</div>
		<div class="cshield-progress" <?php echo $cshield_running ? '' : 'hidden'; ?>>
			<div class="cshield-progress__bar"><span style="width: <?php echo esc_attr( $cshield_progress['percent'] ); ?>%"></span></div>
			<p class="cshield-progress__text" aria-live="polite"></p>
		</div>
		<p class="cshield-small">
			<?php esc_html_e( 'Compares WordPress core and every plugin and theme from WordPress.org with the official release, flags PHP files that do not belong, searches everything for malware and backdoor patterns, finds backups and logs that anyone could download, and reports files that changed since the last scan without an update.', 'chaos-shield' ); ?>
		</p>
		<?php if ( $cshield_results && ! empty( $cshield_results['org_checked'] ) ) : ?>
			<p class="cshield-small">
				<?php
				/* translators: %d: number of plugins and themes. */
				echo esc_html( sprintf( _n( '%d plugin or theme was compared with its official release.', '%d plugins and themes were compared with their official release.', (int) $cshield_results['org_checked'], 'chaos-shield' ), (int) $cshield_results['org_checked'] ) );
				?>
			</p>
		<?php endif; ?>
		<?php if ( $cshield_results && ! $cshield_results['core_checked'] ) : ?>
			<p class="cshield-hint"><?php esc_html_e( 'WordPress.org could not be reached for core checksums, so core files were only searched for malware patterns this time.', 'chaos-shield' ); ?></p>
		<?php endif; ?>
	</section>

	<?php if ( $cshield_results ) : ?>
		<section class="cshield-card cshield-card--full">
			<div class="cshield-card__head">
				<h2>
					<?php
					/* translators: %d: number of findings. */
					echo esc_html( sprintf( _n( '%d finding', '%d findings', count( $cshield_open ), 'chaos-shield' ), count( $cshield_open ) ) );
					?>
				</h2>
				<?php if ( $cshield_reviewed ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
						<input type="hidden" name="action" value="cshield_ignore">
						<input type="hidden" name="finding" value="all">
						<?php wp_nonce_field( 'cshield_ignore' ); ?>
						<button type="submit" class="cshield-link">
							<?php
							/* translators: %d: number of reviewed findings. */
							echo esc_html( sprintf( __( 'Show %d reviewed', 'chaos-shield' ), $cshield_reviewed ) );
							?>
						</button>
					</form>
				<?php endif; ?>
			</div>
			<?php if ( ! $cshield_open ) : ?>
				<p class="cshield-empty"><?php esc_html_e( 'Nothing suspicious found. Official files match WordPress.org.', 'chaos-shield' ); ?></p>
			<?php else : ?>
				<ul class="cshield-checks cshield-findings">
					<?php foreach ( $cshield_open as $cshield_f ) : ?>
						<li class="cshield-check cshield-check--<?php echo 'high' === $cshield_f['severity'] ? 'fail' : 'warn'; ?>">
							<span class="cshield-badge"><?php echo esc_html( $cshield_sev[ $cshield_f['severity'] ] ); ?></span>
							<div class="cshield-finding">
								<strong><?php echo esc_html( $cshield_f['label'] ); ?></strong>
								<p><code><?php echo esc_html( $cshield_f['file'] . ( $cshield_f['line'] ? ':' . $cshield_f['line'] : '' ) ); ?></code></p>
								<?php if ( $cshield_f['snippet'] ) : ?>
									<pre class="cshield-snippet"><?php echo esc_html( $cshield_f['snippet'] ); ?></pre>
								<?php endif; ?>
							</div>
							<div class="cshield-finding__action">
								<?php if ( in_array( $cshield_f['rule'], Cleanup::REPAIRABLE, true ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
									<input type="hidden" name="action" value="cshield_cleanup">
									<input type="hidden" name="op" value="repair">
									<input type="hidden" name="finding" value="<?php echo esc_attr( $cshield_f['id'] ); ?>">
									<?php wp_nonce_field( 'cshield_cleanup' ); ?>
									<button type="submit" class="cshield-link"><?php esc_html_e( 'Repair from WordPress.org', 'chaos-shield' ); ?></button>
								</form>
								<?php else : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
									<input type="hidden" name="action" value="cshield_cleanup">
									<input type="hidden" name="op" value="quarantine">
									<input type="hidden" name="finding" value="<?php echo esc_attr( $cshield_f['id'] ); ?>">
									<?php wp_nonce_field( 'cshield_cleanup' ); ?>
									<button type="submit" class="cshield-link cshield-link--danger"><?php esc_html_e( 'Quarantine', 'chaos-shield' ); ?></button>
								</form>
								<?php endif; ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
								<input type="hidden" name="action" value="cshield_ignore">
								<input type="hidden" name="finding" value="<?php echo esc_attr( $cshield_f['id'] ); ?>">
								<?php wp_nonce_field( 'cshield_ignore' ); ?>
								<button type="submit" class="cshield-link"><?php esc_html_e( 'Mark reviewed', 'chaos-shield' ); ?></button>
							</form>
							</div>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="cshield-small"><?php esc_html_e( 'A finding is not proof of a hack: some premium plugins hide their code on purpose. Compare the file with a fresh download of the plugin or theme. Repair puts back the official copy of a modified core, plugin or theme file. Quarantine moves any other file to a locked folder where it cannot run.', 'chaos-shield' ); ?></p>
			<?php endif; ?>
		</section>
	<?php endif; ?>

	<?php $cshield_q = Cleanup::quarantined(); ?>
	<?php if ( $cshield_q ) : ?>
		<section class="cshield-card cshield-card--full">
			<h2><?php esc_html_e( 'Quarantine', 'chaos-shield' ); ?></h2>
			<p class="cshield-small"><?php esc_html_e( 'Quarantined files are moved to a locked folder where they cannot run. Restore one if a plugin breaks, or delete it for good.', 'chaos-shield' ); ?></p>
			<table class="cshield-table">
				<thead><tr><th><?php esc_html_e( 'File', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Why', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Quarantined', 'chaos-shield' ); ?></th><th></th></tr></thead>
				<tbody>
				<?php foreach ( $cshield_q as $cshield_qid => $cshield_item ) : ?>
					<tr>
						<td><code><?php echo esc_html( $cshield_item['file'] ); ?></code></td>
						<td><?php echo esc_html( $cshield_item['label'] ); ?></td>
						<td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cshield_item['time'] ) ); ?></td>
						<td class="cshield-right">
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
									<input type="hidden" name="action" value="cshield_cleanup">
									<input type="hidden" name="op" value="restore">
									<input type="hidden" name="qid" value="<?php echo esc_attr( $cshield_qid ); ?>">
									<?php wp_nonce_field( 'cshield_cleanup' ); ?>
									<button type="submit" class="cshield-link"><?php esc_html_e( 'Restore', 'chaos-shield' ); ?></button>
								</form>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
									<input type="hidden" name="action" value="cshield_cleanup">
									<input type="hidden" name="op" value="delete">
									<input type="hidden" name="qid" value="<?php echo esc_attr( $cshield_qid ); ?>">
									<?php wp_nonce_field( 'cshield_cleanup' ); ?>
									<button type="submit" class="cshield-link cshield-link--danger"><?php esc_html_e( 'Delete for good', 'chaos-shield' ); ?></button>
								</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</section>
	<?php endif; ?>

	<?php $cshield_db = Cleanup::db_results(); ?>
	<section class="cshield-card cshield-card--full">
		<div class="cshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Database scan', 'chaos-shield' ); ?></h2>
				<p>
					<?php
					if ( $cshield_db ) {
						printf(
							/* translators: %s: date. */
							esc_html__( 'Last checked %s.', 'chaos-shield' ),
							esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cshield_db['checked'] ) )
						);
					} else {
						esc_html_e( 'Looks for scripts from other sites, obfuscated code and hidden iframes injected into posts, pages and settings.', 'chaos-shield' );
					}
					?>
				</p>
			</div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
									<input type="hidden" name="action" value="cshield_cleanup">
									<input type="hidden" name="op" value="dbscan">
									<input type="hidden" name="scope" value="<?php echo esc_attr( 'all' ); ?>">
									<?php wp_nonce_field( 'cshield_cleanup' ); ?>
									<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Scan database', 'chaos-shield' ); ?></button>
								</form>
		</div>
		<?php if ( $cshield_db ) : ?>
			<?php if ( ! $cshield_db['findings'] ) : ?>
				<p class="cshield-empty"><?php esc_html_e( 'No injected code found in posts, pages or settings.', 'chaos-shield' ); ?></p>
			<?php else : ?>
				<ul class="cshield-checks cshield-findings">
					<?php foreach ( $cshield_db['findings'] as $cshield_d ) : ?>
						<li class="cshield-check cshield-check--warn">
							<span class="cshield-badge"><?php esc_html_e( 'Review', 'chaos-shield' ); ?></span>
							<div class="cshield-finding">
								<strong><?php echo esc_html( $cshield_d['label'] ); ?></strong>
								<p><?php echo esc_html( $cshield_d['title'] ); ?></p>
								<pre class="cshield-snippet"><?php echo esc_html( $cshield_d['snippet'] ); ?></pre>
							</div>
							<?php if ( $cshield_d['edit'] ) : ?>
								<a class="cshield-link cshield-finding__action" href="<?php echo esc_url( $cshield_d['edit'] ); ?>"><?php esc_html_e( 'Edit', 'chaos-shield' ); ?></a>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="cshield-small"><?php esc_html_e( 'Analytics, chat and ad scripts you added yourself can show up here. Remove anything you do not recognise, then change all passwords.', 'chaos-shield' ); ?></p>
			<?php endif; ?>
		<?php endif; ?>
	</section>
</div>
