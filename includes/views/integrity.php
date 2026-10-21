<?php
/**
 * Critical file fingerprints card, on the Scan tab.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_int     = Integrity::state();
$sshield_files   = Integrity::files();
$sshield_changed = Integrity::changed();
$sshield_groups  = Integrity::groups();
$sshield_when    = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$sshield_iform   = static function ( $op, $label, $css, $file = '', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form"<?php echo $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : ''; ?>>
		<input type="hidden" name="action" value="<?php echo esc_attr( Integrity::ACTION ); ?>">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php if ( $file ) : ?>
			<input type="hidden" name="file" value="<?php echo esc_attr( $file ); ?>">
		<?php endif; ?>
		<?php wp_nonce_field( Integrity::ACTION ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
$sshield_short   = static function ( $rec ) {
	return empty( $rec['exists'] ) ? '' : substr( $rec['sha256'], 0, 16 );
};
?>
<section class="sshield-card sshield-card--full" id="sshield-integrity">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Critical file fingerprints', 'sentinel-shield' ); ?></h2>
			<p>
				<?php
				if ( ! Integrity::enabled() ) {
					esc_html_e( 'Critical file watch is off. Switch it on under Hardening to fingerprint these files every hour.', 'sentinel-shield' );
				} elseif ( ! $sshield_int['checked'] ) {
					esc_html_e( 'No fingerprints yet. They are taken within a few minutes, or choose Check now.', 'sentinel-shield' );
				} else {
					printf(
						/* translators: 1: number of files, 2: date and time. */
						esc_html__( '%1$s files fingerprinted with SHA-256, last checked %2$s. Checked every hour; a change alerts you and stays listed until you accept it or put it back.', 'sentinel-shield' ),
						esc_html( number_format_i18n( count( array_filter( wp_list_pluck( wp_list_pluck( $sshield_int['files'], 'base' ), 'exists' ) ) ) ) ),
						esc_html( wp_date( $sshield_when, (int) $sshield_int['checked'] ) )
					);
				}
				?>
			</p>
		</div>
		<div class="sshield-inline-actions">
			<?php
			if ( Integrity::enabled() ) {
				$sshield_iform( 'check', __( 'Check now', 'sentinel-shield' ), 'sshield-btn' );
			}
			if ( $sshield_int['checked'] ) {
				$sshield_iform( 'export', __( 'Download fingerprints', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' );
			}
			?>
		</div>
	</div>

	<?php if ( $sshield_changed ) : ?>
		<div class="sshield-notice sshield-notice--warn sshield-notice--incidents" role="alert">
			<span>
				<?php
				/* translators: %d: number of files. */
				echo esc_html( sprintf( _n( '%d critical file no longer matches its fingerprint. If you did not change it, treat it as a break-in.', '%d critical files no longer match their fingerprints. If you did not change them, treat it as a break-in.', count( $sshield_changed ), 'sentinel-shield' ), count( $sshield_changed ) ) );
				?>
			</span>
			<?php
			if ( count( $sshield_changed ) > 1 ) {
				$sshield_iform( 'accept_all', __( 'Accept all', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', '', __( 'Accept every change as the new fingerprint? Only do this if you made the changes.', 'sentinel-shield' ) );
			}
			?>
		</div>
		<ul class="sshield-checks sshield-findings">
			<?php foreach ( $sshield_changed as $sshield_name => $sshield_e ) : ?>
				<?php
				$sshield_text  = isset( $sshield_e['base']['text'] ) || empty( $sshield_e['base']['exists'] );
				$sshield_isnew = empty( $sshield_e['base']['exists'] );
				$sshield_gone  = empty( $sshield_e['now']['exists'] );
				$sshield_group = isset( $sshield_files[ $sshield_name ] ) ? $sshield_files[ $sshield_name ]['group'] : '';
				?>
				<li class="sshield-check sshield-check--fail">
					<span class="sshield-badge"><?php echo esc_html( $sshield_isnew ? __( 'New', 'sentinel-shield' ) : ( $sshield_gone ? __( 'Deleted', 'sentinel-shield' ) : __( 'Changed', 'sentinel-shield' ) ) ); ?></span>
					<div class="sshield-finding">
						<strong><code><?php echo esc_html( $sshield_name ); ?></code></strong>
						<p>
							<?php
							echo esc_html( isset( $sshield_groups[ $sshield_group ] ) ? $sshield_groups[ $sshield_group ] . '. ' : '' );
							echo esc_html( ucfirst( Integrity::describe( $sshield_e ) ) );
							if ( ! empty( $sshield_e['seen'] ) ) {
								/* translators: %s: date and time. */
								echo esc_html( ' ' . sprintf( __( 'Noticed %s.', 'sentinel-shield' ), wp_date( $sshield_when, (int) $sshield_e['seen'] ) ) );
							}
							?>
						</p>
						<?php if ( ! $sshield_gone && ! $sshield_isnew ) : ?>
							<p class="sshield-small">
								<?php
								printf(
									/* translators: 1: old fingerprint, 2: new fingerprint. */
									esc_html__( 'SHA-256 was %1$s…, now %2$s…', 'sentinel-shield' ),
									'<code>' . esc_html( $sshield_short( $sshield_e['base'] ) ) . '</code>',
									'<code>' . esc_html( $sshield_short( $sshield_e['now'] ) ) . '</code>'
								);
								?>
							</p>
						<?php endif; ?>
						<?php if ( ! $sshield_gone ) : ?>
							<details class="sshield-diff">
								<summary><?php esc_html_e( 'Show what changed', 'sentinel-shield' ); ?></summary>
								<?php
								if ( 'wp-config.php' === $sshield_name ) {
									$sshield_lines      = Integrity::config_changes( $sshield_e );
									$sshield_gone_lines = Integrity::config_removed( $sshield_e );
									if ( null === $sshield_lines ) {
										echo '<p class="sshield-small">' . esc_html__( 'The line-by-line record is not available for this version.', 'sentinel-shield' ) . '</p>';
									} else {
										if ( $sshield_lines ) {
											echo '<p class="sshield-small">' . esc_html__( 'New or changed lines (passwords, keys and salts are hidden):', 'sentinel-shield' ) . '</p><pre class="sshield-snippet">';
											foreach ( $sshield_lines as $sshield_no => $sshield_line ) {
												echo esc_html( str_pad( (string) $sshield_no, 5, ' ', STR_PAD_LEFT ) . '  ' . $sshield_line ) . "\n";
											}
											echo '</pre>';
										}
										if ( $sshield_gone_lines ) {
											/* translators: %d: number of lines. */
											echo '<p class="sshield-small">' . esc_html( sprintf( _n( '%d line of the accepted version was removed.', '%d lines of the accepted version were removed.', $sshield_gone_lines, 'sentinel-shield' ), $sshield_gone_lines ) ) . '</p>';
										}
									}
								} elseif ( isset( $sshield_e['now']['text'] ) && ( isset( $sshield_e['base']['text'] ) || $sshield_isnew ) ) {
									$sshield_diff = wp_text_diff(
										$sshield_isnew ? '' : $sshield_e['base']['text'],
										$sshield_e['now']['text'],
										array(
											'title_left'  => __( 'Accepted', 'sentinel-shield' ),
											'title_right' => __( 'Now', 'sentinel-shield' ),
										)
									);
									echo $sshield_diff ? '<div class="sshield-difftable">' . wp_kses_post( $sshield_diff ) . '</div>' : '<p class="sshield-small">' . esc_html__( 'Only spaces or line endings changed.', 'sentinel-shield' ) . '</p>';
								} else {
									echo '<p class="sshield-small">' . esc_html__( 'This file is code, so only its fingerprint is kept. Compare it with a restore point or a fresh copy, or run the file scan for known malware.', 'sentinel-shield' ) . '</p>';
								}
								?>
							</details>
						<?php endif; ?>
					</div>
					<div class="sshield-finding__action sshield-inline-actions">
						<?php
						if ( $sshield_text ) {
							$sshield_iform(
								'restore',
								$sshield_isnew ? __( 'Delete it', 'sentinel-shield' ) : __( 'Put back', 'sentinel-shield' ),
								'sshield-link sshield-link--danger',
								$sshield_name,
								$sshield_isnew ? __( 'Delete this file? A copy is saved as a restore point first.', 'sentinel-shield' ) : __( 'Put the accepted version back? The current one is saved as a restore point first.', 'sentinel-shield' )
							);
						}
						$sshield_iform( 'accept', __( 'Accept', 'sentinel-shield' ), 'sshield-link', $sshield_name, __( 'Accept this version as the new fingerprint? Only do this if you made the change.', 'sentinel-shield' ) );
						?>
					</div>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php endif; ?>

	<?php if ( $sshield_int['files'] ) : ?>
		<details class="sshield-diff sshield-int-list">
			<summary><?php esc_html_e( 'All fingerprints', 'sentinel-shield' ); ?></summary>
			<div class="sshield-table-wrap">
				<table class="sshield-table sshield-table--int">
					<thead><tr><th><?php esc_html_e( 'File', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'SHA-256', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'MD5', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Modified', 'sentinel-shield' ); ?></th></tr></thead>
					<tbody>
						<?php foreach ( $sshield_int['files'] as $sshield_name => $sshield_e ) : ?>
							<?php
							$sshield_rec = empty( $sshield_e['now'] ) ? $sshield_e['base'] : $sshield_e['now'];
							if ( empty( $sshield_rec['exists'] ) ) {
								continue;
							}
							?>
							<tr<?php echo empty( $sshield_e['now'] ) ? '' : ' class="is-changed"'; ?>>
								<td><code><?php echo esc_html( $sshield_name ); ?></code></td>
								<td><code title="<?php echo esc_attr( $sshield_rec['sha256'] ); ?>"><?php echo esc_html( substr( $sshield_rec['sha256'], 0, 16 ) ); ?>…</code></td>
								<td><code title="<?php echo esc_attr( $sshield_rec['md5'] ); ?>"><?php echo esc_html( substr( $sshield_rec['md5'], 0, 12 ) ); ?>…</code></td>
								<td><?php echo esc_html( wp_date( $sshield_when, (int) $sshield_rec['mtime'] ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="sshield-small"><?php esc_html_e( 'Also watched while missing, so they are reported if they appear: other drop-ins, .user.ini, php.ini and the .htaccess files. Keep the downloaded fingerprints somewhere off the site to compare against later.', 'sentinel-shield' ); ?></p>
		</details>
	<?php endif; ?>
</section>
