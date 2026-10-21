<?php
/**
 * Critical file fingerprints card, on the Scan tab.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_int     = Integrity::state();
$cshield_files   = Integrity::files();
$cshield_changed = Integrity::changed();
$cshield_groups  = Integrity::groups();
$cshield_when    = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$cshield_iform   = static function ( $op, $label, $css, $file = '', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form"<?php echo $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : ''; ?>>
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
$cshield_short   = static function ( $rec ) {
	return empty( $rec['exists'] ) ? '' : substr( $rec['sha256'], 0, 16 );
};
?>
<section class="cshield-card cshield-card--full" id="cshield-integrity">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Critical file fingerprints', 'chaos-shield' ); ?></h2>
			<p>
				<?php
				if ( ! Integrity::enabled() ) {
					esc_html_e( 'Critical file watch is off. Switch it on under Hardening to fingerprint these files every hour.', 'chaos-shield' );
				} elseif ( ! $cshield_int['checked'] ) {
					esc_html_e( 'No fingerprints yet. They are taken within a few minutes, or choose Check now.', 'chaos-shield' );
				} else {
					printf(
						/* translators: 1: number of files, 2: date and time. */
						esc_html__( '%1$s files fingerprinted with SHA-256, last checked %2$s. Checked every hour; a change alerts you and stays listed until you accept it or put it back.', 'chaos-shield' ),
						esc_html( number_format_i18n( count( array_filter( wp_list_pluck( wp_list_pluck( $cshield_int['files'], 'base' ), 'exists' ) ) ) ) ),
						esc_html( wp_date( $cshield_when, (int) $cshield_int['checked'] ) )
					);
				}
				?>
			</p>
		</div>
		<div class="cshield-inline-actions">
			<?php
			if ( Integrity::enabled() ) {
				$cshield_iform( 'check', __( 'Check now', 'chaos-shield' ), 'cshield-btn' );
			}
			if ( $cshield_int['checked'] ) {
				$cshield_iform( 'export', __( 'Download fingerprints', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' );
			}
			?>
		</div>
	</div>

	<?php if ( $cshield_changed ) : ?>
		<div class="cshield-notice cshield-notice--warn cshield-notice--incidents" role="alert">
			<span>
				<?php
				/* translators: %d: number of files. */
				echo esc_html( sprintf( _n( '%d critical file no longer matches its fingerprint. If you did not change it, treat it as a break-in.', '%d critical files no longer match their fingerprints. If you did not change them, treat it as a break-in.', count( $cshield_changed ), 'chaos-shield' ), count( $cshield_changed ) ) );
				?>
			</span>
			<?php
			if ( count( $cshield_changed ) > 1 ) {
				$cshield_iform( 'accept_all', __( 'Accept all', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', '', __( 'Accept every change as the new fingerprint? Only do this if you made the changes.', 'chaos-shield' ) );
			}
			?>
		</div>
		<ul class="cshield-checks cshield-findings">
			<?php foreach ( $cshield_changed as $cshield_name => $cshield_e ) : ?>
				<?php
				$cshield_text  = isset( $cshield_e['base']['text'] ) || empty( $cshield_e['base']['exists'] );
				$cshield_isnew = empty( $cshield_e['base']['exists'] );
				$cshield_gone  = empty( $cshield_e['now']['exists'] );
				$cshield_group = isset( $cshield_files[ $cshield_name ] ) ? $cshield_files[ $cshield_name ]['group'] : '';
				?>
				<li class="cshield-check cshield-check--fail">
					<span class="cshield-badge"><?php echo esc_html( $cshield_isnew ? __( 'New', 'chaos-shield' ) : ( $cshield_gone ? __( 'Deleted', 'chaos-shield' ) : __( 'Changed', 'chaos-shield' ) ) ); ?></span>
					<div class="cshield-finding">
						<strong><code><?php echo esc_html( $cshield_name ); ?></code></strong>
						<p>
							<?php
							echo esc_html( isset( $cshield_groups[ $cshield_group ] ) ? $cshield_groups[ $cshield_group ] . '. ' : '' );
							echo esc_html( ucfirst( Integrity::describe( $cshield_e ) ) );
							if ( ! empty( $cshield_e['seen'] ) ) {
								/* translators: %s: date and time. */
								echo esc_html( ' ' . sprintf( __( 'Noticed %s.', 'chaos-shield' ), wp_date( $cshield_when, (int) $cshield_e['seen'] ) ) );
							}
							?>
						</p>
						<?php if ( ! $cshield_gone && ! $cshield_isnew ) : ?>
							<p class="cshield-small">
								<?php
								printf(
									/* translators: 1: old fingerprint, 2: new fingerprint. */
									esc_html__( 'SHA-256 was %1$s…, now %2$s…', 'chaos-shield' ),
									'<code>' . esc_html( $cshield_short( $cshield_e['base'] ) ) . '</code>',
									'<code>' . esc_html( $cshield_short( $cshield_e['now'] ) ) . '</code>'
								);
								?>
							</p>
						<?php endif; ?>
						<?php if ( ! $cshield_gone ) : ?>
							<details class="cshield-diff">
								<summary><?php esc_html_e( 'Show what changed', 'chaos-shield' ); ?></summary>
								<?php
								if ( 'wp-config.php' === $cshield_name ) {
									$cshield_lines      = Integrity::config_changes( $cshield_e );
									$cshield_gone_lines = Integrity::config_removed( $cshield_e );
									if ( null === $cshield_lines ) {
										echo '<p class="cshield-small">' . esc_html__( 'The line-by-line record is not available for this version.', 'chaos-shield' ) . '</p>';
									} else {
										if ( $cshield_lines ) {
											echo '<p class="cshield-small">' . esc_html__( 'New or changed lines (passwords, keys and salts are hidden):', 'chaos-shield' ) . '</p><pre class="cshield-snippet">';
											foreach ( $cshield_lines as $cshield_no => $cshield_line ) {
												echo esc_html( str_pad( (string) $cshield_no, 5, ' ', STR_PAD_LEFT ) . '  ' . $cshield_line ) . "\n";
											}
											echo '</pre>';
										}
										if ( $cshield_gone_lines ) {
											/* translators: %d: number of lines. */
											echo '<p class="cshield-small">' . esc_html( sprintf( _n( '%d line of the accepted version was removed.', '%d lines of the accepted version were removed.', $cshield_gone_lines, 'chaos-shield' ), $cshield_gone_lines ) ) . '</p>';
										}
									}
								} elseif ( isset( $cshield_e['now']['text'] ) && ( isset( $cshield_e['base']['text'] ) || $cshield_isnew ) ) {
									$cshield_diff = wp_text_diff(
										$cshield_isnew ? '' : $cshield_e['base']['text'],
										$cshield_e['now']['text'],
										array(
											'title_left'  => __( 'Accepted', 'chaos-shield' ),
											'title_right' => __( 'Now', 'chaos-shield' ),
										)
									);
									echo $cshield_diff ? '<div class="cshield-difftable">' . wp_kses_post( $cshield_diff ) . '</div>' : '<p class="cshield-small">' . esc_html__( 'Only spaces or line endings changed.', 'chaos-shield' ) . '</p>';
								} else {
									echo '<p class="cshield-small">' . esc_html__( 'This file is code, so only its fingerprint is kept. Compare it with a restore point or a fresh copy, or run the file scan for known malware.', 'chaos-shield' ) . '</p>';
								}
								?>
							</details>
						<?php endif; ?>
					</div>
					<div class="cshield-finding__action cshield-inline-actions">
						<?php
						if ( $cshield_text ) {
							$cshield_iform(
								'restore',
								$cshield_isnew ? __( 'Delete it', 'chaos-shield' ) : __( 'Put back', 'chaos-shield' ),
								'cshield-link cshield-link--danger',
								$cshield_name,
								$cshield_isnew ? __( 'Delete this file? A copy is saved as a restore point first.', 'chaos-shield' ) : __( 'Put the accepted version back? The current one is saved as a restore point first.', 'chaos-shield' )
							);
						}
						$cshield_iform( 'accept', __( 'Accept', 'chaos-shield' ), 'cshield-link', $cshield_name, __( 'Accept this version as the new fingerprint? Only do this if you made the change.', 'chaos-shield' ) );
						?>
					</div>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php endif; ?>

	<?php if ( $cshield_int['files'] ) : ?>
		<details class="cshield-diff cshield-int-list">
			<summary><?php esc_html_e( 'All fingerprints', 'chaos-shield' ); ?></summary>
			<div class="cshield-table-wrap">
				<table class="cshield-table cshield-table--int">
					<thead><tr><th><?php esc_html_e( 'File', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'SHA-256', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'MD5', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Modified', 'chaos-shield' ); ?></th></tr></thead>
					<tbody>
						<?php foreach ( $cshield_int['files'] as $cshield_name => $cshield_e ) : ?>
							<?php
							$cshield_rec = empty( $cshield_e['now'] ) ? $cshield_e['base'] : $cshield_e['now'];
							if ( empty( $cshield_rec['exists'] ) ) {
								continue;
							}
							?>
							<tr<?php echo empty( $cshield_e['now'] ) ? '' : ' class="is-changed"'; ?>>
								<td><code><?php echo esc_html( $cshield_name ); ?></code></td>
								<td><code title="<?php echo esc_attr( $cshield_rec['sha256'] ); ?>"><?php echo esc_html( substr( $cshield_rec['sha256'], 0, 16 ) ); ?>…</code></td>
								<td><code title="<?php echo esc_attr( $cshield_rec['md5'] ); ?>"><?php echo esc_html( substr( $cshield_rec['md5'], 0, 12 ) ); ?>…</code></td>
								<td><?php echo esc_html( wp_date( $cshield_when, (int) $cshield_rec['mtime'] ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="cshield-small"><?php esc_html_e( 'Also watched while missing, so they are reported if they appear: other drop-ins, .user.ini, php.ini and the .htaccess files. Keep the downloaded fingerprints somewhere off the site to compare against later.', 'chaos-shield' ); ?></p>
		</details>
	<?php endif; ?>
</section>
