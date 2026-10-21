<?php
/**
 * Backups tab: restore points, database backup and settings export.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_points  = Restore_Points::all();
$sshield_reasons = Restore_Points::reasons();
$sshield_when    = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$sshield_form    = static function ( $op, $label, $css = 'sshield-btn', $point = '', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form"<?php echo $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : ''; ?>>
		<input type="hidden" name="action" value="<?php echo esc_attr( Restore_Points::ACTION ); ?>">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php if ( $point ) : ?>
			<input type="hidden" name="point" value="<?php echo esc_attr( $point ); ?>">
		<?php endif; ?>
		<?php wp_nonce_field( Restore_Points::ACTION ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<div class="sshield-grid">
	<section class="sshield-card sshield-card--full">
		<div class="sshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Restore points', 'sentinel-shield' ); ?></h2>
				<p>
					<?php
					if ( Restore_Points::enabled() ) {
						esc_html_e( 'Taken on their own before a plugin or theme updates, before a file is repaired and before these settings change. Restoring one saves the current state first, so you can always go back.', 'sentinel-shield' );
					} else {
						esc_html_e( 'Automatic restore points are off. Switch on Restore points under Hardening to take them before updates, repairs and settings changes.', 'sentinel-shield' );
					}
					?>
				</p>
			</div>
			<?php $sshield_form( 'create', __( 'Create a restore point', 'sentinel-shield' ) ); ?>
		</div>
		<?php if ( ! $sshield_points ) : ?>
			<p class="sshield-empty"><?php esc_html_e( 'No restore points yet. The first one appears before the next update or settings change.', 'sentinel-shield' ); ?></p>
		<?php else : ?>
			<div class="sshield-table-wrap">
				<table class="sshield-table sshield-table--points">
					<thead><tr><th><?php esc_html_e( 'When', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Why', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'What it holds', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Size', 'sentinel-shield' ); ?></th><th></th></tr></thead>
					<tbody>
						<?php foreach ( $sshield_points as $sshield_id => $sshield_p ) : ?>
							<?php
							$sshield_holds = array();
							if ( $sshield_p['files'] ) {
								/* translators: %s: number of files. */
								$sshield_holds[] = sprintf( _n( '%s file', '%s files', $sshield_p['files'], 'sentinel-shield' ), number_format_i18n( $sshield_p['files'] ) );
							}
							if ( $sshield_p['settings'] ) {
								$sshield_holds[] = __( 'settings', 'sentinel-shield' );
							}
							$sshield_user = $sshield_p['user'] ? get_userdata( $sshield_p['user'] ) : null;
							?>
							<tr>
								<td>
									<?php echo esc_html( wp_date( $sshield_when, $sshield_p['time'] ) ); ?>
									<?php if ( $sshield_user ) : ?>
										<span class="sshield-small"><?php echo esc_html( $sshield_user->user_login ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( isset( $sshield_reasons[ $sshield_p['reason'] ] ) ? $sshield_reasons[ $sshield_p['reason'] ] : $sshield_p['reason'] ); ?></td>
								<td><?php echo esc_html( $sshield_p['label'] ); ?> <span class="sshield-small"><?php echo esc_html( implode( ', ', $sshield_holds ) ); ?></span></td>
								<td><?php echo esc_html( size_format( max( 1, (int) $sshield_p['bytes'] ), 1 ) ); ?></td>
								<td class="sshield-right">
									<?php
									$sshield_form( 'restore', __( 'Restore', 'sentinel-shield' ), 'sshield-link', $sshield_id, __( 'Put this restore point back? The current state is saved first, so you can undo it.', 'sentinel-shield' ) );
									$sshield_form( 'delete', __( 'Delete', 'sentinel-shield' ), 'sshield-link sshield-link--danger', $sshield_id, __( 'Delete this restore point for good?', 'sentinel-shield' ) );
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="sshield-small">
				<?php
				printf(
					/* translators: 1: total size, 2: number of days, 3: number of points. */
					esc_html__( 'Using %1$s. Points are kept for %2$s days, up to %3$s of them, oldest removed first. Rolling a plugin back does not undo changes its update made to the database.', 'sentinel-shield' ),
					esc_html( size_format( max( 1, Restore_Points::size() ), 1 ) ),
					esc_html( number_format_i18n( Restore_Points::MAX_AGE / DAY_IN_SECONDS ) ),
					esc_html( number_format_i18n( Restore_Points::MAX_POINTS ) )
				);
				?>
			</p>
		<?php endif; ?>
	</section>

	<section class="sshield-card">
		<h2><?php esc_html_e( 'Database backup', 'sentinel-shield' ); ?></h2>
		<p class="sshield-small">
			<?php
			echo esc_html(
				Network::active()
					? __( 'Downloads every table of the network as one compressed SQL file. It holds password hashes and private content, so keep it somewhere safe.', 'sentinel-shield' )
					: __( 'Downloads every table of this site as one compressed SQL file. It holds password hashes and private content, so keep it somewhere safe.', 'sentinel-shield' )
			);
			?>
		</p>
		<?php $sshield_form( 'database', __( 'Download database backup', 'sentinel-shield' ) ); ?>
		<p class="sshield-small"><?php esc_html_e( 'To restore it, import the file with phpMyAdmin, Adminer or wp db import. This is a copy of the database only; your host\'s full backups also cover uploads and code.', 'sentinel-shield' ); ?></p>
	</section>

	<section class="sshield-card">
		<h2><?php esc_html_e( 'Move settings between sites', 'sentinel-shield' ); ?></h2>
		<p class="sshield-small"><?php esc_html_e( 'Export these settings and import them on another site running Sentinel Shield. The login address and your own IP stay as they are on the receiving site, and its previous settings are saved as a restore point.', 'sentinel-shield' ); ?></p>
		<?php $sshield_form( 'export', __( 'Export settings', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' ); ?>
		<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-import">
			<input type="hidden" name="action" value="<?php echo esc_attr( Restore_Points::ACTION ); ?>">
			<input type="hidden" name="op" value="import">
			<?php wp_nonce_field( Restore_Points::ACTION ); ?>
			<label><span><?php esc_html_e( 'Settings file (.json)', 'sentinel-shield' ); ?></span>
				<input type="file" name="settings" accept=".json,application/json" required></label>
			<button type="submit" class="sshield-btn"><?php esc_html_e( 'Import settings', 'sentinel-shield' ); ?></button>
		</form>
	</section>
</div>
