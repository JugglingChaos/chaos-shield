<?php
/**
 * Backups tab: restore points, database backup and settings export.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_points  = Restore_Points::all();
$cshield_reasons = Restore_Points::reasons();
$cshield_when    = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$cshield_form    = static function ( $op, $label, $css = 'cshield-btn', $point = '', $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form"<?php echo $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : ''; ?>>
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
<div class="cshield-grid">
	<section class="cshield-card cshield-card--full">
		<div class="cshield-card__head">
			<div>
				<h2><?php esc_html_e( 'Restore points', 'chaos-shield' ); ?></h2>
				<p>
					<?php
					if ( Restore_Points::enabled() ) {
						esc_html_e( 'Taken on their own before a plugin or theme updates, before a file is repaired and before these settings change. Restoring one saves the current state first, so you can always go back.', 'chaos-shield' );
					} else {
						esc_html_e( 'Automatic restore points are off. Switch on Restore points under Hardening to take them before updates, repairs and settings changes.', 'chaos-shield' );
					}
					?>
				</p>
			</div>
			<?php $cshield_form( 'create', __( 'Create a restore point', 'chaos-shield' ) ); ?>
		</div>
		<?php if ( ! $cshield_points ) : ?>
			<p class="cshield-empty"><?php esc_html_e( 'No restore points yet. The first one appears before the next update or settings change.', 'chaos-shield' ); ?></p>
		<?php else : ?>
			<div class="cshield-table-wrap">
				<table class="cshield-table cshield-table--points">
					<thead><tr><th><?php esc_html_e( 'When', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Why', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'What it holds', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Size', 'chaos-shield' ); ?></th><th></th></tr></thead>
					<tbody>
						<?php foreach ( $cshield_points as $cshield_id => $cshield_p ) : ?>
							<?php
							$cshield_holds = array();
							if ( $cshield_p['files'] ) {
								/* translators: %s: number of files. */
								$cshield_holds[] = sprintf( _n( '%s file', '%s files', $cshield_p['files'], 'chaos-shield' ), number_format_i18n( $cshield_p['files'] ) );
							}
							if ( $cshield_p['settings'] ) {
								$cshield_holds[] = __( 'settings', 'chaos-shield' );
							}
							$cshield_user = $cshield_p['user'] ? get_userdata( $cshield_p['user'] ) : null;
							?>
							<tr>
								<td>
									<?php echo esc_html( wp_date( $cshield_when, $cshield_p['time'] ) ); ?>
									<?php if ( $cshield_user ) : ?>
										<span class="cshield-small"><?php echo esc_html( $cshield_user->user_login ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( isset( $cshield_reasons[ $cshield_p['reason'] ] ) ? $cshield_reasons[ $cshield_p['reason'] ] : $cshield_p['reason'] ); ?></td>
								<td><?php echo esc_html( $cshield_p['label'] ); ?> <span class="cshield-small"><?php echo esc_html( implode( ', ', $cshield_holds ) ); ?></span></td>
								<td><?php echo esc_html( size_format( max( 1, (int) $cshield_p['bytes'] ), 1 ) ); ?></td>
								<td class="cshield-right">
									<?php
									$cshield_form( 'restore', __( 'Restore', 'chaos-shield' ), 'cshield-link', $cshield_id, __( 'Put this restore point back? The current state is saved first, so you can undo it.', 'chaos-shield' ) );
									$cshield_form( 'delete', __( 'Delete', 'chaos-shield' ), 'cshield-link cshield-link--danger', $cshield_id, __( 'Delete this restore point for good?', 'chaos-shield' ) );
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="cshield-small">
				<?php
				printf(
					/* translators: 1: total size, 2: number of days, 3: number of points. */
					esc_html__( 'Using %1$s. Points are kept for %2$s days, up to %3$s of them, oldest removed first. Rolling a plugin back does not undo changes its update made to the database.', 'chaos-shield' ),
					esc_html( size_format( max( 1, Restore_Points::size() ), 1 ) ),
					esc_html( number_format_i18n( Restore_Points::MAX_AGE / DAY_IN_SECONDS ) ),
					esc_html( number_format_i18n( Restore_Points::MAX_POINTS ) )
				);
				?>
			</p>
		<?php endif; ?>
	</section>

	<section class="cshield-card">
		<h2><?php esc_html_e( 'Database backup', 'chaos-shield' ); ?></h2>
		<p class="cshield-small">
			<?php
			echo esc_html(
				Network::active()
					? __( 'Downloads every table of the network as one compressed SQL file. It holds password hashes and private content, so keep it somewhere safe.', 'chaos-shield' )
					: __( 'Downloads every table of this site as one compressed SQL file. It holds password hashes and private content, so keep it somewhere safe.', 'chaos-shield' )
			);
			?>
		</p>
		<?php $cshield_form( 'database', __( 'Download database backup', 'chaos-shield' ) ); ?>
		<p class="cshield-small"><?php esc_html_e( 'To restore it, import the file with phpMyAdmin, Adminer or wp db import. This is a copy of the database only; your host\'s full backups also cover uploads and code.', 'chaos-shield' ); ?></p>
	</section>

	<section class="cshield-card">
		<h2><?php esc_html_e( 'Move settings between sites', 'chaos-shield' ); ?></h2>
		<p class="cshield-small"><?php esc_html_e( 'Export these settings and import them on another site running Chaos Shield. The login address and your own IP stay as they are on the receiving site, and its previous settings are saved as a restore point.', 'chaos-shield' ); ?></p>
		<?php $cshield_form( 'export', __( 'Export settings', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' ); ?>
		<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-import">
			<input type="hidden" name="action" value="<?php echo esc_attr( Restore_Points::ACTION ); ?>">
			<input type="hidden" name="op" value="import">
			<?php wp_nonce_field( Restore_Points::ACTION ); ?>
			<label><span><?php esc_html_e( 'Settings file (.json)', 'chaos-shield' ); ?></span>
				<input type="file" name="settings" accept=".json,application/json" required></label>
			<button type="submit" class="cshield-btn"><?php esc_html_e( 'Import settings', 'chaos-shield' ); ?></button>
		</form>
	</section>
</div>
