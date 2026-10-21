<?php
/**
 * Firewall tab: mode, sensitivity, rules, recent hits and exceptions.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_on       = Settings::enabled( 'firewall' );
$sshield_learning = Firewall::learning();
$sshield_rules    = Firewall::rules( true );
$sshield_off      = (array) Settings::get( 'fw_rules_off' );
$sshield_hits     = Firewall::hits();
$sshield_exc      = Firewall::exceptions();
$sshield_when     = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$sshield_levels   = array(
	'relaxed'  => __( 'Relaxed: block only when several attack signs add up', 'sentinel-shield' ),
	'balanced' => __( 'Balanced: block clear attacks (recommended)', 'sentinel-shield' ),
	'strict'   => __( 'Strict: also block suspicious requests', 'sentinel-shield' ),
);
$sshield_post     = static function ( $op, array $fields, $label, $css ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form">
		<input type="hidden" name="action" value="sshield_firewall">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php foreach ( $fields as $sshield_k => $sshield_v ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $sshield_k ); ?>" value="<?php echo esc_attr( $sshield_v ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( 'sshield_firewall' ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<?php if ( ! $sshield_on ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="status"><?php esc_html_e( 'The request firewall is switched off under Hardening, so nothing below is enforced.', 'sentinel-shield' ); ?></div>
<?php elseif ( $sshield_learning ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="status">
		<?php
		/* translators: %s: date. */
		echo esc_html( sprintf( __( 'Learning mode: requests that would be blocked are only recorded, until %s. Allow any that are yours, then blocking starts again on its own.', 'sentinel-shield' ), wp_date( $sshield_when, (int) Settings::get( 'fw_learn_until' ) ) ) );
		?>
	</div>
<?php endif; ?>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="sshield_firewall">
	<input type="hidden" name="op" value="settings">
	<?php wp_nonce_field( 'sshield_firewall' ); ?>
	<div class="sshield-grid">
		<section class="sshield-card">
			<h2><?php esc_html_e( 'How the firewall decides', 'sentinel-shield' ); ?></h2>
			<p class="sshield-small"><?php esc_html_e( 'Every part of a request is decoded and checked: the address, form and JSON fields, cookies, the referrer, the browser name and uploaded file names. Clear attack signs score 5 and suspicious ones 3. The request is blocked when the total reaches the level you pick.', 'sentinel-shield' ); ?></p>
			<div class="sshield-fields sshield-fields--one">
				<label><span><?php esc_html_e( 'Mode', 'sentinel-shield' ); ?></span>
					<select name="mode">
						<option value="block" <?php selected( ! $sshield_learning ); ?>><?php esc_html_e( 'Block attacks', 'sentinel-shield' ); ?></option>
						<option value="learn" <?php selected( $sshield_learning ); ?>><?php esc_html_e( 'Learning: only record for 7 days', 'sentinel-shield' ); ?></option>
					</select>
				</label>
				<label><span><?php esc_html_e( 'Sensitivity', 'sentinel-shield' ); ?></span>
					<select name="sensitivity">
						<?php foreach ( $sshield_levels as $sshield_key => $sshield_text ) : ?>
							<option value="<?php echo esc_attr( $sshield_key ); ?>" <?php selected( Settings::get( 'fw_sensitivity' ), $sshield_key ); ?>><?php echo esc_html( $sshield_text ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
			</div>
			<p class="sshield-small"><?php esc_html_e( 'Administrators are never blocked. Form fields from signed-in authors and editors skip the content rules, because posts can hold HTML and code.', 'sentinel-shield' ); ?></p>
		</section>
		<section class="sshield-card">
			<h2><?php esc_html_e( 'Rules', 'sentinel-shield' ); ?></h2>
			<ul class="sshield-optlist sshield-rules">
				<?php foreach ( $sshield_rules as $sshield_key => $sshield_rule ) : ?>
					<li>
						<label>
							<input type="checkbox" name="rules_on[]" value="<?php echo esc_attr( $sshield_key ); ?>" <?php checked( ! in_array( $sshield_key, $sshield_off, true ) ); ?>>
							<span>
								<strong><?php echo esc_html( $sshield_rule['label'] ); ?></strong>
								<span class="sshield-pill"><?php echo esc_html( (int) $sshield_rule['score'] >= 5 ? __( 'Blocks', 'sentinel-shield' ) : __( 'Adds up', 'sentinel-shield' ) ); ?></span>
								<span class="sshield-small"><?php echo esc_html( isset( $sshield_rule['info'] ) ? $sshield_rule['info'] : '' ); ?></span>
							</span>
						</label>
					</li>
				<?php endforeach; ?>
			</ul>
		</section>
	</div>
	<div class="sshield-actions">
		<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save changes', 'sentinel-shield' ); ?></button>
	</div>
</form>

<section class="sshield-card sshield-card--full">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Recent firewall hits', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'The last 100 requests the firewall stopped or, in learning mode, would have stopped. A visitor who was blocked sees the reference, so you can find their request here. If it was yours, choose Allow to stop that rule firing on that address and field.', 'sentinel-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! $sshield_hits ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'Nothing stopped yet.', 'sentinel-shield' ); ?></p>
	<?php else : ?>
		<div class="sshield-table-wrap">
			<table class="sshield-table sshield-table--hits">
				<thead><tr><th><?php esc_html_e( 'When', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Request', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'What matched', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Result', 'sentinel-shield' ); ?></th><th></th></tr></thead>
				<tbody>
					<?php foreach ( array_slice( $sshield_hits, 0, 50 ) as $sshield_hit ) : ?>
						<tr>
							<td>
								<?php echo esc_html( wp_date( $sshield_when, $sshield_hit['time'] ) ); ?>
								<span class="sshield-small"><code><?php echo esc_html( $sshield_hit['ip'] ); ?></code> · <?php echo esc_html( $sshield_hit['ref'] ); ?></span>
							</td>
							<td><code><?php echo esc_html( strtoupper( $sshield_hit['method'] ) . ' ' . $sshield_hit['path'] ); ?></code></td>
							<td>
								<?php foreach ( $sshield_hit['hits'] as $sshield_h ) : ?>
									<span class="sshield-hit">
										<strong><?php echo esc_html( isset( $sshield_rules[ $sshield_h['rule'] ] ) ? $sshield_rules[ $sshield_h['rule'] ]['label'] : $sshield_h['rule'] ); ?></strong>
										<?php
										/* translators: %s: field name such as POST:comment. */
										echo esc_html( sprintf( __( 'in %s', 'sentinel-shield' ), $sshield_h['field'] ) );
										?>
										<code><?php echo esc_html( $sshield_h['snippet'] ); ?></code>
									</span>
								<?php endforeach; ?>
							</td>
							<td>
								<span class="sshield-tag sshield-tag--<?php echo 'blocked' === $sshield_hit['action'] ? 'blocked' : 'system'; ?>"><?php echo esc_html( 'blocked' === $sshield_hit['action'] ? __( 'Blocked', 'sentinel-shield' ) : __( 'Recorded', 'sentinel-shield' ) ); ?></span>
								<span class="sshield-small">
									<?php
									/* translators: %d: score. */
									echo esc_html( sprintf( __( 'score %d', 'sentinel-shield' ), $sshield_hit['score'] ) );
									?>
								</span>
							</td>
							<td class="sshield-right"><?php $sshield_post( 'allow', array( 'ref' => $sshield_hit['ref'] ), __( 'Allow', 'sentinel-shield' ), 'sshield-link' ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</section>

<div class="sshield-grid">
	<section class="sshield-card">
		<h2><?php esc_html_e( 'Exceptions', 'sentinel-shield' ); ?></h2>
		<?php if ( ! $sshield_exc ) : ?>
			<p class="sshield-empty"><?php esc_html_e( 'No exceptions. Every rule applies everywhere.', 'sentinel-shield' ); ?></p>
		<?php else : ?>
			<div class="sshield-table-wrap">
				<table class="sshield-table">
					<thead><tr><th><?php esc_html_e( 'Rule', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Where', 'sentinel-shield' ); ?></th><th></th></tr></thead>
					<tbody>
						<?php foreach ( $sshield_exc as $sshield_i => $sshield_e ) : ?>
							<tr>
								<td><?php echo esc_html( isset( $sshield_rules[ $sshield_e['rule'] ] ) ? $sshield_rules[ $sshield_e['rule'] ]['label'] : $sshield_e['rule'] ); ?></td>
								<td>
									<code><?php echo esc_html( '' === $sshield_e['path'] ? __( 'any address', 'sentinel-shield' ) : $sshield_e['path'] ); ?></code>
									<span class="sshield-small"><?php echo esc_html( '' === $sshield_e['field'] ? __( 'any field', 'sentinel-shield' ) : $sshield_e['field'] ); ?></span>
								</td>
								<td class="sshield-right"><?php $sshield_post( 'remove', array( 'exception' => $sshield_i ), __( 'Remove', 'sentinel-shield' ), 'sshield-link sshield-link--danger' ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</section>
	<section class="sshield-card">
		<h2><?php esc_html_e( 'PHP in the uploads folder', 'sentinel-shield' ); ?></h2>
		<p class="sshield-small"><?php esc_html_e( 'Uploads should only hold images and documents. A rule in uploads/.htaccess stops the web server from running any PHP file there, so a web shell that slips in cannot run. It works on Apache and LiteSpeed.', 'sentinel-shield' ); ?></p>
		<?php if ( Firewall::uploads_protected() ) : ?>
			<p><span class="sshield-tag sshield-tag--scan"><?php esc_html_e( 'On', 'sentinel-shield' ); ?></span></p>
			<?php $sshield_post( 'uploads_off', array(), __( 'Remove the rule', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' ); ?>
		<?php else : ?>
			<?php $sshield_post( 'uploads_on', array(), __( 'Block PHP in uploads', 'sentinel-shield' ), 'sshield-btn' ); ?>
		<?php endif; ?>
		<p class="sshield-small"><?php esc_html_e( 'On nginx, ask your host to add this to the server block:', 'sentinel-shield' ); ?></p>
		<pre class="sshield-code"><code>location ~* /wp-content/uploads/.*\.(php\d?|phtml|phar)$ { deny all; }</code></pre>
	</section>
</div>
