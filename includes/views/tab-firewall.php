<?php
/**
 * Firewall tab: mode, sensitivity, rules, recent hits and exceptions.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_on       = Settings::enabled( 'firewall' );
$cshield_learning = Firewall::learning();
$cshield_rules    = Firewall::rules( true );
$cshield_off      = (array) Settings::get( 'fw_rules_off' );
$cshield_hits     = Firewall::hits();
$cshield_exc      = Firewall::exceptions();
$cshield_when     = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$cshield_levels   = array(
	'relaxed'  => __( 'Relaxed: block only when several attack signs add up', 'chaos-shield' ),
	'balanced' => __( 'Balanced: block clear attacks (recommended)', 'chaos-shield' ),
	'strict'   => __( 'Strict: also block suspicious requests', 'chaos-shield' ),
);
$cshield_post     = static function ( $op, array $fields, $label, $css ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
		<input type="hidden" name="action" value="cshield_firewall">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php foreach ( $fields as $cshield_k => $cshield_v ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $cshield_k ); ?>" value="<?php echo esc_attr( $cshield_v ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( 'cshield_firewall' ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<?php if ( ! $cshield_on ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="status"><?php esc_html_e( 'The request firewall is switched off under Hardening, so nothing below is enforced.', 'chaos-shield' ); ?></div>
<?php elseif ( $cshield_learning ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="status">
		<?php
		/* translators: %s: date. */
		echo esc_html( sprintf( __( 'Learning mode: requests that would be blocked are only recorded, until %s. Allow any that are yours, then blocking starts again on its own.', 'chaos-shield' ), wp_date( $cshield_when, (int) Settings::get( 'fw_learn_until' ) ) ) );
		?>
	</div>
<?php endif; ?>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="cshield_firewall">
	<input type="hidden" name="op" value="settings">
	<?php wp_nonce_field( 'cshield_firewall' ); ?>
	<div class="cshield-grid">
		<section class="cshield-card">
			<h2><?php esc_html_e( 'How the firewall decides', 'chaos-shield' ); ?></h2>
			<p class="cshield-small"><?php esc_html_e( 'Every part of a request is decoded and checked: the address, form and JSON fields, cookies, the referrer, the browser name and uploaded file names. Clear attack signs score 5 and suspicious ones 3. The request is blocked when the total reaches the level you pick.', 'chaos-shield' ); ?></p>
			<div class="cshield-fields cshield-fields--one">
				<label><span><?php esc_html_e( 'Mode', 'chaos-shield' ); ?></span>
					<select name="mode">
						<option value="block" <?php selected( ! $cshield_learning ); ?>><?php esc_html_e( 'Block attacks', 'chaos-shield' ); ?></option>
						<option value="learn" <?php selected( $cshield_learning ); ?>><?php esc_html_e( 'Learning: only record for 7 days', 'chaos-shield' ); ?></option>
					</select>
				</label>
				<label><span><?php esc_html_e( 'Sensitivity', 'chaos-shield' ); ?></span>
					<select name="sensitivity">
						<?php foreach ( $cshield_levels as $cshield_key => $cshield_text ) : ?>
							<option value="<?php echo esc_attr( $cshield_key ); ?>" <?php selected( Settings::get( 'fw_sensitivity' ), $cshield_key ); ?>><?php echo esc_html( $cshield_text ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
			</div>
			<p class="cshield-small"><?php esc_html_e( 'Administrators are never blocked. Form fields from signed-in authors and editors skip the content rules, because posts can hold HTML and code.', 'chaos-shield' ); ?></p>
		</section>
		<section class="cshield-card">
			<h2><?php esc_html_e( 'Rules', 'chaos-shield' ); ?></h2>
			<ul class="cshield-optlist cshield-rules">
				<?php foreach ( $cshield_rules as $cshield_key => $cshield_rule ) : ?>
					<li>
						<label>
							<input type="checkbox" name="rules_on[]" value="<?php echo esc_attr( $cshield_key ); ?>" <?php checked( ! in_array( $cshield_key, $cshield_off, true ) ); ?>>
							<span>
								<strong><?php echo esc_html( $cshield_rule['label'] ); ?></strong>
								<span class="cshield-pill"><?php echo esc_html( (int) $cshield_rule['score'] >= 5 ? __( 'Blocks', 'chaos-shield' ) : __( 'Adds up', 'chaos-shield' ) ); ?></span>
								<span class="cshield-small"><?php echo esc_html( isset( $cshield_rule['info'] ) ? $cshield_rule['info'] : '' ); ?></span>
							</span>
						</label>
					</li>
				<?php endforeach; ?>
			</ul>
		</section>
	</div>
	<div class="cshield-actions">
		<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save changes', 'chaos-shield' ); ?></button>
	</div>
</form>

<section class="cshield-card cshield-card--full">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Recent firewall hits', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'The last 100 requests the firewall stopped or, in learning mode, would have stopped. A visitor who was blocked sees the reference, so you can find their request here. If it was yours, choose Allow to stop that rule firing on that address and field.', 'chaos-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! $cshield_hits ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'Nothing stopped yet.', 'chaos-shield' ); ?></p>
	<?php else : ?>
		<div class="cshield-table-wrap">
			<table class="cshield-table cshield-table--hits">
				<thead><tr><th><?php esc_html_e( 'When', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Request', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'What matched', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Result', 'chaos-shield' ); ?></th><th></th></tr></thead>
				<tbody>
					<?php foreach ( array_slice( $cshield_hits, 0, 50 ) as $cshield_hit ) : ?>
						<tr>
							<td>
								<?php echo esc_html( wp_date( $cshield_when, $cshield_hit['time'] ) ); ?>
								<span class="cshield-small"><code><?php echo esc_html( $cshield_hit['ip'] ); ?></code> · <?php echo esc_html( $cshield_hit['ref'] ); ?></span>
							</td>
							<td><code><?php echo esc_html( strtoupper( $cshield_hit['method'] ) . ' ' . $cshield_hit['path'] ); ?></code></td>
							<td>
								<?php foreach ( $cshield_hit['hits'] as $cshield_h ) : ?>
									<span class="cshield-hit">
										<strong><?php echo esc_html( isset( $cshield_rules[ $cshield_h['rule'] ] ) ? $cshield_rules[ $cshield_h['rule'] ]['label'] : $cshield_h['rule'] ); ?></strong>
										<?php
										/* translators: %s: field name such as POST:comment. */
										echo esc_html( sprintf( __( 'in %s', 'chaos-shield' ), $cshield_h['field'] ) );
										?>
										<code><?php echo esc_html( $cshield_h['snippet'] ); ?></code>
									</span>
								<?php endforeach; ?>
							</td>
							<td>
								<span class="cshield-tag cshield-tag--<?php echo 'blocked' === $cshield_hit['action'] ? 'blocked' : 'system'; ?>"><?php echo esc_html( 'blocked' === $cshield_hit['action'] ? __( 'Blocked', 'chaos-shield' ) : __( 'Recorded', 'chaos-shield' ) ); ?></span>
								<span class="cshield-small">
									<?php
									/* translators: %d: score. */
									echo esc_html( sprintf( __( 'score %d', 'chaos-shield' ), $cshield_hit['score'] ) );
									?>
								</span>
							</td>
							<td class="cshield-right"><?php $cshield_post( 'allow', array( 'ref' => $cshield_hit['ref'] ), __( 'Allow', 'chaos-shield' ), 'cshield-link' ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</section>

<div class="cshield-grid">
	<section class="cshield-card">
		<h2><?php esc_html_e( 'Exceptions', 'chaos-shield' ); ?></h2>
		<?php if ( ! $cshield_exc ) : ?>
			<p class="cshield-empty"><?php esc_html_e( 'No exceptions. Every rule applies everywhere.', 'chaos-shield' ); ?></p>
		<?php else : ?>
			<div class="cshield-table-wrap">
				<table class="cshield-table">
					<thead><tr><th><?php esc_html_e( 'Rule', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Where', 'chaos-shield' ); ?></th><th></th></tr></thead>
					<tbody>
						<?php foreach ( $cshield_exc as $cshield_i => $cshield_e ) : ?>
							<tr>
								<td><?php echo esc_html( isset( $cshield_rules[ $cshield_e['rule'] ] ) ? $cshield_rules[ $cshield_e['rule'] ]['label'] : $cshield_e['rule'] ); ?></td>
								<td>
									<code><?php echo esc_html( '' === $cshield_e['path'] ? __( 'any address', 'chaos-shield' ) : $cshield_e['path'] ); ?></code>
									<span class="cshield-small"><?php echo esc_html( '' === $cshield_e['field'] ? __( 'any field', 'chaos-shield' ) : $cshield_e['field'] ); ?></span>
								</td>
								<td class="cshield-right"><?php $cshield_post( 'remove', array( 'exception' => $cshield_i ), __( 'Remove', 'chaos-shield' ), 'cshield-link cshield-link--danger' ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</section>
	<section class="cshield-card">
		<h2><?php esc_html_e( 'PHP in the uploads folder', 'chaos-shield' ); ?></h2>
		<p class="cshield-small"><?php esc_html_e( 'Uploads should only hold images and documents. A rule in uploads/.htaccess stops the web server from running any PHP file there, so a web shell that slips in cannot run. It works on Apache and LiteSpeed.', 'chaos-shield' ); ?></p>
		<?php if ( Firewall::uploads_protected() ) : ?>
			<p><span class="cshield-tag cshield-tag--scan"><?php esc_html_e( 'On', 'chaos-shield' ); ?></span></p>
			<?php $cshield_post( 'uploads_off', array(), __( 'Remove the rule', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' ); ?>
		<?php else : ?>
			<?php $cshield_post( 'uploads_on', array(), __( 'Block PHP in uploads', 'chaos-shield' ), 'cshield-btn' ); ?>
		<?php endif; ?>
		<p class="cshield-small"><?php esc_html_e( 'On nginx, ask your host to add this to the server block:', 'chaos-shield' ); ?></p>
		<pre class="cshield-code"><code>location ~* /wp-content/uploads/.*\.(php\d?|phtml|phar)$ { deny all; }</code></pre>
	</section>
</div>
