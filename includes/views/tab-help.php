<?php
/**
 * Visitor help tab: switches, the owner's FAQ and visitor messages.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_requests = Help::requests();
$sshield_open_req = array_filter(
	$sshield_requests,
	static function ( $r ) {
		return 'open' === $r['status'];
	}
);
$sshield_reasons  = Help::reason_names();
$sshield_faq      = Help::faq();
$sshield_when     = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$sshield_hform    = static function ( $op, $label, $css, $id = '', $extra = array(), $target = false ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form"<?php echo $target ? ' target="_blank"' : ''; ?>>
		<input type="hidden" name="action" value="<?php echo esc_attr( Help::ACTION ); ?>">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php if ( $id ) : ?>
			<input type="hidden" name="request" value="<?php echo esc_attr( $id ); ?>">
		<?php endif; ?>
		<?php foreach ( $extra as $sshield_k => $sshield_v ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $sshield_k ); ?>" value="<?php echo esc_attr( $sshield_v ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( Help::ACTION ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<section class="sshield-card sshield-card--full" id="sshield-help-inbox">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Messages from visitors', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'Visitors who were blocked, locked out or stuck can send you a message from the help assistant. Allow lifts their ban and lockout, unblocks their exact IP and lets the blocked request through next time.', 'sentinel-shield' ); ?></p>
		</div>
		<?php
		if ( count( $sshield_requests ) > count( $sshield_open_req ) ) {
			$sshield_hform( 'clear', __( 'Remove handled', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' );
		}
		?>
	</div>
	<?php if ( ! $sshield_requests ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'No messages yet.', 'sentinel-shield' ); ?></p>
	<?php else : ?>
		<ul class="sshield-checks sshield-findings">
			<?php foreach ( array_slice( $sshield_requests, 0, 50 ) as $sshield_r ) : ?>
				<li class="sshield-check sshield-check--<?php echo 'open' === $sshield_r['status'] ? 'warn' : 'pass'; ?>">
					<span class="sshield-badge">
						<?php
						$sshield_states = array(
							'open'      => __( 'New', 'sentinel-shield' ),
							'allowed'   => __( 'Allowed', 'sentinel-shield' ),
							'dismissed' => __( 'Dismissed', 'sentinel-shield' ),
						);
						echo esc_html( isset( $sshield_states[ $sshield_r['status'] ] ) ? $sshield_states[ $sshield_r['status'] ] : $sshield_r['status'] );
						?>
					</span>
					<div class="sshield-finding">
						<strong><?php echo esc_html( isset( $sshield_reasons[ $sshield_r['reason'] ] ) ? $sshield_reasons[ $sshield_r['reason'] ] : $sshield_r['reason'] ); ?></strong>
						<p class="sshield-help-msg"><?php echo esc_html( $sshield_r['message'] ); ?></p>
						<p class="sshield-small">
							<?php
							echo esc_html( trim( $sshield_r['name'] . ' ' ) );
							?>
							<a href="<?php echo esc_url( 'mailto:' . $sshield_r['email'] ); ?>"><?php echo esc_html( $sshield_r['email'] ); ?></a>
							· <code><?php echo esc_html( $sshield_r['ip'] ); ?></code>
							<?php if ( $sshield_r['ref'] ) : ?>
								· <?php esc_html_e( 'Reference', 'sentinel-shield' ); ?> <code><?php echo esc_html( $sshield_r['ref'] ); ?></code>
							<?php endif; ?>
							· <?php echo esc_html( wp_date( $sshield_when, (int) $sshield_r['time'] ) ); ?>
							<?php if ( $sshield_r['page'] ) : ?>
								· <code><?php echo esc_html( $sshield_r['page'] ); ?></code>
							<?php endif; ?>
						</p>
					</div>
					<?php if ( 'open' === $sshield_r['status'] ) : ?>
						<div class="sshield-finding__action sshield-inline-actions">
							<?php
							$sshield_hform( 'allow', __( 'Allow', 'sentinel-shield' ), 'sshield-link', $sshield_r['id'] );
							$sshield_hform( 'always', __( 'Always allow this IP', 'sentinel-shield' ), 'sshield-link', $sshield_r['id'] );
							$sshield_hform( 'dismiss', __( 'Dismiss', 'sentinel-shield' ), 'sshield-link sshield-link--danger', $sshield_r['id'] );
							?>
						</div>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
		<p class="sshield-small"><?php esc_html_e( 'Reply by email from the address shown. Messages are kept for 30 days. Each IP can send three messages an hour.', 'sentinel-shield' ); ?></p>
	<?php endif; ?>
</section>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="<?php echo esc_attr( Help::ACTION ); ?>">
	<input type="hidden" name="op" value="save">
	<?php wp_nonce_field( Help::ACTION ); ?>
	<div class="sshield-grid">
		<section class="sshield-card">
			<h2><?php esc_html_e( 'Where the assistant appears', 'sentinel-shield' ); ?></h2>
			<ul class="sshield-optlist">
				<li><label><input type="checkbox" name="sshield[visitor_help]" value="1" <?php checked( Settings::enabled( 'visitor_help' ) ); ?>> <?php esc_html_e( 'On block and rate-limit pages, and as sign-in help on the login page', 'sentinel-shield' ); ?></label></li>
				<li><label><input type="checkbox" name="sshield[help_bubble]" value="1" <?php checked( Settings::enabled( 'help_bubble' ) ); ?>> <?php esc_html_e( 'As a help bubble on every page of the site, answering your questions below', 'sentinel-shield' ); ?></label></li>
				<li><label><input type="checkbox" name="sshield[help_contact]" value="1" <?php checked( Settings::enabled( 'help_contact' ) ); ?>> <?php esc_html_e( 'Let visitors send you a message from the assistant', 'sentinel-shield' ); ?></label></li>
			</ul>
			<p class="sshield-small"><?php esc_html_e( 'Answers are matched in the visitor\'s browser from the built-in security answers and your own. Nothing is sent to an outside service, and block pages never say which rule fired. Without the switch above, blocked visitors get a one-line text page.', 'sentinel-shield' ); ?></p>
			<div class="sshield-inline-actions sshield-help-previews">
				<span class="sshield-small"><?php esc_html_e( 'Preview:', 'sentinel-shield' ); ?></span>
				<?php
				foreach ( array(
					'firewall' => __( 'Firewall block', 'sentinel-shield' ),
					'ban'      => __( 'Ban', 'sentinel-shield' ),
					'country'  => __( 'Country', 'sentinel-shield' ),
					'rate'     => __( 'Rate limit', 'sentinel-shield' ),
				) as $sshield_reason => $sshield_label ) {
					$sshield_hform( 'preview', $sshield_label, 'sshield-link', '', array( 'reason' => $sshield_reason ), true );
				}
				?>
			</div>
		</section>
		<section class="sshield-card">
			<h2><?php esc_html_e( 'Look of the site bubble', 'sentinel-shield' ); ?></h2>
			<div class="sshield-fields sshield-fields--one">
				<label><span><?php esc_html_e( 'Title', 'sentinel-shield' ); ?></span>
					<input type="text" name="sshield[help_title]" maxlength="60" value="<?php echo esc_attr( Settings::get( 'help_title' ) ); ?>" placeholder="<?php esc_attr_e( 'Help', 'sentinel-shield' ); ?>"></label>
				<label><span><?php esc_html_e( 'Greeting', 'sentinel-shield' ); ?></span>
					<input type="text" name="sshield[help_greeting]" maxlength="200" value="<?php echo esc_attr( Settings::get( 'help_greeting' ) ); ?>" placeholder="<?php esc_attr_e( 'Hi! Ask a question or pick one below.', 'sentinel-shield' ); ?>"></label>
				<label><span><?php esc_html_e( 'Colour', 'sentinel-shield' ); ?></span>
					<input type="color" name="sshield[help_color]" value="<?php echo esc_attr( Settings::get( 'help_color' ) ); ?>" class="sshield-color"></label>
			</div>
		</section>
		<section class="sshield-card sshield-card--full">
			<h2><?php esc_html_e( 'Your questions and answers', 'sentinel-shield' ); ?></h2>
			<p class="sshield-small"><?php esc_html_e( 'Shown in the site bubble. Keywords help the assistant match how people actually ask, separated by commas. Write [link text](https://example.com/page) to add a link. Up to 50.', 'sentinel-shield' ); ?></p>
			<div class="sshield-faq" data-max="<?php echo esc_attr( Help::MAX_FAQ ); ?>">
				<?php
				$sshield_rows = $sshield_faq ? $sshield_faq : array(
					array(
						'q' => '',
						'a' => '',
						'k' => '',
					),
				);
				foreach ( $sshield_rows as $sshield_i => $sshield_row ) :
					?>
					<fieldset class="sshield-faq__row">
						<legend class="screen-reader-text"><?php esc_html_e( 'Question', 'sentinel-shield' ); ?></legend>
						<div class="sshield-fields sshield-fields--two">
							<label><span><?php esc_html_e( 'Question', 'sentinel-shield' ); ?></span>
								<input type="text" name="faq[<?php echo esc_attr( $sshield_i ); ?>][q]" maxlength="200" value="<?php echo esc_attr( $sshield_row['q'] ); ?>" placeholder="<?php esc_attr_e( 'Do you ship abroad?', 'sentinel-shield' ); ?>"></label>
							<label><span><?php esc_html_e( 'Keywords', 'sentinel-shield' ); ?></span>
								<input type="text" name="faq[<?php echo esc_attr( $sshield_i ); ?>][k]" maxlength="300" value="<?php echo esc_attr( $sshield_row['k'] ); ?>" placeholder="<?php esc_attr_e( 'shipping, delivery, international, abroad', 'sentinel-shield' ); ?>"></label>
						</div>
						<label class="sshield-faq__answer"><span><?php esc_html_e( 'Answer', 'sentinel-shield' ); ?></span>
							<textarea name="faq[<?php echo esc_attr( $sshield_i ); ?>][a]" rows="2" maxlength="1500" class="sshield-textarea"><?php echo esc_textarea( $sshield_row['a'] ); ?></textarea></label>
						<button type="button" class="sshield-link sshield-link--danger sshield-faq__remove"><?php esc_html_e( 'Remove', 'sentinel-shield' ); ?></button>
					</fieldset>
				<?php endforeach; ?>
			</div>
			<button type="button" class="sshield-btn sshield-btn--ghost sshield-faq__add"><?php esc_html_e( 'Add a question', 'sentinel-shield' ); ?></button>
		</section>
	</div>
	<div class="sshield-actions">
		<button type="submit" class="sshield-btn"><?php esc_html_e( 'Save changes', 'sentinel-shield' ); ?></button>
	</div>
</form>
