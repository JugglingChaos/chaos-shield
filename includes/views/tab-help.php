<?php
/**
 * Visitor help tab: switches, the owner's FAQ and visitor messages.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_requests = Help::requests();
$cshield_open_req = array_filter(
	$cshield_requests,
	static function ( $r ) {
		return 'open' === $r['status'];
	}
);
$cshield_reasons  = Help::reason_names();
$cshield_faq      = Help::faq();
$cshield_when     = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$cshield_hform    = static function ( $op, $label, $css, $id = '', $extra = array(), $target = false ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form"<?php echo $target ? ' target="_blank"' : ''; ?>>
		<input type="hidden" name="action" value="<?php echo esc_attr( Help::ACTION ); ?>">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php if ( $id ) : ?>
			<input type="hidden" name="request" value="<?php echo esc_attr( $id ); ?>">
		<?php endif; ?>
		<?php foreach ( $extra as $cshield_k => $cshield_v ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $cshield_k ); ?>" value="<?php echo esc_attr( $cshield_v ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( Help::ACTION ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
?>
<section class="cshield-card cshield-card--full" id="cshield-help-inbox">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Messages from visitors', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'Visitors who were blocked, locked out or stuck can send you a message from the help assistant. Allow lifts their ban and lockout, unblocks their exact IP and lets the blocked request through next time.', 'chaos-shield' ); ?></p>
		</div>
		<?php
		if ( count( $cshield_requests ) > count( $cshield_open_req ) ) {
			$cshield_hform( 'clear', __( 'Remove handled', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' );
		}
		?>
	</div>
	<?php if ( ! $cshield_requests ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'No messages yet.', 'chaos-shield' ); ?></p>
	<?php else : ?>
		<ul class="cshield-checks cshield-findings">
			<?php foreach ( array_slice( $cshield_requests, 0, 50 ) as $cshield_r ) : ?>
				<li class="cshield-check cshield-check--<?php echo 'open' === $cshield_r['status'] ? 'warn' : 'pass'; ?>">
					<span class="cshield-badge">
						<?php
						$cshield_states = array(
							'open'      => __( 'New', 'chaos-shield' ),
							'allowed'   => __( 'Allowed', 'chaos-shield' ),
							'dismissed' => __( 'Dismissed', 'chaos-shield' ),
						);
						echo esc_html( isset( $cshield_states[ $cshield_r['status'] ] ) ? $cshield_states[ $cshield_r['status'] ] : $cshield_r['status'] );
						?>
					</span>
					<div class="cshield-finding">
						<strong><?php echo esc_html( isset( $cshield_reasons[ $cshield_r['reason'] ] ) ? $cshield_reasons[ $cshield_r['reason'] ] : $cshield_r['reason'] ); ?></strong>
						<p class="cshield-help-msg"><?php echo esc_html( $cshield_r['message'] ); ?></p>
						<p class="cshield-small">
							<?php
							echo esc_html( trim( $cshield_r['name'] . ' ' ) );
							?>
							<a href="<?php echo esc_url( 'mailto:' . $cshield_r['email'] ); ?>"><?php echo esc_html( $cshield_r['email'] ); ?></a>
							· <code><?php echo esc_html( $cshield_r['ip'] ); ?></code>
							<?php if ( $cshield_r['ref'] ) : ?>
								· <?php esc_html_e( 'Reference', 'chaos-shield' ); ?> <code><?php echo esc_html( $cshield_r['ref'] ); ?></code>
							<?php endif; ?>
							· <?php echo esc_html( wp_date( $cshield_when, (int) $cshield_r['time'] ) ); ?>
							<?php if ( $cshield_r['page'] ) : ?>
								· <code><?php echo esc_html( $cshield_r['page'] ); ?></code>
							<?php endif; ?>
						</p>
					</div>
					<?php if ( 'open' === $cshield_r['status'] ) : ?>
						<div class="cshield-finding__action cshield-inline-actions">
							<?php
							$cshield_hform( 'allow', __( 'Allow', 'chaos-shield' ), 'cshield-link', $cshield_r['id'] );
							$cshield_hform( 'always', __( 'Always allow this IP', 'chaos-shield' ), 'cshield-link', $cshield_r['id'] );
							$cshield_hform( 'dismiss', __( 'Dismiss', 'chaos-shield' ), 'cshield-link cshield-link--danger', $cshield_r['id'] );
							?>
						</div>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
		<p class="cshield-small"><?php esc_html_e( 'Reply by email from the address shown. Messages are kept for 30 days. Each IP can send three messages an hour.', 'chaos-shield' ); ?></p>
	<?php endif; ?>
</section>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="<?php echo esc_attr( Help::ACTION ); ?>">
	<input type="hidden" name="op" value="save">
	<?php wp_nonce_field( Help::ACTION ); ?>
	<div class="cshield-grid">
		<section class="cshield-card">
			<h2><?php esc_html_e( 'Where the assistant appears', 'chaos-shield' ); ?></h2>
			<ul class="cshield-optlist">
				<li><label><input type="checkbox" name="cshield[visitor_help]" value="1" <?php checked( Settings::enabled( 'visitor_help' ) ); ?>> <?php esc_html_e( 'On block and rate-limit pages, and as sign-in help on the login page', 'chaos-shield' ); ?></label></li>
				<li><label><input type="checkbox" name="cshield[help_bubble]" value="1" <?php checked( Settings::enabled( 'help_bubble' ) ); ?>> <?php esc_html_e( 'As a help bubble on every page of the site, answering your questions below', 'chaos-shield' ); ?></label></li>
				<li><label><input type="checkbox" name="cshield[help_contact]" value="1" <?php checked( Settings::enabled( 'help_contact' ) ); ?>> <?php esc_html_e( 'Let visitors send you a message from the assistant', 'chaos-shield' ); ?></label></li>
			</ul>
			<p class="cshield-small"><?php esc_html_e( 'Answers are matched in the visitor\'s browser from the built-in security answers and your own. Nothing is sent to an outside service, and block pages never say which rule fired. Without the switch above, blocked visitors get a one-line text page.', 'chaos-shield' ); ?></p>
			<div class="cshield-inline-actions cshield-help-previews">
				<span class="cshield-small"><?php esc_html_e( 'Preview:', 'chaos-shield' ); ?></span>
				<?php
				foreach ( array(
					'firewall' => __( 'Firewall block', 'chaos-shield' ),
					'ban'      => __( 'Ban', 'chaos-shield' ),
					'country'  => __( 'Country', 'chaos-shield' ),
					'rate'     => __( 'Rate limit', 'chaos-shield' ),
				) as $cshield_reason => $cshield_label ) {
					$cshield_hform( 'preview', $cshield_label, 'cshield-link', '', array( 'reason' => $cshield_reason ), true );
				}
				?>
			</div>
		</section>
		<section class="cshield-card">
			<h2><?php esc_html_e( 'Look of the site bubble', 'chaos-shield' ); ?></h2>
			<div class="cshield-fields cshield-fields--one">
				<label><span><?php esc_html_e( 'Title', 'chaos-shield' ); ?></span>
					<input type="text" name="cshield[help_title]" maxlength="60" value="<?php echo esc_attr( Settings::get( 'help_title' ) ); ?>" placeholder="<?php esc_attr_e( 'Help', 'chaos-shield' ); ?>"></label>
				<label><span><?php esc_html_e( 'Greeting', 'chaos-shield' ); ?></span>
					<input type="text" name="cshield[help_greeting]" maxlength="200" value="<?php echo esc_attr( Settings::get( 'help_greeting' ) ); ?>" placeholder="<?php esc_attr_e( 'Hi! Ask a question or pick one below.', 'chaos-shield' ); ?>"></label>
				<label><span><?php esc_html_e( 'Colour', 'chaos-shield' ); ?></span>
					<input type="color" name="cshield[help_color]" value="<?php echo esc_attr( Settings::get( 'help_color' ) ); ?>" class="cshield-color"></label>
			</div>
		</section>
		<section class="cshield-card cshield-card--full">
			<h2><?php esc_html_e( 'Your questions and answers', 'chaos-shield' ); ?></h2>
			<p class="cshield-small"><?php esc_html_e( 'Shown in the site bubble. Keywords help the assistant match how people actually ask, separated by commas. Write [link text](https://example.com/page) to add a link. Up to 50.', 'chaos-shield' ); ?></p>
			<div class="cshield-faq" data-max="<?php echo esc_attr( Help::MAX_FAQ ); ?>">
				<?php
				$cshield_rows = $cshield_faq ? $cshield_faq : array(
					array(
						'q' => '',
						'a' => '',
						'k' => '',
					),
				);
				foreach ( $cshield_rows as $cshield_i => $cshield_row ) :
					?>
					<fieldset class="cshield-faq__row">
						<legend class="screen-reader-text"><?php esc_html_e( 'Question', 'chaos-shield' ); ?></legend>
						<div class="cshield-fields cshield-fields--two">
							<label><span><?php esc_html_e( 'Question', 'chaos-shield' ); ?></span>
								<input type="text" name="faq[<?php echo esc_attr( $cshield_i ); ?>][q]" maxlength="200" value="<?php echo esc_attr( $cshield_row['q'] ); ?>" placeholder="<?php esc_attr_e( 'Do you ship abroad?', 'chaos-shield' ); ?>"></label>
							<label><span><?php esc_html_e( 'Keywords', 'chaos-shield' ); ?></span>
								<input type="text" name="faq[<?php echo esc_attr( $cshield_i ); ?>][k]" maxlength="300" value="<?php echo esc_attr( $cshield_row['k'] ); ?>" placeholder="<?php esc_attr_e( 'shipping, delivery, international, abroad', 'chaos-shield' ); ?>"></label>
						</div>
						<label class="cshield-faq__answer"><span><?php esc_html_e( 'Answer', 'chaos-shield' ); ?></span>
							<textarea name="faq[<?php echo esc_attr( $cshield_i ); ?>][a]" rows="2" maxlength="1500" class="cshield-textarea"><?php echo esc_textarea( $cshield_row['a'] ); ?></textarea></label>
						<button type="button" class="cshield-link cshield-link--danger cshield-faq__remove"><?php esc_html_e( 'Remove', 'chaos-shield' ); ?></button>
					</fieldset>
				<?php endforeach; ?>
			</div>
			<button type="button" class="cshield-btn cshield-btn--ghost cshield-faq__add"><?php esc_html_e( 'Add a question', 'chaos-shield' ); ?></button>
		</section>
	</div>
	<div class="cshield-actions">
		<button type="submit" class="cshield-btn"><?php esc_html_e( 'Save changes', 'chaos-shield' ); ?></button>
	</div>
</form>
