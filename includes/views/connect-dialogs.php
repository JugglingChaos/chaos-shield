<?php
/**
 * One dialog per outside service. Each opens the service in a small window beside
 * this page, then checks and saves what the user pastes back.
 *
 * Expects $cshield_kinds, the kinds of service shown on this tab.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

foreach ( Connections::services() as $cshield_svc => $cshield_s ) :
	if ( ! in_array( $cshield_s['kind'], $cshield_kinds, true ) ) {
		continue;
	}
	$cshield_captcha = 'captcha' === $cshield_s['kind'];
	$cshield_saved   = ( $cshield_captcha && Captcha::configured( $cshield_svc ) ) || ( 'edge' === $cshield_s['kind'] && Cloudflare::connected() );
	$cshield_details = $cshield_captcha ? Captcha::details( $cshield_svc ) : array();
	?>
	<dialog class="cshield-connect" id="cshield-connect-<?php echo esc_attr( $cshield_svc ); ?>" data-service="<?php echo esc_attr( $cshield_svc ); ?>" data-kind="<?php echo esc_attr( $cshield_s['kind'] ); ?>" data-open="<?php echo esc_url( $cshield_s['open'] ); ?>"<?php echo $cshield_captcha ? ' data-script="' . esc_url( $cshield_details['script'] . '?render=explicit' ) . '" data-key-test="' . esc_attr( trim( $cshield_details['key_test'], '/i' ) ) . '"' : ''; ?> aria-labelledby="cshield-connect-<?php echo esc_attr( $cshield_svc ); ?>-title">
		<form method="dialog" class="cshield-connect__form" novalidate>
			<header class="cshield-connect__head">
				<h2 id="cshield-connect-<?php echo esc_attr( $cshield_svc ); ?>-title">
					<?php
					/* translators: %s: service name, such as Slack. */
					echo esc_html( sprintf( __( 'Connect %s', 'chaos-shield' ), $cshield_s['name'] ) );
					?>
				</h2>
				<button type="button" class="cshield-connect__close" data-close aria-label="<?php esc_attr_e( 'Close', 'chaos-shield' ); ?>">×</button>
			</header>
			<p class="cshield-small"><?php esc_html_e( 'The service opens in a small window next to this one, so this page stays where it is. Follow the steps there, then paste the result here.', 'chaos-shield' ); ?></p>
			<ol class="cshield-steps">
				<?php foreach ( $cshield_s['steps'] as $cshield_i => $cshield_step ) : ?>
					<li>
						<?php echo esc_html( $cshield_step ); ?>
						<?php if ( 0 === $cshield_i ) : ?>
							<div class="cshield-steps__open">
								<button type="button" class="cshield-btn cshield-btn--ghost" data-popup><?php echo esc_html( $cshield_s['button'] ); ?> <span aria-hidden="true">↗</span></button>
								<span class="cshield-small cshield-connect__blocked" hidden>
									<?php esc_html_e( 'Your browser blocked the window.', 'chaos-shield' ); ?>
									<a href="<?php echo esc_url( $cshield_s['open'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open it in a new tab instead', 'chaos-shield' ); ?></a>
								</span>
							</div>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ol>
			<div class="cshield-fields cshield-fields--one">
				<?php foreach ( $cshield_s['fields'] as $cshield_name => $cshield_label ) : ?>
					<label><span><?php echo esc_html( $cshield_label ); ?></span>
						<input type="<?php echo in_array( $cshield_name, array( 'secret', 'token' ), true ) ? 'password' : ( 'url' === $cshield_name ? 'url' : 'text' ); ?>" name="<?php echo esc_attr( $cshield_name ); ?>" value="<?php echo 'site_key' === $cshield_name && $cshield_saved ? esc_attr( Settings::get( $cshield_details['key'] ) ) : ''; ?>"<?php echo in_array( $cshield_name, array( 'secret', 'token' ), true ) && $cshield_saved ? ' data-saved="1" placeholder="' . esc_attr__( 'Saved. Paste a new one to replace it.', 'chaos-shield' ) . '"' : ''; ?><?php echo isset( $cshield_s['example'] ) ? ' placeholder="' . esc_attr( $cshield_s['example'] ) . '"' : ''; ?> spellcheck="false" autocomplete="off" autocapitalize="off"></label>
				<?php endforeach; ?>
			</div>
			<?php if ( $cshield_captcha ) : ?>
				<div class="cshield-connect__preview" hidden>
					<span class="cshield-small"><?php esc_html_e( 'Live check with your site key:', 'chaos-shield' ); ?></span>
					<div class="cshield-connect__widget"></div>
				</div>
			<?php endif; ?>
			<p class="cshield-connect__msg" role="status" aria-live="polite"></p>
			<footer class="cshield-connect__foot">
				<button type="button" class="cshield-btn cshield-btn--ghost" data-close><?php esc_html_e( 'Cancel', 'chaos-shield' ); ?></button>
				<button type="button" class="cshield-btn cshield-btn--ghost" data-force hidden><?php esc_html_e( 'Save anyway', 'chaos-shield' ); ?></button>
				<button type="button" class="cshield-btn" data-save><?php esc_html_e( 'Check and connect', 'chaos-shield' ); ?></button>
			</footer>
		</form>
	</dialog>
<?php endforeach; ?>
