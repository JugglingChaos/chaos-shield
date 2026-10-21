<?php
/**
 * One dialog per outside service. Each opens the service in a small window beside
 * this page, then checks and saves what the user pastes back.
 *
 * Expects $sshield_kinds, the kinds of service shown on this tab.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

foreach ( Connections::services() as $sshield_svc => $sshield_s ) :
	if ( ! in_array( $sshield_s['kind'], $sshield_kinds, true ) ) {
		continue;
	}
	$sshield_captcha = 'captcha' === $sshield_s['kind'];
	$sshield_saved   = ( $sshield_captcha && Captcha::configured( $sshield_svc ) ) || ( 'edge' === $sshield_s['kind'] && Cloudflare::connected() );
	$sshield_details = $sshield_captcha ? Captcha::details( $sshield_svc ) : array();
	?>
	<dialog class="sshield-connect" id="sshield-connect-<?php echo esc_attr( $sshield_svc ); ?>" data-service="<?php echo esc_attr( $sshield_svc ); ?>" data-kind="<?php echo esc_attr( $sshield_s['kind'] ); ?>" data-open="<?php echo esc_url( $sshield_s['open'] ); ?>"<?php echo $sshield_captcha ? ' data-script="' . esc_url( $sshield_details['script'] . '?render=explicit' ) . '" data-key-test="' . esc_attr( trim( $sshield_details['key_test'], '/i' ) ) . '"' : ''; ?> aria-labelledby="sshield-connect-<?php echo esc_attr( $sshield_svc ); ?>-title">
		<form method="dialog" class="sshield-connect__form" novalidate>
			<header class="sshield-connect__head">
				<h2 id="sshield-connect-<?php echo esc_attr( $sshield_svc ); ?>-title">
					<?php
					/* translators: %s: service name, such as Slack. */
					echo esc_html( sprintf( __( 'Connect %s', 'sentinel-shield' ), $sshield_s['name'] ) );
					?>
				</h2>
				<button type="button" class="sshield-connect__close" data-close aria-label="<?php esc_attr_e( 'Close', 'sentinel-shield' ); ?>">×</button>
			</header>
			<p class="sshield-small"><?php esc_html_e( 'The service opens in a small window next to this one, so this page stays where it is. Follow the steps there, then paste the result here.', 'sentinel-shield' ); ?></p>
			<ol class="sshield-steps">
				<?php foreach ( $sshield_s['steps'] as $sshield_i => $sshield_step ) : ?>
					<li>
						<?php echo esc_html( $sshield_step ); ?>
						<?php if ( 0 === $sshield_i ) : ?>
							<div class="sshield-steps__open">
								<button type="button" class="sshield-btn sshield-btn--ghost" data-popup><?php echo esc_html( $sshield_s['button'] ); ?> <span aria-hidden="true">↗</span></button>
								<span class="sshield-small sshield-connect__blocked" hidden>
									<?php esc_html_e( 'Your browser blocked the window.', 'sentinel-shield' ); ?>
									<a href="<?php echo esc_url( $sshield_s['open'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open it in a new tab instead', 'sentinel-shield' ); ?></a>
								</span>
							</div>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ol>
			<div class="sshield-fields sshield-fields--one">
				<?php foreach ( $sshield_s['fields'] as $sshield_name => $sshield_label ) : ?>
					<label><span><?php echo esc_html( $sshield_label ); ?></span>
						<input type="<?php echo in_array( $sshield_name, array( 'secret', 'token' ), true ) ? 'password' : ( 'url' === $sshield_name ? 'url' : 'text' ); ?>" name="<?php echo esc_attr( $sshield_name ); ?>" value="<?php echo 'site_key' === $sshield_name && $sshield_saved ? esc_attr( Settings::get( $sshield_details['key'] ) ) : ''; ?>"<?php echo in_array( $sshield_name, array( 'secret', 'token' ), true ) && $sshield_saved ? ' data-saved="1" placeholder="' . esc_attr__( 'Saved. Paste a new one to replace it.', 'sentinel-shield' ) . '"' : ''; ?><?php echo isset( $sshield_s['example'] ) ? ' placeholder="' . esc_attr( $sshield_s['example'] ) . '"' : ''; ?> spellcheck="false" autocomplete="off" autocapitalize="off"></label>
				<?php endforeach; ?>
			</div>
			<?php if ( $sshield_captcha ) : ?>
				<div class="sshield-connect__preview" hidden>
					<span class="sshield-small"><?php esc_html_e( 'Live check with your site key:', 'sentinel-shield' ); ?></span>
					<div class="sshield-connect__widget"></div>
				</div>
			<?php endif; ?>
			<p class="sshield-connect__msg" role="status" aria-live="polite"></p>
			<footer class="sshield-connect__foot">
				<button type="button" class="sshield-btn sshield-btn--ghost" data-close><?php esc_html_e( 'Cancel', 'sentinel-shield' ); ?></button>
				<button type="button" class="sshield-btn sshield-btn--ghost" data-force hidden><?php esc_html_e( 'Save anyway', 'sentinel-shield' ); ?></button>
				<button type="button" class="sshield-btn" data-save><?php esc_html_e( 'Check and connect', 'sentinel-shield' ); ?></button>
			</footer>
		</form>
	</dialog>
<?php endforeach; ?>
