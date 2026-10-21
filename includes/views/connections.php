<?php
/**
 * Connection rows for one kind of outside service, and the dialogs that connect them.
 *
 * Expects $sshield_kind ('captcha' or 'chat'). The dialogs are printed once at
 * the end of the page by connect-dialogs.php, outside every form.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_when = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
?>
<ul class="sshield-connections">
	<?php foreach ( Connections::of( $sshield_kind ) as $sshield_svc => $sshield_s ) : ?>
		<?php
		if ( 'captcha' === $sshield_kind ) {
			$sshield_linked = Captcha::configured( $sshield_svc );
			$sshield_live   = $sshield_linked && Captcha::provider() === $sshield_svc && Settings::enabled( 'captcha' );
			$sshield_detail = $sshield_linked ? (string) Settings::get( Captcha::details( $sshield_svc )['key'] ) : '';
			$sshield_detail = $sshield_detail ? substr( $sshield_detail, 0, 8 ) . '…' : '';
		} elseif ( 'edge' === $sshield_kind ) {
			$sshield_linked = Cloudflare::connected();
			$sshield_live   = $sshield_linked;
			$sshield_detail = $sshield_linked ? Cloudflare::zone()['name'] . ( Cloudflare::zone()['plan'] ? ' · ' . Cloudflare::zone()['plan'] : '' ) : '';
		} else {
			$sshield_linked = Connections::chat() === $sshield_svc;
			$sshield_live   = $sshield_linked;
			$sshield_detail = $sshield_linked ? Connections::chat_hint() : '';
		}
		$sshield_checked = Connections::checked( $sshield_svc );
		?>
		<li class="sshield-connection<?php echo $sshield_linked ? ' is-linked' : ''; ?>">
			<div class="sshield-connection__text">
				<strong><?php echo esc_html( $sshield_s['name'] ); ?></strong>
				<?php if ( $sshield_live ) : ?>
					<span class="sshield-tag sshield-tag--scan"><?php echo esc_html( 'captcha' === $sshield_kind ? __( 'In use', 'sentinel-shield' ) : __( 'Connected', 'sentinel-shield' ) ); ?></span>
				<?php elseif ( $sshield_linked ) : ?>
					<span class="sshield-tag sshield-tag--system"><?php esc_html_e( 'Keys saved', 'sentinel-shield' ); ?></span>
				<?php endif; ?>
				<span class="sshield-small">
					<?php
					if ( $sshield_linked ) {
						echo esc_html( $sshield_detail );
						if ( $sshield_checked ) {
							/* translators: %s: date and time. */
							echo ' · ' . esc_html( sprintf( __( 'checked %s', 'sentinel-shield' ), wp_date( $sshield_when, $sshield_checked ) ) );
						}
					} else {
						echo esc_html( $sshield_s['blurb'] );
					}
					?>
				</span>
			</div>
			<div class="sshield-connection__actions">
				<?php if ( $sshield_linked && 'chat' === $sshield_kind ) : ?>
					<button type="button" class="sshield-link" data-connect-test="<?php echo esc_attr( $sshield_svc ); ?>"><?php esc_html_e( 'Send test', 'sentinel-shield' ); ?></button>
				<?php endif; ?>
				<?php if ( $sshield_linked ) : ?>
					<button type="button" class="sshield-link sshield-link--danger" data-connect-remove="<?php echo esc_attr( $sshield_svc ); ?>"><?php esc_html_e( 'Disconnect', 'sentinel-shield' ); ?></button>
				<?php endif; ?>
				<button type="button" class="sshield-btn<?php echo $sshield_linked ? ' sshield-btn--ghost' : ''; ?>" data-connect="<?php echo esc_attr( $sshield_svc ); ?>" aria-haspopup="dialog">
					<?php
					if ( $sshield_linked ) {
						esc_html_e( 'Change', 'sentinel-shield' );
					} elseif ( 'captcha' === $sshield_kind && Captcha::configured() && ! $sshield_linked ) {
						esc_html_e( 'Switch to this', 'sentinel-shield' );
					} else {
						esc_html_e( 'Connect', 'sentinel-shield' );
					}
					?>
				</button>
			</div>
		</li>
	<?php endforeach; ?>
</ul>
<p class="sshield-small sshield-connection__status" role="status" aria-live="polite" hidden></p>
