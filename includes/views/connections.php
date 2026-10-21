<?php
/**
 * Connection rows for one kind of outside service, and the dialogs that connect them.
 *
 * Expects $cshield_kind ('captcha' or 'chat'). The dialogs are printed once at
 * the end of the page by connect-dialogs.php, outside every form.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_when = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
?>
<ul class="cshield-connections">
	<?php foreach ( Connections::of( $cshield_kind ) as $cshield_svc => $cshield_s ) : ?>
		<?php
		if ( 'captcha' === $cshield_kind ) {
			$cshield_linked = Captcha::configured( $cshield_svc );
			$cshield_live   = $cshield_linked && Captcha::provider() === $cshield_svc && Settings::enabled( 'captcha' );
			$cshield_detail = $cshield_linked ? (string) Settings::get( Captcha::details( $cshield_svc )['key'] ) : '';
			$cshield_detail = $cshield_detail ? substr( $cshield_detail, 0, 8 ) . '…' : '';
		} elseif ( 'edge' === $cshield_kind ) {
			$cshield_linked = Cloudflare::connected();
			$cshield_live   = $cshield_linked;
			$cshield_detail = $cshield_linked ? Cloudflare::zone()['name'] . ( Cloudflare::zone()['plan'] ? ' · ' . Cloudflare::zone()['plan'] : '' ) : '';
		} else {
			$cshield_linked = Connections::chat() === $cshield_svc;
			$cshield_live   = $cshield_linked;
			$cshield_detail = $cshield_linked ? Connections::chat_hint() : '';
		}
		$cshield_checked = Connections::checked( $cshield_svc );
		?>
		<li class="cshield-connection<?php echo $cshield_linked ? ' is-linked' : ''; ?>">
			<div class="cshield-connection__text">
				<strong><?php echo esc_html( $cshield_s['name'] ); ?></strong>
				<?php if ( $cshield_live ) : ?>
					<span class="cshield-tag cshield-tag--scan"><?php echo esc_html( 'captcha' === $cshield_kind ? __( 'In use', 'chaos-shield' ) : __( 'Connected', 'chaos-shield' ) ); ?></span>
				<?php elseif ( $cshield_linked ) : ?>
					<span class="cshield-tag cshield-tag--system"><?php esc_html_e( 'Keys saved', 'chaos-shield' ); ?></span>
				<?php endif; ?>
				<span class="cshield-small">
					<?php
					if ( $cshield_linked ) {
						echo esc_html( $cshield_detail );
						if ( $cshield_checked ) {
							/* translators: %s: date and time. */
							echo ' · ' . esc_html( sprintf( __( 'checked %s', 'chaos-shield' ), wp_date( $cshield_when, $cshield_checked ) ) );
						}
					} else {
						echo esc_html( $cshield_s['blurb'] );
					}
					?>
				</span>
			</div>
			<div class="cshield-connection__actions">
				<?php if ( $cshield_linked && 'chat' === $cshield_kind ) : ?>
					<button type="button" class="cshield-link" data-connect-test="<?php echo esc_attr( $cshield_svc ); ?>"><?php esc_html_e( 'Send test', 'chaos-shield' ); ?></button>
				<?php endif; ?>
				<?php if ( $cshield_linked ) : ?>
					<button type="button" class="cshield-link cshield-link--danger" data-connect-remove="<?php echo esc_attr( $cshield_svc ); ?>"><?php esc_html_e( 'Disconnect', 'chaos-shield' ); ?></button>
				<?php endif; ?>
				<button type="button" class="cshield-btn<?php echo $cshield_linked ? ' cshield-btn--ghost' : ''; ?>" data-connect="<?php echo esc_attr( $cshield_svc ); ?>" aria-haspopup="dialog">
					<?php
					if ( $cshield_linked ) {
						esc_html_e( 'Change', 'chaos-shield' );
					} elseif ( 'captcha' === $cshield_kind && Captcha::configured() && ! $cshield_linked ) {
						esc_html_e( 'Switch to this', 'chaos-shield' );
					} else {
						esc_html_e( 'Connect', 'chaos-shield' );
					}
					?>
				</button>
			</div>
		</li>
	<?php endforeach; ?>
</ul>
<p class="cshield-small cshield-connection__status" role="status" aria-live="polite" hidden></p>
