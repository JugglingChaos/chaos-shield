<?php
/**
 * Edge tab: under attack mode, Cloudflare and other edge services, HTTPS, page scripts and exposed files.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

$cshield_when   = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$cshield_attack = Attack_Mode::state();
$cshield_on     = Attack_Mode::active();
$cshield_check  = Page_Check::state();
$cshield_https  = Https::state();
$cshield_exp    = Exposure::state();
$cshield_sc     = Scripts::state();
$cshield_counts = Scripts::counts();
$cshield_cf     = Cloudflare::connected();
$cshield_cfst   = Cloudflare::status();
$cshield_zone   = Cloudflare::zone();
$cshield_eform  = static function ( $op, $label, $css, array $extra = array(), $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form"<?php echo $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : ''; ?>>
		<input type="hidden" name="action" value="<?php echo esc_attr( Edge::ACTION ); ?>">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php foreach ( $extra as $cshield_k => $cshield_v ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $cshield_k ); ?>" value="<?php echo esc_attr( $cshield_v ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( Edge::ACTION ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
// Opens a settings form that saves only the fields it names.
$cshield_open  = static function ( array $fields ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-edge-form">
		<input type="hidden" name="action" value="<?php echo esc_attr( Edge::ACTION ); ?>">
		<input type="hidden" name="op" value="save">
		<input type="hidden" name="fields" value="<?php echo esc_attr( implode( ',', $fields ) ); ?>">
		<?php wp_nonce_field( Edge::ACTION ); ?>
	<?php
};
$cshield_close = static function () {
	?>
		<div class="cshield-actions cshield-actions--inline"><button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Save', 'chaos-shield' ); ?></button></div>
	</form>
	<?php
};
$cshield_box   = static function ( $key, $label, $hint = '' ) {
	?>
	<li><label><input type="checkbox" name="cshield[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( (bool) Settings::get( $key ) ); ?>> <?php echo esc_html( $label ); ?></label>
		<?php if ( $hint ) : ?>
			<span class="cshield-small"><?php echo esc_html( $hint ); ?></span>
		<?php endif; ?>
	</li>
	<?php
};
?>
<div class="cshield-edge-head">
	<p class="cshield-small">
		<?php
		if ( $cshield_check ) {
			printf(
				/* translators: 1: date and time, 2: number of pages. */
				esc_html__( 'Your pages were last looked at from outside on %1$s (%2$s pages). This runs every day.', 'chaos-shield' ),
				esc_html( wp_date( $cshield_when, (int) $cshield_check['checked'] ) ),
				esc_html( number_format_i18n( count( $cshield_check['pages'] ) ) )
			);
		} else {
			esc_html_e( 'Your pages have not been looked at from outside yet. It runs every day, or choose Check now.', 'chaos-shield' );
		}
		?>
	</p>
	<?php $cshield_eform( 'check', __( 'Check now', 'chaos-shield' ), 'cshield-btn' ); ?>
</div>
<?php if ( $cshield_check && 'none' === $cshield_check['error'] ) : ?>
	<div class="cshield-notice cshield-notice--warn" role="alert"><?php esc_html_e( 'The site could not load its own pages, so scripts, mixed content and keys were not checked. Some hosts block a site from calling itself; ask your host to allow it.', 'chaos-shield' ); ?></div>
<?php endif; ?>

<section class="cshield-card cshield-card--full<?php echo $cshield_on ? ' cshield-card--alert' : ''; ?>" id="cshield-attack">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Under attack mode', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'Puts a one-second browser check in front of the site. People pass on their own and keep the pass for 12 hours; bots and scripts that flood the site never reach WordPress. Logged-in users, the allow list, Google and Bing are never checked.', 'chaos-shield' ); ?></p>
		</div>
		<div class="cshield-inline-actions">
			<?php
			if ( $cshield_on ) {
				$cshield_eform( 'attack_off', __( 'Switch off', 'chaos-shield' ), 'cshield-btn' );
			} else {
				$cshield_eform( 'attack_on', __( 'Switch on now', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', array(), __( 'Every visitor who is not logged in will see a short browser check. Switch it on?', 'chaos-shield' ) );
			}
			?>
		</div>
	</div>
	<?php if ( $cshield_on ) : ?>
		<div class="cshield-notice cshield-notice--warn" role="status">
			<?php
			echo esc_html(
				$cshield_attack['auto']
					/* translators: 1: date and time it started, 2: time it ends. */
					? sprintf( __( 'On since %1$s, switched on by the flood detector. It ends on its own at %2$s if the flood has stopped.', 'chaos-shield' ), wp_date( $cshield_when, (int) $cshield_attack['since'] ), wp_date( get_option( 'time_format' ), (int) $cshield_attack['until'] ) )
					/* translators: %s: date and time. */
					: sprintf( __( 'On since %s, switched on by hand. It stays on until you switch it off.', 'chaos-shield' ), wp_date( $cshield_when, (int) $cshield_attack['since'] ) )
			);
			?>
		</div>
	<?php elseif ( $cshield_attack['last'] ) : ?>
		<p class="cshield-small">
			<?php
			/* translators: %s: date and time. */
			echo esc_html( sprintf( __( 'Last ended %s.', 'chaos-shield' ), wp_date( $cshield_when, (int) $cshield_attack['last'] ) ) );
			?>
		</p>
	<?php endif; ?>
	<?php $cshield_open( array( 'attack_auto', 'attack_threshold', 'cf_attack_sync' ) ); ?>
		<ul class="cshield-optlist">
			<li>
				<label><input type="checkbox" name="cshield[attack_auto]" value="1" <?php checked( Settings::enabled( 'attack_auto' ) ); ?>> <?php esc_html_e( 'Switch on by itself during a flood', 'chaos-shield' ); ?></label>
				<label class="cshield-inline-field"><?php esc_html_e( 'when more than', 'chaos-shield' ); ?> <input type="number" name="cshield[attack_threshold]" min="20" max="10000" value="<?php echo esc_attr( Settings::get( 'attack_threshold' ) ); ?>" class="small-text"> <?php esc_html_e( 'requests are blocked in a minute', 'chaos-shield' ); ?></label>
			</li>
			<li><label><input type="checkbox" name="cshield[cf_attack_sync]" value="1" <?php checked( (bool) Settings::get( 'cf_attack_sync' ) ); ?><?php disabled( ! $cshield_cf ); ?>> <?php esc_html_e( 'Switch on Cloudflare\'s Under Attack mode at the same time', 'chaos-shield' ); ?></label>
				<span class="cshield-small"><?php echo esc_html( $cshield_cf ? __( 'Stops the flood before it reaches your server, and is set back to what it was afterwards.', 'chaos-shield' ) : __( 'Connect Cloudflare below first.', 'chaos-shield' ) ); ?></span>
			</li>
		</ul>
		<p class="cshield-small"><?php esc_html_e( 'A plugin can only answer requests that reach the server. A flood big enough to fill the server\'s connection has to be stopped before that, by Cloudflare or your host.', 'chaos-shield' ); ?></p>
	<?php $cshield_close(); ?>
</section>

<section class="cshield-card cshield-card--full" id="cshield-cloudflare">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Cloudflare and other edge services', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'For what no plugin can do on the server: large floods, a worldwide cache and free certificates. With Cloudflare connected, banned and blocked IPs are refused at Cloudflare before they reach you.', 'chaos-shield' ); ?></p>
		</div>
	</div>
	<?php
	$cshield_kind = 'edge';
	require CSHIELD_DIR . 'includes/views/connections.php';
	?>
	<?php if ( $cshield_cf ) : ?>
		<?php
		$cshield_ssl_names = array(
			'off'      => __( 'Off', 'chaos-shield' ),
			'flexible' => __( 'Flexible', 'chaos-shield' ),
			'full'     => __( 'Full', 'chaos-shield' ),
			'strict'   => __( 'Full (strict)', 'chaos-shield' ),
		);
		$cshield_levels    = array(
			'essentially_off' => __( 'Essentially off', 'chaos-shield' ),
			'low'             => __( 'Low', 'chaos-shield' ),
			'medium'          => __( 'Medium', 'chaos-shield' ),
			'high'            => __( 'High', 'chaos-shield' ),
			'under_attack'    => __( 'Under Attack', 'chaos-shield' ),
		);
		$cshield_rules     = Cloudflare::rules();
		$cshield_proxy     = 'HTTP_CF_CONNECTING_IP' === Settings::get( 'proxy_header' );
		?>
		<ul class="cshield-checks cshield-cf-status">
			<li class="cshield-check cshield-check--<?php echo empty( $cshield_zone['can']['firewall'] ) ? 'warn' : ( $cshield_cfst['error'] ? 'warn' : 'pass' ); ?>">
				<span class="cshield-badge"><?php echo esc_html( number_format_i18n( count( $cshield_rules ) ) ); ?></span>
				<div class="cshield-finding">
					<strong><?php esc_html_e( 'IPs blocked at Cloudflare', 'chaos-shield' ); ?></strong>
					<p>
						<?php
						if ( empty( $cshield_zone['can']['firewall'] ) ) {
							esc_html_e( 'The token cannot edit IP Access rules. Add Firewall Services: Edit to it and connect again.', 'chaos-shield' );
						} elseif ( ! Settings::get( 'cf_sync_bans' ) ) {
							esc_html_e( 'Sending bans to Cloudflare is off.', 'chaos-shield' );
						} else {
							echo esc_html( $cshield_cfst['synced'] ? sprintf( /* translators: %s: date and time. */ __( 'Bans and single blocked IPs are sent within a minute and removed when they end. Last sync %s.', 'chaos-shield' ), wp_date( $cshield_when, (int) $cshield_cfst['synced'] ) ) : __( 'Bans and single blocked IPs are sent within a minute and removed when they end.', 'chaos-shield' ) );
						}
						if ( $cshield_cfst['error'] ) {
							echo ' ' . esc_html( $cshield_cfst['error'] );
						}
						?>
					</p>
				</div>
			</li>
			<li class="cshield-check cshield-check--<?php echo in_array( $cshield_cfst['ssl'], array( 'full', 'strict' ), true ) ? 'pass' : 'warn'; ?>">
				<span class="cshield-badge"><?php esc_html_e( 'SSL', 'chaos-shield' ); ?></span>
				<div class="cshield-finding">
					<strong><?php echo esc_html( isset( $cshield_ssl_names[ $cshield_cfst['ssl'] ] ) ? $cshield_ssl_names[ $cshield_cfst['ssl'] ] : __( 'Unknown', 'chaos-shield' ) ); ?></strong>
					<p>
						<?php
						if ( 'strict' === $cshield_cfst['ssl'] ) {
							esc_html_e( 'Visitors and Cloudflare both talk to your server over checked HTTPS. This is the best setting.', 'chaos-shield' );
						} elseif ( 'full' === $cshield_cfst['ssl'] ) {
							esc_html_e( 'Encrypted all the way, but Cloudflare does not check your server\'s certificate. Choose Full (strict) in Cloudflare under SSL/TLS once the server has a valid certificate.', 'chaos-shield' );
						} elseif ( 'flexible' === $cshield_cfst['ssl'] ) {
							esc_html_e( 'Traffic between Cloudflare and your server is not encrypted, and logins can leak there. Install a certificate on the server (or a free Cloudflare Origin Certificate) and choose Full (strict).', 'chaos-shield' );
						} else {
							esc_html_e( 'HTTPS is off or could not be read. Choose Full (strict) in Cloudflare under SSL/TLS.', 'chaos-shield' );
						}
						?>
					</p>
				</div>
			</li>
			<li class="cshield-check cshield-check--<?php echo 'on' === $cshield_cfst['always_https'] ? 'pass' : 'warn'; ?>">
				<span class="cshield-badge"><?php esc_html_e( 'HTTPS', 'chaos-shield' ); ?></span>
				<div class="cshield-finding">
					<strong><?php esc_html_e( 'Always Use HTTPS', 'chaos-shield' ); ?></strong>
					<p><?php echo esc_html( 'on' === $cshield_cfst['always_https'] ? __( 'On. Cloudflare sends http visitors to HTTPS.', 'chaos-shield' ) : __( 'Off. Visitors who type http:// stay on plain http.', 'chaos-shield' ) ); ?></p>
				</div>
				<?php if ( 'on' !== $cshield_cfst['always_https'] && ! empty( $cshield_zone['can']['settings'] ) ) : ?>
					<div class="cshield-finding__action"><?php $cshield_eform( 'cf_https', __( 'Switch on', 'chaos-shield' ), 'cshield-link' ); ?></div>
				<?php endif; ?>
			</li>
			<li class="cshield-check cshield-check--<?php echo $cshield_proxy ? 'pass' : 'warn'; ?>">
				<span class="cshield-badge"><?php esc_html_e( 'IP', 'chaos-shield' ); ?></span>
				<div class="cshield-finding">
					<strong><?php esc_html_e( 'Visitor IPs', 'chaos-shield' ); ?></strong>
					<p>
						<?php
						if ( $cshield_proxy ) {
							esc_html_e( 'Read from Cloudflare\'s CF-Connecting-IP header, trusted only from Cloudflare\'s own addresses.', 'chaos-shield' );
						} elseif ( Cloudflare::in_front() ) {
							esc_html_e( 'Requests come through Cloudflare, but the plugin still reads Cloudflare\'s address instead of the visitor\'s, so bans would hit Cloudflare.', 'chaos-shield' );
						} else {
							esc_html_e( 'This request did not come through Cloudflare. Point the domain\'s name servers at Cloudflare and switch on the orange cloud for it, then read visitor IPs from Cloudflare.', 'chaos-shield' );
						}
						?>
					</p>
				</div>
				<?php if ( ! $cshield_proxy ) : ?>
					<div class="cshield-finding__action"><?php $cshield_eform( 'cf_ip', __( 'Use Cloudflare\'s visitor IP', 'chaos-shield' ), 'cshield-link' ); ?></div>
				<?php endif; ?>
			</li>
			<li class="cshield-check cshield-check--<?php echo 'under_attack' === $cshield_cfst['security_level'] ? 'warn' : 'pass'; ?>">
				<span class="cshield-badge"><?php esc_html_e( 'Level', 'chaos-shield' ); ?></span>
				<div class="cshield-finding">
					<strong><?php echo esc_html( isset( $cshield_levels[ $cshield_cfst['security_level'] ] ) ? $cshield_levels[ $cshield_cfst['security_level'] ] : __( 'Unknown', 'chaos-shield' ) ); ?></strong>
					<p><?php esc_html_e( 'Cloudflare\'s security level. Under attack mode raises it to Under Attack while it lasts.', 'chaos-shield' ); ?></p>
				</div>
			</li>
		</ul>
		<div class="cshield-inline-actions cshield-cf-actions">
			<?php
			$cshield_eform( 'cf_sync', __( 'Sync now', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' );
			$cshield_eform( 'cf_purge', __( 'Clear Cloudflare cache', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', array(), __( 'Clear every cached page and file at Cloudflare? The site may be slower for a few minutes.', 'chaos-shield' ) );
			?>
		</div>
		<?php $cshield_open( array( 'cf_sync_bans' ) ); ?>
			<ul class="cshield-optlist">
				<?php $cshield_box( 'cf_sync_bans', __( 'Send bans and single blocked IPs to Cloudflare', 'chaos-shield' ), __( 'Added as IP Access rules marked Chaos Shield. They come off again when the ban ends, when you disconnect, and when the plugin is deactivated.', 'chaos-shield' ) ); ?>
			</ul>
		<?php $cshield_close(); ?>
	<?php endif; ?>

	<details class="cshield-diff cshield-others">
		<summary><?php esc_html_e( 'Using another firewall or CDN?', 'chaos-shield' ); ?></summary>
		<p class="cshield-small"><?php esc_html_e( 'Sucuri, Bunny, Fastly, a load balancer or your host\'s firewall can sit in front of the site too. Two things make them work with Chaos Shield:', 'chaos-shield' ); ?></p>
		<ol class="cshield-steps">
			<li>
				<?php esc_html_e( 'Tell the plugin which header carries the visitor IP, so bans hit the visitor and not the service.', 'chaos-shield' ); ?>
				<a href="<?php echo esc_url( Admin::url( 'access' ) ); ?>"><?php esc_html_e( 'Set it under Access', 'chaos-shield' ); ?></a>
			</li>
			<li>
				<?php esc_html_e( 'Let the service or your server firewall download the ban list. It is a private address that lists every banned and blocked IP, one per line; CSF, ipset scripts, pfSense and most firewalls can read it on a schedule.', 'chaos-shield' ); ?>
				<?php $cshield_open( array( 'ban_feed' ) ); ?>
					<ul class="cshield-optlist">
						<?php $cshield_box( 'ban_feed', __( 'Publish the ban list at a private address', 'chaos-shield' ) ); ?>
					</ul>
				<?php $cshield_close(); ?>
				<?php if ( Settings::get( 'ban_feed' ) ) : ?>
					<div class="cshield-copy">
						<input type="text" readonly value="<?php echo esc_attr( Edge::feed_url() ); ?>" class="cshield-copy__input" aria-label="<?php esc_attr_e( 'Ban list address', 'chaos-shield' ); ?>" onclick="this.select()">
						<button type="button" class="cshield-btn cshield-btn--ghost" data-copy><?php esc_html_e( 'Copy', 'chaos-shield' ); ?></button>
						<?php $cshield_eform( 'feed_new', __( 'New address', 'chaos-shield' ), 'cshield-link', array(), __( 'Make a new address? The old one stops working, so update the services that read it.', 'chaos-shield' ) ); ?>
					</div>
				<?php endif; ?>
			</li>
		</ol>
	</details>
</section>

<section class="cshield-card cshield-card--full" id="cshield-https">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'HTTPS', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'Certificates come from your host or Cloudflare, and most give them free. The plugin watches the one you have, warns two weeks before it lapses, and keeps visitors on HTTPS.', 'chaos-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! $cshield_https['checked'] ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'Not checked yet. Choose Check now at the top.', 'chaos-shield' ); ?></p>
	<?php elseif ( ! $cshield_https['site_https'] ) : ?>
		<div class="cshield-notice cshield-notice--warn" role="status"><?php esc_html_e( 'The site address starts with http://, so logins and cookies travel unencrypted. Get a free certificate from your host or Cloudflare, then change both addresses under Settings, General to https://.', 'chaos-shield' ); ?></div>
	<?php else : ?>
		<?php
		$cshield_cert = $cshield_https['cert'];
		$cshield_days = isset( $cshield_cert['expires'] ) ? Uptime::days_left( (int) $cshield_cert['expires'] ) : null;
		$cshield_red  = $cshield_https['redirect'];
		?>
		<ul class="cshield-checks">
			<li class="cshield-check cshield-check--<?php echo null === $cshield_days || $cshield_days < 0 || empty( $cshield_cert['trusted'] ) ? 'fail' : ( $cshield_days <= Uptime::SSL_WARN ? 'warn' : 'pass' ); ?>">
				<span class="cshield-badge"><?php echo esc_html( null === $cshield_days ? '?' : number_format_i18n( max( 0, $cshield_days ) ) ); ?></span>
				<div class="cshield-finding">
					<strong><?php esc_html_e( 'Certificate', 'chaos-shield' ); ?></strong>
					<p>
						<?php
						if ( null === $cshield_days ) {
							echo esc_html( $cshield_cert['error'] ? $cshield_cert['error'] : __( 'The certificate could not be read.', 'chaos-shield' ) );
						} else {
							printf(
								/* translators: 1: issuer, 2: date, 3: days. */
								esc_html__( 'Issued by %1$s, valid until %2$s (%3$s days left).', 'chaos-shield' ),
								esc_html( $cshield_cert['issuer'] ? $cshield_cert['issuer'] : '?' ),
								esc_html( wp_date( get_option( 'date_format' ), (int) $cshield_cert['expires'] ) ),
								esc_html( number_format_i18n( $cshield_days ) )
							);
							if ( empty( $cshield_cert['trusted'] ) ) {
								echo ' ' . esc_html__( 'Browsers do not trust it:', 'chaos-shield' ) . ' ' . esc_html( $cshield_cert['error'] );
							}
						}
						?>
					</p>
				</div>
			</li>
			<li class="cshield-check cshield-check--<?php echo ! empty( $cshield_red['ok'] ) || Settings::get( 'force_https' ) ? 'pass' : 'warn'; ?>">
				<span class="cshield-badge"><?php echo esc_html( ! empty( $cshield_red['code'] ) ? (string) $cshield_red['code'] : '?' ); ?></span>
				<div class="cshield-finding">
					<strong><?php esc_html_e( 'http:// to https://', 'chaos-shield' ); ?></strong>
					<p><?php echo esc_html( ! empty( $cshield_red['ok'] ) ? __( 'Visitors who type http:// are sent to HTTPS.', 'chaos-shield' ) : __( 'The site still answers on plain http. Switch on the redirect below.', 'chaos-shield' ) ); ?></p>
				</div>
			</li>
			<li class="cshield-check cshield-check--<?php echo $cshield_https['mixed'] && ! Settings::get( 'https_upgrade' ) ? 'warn' : 'pass'; ?>">
				<span class="cshield-badge"><?php echo esc_html( number_format_i18n( count( $cshield_https['mixed'] ) ) ); ?></span>
				<div class="cshield-finding">
					<strong><?php esc_html_e( 'Mixed content', 'chaos-shield' ); ?></strong>
					<p><?php echo esc_html( $cshield_https['mixed'] ? __( 'These files load over plain http on HTTPS pages, so browsers block them or warn. The fix below loads them over HTTPS; changing the addresses in your content fixes them for good.', 'chaos-shield' ) : __( 'Every page checked loads its files over HTTPS.', 'chaos-shield' ) ); ?></p>
					<?php if ( $cshield_https['mixed'] ) : ?>
						<details class="cshield-diff">
							<summary><?php esc_html_e( 'Show the files', 'chaos-shield' ); ?></summary>
							<ul class="cshield-plain">
								<?php foreach ( $cshield_https['mixed'] as $cshield_m ) : ?>
									<li><code><?php echo esc_html( $cshield_m['url'] ); ?></code> <span class="cshield-small">(<?php echo esc_html( $cshield_m['tag'] . ', ' . $cshield_m['page'] ); ?>)</span></li>
								<?php endforeach; ?>
							</ul>
						</details>
					<?php endif; ?>
				</div>
			</li>
		</ul>
	<?php endif; ?>
	<?php $cshield_open( array( 'force_https', 'https_upgrade' ) ); ?>
		<ul class="cshield-optlist">
			<?php
			$cshield_box( 'force_https', __( 'Send every visitor to HTTPS', 'chaos-shield' ), __( 'Only switches on after the site answers on HTTPS with a trusted certificate, so it cannot lock you out. Works behind Cloudflare and other proxies.', 'chaos-shield' ) );
			$cshield_box( 'https_upgrade', __( 'Load http:// images and scripts over HTTPS', 'chaos-shield' ), __( 'Fixes mixed content in the browser, without changing your content.', 'chaos-shield' ) );
			?>
		</ul>
	<?php $cshield_close(); ?>
</section>

<?php
$cshield_rep      = Reputation::state();
$cshield_rep_exp  = $cshield_rep['expiry'];
$cshield_rep_days = ! empty( $cshield_rep_exp['expires'] ) ? Uptime::days_left( (int) $cshield_rep_exp['expires'] ) : null;
$cshield_rep_says = array(
	'clean'   => __( 'Not listed', 'chaos-shield' ),
	'listed'  => __( 'Listed', 'chaos-shield' ),
	'refused' => __( 'Would not answer this server', 'chaos-shield' ),
	'error'   => __( 'Could not be checked', 'chaos-shield' ),
	'skip'    => __( 'Not checked: no public address', 'chaos-shield' ),
);
?>
<section class="cshield-card cshield-card--full" id="cshield-reputation">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Reputation', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'A hacked site often ends up on spam and malware blocklists before anyone notices, and a lapsed domain takes the site and its email down. Both are checked every day.', 'chaos-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! $cshield_rep['checked'] ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'Not checked yet. Choose Check now at the top.', 'chaos-shield' ); ?></p>
	<?php else : ?>
		<ul class="cshield-checks">
			<?php if ( $cshield_rep_exp ) : ?>
				<li class="cshield-check cshield-check--<?php echo null === $cshield_rep_days ? 'warn' : ( $cshield_rep_days < 0 ? 'fail' : ( $cshield_rep_days <= Reputation::EXPIRY_WARN ? 'warn' : 'pass' ) ); ?>">
					<span class="cshield-badge"><?php echo esc_html( null === $cshield_rep_days ? '?' : number_format_i18n( max( 0, $cshield_rep_days ) ) ); ?></span>
					<div class="cshield-finding">
						<strong>
							<?php
							/* translators: %s: domain. */
							echo esc_html( sprintf( __( 'Domain %s', 'chaos-shield' ), $cshield_rep_exp['domain'] ) );
							?>
						</strong>
						<p>
							<?php
							if ( null === $cshield_rep_days ) {
								echo esc_html( $cshield_rep_exp['error'] );
							} else {
								echo esc_html(
									sprintf(
										/* translators: 1: date, 2: registrar. */
										__( 'Registered until %1$s with %2$s.', 'chaos-shield' ),
										wp_date( get_option( 'date_format' ), (int) $cshield_rep_exp['expires'] ),
										'' !== $cshield_rep_exp['registrar'] ? $cshield_rep_exp['registrar'] : __( 'an unknown registrar', 'chaos-shield' )
									) . ( $cshield_rep_days <= Reputation::EXPIRY_WARN ? ' ' . __( 'Renew it soon, and switch on automatic renewal if your registrar offers it.', 'chaos-shield' ) : '' )
								);
							}
							?>
						</p>
					</div>
				</li>
			<?php endif; ?>
			<?php foreach ( $cshield_rep['lists'] as $cshield_row ) : ?>
				<li class="cshield-check cshield-check--<?php echo 'listed' === $cshield_row['status'] ? 'fail' : ( 'clean' === $cshield_row['status'] ? 'pass' : 'warn' ); ?>">
					<span class="cshield-badge"><?php echo 'listed' === $cshield_row['status'] ? '!' : ( 'clean' === $cshield_row['status'] ? '✓' : '?' ); ?></span>
					<div class="cshield-finding">
						<strong><?php echo esc_html( $cshield_row['label'] ); ?></strong>
						<p>
							<?php echo esc_html( isset( $cshield_rep_says[ $cshield_row['status'] ] ) ? $cshield_rep_says[ $cshield_row['status'] ] : $cshield_row['status'] ); ?>
							<?php if ( 'listed' === $cshield_row['status'] ) : ?>
								<?php esc_html_e( 'Scan for malware and clean up first, then ask for a review:', 'chaos-shield' ); ?>
								<a href="<?php echo esc_url( $cshield_row['url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'removal page', 'chaos-shield' ); ?></a>
							<?php endif; ?>
						</p>
					</div>
				</li>
			<?php endforeach; ?>
		</ul>
		<p class="cshield-small">
			<?php
			echo esc_html(
				'' !== $cshield_rep['ip']
					/* translators: 1: domain, 2: IP address, 3: date and time. */
					? sprintf( __( 'Checked %1$s and its server %2$s on %3$s.', 'chaos-shield' ), $cshield_rep['domain'], $cshield_rep['ip'], wp_date( $cshield_when, (int) $cshield_rep['checked'] ) )
					/* translators: 1: domain, 2: date and time. */
					: sprintf( __( 'Checked %1$s on %2$s.', 'chaos-shield' ), $cshield_rep['domain'], wp_date( $cshield_when, (int) $cshield_rep['checked'] ) )
			);
			?>
		</p>
	<?php endif; ?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="cshield-inline-form">
		<input type="hidden" name="action" value="cshield_reputation">
		<input type="hidden" name="op" value="key">
		<?php wp_nonce_field( 'cshield_reputation' ); ?>
		<label><span><?php esc_html_e( 'Google Safe Browsing API key (optional, free)', 'chaos-shield' ); ?></span>
			<input type="password" name="gsb_key" value="" autocomplete="off" spellcheck="false" placeholder="<?php echo esc_attr( Network::get_option( Reputation::KEY, '' ) ? __( 'Saved', 'chaos-shield' ) : 'AIza…' ); ?>"></label>
		<?php if ( Network::get_option( Reputation::KEY, '' ) ) : ?>
			<label class="cshield-check-line"><input type="checkbox" name="forget" value="1"> <?php esc_html_e( 'Remove the key', 'chaos-shield' ); ?></label>
		<?php endif; ?>
		<button type="submit" class="cshield-btn cshield-btn--ghost"><?php esc_html_e( 'Save and check', 'chaos-shield' ); ?></button>
	</form>
	<p class="cshield-small"><?php esc_html_e( 'With a key, Google is also asked whether it flags the site as dangerous, the warning Chrome and Google Search show. Create one in the Google Cloud console with the Safe Browsing API switched on.', 'chaos-shield' ); ?></p>
	<?php $cshield_open( array( 'reputation_check' ) ); ?>
		<ul class="cshield-optlist">
			<?php $cshield_box( 'reputation_check', __( 'Check blocklists and the domain every day', 'chaos-shield' ) ); ?>
		</ul>
	<?php $cshield_close(); ?>
</section>

<section class="cshield-card cshield-card--full" id="cshield-scripts">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Page scripts', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'Every script your pages load, from your site and from others. Card skimmers and injected ads arrive as one extra script, so a new one alerts you. Scripts found on the first look are approved; later ones wait for you.', 'chaos-shield' ); ?></p>
		</div>
		<?php if ( $cshield_counts['new'] > 1 ) : ?>
			<div class="cshield-inline-actions"><?php $cshield_eform( 'approve_all', __( 'Approve all new', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost', array(), __( 'Approve every new script the page check found? Only do this if you added them. Browser reports are approved one by one.', 'chaos-shield' ) ); ?></div>
		<?php endif; ?>
	</div>
	<?php if ( ! Settings::enabled( 'script_watch' ) ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'The page script monitor is off.', 'chaos-shield' ); ?></p>
	<?php elseif ( ! $cshield_sc['checked'] && ! $cshield_sc['items'] ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'No scripts listed yet. Choose Check now at the top.', 'chaos-shield' ); ?></p>
	<?php else : ?>
		<p class="cshield-small">
			<?php
			printf(
				/* translators: 1: total, 2: new, 3: blocked, 4: flagged. */
				esc_html__( '%1$s scripts: %2$s new, %3$s blocked, %4$s look harmful.', 'chaos-shield' ),
				esc_html( number_format_i18n( $cshield_counts['total'] ) ),
				esc_html( number_format_i18n( $cshield_counts['new'] ) ),
				esc_html( number_format_i18n( $cshield_counts['blocked'] ) ),
				esc_html( number_format_i18n( $cshield_counts['flagged'] ) )
			);
			?>
		</p>
		<div class="cshield-table-wrap">
			<table class="cshield-table cshield-table--scripts">
				<thead><tr><th><?php esc_html_e( 'Status', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Script', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'Pages', 'chaos-shield' ); ?></th><th><?php esc_html_e( 'First seen', 'chaos-shield' ); ?></th><th><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'chaos-shield' ); ?></span></th></tr></thead>
				<tbody>
					<?php foreach ( Scripts::items() as $cshield_key => $cshield_it ) : ?>
						<?php
						$cshield_states = array(
							'new'      => __( 'New', 'chaos-shield' ),
							'approved' => __( 'Approved', 'chaos-shield' ),
							'blocked'  => __( 'Blocked', 'chaos-shield' ),
						);
						$cshield_tone   = $cshield_it['flag'] ? 'fail' : ( 'new' === $cshield_it['status'] ? 'warn' : ( 'blocked' === $cshield_it['status'] ? 'blocked' : 'pass' ) );
						$cshield_kinds  = array(
							'own'      => __( 'This site', 'chaos-shield' ),
							'external' => __( 'Outside service', 'chaos-shield' ),
							'report'   => __( 'Reported by a browser', 'chaos-shield' ),
							'inline'   => __( 'In the page', 'chaos-shield' ),
							'keyword'  => __( 'Reported by a browser', 'chaos-shield' ),
						);
						?>
						<tr class="is-<?php echo esc_attr( $cshield_tone ); ?>">
							<td><span class="cshield-pill cshield-pill--<?php echo esc_attr( $cshield_tone ); ?>"><?php echo esc_html( isset( $cshield_states[ $cshield_it['status'] ] ) ? $cshield_states[ $cshield_it['status'] ] : $cshield_it['status'] ); ?></span></td>
							<td>
								<code class="cshield-break"><?php echo esc_html( Scripts::label( $cshield_it ) ); ?></code>
								<span class="cshield-small"><?php echo esc_html( isset( $cshield_kinds[ $cshield_it['kind'] ] ) ? $cshield_kinds[ $cshield_it['kind'] ] : '' ); ?><?php echo $cshield_it['changed'] ? ' · ' . esc_html__( 'content changed since approved', 'chaos-shield' ) : ''; ?></span>
								<?php if ( $cshield_it['flag'] ) : ?>
									<strong class="cshield-flag"><?php echo esc_html( $cshield_it['flag'] ); ?></strong>
								<?php endif; ?>
								<?php if ( ! empty( $cshield_it['snippet'] ) ) : ?>
									<code class="cshield-small cshield-break"><?php echo esc_html( $cshield_it['snippet'] ); ?></code>
								<?php endif; ?>
							</td>
							<td><span class="cshield-small"><?php echo esc_html( implode( ', ', $cshield_it['pages'] ) ); ?></span></td>
							<td><span class="cshield-small"><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $cshield_it['first'] ) ); ?></span></td>
							<td class="cshield-inline-actions">
								<?php
								if ( 'approved' !== $cshield_it['status'] || $cshield_it['flag'] ) {
									$cshield_eform( 'approve', __( 'Approve', 'chaos-shield' ), 'cshield-link', array( 'script[]' => $cshield_key ) );
								}
								if ( 'blocked' !== $cshield_it['status'] && 'own' !== $cshield_it['kind'] && 'inline' !== $cshield_it['kind'] ) {
									$cshield_eform( 'block', __( 'Block', 'chaos-shield' ), 'cshield-link cshield-link--danger', array( 'script[]' => $cshield_key ) );
								}
								$cshield_eform( 'forget', __( 'Remove', 'chaos-shield' ), 'cshield-link', array( 'script[]' => $cshield_key ) );
								?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<p class="cshield-small"><?php esc_html_e( 'Remove takes a script off the list; it comes back as new if your pages still load it. Blocking works for a whole domain and only takes effect with the policy below set to Enforce.', 'chaos-shield' ); ?></p>
	<?php endif; ?>
	<?php $cshield_open( array( 'script_watch', 'csp_mode' ) ); ?>
		<ul class="cshield-optlist">
			<?php $cshield_box( 'script_watch', __( 'Watch the scripts on my pages', 'chaos-shield' ) ); ?>
		</ul>
		<fieldset class="cshield-radio-group">
			<legend><?php esc_html_e( 'Content Security Policy for scripts', 'chaos-shield' ); ?></legend>
			<?php
			$cshield_modes = array(
				'off'     => array( __( 'Off', 'chaos-shield' ), __( 'Browsers run any script a page loads.', 'chaos-shield' ) ),
				'report'  => array( __( 'Report only', 'chaos-shield' ), __( 'Browsers report scripts that are not approved, including ones other scripts load later, without stopping them. Start here for a week.', 'chaos-shield' ) ),
				'enforce' => array( __( 'Enforce', 'chaos-shield' ), __( 'Browsers refuse scripts from domains you have not approved. New scripts are blocked until you approve them. Editors only get reports, so page builders keep working.', 'chaos-shield' ) ),
			);
			foreach ( $cshield_modes as $cshield_mode => $cshield_m ) :
				?>
				<label class="cshield-radio"><input type="radio" name="cshield[csp_mode]" value="<?php echo esc_attr( $cshield_mode ); ?>" <?php checked( Settings::get( 'csp_mode' ), $cshield_mode ); ?>> <strong><?php echo esc_html( $cshield_m[0] ); ?></strong> <span class="cshield-small"><?php echo esc_html( $cshield_m[1] ); ?></span></label>
			<?php endforeach; ?>
		</fieldset>
		<?php if ( 'off' !== Settings::get( 'csp_mode' ) ) : ?>
			<p class="cshield-small">
				<?php
				/* translators: %s: number of reports. */
				echo esc_html( sprintf( __( 'Reports received: %s.', 'chaos-shield' ), number_format_i18n( (int) $cshield_sc['reports'] ) ) );
				?>
			</p>
			<code class="cshield-small cshield-break"><?php echo esc_html( Scripts::policy() ); ?></code>
		<?php endif; ?>
	<?php $cshield_close(); ?>
</section>

<section class="cshield-card cshield-card--full" id="cshield-exposure">
	<div class="cshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Exposed files and keys', 'chaos-shield' ); ?></h2>
			<p><?php esc_html_e( 'Backups, database dumps, logs, .env and .git folders left where anyone can download them are one of the easiest ways into a site. Each is asked for over the web every day, and your pages and scripts are searched for secret keys.', 'chaos-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! Settings::enabled( 'exposure_check' ) ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'The check is off.', 'chaos-shield' ); ?></p>
	<?php elseif ( ! $cshield_exp['checked'] ) : ?>
		<p class="cshield-empty"><?php esc_html_e( 'Not checked yet. Choose Check now at the top.', 'chaos-shield' ); ?></p>
	<?php elseif ( ! $cshield_exp['files'] && ! $cshield_exp['keys'] ) : ?>
		<p class="cshield-empty cshield-empty--ok"><?php esc_html_e( 'Nothing private can be downloaded, and no keys show in your pages.', 'chaos-shield' ); ?></p>
	<?php else : ?>
		<ul class="cshield-checks cshield-findings">
			<?php foreach ( $cshield_exp['keys'] as $cshield_k ) : ?>
				<li class="cshield-check cshield-check--fail">
					<span class="cshield-badge"><?php esc_html_e( 'Key', 'chaos-shield' ); ?></span>
					<div class="cshield-finding">
						<strong><?php echo esc_html( $cshield_k['type'] ); ?> <code><?php echo esc_html( $cshield_k['masked'] ); ?></code></strong>
						<p>
							<?php
							/* translators: %s: page or script. */
							echo esc_html( sprintf( __( 'Visible to anyone in %s. Replace it with a new key at the service that issued it, then remove it from the page or script: it may already have been copied.', 'chaos-shield' ), $cshield_k['where'] ) );
							?>
						</p>
					</div>
				</li>
			<?php endforeach; ?>
			<?php foreach ( $cshield_exp['files'] as $cshield_f ) : ?>
				<li class="cshield-check cshield-check--<?php echo $cshield_f['public'] ? 'fail' : 'warn'; ?>">
					<span class="cshield-badge"><?php echo esc_html( $cshield_f['public'] ? __( 'Public', 'chaos-shield' ) : __( 'On server', 'chaos-shield' ) ); ?></span>
					<div class="cshield-finding">
						<strong><code><?php echo esc_html( $cshield_f['path'] ); ?></code></strong>
						<p>
							<?php
							echo esc_html( Exposure::describe( $cshield_f['kind'] ) . '. ' );
							echo esc_html( $cshield_f['public'] ? __( 'Anyone can download it right now.', 'chaos-shield' ) : __( 'It cannot be downloaded now, but it sits in a public folder: one server change and it could be.', 'chaos-shield' ) );
							if ( $cshield_f['size'] ) {
								echo ' ' . esc_html( size_format( $cshield_f['size'] ) );
							}
							?>
						</p>
					</div>
					<?php if ( $cshield_f['local'] && is_file( ABSPATH . $cshield_f['path'] ) && 'listing' !== $cshield_f['kind'] && 'git' !== $cshield_f['kind'] ) : ?>
						<div class="cshield-finding__action">
							<?php $cshield_eform( 'delete_file', __( 'Delete', 'chaos-shield' ), 'cshield-link cshield-link--danger', array( 'file' => $cshield_f['id'] ), __( 'Delete this file for good? Download it first if you still need it.', 'chaos-shield' ) ); ?>
						</div>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php endif; ?>
	<?php if ( Settings::enabled( 'exposure_check' ) ) : ?>
		<div class="cshield-exposure-block">
			<?php if ( Exposure::apache() ) : ?>
				<p class="cshield-small">
					<?php
					echo esc_html(
						Exposure::protected_now()
							? __( 'Blocked in .htaccess: hidden files, .git, backups, dumps and logs cannot be downloaded, and folder listings are off.', 'chaos-shield' )
							: __( 'Block downloads of hidden files, .git, backups, dumps and logs for good with a few lines in the site\'s .htaccess. The home page is checked right after, and the lines are taken out again if the server objects.', 'chaos-shield' )
					);
					?>
				</p>
				<?php
				if ( Exposure::protected_now() ) {
					$cshield_eform( 'unprotect', __( 'Remove the block', 'chaos-shield' ), 'cshield-link' );
				} else {
					$cshield_eform( 'protect', __( 'Block these files', 'chaos-shield' ), 'cshield-btn cshield-btn--ghost' );
				}
				?>
			<?php else : ?>
				<details class="cshield-diff">
					<summary><?php esc_html_e( 'Block these files on nginx', 'chaos-shield' ); ?></summary>
					<p class="cshield-small"><?php esc_html_e( 'This server does not read .htaccess. Add these lines to the site\'s server block, or ask your host to:', 'chaos-shield' ); ?></p>
					<pre class="cshield-snippet"><?php echo esc_html( Exposure::nginx() ); ?></pre>
				</details>
			<?php endif; ?>
		</div>
	<?php endif; ?>
	<?php $cshield_open( array( 'exposure_check' ) ); ?>
		<ul class="cshield-optlist">
			<?php $cshield_box( 'exposure_check', __( 'Check every day for exposed files and keys', 'chaos-shield' ) ); ?>
		</ul>
	<?php $cshield_close(); ?>
</section>
