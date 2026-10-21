<?php
/**
 * Edge tab: under attack mode, Cloudflare and other edge services, HTTPS, page scripts and exposed files.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

$sshield_when   = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
$sshield_attack = Attack_Mode::state();
$sshield_on     = Attack_Mode::active();
$sshield_check  = Page_Check::state();
$sshield_https  = Https::state();
$sshield_exp    = Exposure::state();
$sshield_sc     = Scripts::state();
$sshield_counts = Scripts::counts();
$sshield_cf     = Cloudflare::connected();
$sshield_cfst   = Cloudflare::status();
$sshield_zone   = Cloudflare::zone();
$sshield_eform  = static function ( $op, $label, $css, array $extra = array(), $confirm = '' ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-inline-form"<?php echo $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : ''; ?>>
		<input type="hidden" name="action" value="<?php echo esc_attr( Edge::ACTION ); ?>">
		<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
		<?php foreach ( $extra as $sshield_k => $sshield_v ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $sshield_k ); ?>" value="<?php echo esc_attr( $sshield_v ); ?>">
		<?php endforeach; ?>
		<?php wp_nonce_field( Edge::ACTION ); ?>
		<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
	</form>
	<?php
};
// Opens a settings form that saves only the fields it names.
$sshield_open  = static function ( array $fields ) {
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="sshield-edge-form">
		<input type="hidden" name="action" value="<?php echo esc_attr( Edge::ACTION ); ?>">
		<input type="hidden" name="op" value="save">
		<input type="hidden" name="fields" value="<?php echo esc_attr( implode( ',', $fields ) ); ?>">
		<?php wp_nonce_field( Edge::ACTION ); ?>
	<?php
};
$sshield_close = static function () {
	?>
		<div class="sshield-actions sshield-actions--inline"><button type="submit" class="sshield-btn sshield-btn--ghost"><?php esc_html_e( 'Save', 'sentinel-shield' ); ?></button></div>
	</form>
	<?php
};
$sshield_box   = static function ( $key, $label, $hint = '' ) {
	?>
	<li><label><input type="checkbox" name="sshield[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( (bool) Settings::get( $key ) ); ?>> <?php echo esc_html( $label ); ?></label>
		<?php if ( $hint ) : ?>
			<span class="sshield-small"><?php echo esc_html( $hint ); ?></span>
		<?php endif; ?>
	</li>
	<?php
};
?>
<div class="sshield-edge-head">
	<p class="sshield-small">
		<?php
		if ( $sshield_check ) {
			printf(
				/* translators: 1: date and time, 2: number of pages. */
				esc_html__( 'Your pages were last looked at from outside on %1$s (%2$s pages). This runs every day.', 'sentinel-shield' ),
				esc_html( wp_date( $sshield_when, (int) $sshield_check['checked'] ) ),
				esc_html( number_format_i18n( count( $sshield_check['pages'] ) ) )
			);
		} else {
			esc_html_e( 'Your pages have not been looked at from outside yet. It runs every day, or choose Check now.', 'sentinel-shield' );
		}
		?>
	</p>
	<?php $sshield_eform( 'check', __( 'Check now', 'sentinel-shield' ), 'sshield-btn' ); ?>
</div>
<?php if ( $sshield_check && 'none' === $sshield_check['error'] ) : ?>
	<div class="sshield-notice sshield-notice--warn" role="alert"><?php esc_html_e( 'The site could not load its own pages, so scripts, mixed content and keys were not checked. Some hosts block a site from calling itself; ask your host to allow it.', 'sentinel-shield' ); ?></div>
<?php endif; ?>

<section class="sshield-card sshield-card--full<?php echo $sshield_on ? ' sshield-card--alert' : ''; ?>" id="sshield-attack">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Under attack mode', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'Puts a one-second browser check in front of the site. People pass on their own and keep the pass for 12 hours; bots and scripts that flood the site never reach WordPress. Logged-in users, the allow list, Google and Bing are never checked.', 'sentinel-shield' ); ?></p>
		</div>
		<div class="sshield-inline-actions">
			<?php
			if ( $sshield_on ) {
				$sshield_eform( 'attack_off', __( 'Switch off', 'sentinel-shield' ), 'sshield-btn' );
			} else {
				$sshield_eform( 'attack_on', __( 'Switch on now', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', array(), __( 'Every visitor who is not logged in will see a short browser check. Switch it on?', 'sentinel-shield' ) );
			}
			?>
		</div>
	</div>
	<?php if ( $sshield_on ) : ?>
		<div class="sshield-notice sshield-notice--warn" role="status">
			<?php
			echo esc_html(
				$sshield_attack['auto']
					/* translators: 1: date and time it started, 2: time it ends. */
					? sprintf( __( 'On since %1$s, switched on by the flood detector. It ends on its own at %2$s if the flood has stopped.', 'sentinel-shield' ), wp_date( $sshield_when, (int) $sshield_attack['since'] ), wp_date( get_option( 'time_format' ), (int) $sshield_attack['until'] ) )
					/* translators: %s: date and time. */
					: sprintf( __( 'On since %s, switched on by hand. It stays on until you switch it off.', 'sentinel-shield' ), wp_date( $sshield_when, (int) $sshield_attack['since'] ) )
			);
			?>
		</div>
	<?php elseif ( $sshield_attack['last'] ) : ?>
		<p class="sshield-small">
			<?php
			/* translators: %s: date and time. */
			echo esc_html( sprintf( __( 'Last ended %s.', 'sentinel-shield' ), wp_date( $sshield_when, (int) $sshield_attack['last'] ) ) );
			?>
		</p>
	<?php endif; ?>
	<?php $sshield_open( array( 'attack_auto', 'attack_threshold', 'cf_attack_sync' ) ); ?>
		<ul class="sshield-optlist">
			<li>
				<label><input type="checkbox" name="sshield[attack_auto]" value="1" <?php checked( Settings::enabled( 'attack_auto' ) ); ?>> <?php esc_html_e( 'Switch on by itself during a flood', 'sentinel-shield' ); ?></label>
				<label class="sshield-inline-field"><?php esc_html_e( 'when more than', 'sentinel-shield' ); ?> <input type="number" name="sshield[attack_threshold]" min="20" max="10000" value="<?php echo esc_attr( Settings::get( 'attack_threshold' ) ); ?>" class="small-text"> <?php esc_html_e( 'requests are blocked in a minute', 'sentinel-shield' ); ?></label>
			</li>
			<li><label><input type="checkbox" name="sshield[cf_attack_sync]" value="1" <?php checked( (bool) Settings::get( 'cf_attack_sync' ) ); ?><?php disabled( ! $sshield_cf ); ?>> <?php esc_html_e( 'Switch on Cloudflare\'s Under Attack mode at the same time', 'sentinel-shield' ); ?></label>
				<span class="sshield-small"><?php echo esc_html( $sshield_cf ? __( 'Stops the flood before it reaches your server, and is set back to what it was afterwards.', 'sentinel-shield' ) : __( 'Connect Cloudflare below first.', 'sentinel-shield' ) ); ?></span>
			</li>
		</ul>
		<p class="sshield-small"><?php esc_html_e( 'A plugin can only answer requests that reach the server. A flood big enough to fill the server\'s connection has to be stopped before that, by Cloudflare or your host.', 'sentinel-shield' ); ?></p>
	<?php $sshield_close(); ?>
</section>

<section class="sshield-card sshield-card--full" id="sshield-cloudflare">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Cloudflare and other edge services', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'For what no plugin can do on the server: large floods, a worldwide cache and free certificates. With Cloudflare connected, banned and blocked IPs are refused at Cloudflare before they reach you.', 'sentinel-shield' ); ?></p>
		</div>
	</div>
	<?php
	$sshield_kind = 'edge';
	require SSHIELD_DIR . 'includes/views/connections.php';
	?>
	<?php if ( $sshield_cf ) : ?>
		<?php
		$sshield_ssl_names = array(
			'off'      => __( 'Off', 'sentinel-shield' ),
			'flexible' => __( 'Flexible', 'sentinel-shield' ),
			'full'     => __( 'Full', 'sentinel-shield' ),
			'strict'   => __( 'Full (strict)', 'sentinel-shield' ),
		);
		$sshield_levels    = array(
			'essentially_off' => __( 'Essentially off', 'sentinel-shield' ),
			'low'             => __( 'Low', 'sentinel-shield' ),
			'medium'          => __( 'Medium', 'sentinel-shield' ),
			'high'            => __( 'High', 'sentinel-shield' ),
			'under_attack'    => __( 'Under Attack', 'sentinel-shield' ),
		);
		$sshield_rules     = Cloudflare::rules();
		$sshield_proxy     = 'HTTP_CF_CONNECTING_IP' === Settings::get( 'proxy_header' );
		?>
		<ul class="sshield-checks sshield-cf-status">
			<li class="sshield-check sshield-check--<?php echo empty( $sshield_zone['can']['firewall'] ) ? 'warn' : ( $sshield_cfst['error'] ? 'warn' : 'pass' ); ?>">
				<span class="sshield-badge"><?php echo esc_html( number_format_i18n( count( $sshield_rules ) ) ); ?></span>
				<div class="sshield-finding">
					<strong><?php esc_html_e( 'IPs blocked at Cloudflare', 'sentinel-shield' ); ?></strong>
					<p>
						<?php
						if ( empty( $sshield_zone['can']['firewall'] ) ) {
							esc_html_e( 'The token cannot edit IP Access rules. Add Firewall Services: Edit to it and connect again.', 'sentinel-shield' );
						} elseif ( ! Settings::get( 'cf_sync_bans' ) ) {
							esc_html_e( 'Sending bans to Cloudflare is off.', 'sentinel-shield' );
						} else {
							echo esc_html( $sshield_cfst['synced'] ? sprintf( /* translators: %s: date and time. */ __( 'Bans and single blocked IPs are sent within a minute and removed when they end. Last sync %s.', 'sentinel-shield' ), wp_date( $sshield_when, (int) $sshield_cfst['synced'] ) ) : __( 'Bans and single blocked IPs are sent within a minute and removed when they end.', 'sentinel-shield' ) );
						}
						if ( $sshield_cfst['error'] ) {
							echo ' ' . esc_html( $sshield_cfst['error'] );
						}
						?>
					</p>
				</div>
			</li>
			<li class="sshield-check sshield-check--<?php echo in_array( $sshield_cfst['ssl'], array( 'full', 'strict' ), true ) ? 'pass' : 'warn'; ?>">
				<span class="sshield-badge"><?php esc_html_e( 'SSL', 'sentinel-shield' ); ?></span>
				<div class="sshield-finding">
					<strong><?php echo esc_html( isset( $sshield_ssl_names[ $sshield_cfst['ssl'] ] ) ? $sshield_ssl_names[ $sshield_cfst['ssl'] ] : __( 'Unknown', 'sentinel-shield' ) ); ?></strong>
					<p>
						<?php
						if ( 'strict' === $sshield_cfst['ssl'] ) {
							esc_html_e( 'Visitors and Cloudflare both talk to your server over checked HTTPS. This is the best setting.', 'sentinel-shield' );
						} elseif ( 'full' === $sshield_cfst['ssl'] ) {
							esc_html_e( 'Encrypted all the way, but Cloudflare does not check your server\'s certificate. Choose Full (strict) in Cloudflare under SSL/TLS once the server has a valid certificate.', 'sentinel-shield' );
						} elseif ( 'flexible' === $sshield_cfst['ssl'] ) {
							esc_html_e( 'Traffic between Cloudflare and your server is not encrypted, and logins can leak there. Install a certificate on the server (or a free Cloudflare Origin Certificate) and choose Full (strict).', 'sentinel-shield' );
						} else {
							esc_html_e( 'HTTPS is off or could not be read. Choose Full (strict) in Cloudflare under SSL/TLS.', 'sentinel-shield' );
						}
						?>
					</p>
				</div>
			</li>
			<li class="sshield-check sshield-check--<?php echo 'on' === $sshield_cfst['always_https'] ? 'pass' : 'warn'; ?>">
				<span class="sshield-badge"><?php esc_html_e( 'HTTPS', 'sentinel-shield' ); ?></span>
				<div class="sshield-finding">
					<strong><?php esc_html_e( 'Always Use HTTPS', 'sentinel-shield' ); ?></strong>
					<p><?php echo esc_html( 'on' === $sshield_cfst['always_https'] ? __( 'On. Cloudflare sends http visitors to HTTPS.', 'sentinel-shield' ) : __( 'Off. Visitors who type http:// stay on plain http.', 'sentinel-shield' ) ); ?></p>
				</div>
				<?php if ( 'on' !== $sshield_cfst['always_https'] && ! empty( $sshield_zone['can']['settings'] ) ) : ?>
					<div class="sshield-finding__action"><?php $sshield_eform( 'cf_https', __( 'Switch on', 'sentinel-shield' ), 'sshield-link' ); ?></div>
				<?php endif; ?>
			</li>
			<li class="sshield-check sshield-check--<?php echo $sshield_proxy ? 'pass' : 'warn'; ?>">
				<span class="sshield-badge"><?php esc_html_e( 'IP', 'sentinel-shield' ); ?></span>
				<div class="sshield-finding">
					<strong><?php esc_html_e( 'Visitor IPs', 'sentinel-shield' ); ?></strong>
					<p>
						<?php
						if ( $sshield_proxy ) {
							esc_html_e( 'Read from Cloudflare\'s CF-Connecting-IP header, trusted only from Cloudflare\'s own addresses.', 'sentinel-shield' );
						} elseif ( Cloudflare::in_front() ) {
							esc_html_e( 'Requests come through Cloudflare, but the plugin still reads Cloudflare\'s address instead of the visitor\'s, so bans would hit Cloudflare.', 'sentinel-shield' );
						} else {
							esc_html_e( 'This request did not come through Cloudflare. Point the domain\'s name servers at Cloudflare and switch on the orange cloud for it, then read visitor IPs from Cloudflare.', 'sentinel-shield' );
						}
						?>
					</p>
				</div>
				<?php if ( ! $sshield_proxy ) : ?>
					<div class="sshield-finding__action"><?php $sshield_eform( 'cf_ip', __( 'Use Cloudflare\'s visitor IP', 'sentinel-shield' ), 'sshield-link' ); ?></div>
				<?php endif; ?>
			</li>
			<li class="sshield-check sshield-check--<?php echo 'under_attack' === $sshield_cfst['security_level'] ? 'warn' : 'pass'; ?>">
				<span class="sshield-badge"><?php esc_html_e( 'Level', 'sentinel-shield' ); ?></span>
				<div class="sshield-finding">
					<strong><?php echo esc_html( isset( $sshield_levels[ $sshield_cfst['security_level'] ] ) ? $sshield_levels[ $sshield_cfst['security_level'] ] : __( 'Unknown', 'sentinel-shield' ) ); ?></strong>
					<p><?php esc_html_e( 'Cloudflare\'s security level. Under attack mode raises it to Under Attack while it lasts.', 'sentinel-shield' ); ?></p>
				</div>
			</li>
		</ul>
		<div class="sshield-inline-actions sshield-cf-actions">
			<?php
			$sshield_eform( 'cf_sync', __( 'Sync now', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' );
			$sshield_eform( 'cf_purge', __( 'Clear Cloudflare cache', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', array(), __( 'Clear every cached page and file at Cloudflare? The site may be slower for a few minutes.', 'sentinel-shield' ) );
			?>
		</div>
		<?php $sshield_open( array( 'cf_sync_bans' ) ); ?>
			<ul class="sshield-optlist">
				<?php $sshield_box( 'cf_sync_bans', __( 'Send bans and single blocked IPs to Cloudflare', 'sentinel-shield' ), __( 'Added as IP Access rules marked Sentinel Shield. They come off again when the ban ends, when you disconnect, and when the plugin is deactivated.', 'sentinel-shield' ) ); ?>
			</ul>
		<?php $sshield_close(); ?>
	<?php endif; ?>

	<details class="sshield-diff sshield-others">
		<summary><?php esc_html_e( 'Using another firewall or CDN?', 'sentinel-shield' ); ?></summary>
		<p class="sshield-small"><?php esc_html_e( 'Sucuri, Bunny, Fastly, a load balancer or your host\'s firewall can sit in front of the site too. Two things make them work with Sentinel Shield:', 'sentinel-shield' ); ?></p>
		<ol class="sshield-steps">
			<li>
				<?php esc_html_e( 'Tell the plugin which header carries the visitor IP, so bans hit the visitor and not the service.', 'sentinel-shield' ); ?>
				<a href="<?php echo esc_url( Admin::url( 'access' ) ); ?>"><?php esc_html_e( 'Set it under Access', 'sentinel-shield' ); ?></a>
			</li>
			<li>
				<?php esc_html_e( 'Let the service or your server firewall download the ban list. It is a private address that lists every banned and blocked IP, one per line; CSF, ipset scripts, pfSense and most firewalls can read it on a schedule.', 'sentinel-shield' ); ?>
				<?php $sshield_open( array( 'ban_feed' ) ); ?>
					<ul class="sshield-optlist">
						<?php $sshield_box( 'ban_feed', __( 'Publish the ban list at a private address', 'sentinel-shield' ) ); ?>
					</ul>
				<?php $sshield_close(); ?>
				<?php if ( Settings::get( 'ban_feed' ) ) : ?>
					<div class="sshield-copy">
						<input type="text" readonly value="<?php echo esc_attr( Edge::feed_url() ); ?>" class="sshield-copy__input" aria-label="<?php esc_attr_e( 'Ban list address', 'sentinel-shield' ); ?>" onclick="this.select()">
						<button type="button" class="sshield-btn sshield-btn--ghost" data-copy><?php esc_html_e( 'Copy', 'sentinel-shield' ); ?></button>
						<?php $sshield_eform( 'feed_new', __( 'New address', 'sentinel-shield' ), 'sshield-link', array(), __( 'Make a new address? The old one stops working, so update the services that read it.', 'sentinel-shield' ) ); ?>
					</div>
				<?php endif; ?>
			</li>
		</ol>
	</details>
</section>

<section class="sshield-card sshield-card--full" id="sshield-https">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'HTTPS', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'Certificates come from your host or Cloudflare, and most give them free. The plugin watches the one you have, warns two weeks before it lapses, and keeps visitors on HTTPS.', 'sentinel-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! $sshield_https['checked'] ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'Not checked yet. Choose Check now at the top.', 'sentinel-shield' ); ?></p>
	<?php elseif ( ! $sshield_https['site_https'] ) : ?>
		<div class="sshield-notice sshield-notice--warn" role="status"><?php esc_html_e( 'The site address starts with http://, so logins and cookies travel unencrypted. Get a free certificate from your host or Cloudflare, then change both addresses under Settings, General to https://.', 'sentinel-shield' ); ?></div>
	<?php else : ?>
		<?php
		$sshield_cert = $sshield_https['cert'];
		$sshield_days = isset( $sshield_cert['expires'] ) ? Uptime::days_left( (int) $sshield_cert['expires'] ) : null;
		$sshield_red  = $sshield_https['redirect'];
		?>
		<ul class="sshield-checks">
			<li class="sshield-check sshield-check--<?php echo null === $sshield_days || $sshield_days < 0 || empty( $sshield_cert['trusted'] ) ? 'fail' : ( $sshield_days <= Uptime::SSL_WARN ? 'warn' : 'pass' ); ?>">
				<span class="sshield-badge"><?php echo esc_html( null === $sshield_days ? '?' : number_format_i18n( max( 0, $sshield_days ) ) ); ?></span>
				<div class="sshield-finding">
					<strong><?php esc_html_e( 'Certificate', 'sentinel-shield' ); ?></strong>
					<p>
						<?php
						if ( null === $sshield_days ) {
							echo esc_html( $sshield_cert['error'] ? $sshield_cert['error'] : __( 'The certificate could not be read.', 'sentinel-shield' ) );
						} else {
							printf(
								/* translators: 1: issuer, 2: date, 3: days. */
								esc_html__( 'Issued by %1$s, valid until %2$s (%3$s days left).', 'sentinel-shield' ),
								esc_html( $sshield_cert['issuer'] ? $sshield_cert['issuer'] : '?' ),
								esc_html( wp_date( get_option( 'date_format' ), (int) $sshield_cert['expires'] ) ),
								esc_html( number_format_i18n( $sshield_days ) )
							);
							if ( empty( $sshield_cert['trusted'] ) ) {
								echo ' ' . esc_html__( 'Browsers do not trust it:', 'sentinel-shield' ) . ' ' . esc_html( $sshield_cert['error'] );
							}
						}
						?>
					</p>
				</div>
			</li>
			<li class="sshield-check sshield-check--<?php echo ! empty( $sshield_red['ok'] ) || Settings::get( 'force_https' ) ? 'pass' : 'warn'; ?>">
				<span class="sshield-badge"><?php echo esc_html( ! empty( $sshield_red['code'] ) ? (string) $sshield_red['code'] : '?' ); ?></span>
				<div class="sshield-finding">
					<strong><?php esc_html_e( 'http:// to https://', 'sentinel-shield' ); ?></strong>
					<p><?php echo esc_html( ! empty( $sshield_red['ok'] ) ? __( 'Visitors who type http:// are sent to HTTPS.', 'sentinel-shield' ) : __( 'The site still answers on plain http. Switch on the redirect below.', 'sentinel-shield' ) ); ?></p>
				</div>
			</li>
			<li class="sshield-check sshield-check--<?php echo $sshield_https['mixed'] && ! Settings::get( 'https_upgrade' ) ? 'warn' : 'pass'; ?>">
				<span class="sshield-badge"><?php echo esc_html( number_format_i18n( count( $sshield_https['mixed'] ) ) ); ?></span>
				<div class="sshield-finding">
					<strong><?php esc_html_e( 'Mixed content', 'sentinel-shield' ); ?></strong>
					<p><?php echo esc_html( $sshield_https['mixed'] ? __( 'These files load over plain http on HTTPS pages, so browsers block them or warn. The fix below loads them over HTTPS; changing the addresses in your content fixes them for good.', 'sentinel-shield' ) : __( 'Every page checked loads its files over HTTPS.', 'sentinel-shield' ) ); ?></p>
					<?php if ( $sshield_https['mixed'] ) : ?>
						<details class="sshield-diff">
							<summary><?php esc_html_e( 'Show the files', 'sentinel-shield' ); ?></summary>
							<ul class="sshield-plain">
								<?php foreach ( $sshield_https['mixed'] as $sshield_m ) : ?>
									<li><code><?php echo esc_html( $sshield_m['url'] ); ?></code> <span class="sshield-small">(<?php echo esc_html( $sshield_m['tag'] . ', ' . $sshield_m['page'] ); ?>)</span></li>
								<?php endforeach; ?>
							</ul>
						</details>
					<?php endif; ?>
				</div>
			</li>
		</ul>
	<?php endif; ?>
	<?php $sshield_open( array( 'force_https', 'https_upgrade' ) ); ?>
		<ul class="sshield-optlist">
			<?php
			$sshield_box( 'force_https', __( 'Send every visitor to HTTPS', 'sentinel-shield' ), __( 'Only switches on after the site answers on HTTPS with a trusted certificate, so it cannot lock you out. Works behind Cloudflare and other proxies.', 'sentinel-shield' ) );
			$sshield_box( 'https_upgrade', __( 'Load http:// images and scripts over HTTPS', 'sentinel-shield' ), __( 'Fixes mixed content in the browser, without changing your content.', 'sentinel-shield' ) );
			?>
		</ul>
	<?php $sshield_close(); ?>
</section>

<section class="sshield-card sshield-card--full" id="sshield-scripts">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Page scripts', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'Every script your pages load, from your site and from others. Card skimmers and injected ads arrive as one extra script, so a new one alerts you. Scripts found on the first look are approved; later ones wait for you.', 'sentinel-shield' ); ?></p>
		</div>
		<?php if ( $sshield_counts['new'] > 1 ) : ?>
			<div class="sshield-inline-actions"><?php $sshield_eform( 'approve_all', __( 'Approve all new', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost', array(), __( 'Approve every new script? Only do this if you added them.', 'sentinel-shield' ) ); ?></div>
		<?php endif; ?>
	</div>
	<?php if ( ! Settings::enabled( 'script_watch' ) ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'The page script monitor is off.', 'sentinel-shield' ); ?></p>
	<?php elseif ( ! $sshield_sc['checked'] && ! $sshield_sc['items'] ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'No scripts listed yet. Choose Check now at the top.', 'sentinel-shield' ); ?></p>
	<?php else : ?>
		<p class="sshield-small">
			<?php
			printf(
				/* translators: 1: total, 2: new, 3: blocked, 4: flagged. */
				esc_html__( '%1$s scripts: %2$s new, %3$s blocked, %4$s look harmful.', 'sentinel-shield' ),
				esc_html( number_format_i18n( $sshield_counts['total'] ) ),
				esc_html( number_format_i18n( $sshield_counts['new'] ) ),
				esc_html( number_format_i18n( $sshield_counts['blocked'] ) ),
				esc_html( number_format_i18n( $sshield_counts['flagged'] ) )
			);
			?>
		</p>
		<div class="sshield-table-wrap">
			<table class="sshield-table sshield-table--scripts">
				<thead><tr><th><?php esc_html_e( 'Status', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Script', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'Pages', 'sentinel-shield' ); ?></th><th><?php esc_html_e( 'First seen', 'sentinel-shield' ); ?></th><th><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'sentinel-shield' ); ?></span></th></tr></thead>
				<tbody>
					<?php foreach ( Scripts::items() as $sshield_key => $sshield_it ) : ?>
						<?php
						$sshield_states = array(
							'new'      => __( 'New', 'sentinel-shield' ),
							'approved' => __( 'Approved', 'sentinel-shield' ),
							'blocked'  => __( 'Blocked', 'sentinel-shield' ),
						);
						$sshield_tone   = $sshield_it['flag'] ? 'fail' : ( 'new' === $sshield_it['status'] ? 'warn' : ( 'blocked' === $sshield_it['status'] ? 'blocked' : 'pass' ) );
						$sshield_kinds  = array(
							'own'      => __( 'This site', 'sentinel-shield' ),
							'external' => __( 'Outside service', 'sentinel-shield' ),
							'report'   => __( 'Reported by a browser', 'sentinel-shield' ),
							'inline'   => __( 'In the page', 'sentinel-shield' ),
							'keyword'  => __( 'Reported by a browser', 'sentinel-shield' ),
						);
						?>
						<tr class="is-<?php echo esc_attr( $sshield_tone ); ?>">
							<td><span class="sshield-pill sshield-pill--<?php echo esc_attr( $sshield_tone ); ?>"><?php echo esc_html( isset( $sshield_states[ $sshield_it['status'] ] ) ? $sshield_states[ $sshield_it['status'] ] : $sshield_it['status'] ); ?></span></td>
							<td>
								<code class="sshield-break"><?php echo esc_html( Scripts::label( $sshield_it ) ); ?></code>
								<span class="sshield-small"><?php echo esc_html( isset( $sshield_kinds[ $sshield_it['kind'] ] ) ? $sshield_kinds[ $sshield_it['kind'] ] : '' ); ?><?php echo $sshield_it['changed'] ? ' · ' . esc_html__( 'content changed since approved', 'sentinel-shield' ) : ''; ?></span>
								<?php if ( $sshield_it['flag'] ) : ?>
									<strong class="sshield-flag"><?php echo esc_html( $sshield_it['flag'] ); ?></strong>
								<?php endif; ?>
								<?php if ( ! empty( $sshield_it['snippet'] ) ) : ?>
									<code class="sshield-small sshield-break"><?php echo esc_html( $sshield_it['snippet'] ); ?></code>
								<?php endif; ?>
							</td>
							<td><span class="sshield-small"><?php echo esc_html( implode( ', ', $sshield_it['pages'] ) ); ?></span></td>
							<td><span class="sshield-small"><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $sshield_it['first'] ) ); ?></span></td>
							<td class="sshield-inline-actions">
								<?php
								if ( 'approved' !== $sshield_it['status'] || $sshield_it['flag'] ) {
									$sshield_eform( 'approve', __( 'Approve', 'sentinel-shield' ), 'sshield-link', array( 'script[]' => $sshield_key ) );
								}
								if ( 'blocked' !== $sshield_it['status'] && 'own' !== $sshield_it['kind'] && 'inline' !== $sshield_it['kind'] ) {
									$sshield_eform( 'block', __( 'Block', 'sentinel-shield' ), 'sshield-link sshield-link--danger', array( 'script[]' => $sshield_key ) );
								}
								$sshield_eform( 'forget', __( 'Remove', 'sentinel-shield' ), 'sshield-link', array( 'script[]' => $sshield_key ) );
								?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<p class="sshield-small"><?php esc_html_e( 'Remove takes a script off the list; it comes back as new if your pages still load it. Blocking works for a whole domain and only takes effect with the policy below set to Enforce.', 'sentinel-shield' ); ?></p>
	<?php endif; ?>
	<?php $sshield_open( array( 'script_watch', 'csp_mode' ) ); ?>
		<ul class="sshield-optlist">
			<?php $sshield_box( 'script_watch', __( 'Watch the scripts on my pages', 'sentinel-shield' ) ); ?>
		</ul>
		<fieldset class="sshield-radio-group">
			<legend><?php esc_html_e( 'Content Security Policy for scripts', 'sentinel-shield' ); ?></legend>
			<?php
			$sshield_modes = array(
				'off'     => array( __( 'Off', 'sentinel-shield' ), __( 'Browsers run any script a page loads.', 'sentinel-shield' ) ),
				'report'  => array( __( 'Report only', 'sentinel-shield' ), __( 'Browsers report scripts that are not approved, including ones other scripts load later, without stopping them. Start here for a week.', 'sentinel-shield' ) ),
				'enforce' => array( __( 'Enforce', 'sentinel-shield' ), __( 'Browsers refuse scripts from domains you have not approved. New scripts are blocked until you approve them. Editors only get reports, so page builders keep working.', 'sentinel-shield' ) ),
			);
			foreach ( $sshield_modes as $sshield_mode => $sshield_m ) :
				?>
				<label class="sshield-radio"><input type="radio" name="sshield[csp_mode]" value="<?php echo esc_attr( $sshield_mode ); ?>" <?php checked( Settings::get( 'csp_mode' ), $sshield_mode ); ?>> <strong><?php echo esc_html( $sshield_m[0] ); ?></strong> <span class="sshield-small"><?php echo esc_html( $sshield_m[1] ); ?></span></label>
			<?php endforeach; ?>
		</fieldset>
		<?php if ( 'off' !== Settings::get( 'csp_mode' ) ) : ?>
			<p class="sshield-small">
				<?php
				/* translators: %s: number of reports. */
				echo esc_html( sprintf( __( 'Reports received: %s.', 'sentinel-shield' ), number_format_i18n( (int) $sshield_sc['reports'] ) ) );
				?>
			</p>
			<code class="sshield-small sshield-break"><?php echo esc_html( Scripts::policy() ); ?></code>
		<?php endif; ?>
	<?php $sshield_close(); ?>
</section>

<section class="sshield-card sshield-card--full" id="sshield-exposure">
	<div class="sshield-card__head">
		<div>
			<h2><?php esc_html_e( 'Exposed files and keys', 'sentinel-shield' ); ?></h2>
			<p><?php esc_html_e( 'Backups, database dumps, logs, .env and .git folders left where anyone can download them are one of the easiest ways into a site. Each is asked for over the web every day, and your pages and scripts are searched for secret keys.', 'sentinel-shield' ); ?></p>
		</div>
	</div>
	<?php if ( ! Settings::enabled( 'exposure_check' ) ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'The check is off.', 'sentinel-shield' ); ?></p>
	<?php elseif ( ! $sshield_exp['checked'] ) : ?>
		<p class="sshield-empty"><?php esc_html_e( 'Not checked yet. Choose Check now at the top.', 'sentinel-shield' ); ?></p>
	<?php elseif ( ! $sshield_exp['files'] && ! $sshield_exp['keys'] ) : ?>
		<p class="sshield-empty sshield-empty--ok"><?php esc_html_e( 'Nothing private can be downloaded, and no keys show in your pages.', 'sentinel-shield' ); ?></p>
	<?php else : ?>
		<ul class="sshield-checks sshield-findings">
			<?php foreach ( $sshield_exp['keys'] as $sshield_k ) : ?>
				<li class="sshield-check sshield-check--fail">
					<span class="sshield-badge"><?php esc_html_e( 'Key', 'sentinel-shield' ); ?></span>
					<div class="sshield-finding">
						<strong><?php echo esc_html( $sshield_k['type'] ); ?> <code><?php echo esc_html( $sshield_k['masked'] ); ?></code></strong>
						<p>
							<?php
							/* translators: %s: page or script. */
							echo esc_html( sprintf( __( 'Visible to anyone in %s. Replace it with a new key at the service that issued it, then remove it from the page or script: it may already have been copied.', 'sentinel-shield' ), $sshield_k['where'] ) );
							?>
						</p>
					</div>
				</li>
			<?php endforeach; ?>
			<?php foreach ( $sshield_exp['files'] as $sshield_f ) : ?>
				<li class="sshield-check sshield-check--<?php echo $sshield_f['public'] ? 'fail' : 'warn'; ?>">
					<span class="sshield-badge"><?php echo esc_html( $sshield_f['public'] ? __( 'Public', 'sentinel-shield' ) : __( 'On server', 'sentinel-shield' ) ); ?></span>
					<div class="sshield-finding">
						<strong><code><?php echo esc_html( $sshield_f['path'] ); ?></code></strong>
						<p>
							<?php
							echo esc_html( Exposure::describe( $sshield_f['kind'] ) . '. ' );
							echo esc_html( $sshield_f['public'] ? __( 'Anyone can download it right now.', 'sentinel-shield' ) : __( 'It cannot be downloaded now, but it sits in a public folder: one server change and it could be.', 'sentinel-shield' ) );
							if ( $sshield_f['size'] ) {
								echo ' ' . esc_html( size_format( $sshield_f['size'] ) );
							}
							?>
						</p>
					</div>
					<?php if ( $sshield_f['local'] && is_file( ABSPATH . $sshield_f['path'] ) && 'listing' !== $sshield_f['kind'] && 'git' !== $sshield_f['kind'] ) : ?>
						<div class="sshield-finding__action">
							<?php $sshield_eform( 'delete_file', __( 'Delete', 'sentinel-shield' ), 'sshield-link sshield-link--danger', array( 'file' => $sshield_f['id'] ), __( 'Delete this file for good? Download it first if you still need it.', 'sentinel-shield' ) ); ?>
						</div>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php endif; ?>
	<?php if ( Settings::enabled( 'exposure_check' ) ) : ?>
		<div class="sshield-exposure-block">
			<?php if ( Exposure::apache() ) : ?>
				<p class="sshield-small">
					<?php
					echo esc_html(
						Exposure::protected_now()
							? __( 'Blocked in .htaccess: hidden files, .git, backups, dumps and logs cannot be downloaded, and folder listings are off.', 'sentinel-shield' )
							: __( 'Block downloads of hidden files, .git, backups, dumps and logs for good with a few lines in the site\'s .htaccess. The home page is checked right after, and the lines are taken out again if the server objects.', 'sentinel-shield' )
					);
					?>
				</p>
				<?php
				if ( Exposure::protected_now() ) {
					$sshield_eform( 'unprotect', __( 'Remove the block', 'sentinel-shield' ), 'sshield-link' );
				} else {
					$sshield_eform( 'protect', __( 'Block these files', 'sentinel-shield' ), 'sshield-btn sshield-btn--ghost' );
				}
				?>
			<?php else : ?>
				<details class="sshield-diff">
					<summary><?php esc_html_e( 'Block these files on nginx', 'sentinel-shield' ); ?></summary>
					<p class="sshield-small"><?php esc_html_e( 'This server does not read .htaccess. Add these lines to the site\'s server block, or ask your host to:', 'sentinel-shield' ); ?></p>
					<pre class="sshield-snippet"><?php echo esc_html( Exposure::nginx() ); ?></pre>
				</details>
			<?php endif; ?>
		</div>
	<?php endif; ?>
	<?php $sshield_open( array( 'exposure_check' ) ); ?>
		<ul class="sshield-optlist">
			<?php $sshield_box( 'exposure_check', __( 'Check every day for exposed files and keys', 'sentinel-shield' ) ); ?>
		</ul>
	<?php $sshield_close(); ?>
</section>
