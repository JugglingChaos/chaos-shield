<?php
/**
 * Plugin Name:       Chaos Shield
 * Plugin URI:        https://github.com/JugglingChaos/chaos-shield
 * Description:       Lightweight security hub for WordPress: hardening, passkeys and two-factor login, a request firewall with rate limits, malware and file integrity scanning, audit trail, a built-in SIEM, restore points, compliance reports, alerts, multisite support and a multi-site hub.
 * Version:           1.14.1
 * Requires at least: 6.4
 * Requires PHP:      7.4
 * Network:           true
 * Update URI:        https://github.com/JugglingChaos/chaos-shield
 * Author:            Juggling Chaos
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       chaos-shield
 * Domain Path:       /languages
 *
 * @package ChaosShield
 */

defined( 'ABSPATH' ) || exit;

define( 'CSHIELD_VERSION', '1.14.1' );
define( 'CSHIELD_FILE', __FILE__ );
define( 'CSHIELD_DIR', plugin_dir_path( __FILE__ ) );
define( 'CSHIELD_URL', plugin_dir_url( __FILE__ ) );

require_once CSHIELD_DIR . 'includes/class-network.php';
require_once CSHIELD_DIR . 'includes/class-settings.php';
require_once CSHIELD_DIR . 'includes/class-request.php';
require_once CSHIELD_DIR . 'includes/class-events.php';
require_once CSHIELD_DIR . 'includes/class-incidents.php';
require_once CSHIELD_DIR . 'includes/class-detect.php';
require_once CSHIELD_DIR . 'includes/class-siem.php';
require_once CSHIELD_DIR . 'includes/class-alerts.php';
require_once CSHIELD_DIR . 'includes/class-hardening.php';
require_once CSHIELD_DIR . 'includes/class-login-guard.php';
require_once CSHIELD_DIR . 'includes/class-firewall.php';
require_once CSHIELD_DIR . 'includes/class-help.php';
require_once CSHIELD_DIR . 'includes/class-attack-mode.php';
require_once CSHIELD_DIR . 'includes/class-page-check.php';
require_once CSHIELD_DIR . 'includes/class-scripts.php';
require_once CSHIELD_DIR . 'includes/class-https.php';
require_once CSHIELD_DIR . 'includes/class-exposure.php';
require_once CSHIELD_DIR . 'includes/class-cloudflare.php';
require_once CSHIELD_DIR . 'includes/class-edge.php';
require_once CSHIELD_DIR . 'includes/class-bans.php';
require_once CSHIELD_DIR . 'includes/class-threat-feed.php';
require_once CSHIELD_DIR . 'includes/class-traffic.php';
require_once CSHIELD_DIR . 'includes/class-passwords.php';
require_once CSHIELD_DIR . 'includes/class-password-policy.php';
require_once CSHIELD_DIR . 'includes/class-audit.php';
require_once CSHIELD_DIR . 'includes/class-forwarder.php';
require_once CSHIELD_DIR . 'includes/class-export.php';
require_once CSHIELD_DIR . 'includes/class-uptime.php';
require_once CSHIELD_DIR . 'includes/class-login-url.php';
require_once CSHIELD_DIR . 'includes/class-rate-limit.php';
require_once CSHIELD_DIR . 'includes/class-geo.php';
require_once CSHIELD_DIR . 'includes/class-geo-db.php';
require_once CSHIELD_DIR . 'includes/class-captcha.php';
require_once CSHIELD_DIR . 'includes/class-connections.php';
require_once CSHIELD_DIR . 'includes/class-sessions.php';
require_once CSHIELD_DIR . 'includes/class-totp.php';
require_once CSHIELD_DIR . 'includes/class-two-factor.php';
require_once CSHIELD_DIR . 'includes/class-cbor.php';
require_once CSHIELD_DIR . 'includes/class-passkeys.php';
require_once CSHIELD_DIR . 'includes/class-monitor.php';
require_once CSHIELD_DIR . 'includes/class-scanner.php';
require_once CSHIELD_DIR . 'includes/class-integrity.php';
require_once CSHIELD_DIR . 'includes/class-vulns.php';
require_once CSHIELD_DIR . 'includes/class-cleanup.php';
require_once CSHIELD_DIR . 'includes/class-restore-points.php';
require_once CSHIELD_DIR . 'includes/class-backup.php';
require_once CSHIELD_DIR . 'includes/class-posture.php';
require_once CSHIELD_DIR . 'includes/class-api.php';
require_once CSHIELD_DIR . 'includes/class-hub.php';
require_once CSHIELD_DIR . 'includes/class-report.php';
// Left out of the WordPress.org copy, which updates from WordPress.org instead.
if ( is_file( CSHIELD_DIR . 'includes/class-updater.php' ) ) {
	require_once CSHIELD_DIR . 'includes/class-updater.php';
}
require_once CSHIELD_DIR . 'includes/class-admin.php';
require_once CSHIELD_DIR . 'includes/class-plugin.php';

register_activation_hook( __FILE__, array( 'ChaosShield\\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'ChaosShield\\Plugin', 'deactivate' ) );

ChaosShield\Plugin::instance()->boot();
