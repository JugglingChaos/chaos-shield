<?php
/**
 * Email and team chat alerts.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Sends throttled security alerts to the site owner by email and, when connected, to team chat.
 */
final class Alerts {

	/**
	 * Sends an alert if its switch is on and the same alert was not sent recently.
	 *
	 * @param string $key     Alert setting key, such as alert_new_admin.
	 * @param string $subject Short subject, without the site name.
	 * @param string $body    Plain text body.
	 * @param string $dedupe  Optional extra key, so different targets of the same alert are not merged.
	 * @return bool Whether the alert went out by email or chat.
	 */
	public static function send( $key, $subject, $body, $dedupe = '' ) {
		if ( ! Settings::enabled( $key ) ) {
			return false;
		}

		// One email per alert and target every 15 minutes, so an attack cannot flood the inbox.
		$throttle = 'sshield_alert_' . md5( $key . '|' . $dedupe );
		if ( Network::get_transient( $throttle ) ) {
			return false;
		}

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$text = $body . "\n\n"
			. sprintf(
				/* translators: %s: URL of the Sentinel Shield dashboard. */
				__( 'Review it on your Sentinel Shield dashboard: %s', 'sentinel-shield' ),
				Network::admin_url( 'admin.php?page=sentinel-shield&tab=activity' )
			)
			. "\n\n-- \n"
			. sprintf(
				/* translators: 1: site name, 2: site URL. */
				__( 'Sent by Sentinel Shield on %1$s (%2$s). Change alerts under Sentinel Shield > Alerts.', 'sentinel-shield' ),
				$site,
				home_url()
			);

		$sent = (bool) wp_mail( Settings::alert_email(), sprintf( '[%s] %s', $site, $subject ), $text );
		if ( Connections::chat() ) {
			$sent = true === Connections::send_chat( $subject, $body ) || $sent;
		}
		if ( $sent ) {
			Network::set_transient( $throttle, 1, 15 * MINUTE_IN_SECONDS );
		}
		return $sent;
	}
}
