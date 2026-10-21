<?php
/**
 * Weekly security report email.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Builds and sends a plain text summary of the last seven days.
 */
final class Report {

	const LAST_OPTION = 'cshield_report_last';

	/**
	 * Sends the report when a week has passed since the last one. Called from the daily job.
	 */
	public static function maybe_send() {
		if ( ! Settings::enabled( 'alert_weekly_report' ) ) {
			return;
		}
		$last = (int) Network::get_option( self::LAST_OPTION, 0 );
		if ( ! $last ) {
			// First run after install or update: start the clock instead of mailing straight away.
			Network::update_option( self::LAST_OPTION, time(), false );
			return;
		}
		if ( time() - $last >= 7 * DAY_IN_SECONDS - HOUR_IN_SECONDS ) {
			self::send();
		}
	}

	/**
	 * Sends the report now.
	 *
	 * @return bool Whether the email was accepted for delivery.
	 */
	public static function send() {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$sent = (bool) wp_mail(
			Settings::alert_email(),
			/* translators: %s: site name. */
			sprintf( __( '[%s] Weekly security report', 'chaos-shield' ), $site ),
			self::body()
		);
		if ( $sent ) {
			Network::update_option( self::LAST_OPTION, time(), false );
		}
		return $sent;
	}

	/**
	 * Report text.
	 *
	 * @return string
	 */
	public static function body() {
		$checks  = Posture::checks();
		$score   = Posture::score( $checks );
		$counts  = Events::counts_since( time() - WEEK_IN_SECONDS );
		$open    = Scanner::open_findings();
		$results = Scanner::results();
		$cover   = Two_Factor::admin_coverage();
		$n       = static function ( $type ) use ( $counts ) {
			return isset( $counts[ $type ] ) ? $counts[ $type ] : 0;
		};

		$lines   = array();
		$lines[] = sprintf(
			/* translators: 1: site URL, 2: score. */
			__( 'Security report for %1$s. Score: %2$d out of 100.', 'chaos-shield' ),
			home_url(),
			$score
		);
		$lines[] = '';
		$lines[] = __( 'Last 7 days', 'chaos-shield' );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'Logins: %d', 'chaos-shield' ), $n( 'login' ) );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'Lockouts after failed logins: %d', 'chaos-shield' ), $n( 'lockout' ) );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'IPs banned: %d', 'chaos-shield' ), $n( 'ban' ) );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'Firewall block events: %d', 'chaos-shield' ), $n( 'blocked' ) );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'User and role changes: %d', 'chaos-shield' ), $n( 'user' ) );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'Plugin and theme changes: %d', 'chaos-shield' ), $n( 'plugin' ) + $n( 'theme' ) );
		$lines[] = '';
		$lines[] = __( 'Right now', 'chaos-shield' );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'IPs banned: %d', 'chaos-shield' ), count( Bans::bans() ) );
		/* translators: %d: count. */
		$lines[] = '- ' . sprintf( __( 'IPs locked out: %d', 'chaos-shield' ), count( Login_Guard::lockouts() ) );
		if ( Vulns::enabled() ) {
			/* translators: %d: count. */
			$lines[] = '- ' . sprintf( __( 'Installed items with known vulnerabilities: %d', 'chaos-shield' ), count( Vulns::open() ) );
		}
		/* translators: 1: admins with two-factor, 2: all admins. */
		$lines[] = '- ' . sprintf( __( 'Administrators with two-factor: %1$d of %2$d', 'chaos-shield' ), $cover['enabled'], $cover['total'] );
		if ( $results ) {
			$lines[] = '- ' . sprintf(
				/* translators: 1: date, 2: open findings. */
				__( 'Last scan %1$s, %2$d open findings', 'chaos-shield' ),
				wp_date( get_option( 'date_format' ), $results['finished'] ),
				count( $open )
			);
		} else {
			$lines[] = '- ' . __( 'No scan has run yet', 'chaos-shield' );
		}

		$todo = array_filter(
			$checks,
			static function ( $c ) {
				return Posture::PASS !== $c['status'];
			}
		);
		if ( $todo ) {
			$lines[] = '';
			$lines[] = __( 'To fix', 'chaos-shield' );
			foreach ( $todo as $c ) {
				$lines[] = '- ' . $c['label'] . ': ' . wp_strip_all_tags( $c['detail'] );
			}
		}

		$lines[] = '';
		/* translators: %s: dashboard URL. */
		$lines[] = sprintf( __( 'Open the dashboard: %s', 'chaos-shield' ), Network::admin_url( 'admin.php?page=chaos-shield' ) );
		$lines[] = '';
		$lines[] = '-- ';
		$lines[] = __( 'Sent weekly by Chaos Shield. Turn it off under Chaos Shield > Alerts.', 'chaos-shield' );
		return implode( "\n", $lines );
	}
}
