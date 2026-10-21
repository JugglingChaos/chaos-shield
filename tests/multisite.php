<?php
/**
 * Multisite checks: run against a TEST network with `wp eval-file tests/multisite.php`.
 *
 * Needs a network with at least one site besides the main one, Chaos Shield
 * network activated and the test IP helper from tests/fixtures/ as a must-use plugin.
 *
 * @package ChaosShield
 */

// phpcs:disable WordPress.Security.EscapeOutput -- Command line output.

namespace ChaosShield\Tests;

use ChaosShield\Bans;
use ChaosShield\Events;
use ChaosShield\Login_Guard;
use ChaosShield\Network;
use ChaosShield\Plugin;
use ChaosShield\Settings;
use ChaosShield\Siem;

if ( ! defined( 'WP_CLI' ) || ! class_exists( '\ChaosShield\Settings' ) ) {
	echo "Run with: wp eval-file tests/multisite.php\n";
	return;
}

require_once __DIR__ . '/helpers.php';

if ( ! is_multisite() || ! Network::active() ) {
	echo "This needs a multisite network with Chaos Shield network activated.\n";
	\WP_CLI::halt( 1 );
}

$sst_sub = get_sites(
	array(
		'number'       => 1,
		'site__not_in' => array( get_main_site_id() ),
	)
);
if ( ! $sst_sub ) {
	echo "Add a second site to the network first.\n";
	\WP_CLI::halt( 1 );
}
$sst_sub      = $sst_sub[0];
$sst_sub_url  = untrailingslashit( get_home_url( $sst_sub->blog_id ) );
$sst_settings = Network::get_option( Settings::OPTION );
Network::update_option(
	Settings::OPTION,
	array_merge(
		Settings::all(),
		array(
			'limit_login'        => true,
			'login_max_attempts' => 3,
			'firewall'           => true,
			'captcha'            => false,
			'rate_limit'         => false,
			'country_block'      => false,
			'ip_allowlist'       => array(),
		)
	)
);

echo 'Chaos Shield ' . CSHIELD_VERSION . ' multisite checks against ' . network_home_url( '/' ) . "\n";

group(
	'One network, one set of rules',
	function () use ( $sst_sub, $sst_sub_url ) {
		check( 'settings live in the network options', is_array( get_site_option( Settings::OPTION ) ) );
		check( 'the log is one network table', Events::table() === $GLOBALS['wpdb']->base_prefix . 'cshield_log' );

		$user = user();
		$bad  = ip();
		for ( $i = 0; $i < 3; $i++ ) {
			http(
				'POST',
				$sst_sub_url . '/wp-login.php',
				$bad,
				array(
					'body' => array(
						'log' => $user->user_login,
						'pwd' => 'wrong-' . $i,
					),
				)
			);
		}
		check( 'failures on one site lock the IP out', Login_Guard::locked_until( $bad ) > time() );
		check( 'the lockout also holds on the main site', ! logged_in( login( $user->user_login, password( $user ), $bad ) ) );

		$rows = Events::query(
			array(
				'ip'    => $bad,
				'limit' => 20,
			)
		);
		$from = array_unique( array_map( 'intval', wp_list_pluck( $rows, 'blog_id' ) ) );
		check( 'events record the site they happened on', in_array( (int) $sst_sub->blog_id, $from, true ) );
		$path  = trim( $sst_sub->path, '/' );
		$found = Events::query( Siem::parse( 'site:' . ( '' !== $path ? $path : $sst_sub->domain ) . ' ip:' . $bad ) );
		check( 'the SIEM search filters by site', $found && ! array_diff( array_map( 'intval', wp_list_pluck( $found, 'blog_id' ) ), array( (int) $sst_sub->blog_id ) ) );
		check( 'an unknown site matches nothing', array() === Events::query( Siem::parse( 'site:no-such-site' ) ) );

		check( 'the firewall covers every site', 403 === http( 'GET', $sst_sub_url . '/?id=1%20UNION%20SELECT%20user_pass', ip() )['status'] );
	}
);

group(
	'Only super admins manage it',
	function () use ( $sst_sub, $sst_sub_url ) {
		$admin = user();
		add_user_to_blog( $sst_sub->blog_id, $admin->ID, 'administrator' );
		remove_user_from_blog( $admin->ID, get_main_site_id() );
		$cookies = admin_cookies( $admin->ID );
		$me      = ip();
		$page    = http( 'GET', $sst_sub_url . '/wp-admin/admin.php?page=chaos-shield', $me, array( 'cookies' => $cookies ) );
		check( 'a site administrator cannot open the screens', false === strpos( $page['body'], 'cshield-tabs' ) );

		$before = Network::get_option( Settings::OPTION );
		http(
			'POST',
			$sst_sub_url . '/wp-admin/admin-post.php',
			$me,
			array(
				'cookies' => $cookies,
				'body'    => array(
					'action'   => 'cshield_save',
					'_wpnonce' => 'x',
					'cshield'  => array( 'firewall' => '' ),
				),
			)
		);
		wp_cache_flush();
		check( 'a site administrator cannot change the network settings', Network::get_option( Settings::OPTION ) === $before );

		$super = user();
		grant_super_admin( $super->ID );
		$net = http( 'GET', network_admin_url( 'admin.php?page=chaos-shield&tab=activity' ), ip(), array( 'cookies' => admin_cookies( $super->ID ) ) );
		check( 'a super admin opens the screens in Network Admin', 200 === $net['status'] && false !== strpos( $net['body'], 'cshield-tabs' ) );
		check( 'the network log shows a site column', false !== strpos( $net['body'], '<th>Site</th>' ) );
		revoke_super_admin( $super->ID );
	}
);

group(
	'Background jobs run once',
	function () use ( $sst_sub ) {
		Plugin::instance()->schedule();
		check( 'the main site runs the daily job', (bool) Network::next_scheduled( Plugin::DAILY ) );
		switch_to_blog( $sst_sub->blog_id );
		Plugin::instance()->schedule();
		check( 'other sites do not', ! wp_next_scheduled( Plugin::DAILY ) );
		restore_current_blog();
	}
);

foreach ( $GLOBALS['sst']['users'] as $sst_id ) {
	require_once ABSPATH . 'wp-admin/includes/ms.php';
	wpmu_delete_user( $sst_id );
}
foreach ( array_unique( $GLOBALS['sst']['ips'] ) as $sst_ip ) {
	Login_Guard::release( $sst_ip );
	Bans::release( $sst_ip );
}
Network::update_option( Settings::OPTION, $sst_settings );

$sst_fail = count( $GLOBALS['sst']['fail'] );
echo "\n" . $GLOBALS['sst']['pass'] . ' passed, ' . $sst_fail . " failed\n";
if ( $sst_fail ) {
	\WP_CLI::halt( 1 );
}
