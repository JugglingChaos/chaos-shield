<?php
/**
 * Known vulnerability alerts and abandoned plugin warnings.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Checks core, plugins and themes against the free WPVulnerability database.
 *
 * WPVulnerability needs no account or key. It is asked about one slug at a time
 * (core is asked about its version), answers are cached for a day, and the work
 * runs in short cron batches so large sites never hit a time limit.
 */
final class Vulns {

	const API          = 'https://www.wpvulnerability.net/';
	const RESULT       = 'sshield_vulns';
	const CACHE        = 'sshield_vuln_cache';
	const SEEN_OPTION  = 'sshield_vulns_seen';
	const REFRESH_HOOK = 'sshield_vuln_refresh';
	const FRESH        = 72000;
	const ABANDONED    = 63072000;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( self::REFRESH_HOOK, array( __CLASS__, 'cron' ) );
		// Installed versions change after updates, so check again soon.
		add_action( 'upgrader_process_complete', array( __CLASS__, 'schedule_soon' ), 20 );
		add_action( 'activated_plugin', array( __CLASS__, 'schedule_soon' ) );
		add_action( 'init', array( __CLASS__, 'upgrade' ) );
	}

	/**
	 * Drops the Wordfence key and feed matches kept by 1.2 to 1.4, then checks soon.
	 */
	public static function upgrade() {
		if ( false !== Network::get_option( 'sshield_wf_key' ) || ( false === Network::get_option( self::CACHE ) && self::result() && ! isset( self::result()['stale'] ) ) ) {
			Network::delete_option( 'sshield_wf_key' );
			Network::delete_option( self::RESULT );
			Network::update_option( self::CACHE, array(), false );
			self::schedule_soon();
		}
		if ( self::enabled() && ! self::result() && ! Network::next_scheduled( self::REFRESH_HOOK ) ) {
			self::schedule_soon();
		}
	}

	/**
	 * Whether the daily check is switched on.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return Settings::enabled( 'vuln_check' );
	}

	/**
	 * Runs a refresh in the background shortly.
	 */
	public static function schedule_soon() {
		if ( self::enabled() && ! Network::next_scheduled( self::REFRESH_HOOK ) ) {
			Network::schedule_single( time() + 60, self::REFRESH_HOOK );
		}
	}

	/**
	 * Cron batch: continues until every item has a fresh answer.
	 */
	public static function cron() {
		if ( ! self::enabled() ) {
			return;
		}
		$done = self::refresh( 40 );
		if ( false === $done ) {
			Network::schedule_single( time() + 30, self::REFRESH_HOOK );
		}
	}

	/**
	 * Last result.
	 *
	 * @return array|null checked, items, stale, error, pending.
	 */
	public static function result() {
		$result = Network::get_option( self::RESULT );
		return is_array( $result ) ? $result : null;
	}

	/**
	 * Vulnerabilities that affect what is installed now, worst first.
	 *
	 * @return array
	 */
	public static function open() {
		$result = self::result();
		if ( ! $result || empty( $result['items'] ) ) {
			return array();
		}
		$installed = self::installed();
		$open      = array();
		foreach ( $result['items'] as $item ) {
			$key = $item['type'] . ':' . $item['slug'];
			// Drop items fixed by an update since the last check.
			if ( ! isset( $installed[ $key ] ) || ( isset( $item['at'] ) && $item['at'] !== $installed[ $key ]['version'] ) ) {
				continue;
			}
			if ( self::affects( $item['ranges'], $installed[ $key ]['version'] ) ) {
				$item['version'] = $installed[ $key ]['version'];
				$open[]          = $item;
			}
		}
		$rank = array_flip( array( 'c', 'h', 'm', 'l', 'n', '' ) );
		usort(
			$open,
			static function ( $a, $b ) use ( $rank ) {
				return array( $rank[ $a['severity'] ], $a['name'] ) <=> array( $rank[ $b['severity'] ], $b['name'] );
			}
		);
		return $open;
	}

	/**
	 * Plugins and themes that were closed on WordPress.org or not updated in two years.
	 *
	 * @return array Items: type, slug, name, file, closed, updated.
	 */
	public static function stale() {
		$result    = self::result();
		$installed = self::installed();
		$out       = array();
		foreach ( $result && ! empty( $result['stale'] ) ? $result['stale'] : array() as $item ) {
			if ( isset( $installed[ $item['type'] . ':' . $item['slug'] ] ) ) {
				$out[] = $item;
			}
		}
		return $out;
	}

	/**
	 * Asks WPVulnerability about items without a fresh answer, then matches.
	 *
	 * @param int $seconds Time budget.
	 * @return bool|\WP_Error True when finished, false when items are left for the next batch.
	 */
	public static function refresh( $seconds = 20 ) {
		$installed = self::installed();
		$cache     = Network::get_option( self::CACHE );
		$cache     = is_array( $cache ) ? array_intersect_key( $cache, self::cache_keys( $installed ) ) : array();
		$until     = microtime( true ) + $seconds;
		$failed    = array();
		$pending   = 0;

		foreach ( self::cache_keys( $installed ) as $ckey => $item_key ) {
			if ( isset( $cache[ $ckey ] ) && time() - $cache[ $ckey ]['fetched'] < self::FRESH ) {
				continue;
			}
			if ( microtime( true ) >= $until ) {
				++$pending;
				continue;
			}
			$answer = self::fetch( $item_key, $installed[ $item_key ] );
			if ( is_wp_error( $answer ) ) {
				$failed[] = $answer->get_error_message();
				// Keep the older answer, but try again in an hour rather than right away.
				if ( isset( $cache[ $ckey ] ) ) {
					$cache[ $ckey ]['fetched'] = time() - self::FRESH + HOUR_IN_SECONDS;
				}
				continue;
			}
			$cache[ $ckey ] = $answer;
		}
		Network::update_option( self::CACHE, $cache, false );

		$items = array();
		$stale = array();
		foreach ( self::cache_keys( $installed ) as $ckey => $item_key ) {
			if ( ! isset( $cache[ $ckey ] ) ) {
				continue;
			}
			$entry               = $cache[ $ckey ];
			$sw                  = $installed[ $item_key ];
			list( $type, $slug ) = explode( ':', $item_key, 2 );
			foreach ( $entry['vulns'] as $v ) {
				if ( self::affects( $v['ranges'], $sw['version'] ) ) {
					$items[] = array_merge(
						$v,
						array(
							'type' => $type,
							'slug' => $slug,
							'name' => $sw['name'],
							'file' => $sw['file'],
							'at'   => 'core' === $type ? $sw['version'] : null,
						)
					);
				}
			}
			if ( 'core' !== $type && ( $entry['closed'] || ( $entry['updated'] && time() - $entry['updated'] > self::ABANDONED ) ) ) {
				$stale[] = array(
					'type'    => $type,
					'slug'    => $slug,
					'name'    => $sw['name'],
					'file'    => $sw['file'],
					'closed'  => (bool) $entry['closed'],
					'updated' => (int) $entry['updated'],
				);
			}
		}

		$error = '';
		if ( $failed ) {
			/* translators: %s: error message. */
			$error = sprintf( __( 'Some items could not be checked and will be retried: %s', 'sentinel-shield' ), $failed[0] );
		}
		$old = self::result();
		Network::update_option(
			self::RESULT,
			array(
				'checked' => $pending && $old ? (int) $old['checked'] : time(),
				'items'   => $items,
				'stale'   => $stale,
				'error'   => $error,
				'pending' => $pending,
			),
			false
		);
		if ( $failed && count( $failed ) === count( $installed ) ) {
			Events::add( 'system', $error, '', array( 'severity' => Events::NOTICE ) );
			return new \WP_Error( 'sshield_vuln_api', $error );
		}
		if ( $pending ) {
			return false;
		}
		self::alert_new();
		return true;
	}

	/**
	 * Cache keys for the installed items. Core is cached per version.
	 *
	 * @param array $installed From installed().
	 * @return array Cache key => installed key.
	 */
	private static function cache_keys( array $installed ) {
		$out = array();
		foreach ( $installed as $key => $sw ) {
			$is_core = 0 === strpos( $key, 'core:' );
			$out[ $is_core ? 'core:' . $sw['version'] : $key ] = $key;
		}
		return $out;
	}

	/**
	 * Asks the database about one item.
	 *
	 * @param string $key "type:slug".
	 * @param array  $sw  Installed item.
	 * @return array|\WP_Error fetched, vulns, closed, updated.
	 */
	public static function fetch( $key, array $sw ) {
		list( $type, $slug ) = explode( ':', $key, 2 );
		$path                = 'core' === $type ? 'core/' . rawurlencode( $sw['version'] ) : $type . '/' . rawurlencode( $slug );
		$response            = wp_remote_get(
			self::API . $path . '/',
			array(
				'timeout'    => 8,
				'user-agent' => 'SentinelShield/' . SSHIELD_VERSION,
				'headers'    => array( 'Accept' => 'application/json' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || ! is_array( $data ) ) {
			/* translators: %d: HTTP status code. */
			return new \WP_Error( 'sshield_vuln_http', sprintf( __( 'The vulnerability database answered with HTTP %d.', 'sentinel-shield' ), $code ) );
		}
		$body  = isset( $data['data'] ) && is_array( $data['data'] ) ? $data['data'] : array();
		$vulns = array();
		// An error answer means the database does not know the slug, such as a premium plugin.
		if ( empty( $data['error'] ) && ! empty( $body['vulnerability'] ) && is_array( $body['vulnerability'] ) ) {
			foreach ( $body['vulnerability'] as $v ) {
				$parsed = self::parse( $v, 'core' === $type );
				if ( $parsed ) {
					$vulns[] = $parsed;
				}
			}
		}
		return array(
			'fetched' => time(),
			'vulns'   => $vulns,
			'closed'  => ! empty( $body['closed'] ),
			'updated' => isset( $body['latest'] ) ? (int) $body['latest'] : 0,
		);
	}

	/**
	 * Turns one database record into a stored item.
	 *
	 * @param array $v    Record.
	 * @param bool  $core Whether it came from the core endpoint, which already filters by version.
	 * @return array|null
	 */
	public static function parse( $v, $core ) {
		if ( ! is_array( $v ) ) {
			return null;
		}
		$op     = isset( $v['operator'] ) && is_array( $v['operator'] ) ? $v['operator'] : array();
		$ranges = self::ranges( $op );
		if ( ! $ranges && ! $core ) {
			return null;
		}
		$source = isset( $v['source'][0] ) && is_array( $v['source'][0] ) ? $v['source'][0] : array();
		$cvss   = isset( $v['impact']['cvss'] ) && is_array( $v['impact']['cvss'] ) ? $v['impact']['cvss'] : array();
		$id     = ! empty( $v['uuid'] ) ? (string) $v['uuid'] : md5( wp_json_encode( $v ) );
		$cve    = '';
		foreach ( isset( $v['source'] ) ? (array) $v['source'] : array() as $s ) {
			if ( is_array( $s ) && ! empty( $s['id'] ) && 0 === strpos( (string) $s['id'], 'CVE-' ) ) {
				$cve = (string) $s['id'];
				break;
			}
		}
		$max      = isset( $op['max_version'] ) ? (string) $op['max_version'] : '';
		$unfixed  = ! empty( $op['unfixed'] );
		$patched  = array();
		$max_op   = isset( $op['max_operator'] ) ? strtolower( (string) $op['max_operator'] ) : '';
		$severity = isset( $cvss['severity'] ) ? strtolower( substr( (string) $cvss['severity'], 0, 1 ) ) : '';
		if ( ! $unfixed && '' !== $max && 'lt' === $max_op ) {
			$patched[] = $max;
		}
		return array(
			'id'               => sanitize_key( $id ),
			'title'            => self::plain( isset( $v['name'] ) ? $v['name'] : ( isset( $source['name'] ) ? $source['name'] : '' ) ),
			'cve'              => sanitize_text_field( $cve ),
			'ranges'           => $core && ! $ranges ? array( array() ) : $ranges,
			'patched_versions' => $patched,
			'after'            => ! $unfixed && 'le' === $max_op ? $max : '',
			'newest'           => $core && ! $ranges && ! $unfixed,
			'unfixed'          => $unfixed,
			'severity'         => in_array( $severity, array( 'c', 'h', 'm', 'l', 'n' ), true ) ? $severity : '',
			'score'            => isset( $cvss['score'] ) ? (float) $cvss['score'] : 0.0,
			'link'             => ! empty( $source['link'] ) ? esc_url_raw( (string) $source['link'] ) : '',
			'informational'    => false,
		);
	}

	/**
	 * Plain one-line text from the database. Output is escaped where it is shown.
	 *
	 * @param mixed $text Text.
	 * @return string
	 */
	private static function plain( $text ) {
		$text = wp_strip_all_tags( html_entity_decode( (string) $text, ENT_QUOTES, 'UTF-8' ) );
		return mb_substr( trim( (string) preg_replace( '/\s+/', ' ', $text ) ), 0, 300 );
	}

	/**
	 * Converts the database's operator block into version ranges.
	 *
	 * @param array $op min_version, min_operator, max_version, max_operator.
	 * @return array Ranges for affects(), or none when the record names no versions.
	 */
	public static function ranges( array $op ) {
		$map   = array(
			'gt' => array( false, '>' ),
			'ge' => array( true, '>=' ),
			'lt' => array( false, '<' ),
			'le' => array( true, '<=' ),
			'eq' => array( true, '=' ),
		);
		$range = array();
		$min   = isset( $op['min_operator'] ) ? strtolower( (string) $op['min_operator'] ) : '';
		$max   = isset( $op['max_operator'] ) ? strtolower( (string) $op['max_operator'] ) : '';
		if ( isset( $map[ $min ] ) && ! empty( $op['min_version'] ) ) {
			$range['from_version']   = (string) $op['min_version'];
			$range['from_inclusive'] = $map[ $min ][0];
		}
		if ( isset( $map[ $max ] ) && ! empty( $op['max_version'] ) ) {
			$range['to_version']   = (string) $op['max_version'];
			$range['to_inclusive'] = $map[ $max ][0];
		}
		if ( 'eq' === $min && isset( $range['from_version'] ) && ! isset( $range['to_version'] ) ) {
			$range['to_version']   = $range['from_version'];
			$range['to_inclusive'] = true;
		}
		return $range ? array( $range ) : array();
	}

	/**
	 * Emails about vulnerabilities not reported before.
	 */
	private static function alert_new() {
		$open = self::open();
		$seen = (array) Network::get_option( self::SEEN_OPTION, array() );
		$new  = array();
		foreach ( $open as $item ) {
			if ( ! isset( $seen[ $item['id'] ] ) ) {
				$new[] = $item;
			}
		}
		Network::update_option( self::SEEN_OPTION, array_fill_keys( wp_list_pluck( $open, 'id' ), 1 ), false );
		if ( ! $new ) {
			return;
		}
		$lines = array();
		foreach ( $new as $item ) {
			$lines[] = '- ' . $item['name'] . ' ' . $item['version'] . ': ' . $item['title'] . ' (' . self::fix_text( $item ) . ')';
		}
		Events::add(
			'vuln',
			/* translators: %d: number of vulnerabilities. */
			sprintf( _n( '%d new known vulnerability affects this site.', '%d new known vulnerabilities affect this site.', count( $new ), 'sentinel-shield' ), count( $new ) ),
			'',
			array( 'severity' => Events::CRITICAL )
		);
		Alerts::send(
			'alert_vulns',
			/* translators: %d: number of vulnerabilities. */
			sprintf( _n( '%d known vulnerability on your site', '%d known vulnerabilities on your site', count( $new ), 'sentinel-shield' ), count( $new ) ),
			__( 'Installed software on your site has publicly known security holes. Update it as soon as you can:', 'sentinel-shield' ) . "\n\n" . implode( "\n", $lines ),
			md5( implode( ',', wp_list_pluck( $new, 'id' ) ) )
		);
	}

	/**
	 * Says which version fixes an item.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	public static function fix_text( array $item ) {
		if ( ! empty( $item['patched_versions'] ) ) {
			/* translators: %s: versions. */
			return sprintf( __( 'fixed in %s', 'sentinel-shield' ), implode( ', ', $item['patched_versions'] ) );
		}
		if ( ! empty( $item['after'] ) ) {
			/* translators: %s: version. */
			return sprintf( __( 'fixed in a release after %s', 'sentinel-shield' ), $item['after'] );
		}
		if ( ! empty( $item['newest'] ) ) {
			return __( 'update to the newest version', 'sentinel-shield' );
		}
		return __( 'no fix released yet', 'sentinel-shield' );
	}

	/**
	 * Severity label.
	 *
	 * @param string $code c, h, m, l or n.
	 * @return string
	 */
	public static function severity_label( $code ) {
		$labels = array(
			'c' => __( 'Critical', 'sentinel-shield' ),
			'h' => __( 'High', 'sentinel-shield' ),
			'm' => __( 'Medium', 'sentinel-shield' ),
			'l' => __( 'Low', 'sentinel-shield' ),
			'n' => __( 'Info', 'sentinel-shield' ),
		);
		return isset( $labels[ $code ] ) ? $labels[ $code ] : __( 'Vulnerable', 'sentinel-shield' );
	}

	/**
	 * Installed software as "type:slug" => [ name, version, file ].
	 *
	 * @return array
	 */
	public static function installed() {
		global $wp_version;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array(
			'core:wordpress' => array(
				'name'    => 'WordPress',
				'version' => $wp_version,
				'file'    => '',
			),
		);
		foreach ( get_plugins() as $file => $data ) {
			$slug                     = false === strpos( $file, '/' ) ? basename( $file, '.php' ) : dirname( $file );
			$out[ 'plugin:' . $slug ] = array(
				'name'    => $data['Name'],
				'version' => (string) $data['Version'],
				'file'    => $file,
			);
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$out[ 'theme:' . $slug ] = array(
				'name'    => $theme->get( 'Name' ),
				'version' => (string) $theme->get( 'Version' ),
				'file'    => $slug,
			);
		}
		return $out;
	}

	/**
	 * Whether a version falls in any affected range.
	 *
	 * @param array  $ranges  Ranges with from_version, from_inclusive, to_version, to_inclusive.
	 * @param string $version Installed version.
	 * @return bool
	 */
	public static function affects( array $ranges, $version ) {
		if ( '' === (string) $version ) {
			return false;
		}
		foreach ( $ranges as $r ) {
			$from = isset( $r['from_version'] ) ? (string) $r['from_version'] : '*';
			$to   = isset( $r['to_version'] ) ? (string) $r['to_version'] : '*';
			$low  = '*' === $from || version_compare( $version, $from, ! empty( $r['from_inclusive'] ) ? '>=' : '>' );
			$high = '*' === $to || version_compare( $version, $to, ! empty( $r['to_inclusive'] ) ? '<=' : '<' );
			if ( $low && $high ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Core's one-click update link for an item, or ''.
	 *
	 * @param array $item Open item.
	 * @return string
	 */
	public static function update_url( array $item ) {
		if ( 'plugin' === $item['type'] && $item['file'] && current_user_can( 'update_plugins' ) ) {
			return wp_nonce_url( Network::admin_url( 'update.php?action=upgrade-plugin&plugin=' . rawurlencode( $item['file'] ) ), 'upgrade-plugin_' . $item['file'] );
		}
		if ( 'theme' === $item['type'] && current_user_can( 'update_themes' ) ) {
			return wp_nonce_url( Network::admin_url( 'update.php?action=upgrade-theme&theme=' . rawurlencode( $item['file'] ) ), 'upgrade-theme_' . $item['file'] );
		}
		if ( 'core' === $item['type'] && current_user_can( 'update_core' ) ) {
			return Network::admin_url( 'update-core.php' );
		}
		return '';
	}

	/**
	 * Forgets cached answers, for the Check now button.
	 */
	public static function clear_cache() {
		Network::delete_option( self::CACHE );
	}
}
