<?php
/**
 * Updates from GitHub releases.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Offers new GitHub releases as normal WordPress plugin updates.
 *
 * The plugin header's Update URI points at GitHub, so WordPress never asks
 * WordPress.org about this plugin and calls the update_plugins_github.com
 * filter instead. A private repository needs a read-only token in
 * wp-config.php as CSHIELD_GITHUB_TOKEN.
 */
final class Updater {

	const REPO      = 'JugglingChaos/chaos-shield';
	const RELEASE   = 'cshield_update_release';
	const KEEP      = 6 * HOUR_IN_SECONDS;
	const KEEP_FAIL = HOUR_IN_SECONDS;
	const API       = 'https://api.github.com/repos/';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_filter( 'update_plugins_github.com', array( __CLASS__, 'offer' ), 10, 3 );
		add_filter( 'plugins_api', array( __CLASS__, 'details' ), 10, 3 );
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'download' ), 10, 3 );
	}

	/**
	 * Repository the releases come from, as owner/name.
	 *
	 * @return string
	 */
	public static function repo() {
		/**
		 * Filters the GitHub repository Chaos Shield updates from.
		 *
		 * @param string $repo owner/name.
		 */
		$repo = (string) apply_filters( 'cshield_update_repo', defined( 'CSHIELD_UPDATE_REPO' ) ? CSHIELD_UPDATE_REPO : self::REPO );
		return preg_match( '#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repo ) ? $repo : self::REPO;
	}

	/**
	 * Token for a private repository, or ''.
	 *
	 * @return string
	 */
	private static function token() {
		return defined( 'CSHIELD_GITHUB_TOKEN' ) ? (string) CSHIELD_GITHUB_TOKEN : '';
	}

	/**
	 * Request headers for the GitHub API.
	 *
	 * @param string $accept Accept header.
	 * @return array
	 */
	private static function headers( $accept = 'application/vnd.github+json' ) {
		$headers = array(
			'Accept'               => $accept,
			'X-GitHub-Api-Version' => '2022-11-28',
		);
		if ( self::token() ) {
			$headers['Authorization'] = 'Bearer ' . self::token();
		}
		return $headers;
	}

	/**
	 * The latest release, cached for six hours.
	 *
	 * @param bool $fresh Ask GitHub again even if a recent answer is cached.
	 * @return array|null Each: version, tag, url, package, asset, notes, published. Null when there is none or GitHub could not be reached.
	 */
	public static function latest( $fresh = false ) {
		$cached = Network::get_transient( self::RELEASE );
		if ( ! $fresh && is_array( $cached ) ) {
			return $cached['release'];
		}
		$release = self::fetch();
		Network::set_transient( self::RELEASE, array( 'release' => $release ), $release ? self::KEEP : self::KEEP_FAIL );
		return $release;
	}

	/**
	 * Asks GitHub for the latest release.
	 *
	 * @return array|null
	 */
	private static function fetch() {
		$res = wp_remote_get(
			self::API . self::repo() . '/releases/latest',
			array(
				'timeout'    => 10,
				'headers'    => self::headers(),
				'user-agent' => 'ChaosShield/' . CSHIELD_VERSION . '; ' . home_url( '/' ),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $data ) || empty( $data['tag_name'] ) || ! empty( $data['draft'] ) || ! empty( $data['prerelease'] ) ) {
			return null;
		}
		$version = ltrim( (string) $data['tag_name'], 'vV' );
		if ( ! preg_match( '/^\d+(\.\d+){1,3}$/', $version ) ) {
			return null;
		}
		$package = '';
		$asset   = '';
		foreach ( isset( $data['assets'] ) ? (array) $data['assets'] : array() as $a ) {
			if ( isset( $a['name'], $a['url'], $a['browser_download_url'] ) && preg_match( '/^chaos-shield-[0-9.]+\.zip$/', (string) $a['name'] ) ) {
				$package = (string) $a['browser_download_url'];
				$asset   = (string) $a['url'];
				break;
			}
		}
		if ( ! $package ) {
			return null;
		}
		return array(
			'version'   => $version,
			'tag'       => (string) $data['tag_name'],
			'url'       => isset( $data['html_url'] ) ? esc_url_raw( (string) $data['html_url'] ) : 'https://github.com/' . self::repo(),
			'package'   => esc_url_raw( $package ),
			'asset'     => esc_url_raw( $asset ),
			'notes'     => isset( $data['body'] ) ? substr( (string) $data['body'], 0, 20000 ) : '',
			'published' => isset( $data['published_at'] ) ? (int) strtotime( (string) $data['published_at'] ) : 0,
		);
	}

	/**
	 * Answers WordPress's update check for this plugin.
	 *
	 * @param array|false $update      Update found so far.
	 * @param array       $plugin_data Plugin headers.
	 * @param string      $plugin_file Plugin file, relative to the plugins folder.
	 * @return array|false
	 */
	public static function offer( $update, $plugin_data, $plugin_file ) {
		if ( plugin_basename( CSHIELD_FILE ) !== $plugin_file ) {
			return $update;
		}
		// "Check again" on Dashboard > Updates asks GitHub straight away.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only skips a cache.
		$fresh   = isset( $_GET['force-check'] ) && current_user_can( 'update_plugins' );
		$release = self::latest( $fresh );
		if ( ! $release ) {
			return $update;
		}
		return array(
			'id'           => 'github.com/' . self::repo(),
			'slug'         => dirname( $plugin_file ),
			'plugin'       => $plugin_file,
			'version'      => $release['version'],
			'new_version'  => $release['version'],
			'url'          => $release['url'],
			'package'      => self::token() && $release['asset'] ? $release['asset'] : $release['package'],
			'requires_php' => '7.4',
			'requires'     => '6.4',
		);
	}

	/**
	 * Fills the "View details" window for this plugin.
	 *
	 * @param false|object|array $result Result so far.
	 * @param string             $action Requested action.
	 * @param object             $args   Request arguments.
	 * @return false|object|array
	 */
	public static function details( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || dirname( plugin_basename( CSHIELD_FILE ) ) !== $args->slug ) {
			return $result;
		}
		$release = self::latest();
		if ( ! $release ) {
			return $result;
		}
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$headers = get_plugin_data( CSHIELD_FILE, false, true );
		return (object) array(
			'name'          => 'Chaos Shield',
			'slug'          => $args->slug,
			'version'       => $release['version'],
			'author'        => isset( $headers['Author'] ) ? $headers['Author'] : '',
			'homepage'      => 'https://github.com/' . self::repo(),
			'requires'      => '6.4',
			'requires_php'  => '7.4',
			'last_updated'  => $release['published'] ? gmdate( 'Y-m-d H:i:s', $release['published'] ) . ' GMT' : '',
			'download_link' => $release['package'],
			'sections'      => array(
				'description' => '<p>' . esc_html( isset( $headers['Description'] ) ? wp_strip_all_tags( $headers['Description'] ) : '' ) . '</p>',
				'changelog'   => self::notes( $release['notes'] ),
			),
		);
	}

	/**
	 * Release notes as simple HTML: lines starting with * or - become a list.
	 *
	 * @param string $text Release notes.
	 * @return string
	 */
	public static function notes( $text ) {
		$html = '';
		$list = false;
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			$line = trim( $line );
			if ( preg_match( '/^[*-]\s+(.+)$/', $line, $m ) ) {
				$html .= ( $list ? '' : '<ul>' ) . '<li>' . esc_html( $m[1] ) . '</li>';
				$list  = true;
				continue;
			}
			if ( $list ) {
				$html .= '</ul>';
				$list  = false;
			}
			if ( '' !== $line ) {
				$html .= '<p>' . esc_html( ltrim( $line, '#= ' ) ) . '</p>';
			}
		}
		return $html . ( $list ? '</ul>' : '' );
	}

	/**
	 * Downloads a private repository's release with the token.
	 *
	 * GitHub answers the asset address with a redirect to a signed download
	 * address, which must be fetched without the token.
	 *
	 * @param bool|string|\WP_Error $reply   Download so far.
	 * @param string                $package Package address.
	 * @return bool|string|\WP_Error Path of the downloaded file, or the reply untouched.
	 */
	public static function download( $reply, $package ) {
		if ( false !== $reply || ! self::token() || 0 !== strpos( (string) $package, self::API . self::repo() . '/releases/assets/' ) ) {
			return $reply;
		}
		$res = wp_remote_get(
			$package,
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => self::headers( 'application/octet-stream' ),
				'user-agent'  => 'ChaosShield/' . CSHIELD_VERSION,
			)
		);
		$to  = is_wp_error( $res ) ? '' : (string) wp_remote_retrieve_header( $res, 'location' );
		if ( ! $to || 0 !== strpos( $to, 'https://' ) ) {
			return new \WP_Error( 'cshield_update', __( 'GitHub did not hand out the Chaos Shield download. Check CSHIELD_GITHUB_TOKEN in wp-config.php.', 'chaos-shield' ) );
		}
		return download_url( $to );
	}
}
