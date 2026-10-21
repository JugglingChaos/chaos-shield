<?php
/**
 * Time-based one-time passwords (RFC 6238) and secret storage.
 *
 * @package SentinelShield
 */

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * TOTP codes compatible with Google Authenticator, Authy, 1Password and similar apps.
 */
final class Totp {

	const PERIOD   = 30;
	const DIGITS   = 6;
	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * New random secret, base32 encoded (160 bits).
	 *
	 * @return string
	 */
	public static function new_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step.
	 * @return string
	 */
	public static function code( $secret, $step ) {
		$key  = self::base32_decode( $secret );
		$msg  = pack( 'N2', 0, $step );
		$hash = hash_hmac( 'sha1', $msg, $key, true );
		$off  = ord( $hash[19] ) & 0x0f;
		$num  = ( ( ord( $hash[ $off ] ) & 0x7f ) << 24 )
			| ( ord( $hash[ $off + 1 ] ) << 16 )
			| ( ord( $hash[ $off + 2 ] ) << 8 )
			| ord( $hash[ $off + 3 ] );
		return str_pad( (string) ( $num % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Checks a code, allowing one step of clock drift either way.
	 *
	 * @param string $secret    Base32 secret.
	 * @param string $code      Code typed by the user.
	 * @param int    $last_step Last step already used, to stop replays.
	 * @param int    $now       Optional timestamp, for tests.
	 * @return int|false The matching step, or false.
	 */
	public static function verify( $secret, $code, $last_step = 0, $now = null ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS || '' === $secret ) {
			return false;
		}
		$current = (int) floor( ( null === $now ? time() : $now ) / self::PERIOD );
		for ( $offset = -1; $offset <= 1; $offset++ ) {
			$step = $current + $offset;
			if ( $step > $last_step && hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	/**
	 * Builds the otpauth:// URI that authenticator apps read from a QR code.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Account label, usually the username.
	 * @return string
	 */
	public static function uri( $secret, $label ) {
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$issuer = '' !== $issuer ? $issuer : wp_parse_url( home_url(), PHP_URL_HOST );
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d&digits=%d',
			rawurlencode( $issuer ),
			rawurlencode( $label ),
			$secret,
			rawurlencode( $issuer ),
			self::PERIOD,
			self::DIGITS
		);
	}

	/**
	 * Encrypts a secret for storage with a key derived from the site salts.
	 *
	 * @param string $plain Secret.
	 * @return string
	 */
	public static function seal( $plain ) {
		if ( ! function_exists( 'openssl_encrypt' ) || ! in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true ) ) {
			return 'p1:' . $plain;
		}
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag );
		return 'e1:' . base64_encode( $iv . $tag . $ct ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary ciphertext storage.
	}

	/**
	 * Decrypts a stored secret.
	 *
	 * @param string $sealed Stored value.
	 * @return string|false False when the value cannot be read, for example after the salts changed.
	 */
	public static function open( $sealed ) {
		$sealed = (string) $sealed;
		if ( 0 === strpos( $sealed, 'p1:' ) ) {
			return substr( $sealed, 3 );
		}
		if ( 0 !== strpos( $sealed, 'e1:' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return false;
		}
		$raw = base64_decode( substr( $sealed, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary ciphertext storage.
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return false;
		}
		$plain = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
		return false === $plain ? false : $plain;
	}

	/**
	 * Encryption key.
	 *
	 * @return string
	 */
	private static function key() {
		return hash_hmac( 'sha256', 'sentinel-shield-2fa', wp_salt( 'secure_auth' ), true );
	}

	/**
	 * Base32 encoding (RFC 4648, no padding).
	 *
	 * @param string $data Binary data.
	 * @return string
	 */
	public static function base32_encode( $data ) {
		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 decoding. Ignores spaces, padding and case.
	 *
	 * @param string $text Base32 text.
	 * @return string
	 */
	public static function base32_decode( $text ) {
		$text = strtoupper( preg_replace( '/[\s=]/', '', (string) $text ) );
		$bits = '';
		foreach ( str_split( $text ) as $char ) {
			$pos = strpos( self::ALPHABET, $char );
			if ( false === $pos ) {
				return '';
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( strlen( $byte ) === 8 ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}
}
