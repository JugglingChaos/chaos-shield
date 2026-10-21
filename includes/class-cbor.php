<?php
/**
 * CBOR decoding for passkeys.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Minimal CBOR decoder for WebAuthn attestation objects and COSE keys.
 */
final class Cbor {

	/**
	 * Decodes one item.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Read position, moved past the item.
	 * @param int    $depth  Nesting depth.
	 * @return mixed
	 * @throws \UnexpectedValueException On malformed input.
	 */
	public static function decode( $data, &$offset, $depth = 0 ) {
		if ( $depth > 16 || $offset >= strlen( $data ) ) {
			throw new \UnexpectedValueException( 'cbor' );
		}
		$byte  = ord( $data[ $offset++ ] );
		$major = $byte >> 5;
		$info  = $byte & 0x1f;
		if ( 7 === $major ) {
			$simple = array(
				20 => false,
				21 => true,
				22 => null,
			);
			if ( array_key_exists( $info, $simple ) ) {
				return $simple[ $info ];
			}
			throw new \UnexpectedValueException( 'cbor' );
		}
		$len = self::length( $data, $offset, $info );
		switch ( $major ) {
			case 0:
				return $len;
			case 1:
				return -1 - $len;
			case 2:
			case 3:
				if ( $offset + $len > strlen( $data ) ) {
					throw new \UnexpectedValueException( 'cbor' );
				}
				$out     = substr( $data, $offset, $len );
				$offset += $len;
				return $out;
			case 4:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$out[] = self::decode( $data, $offset, $depth + 1 );
				}
				return $out;
			case 5:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$key = self::decode( $data, $offset, $depth + 1 );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new \UnexpectedValueException( 'cbor' );
					}
					$out[ $key ] = self::decode( $data, $offset, $depth + 1 );
				}
				return $out;
			case 6:
				return self::decode( $data, $offset, $depth + 1 ); // Tagged item: the tag is not needed.
		}
		throw new \UnexpectedValueException( 'cbor' );
	}

	/**
	 * Reads the length or value that follows an initial byte.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Read position.
	 * @param int    $info   Additional information bits.
	 * @return int
	 * @throws \UnexpectedValueException On malformed input.
	 */
	private static function length( $data, &$offset, $info ) {
		if ( $info < 24 ) {
			return $info;
		}
		$sizes = array(
			24 => 1,
			25 => 2,
			26 => 4,
			27 => 8,
		);
		if ( ! isset( $sizes[ $info ] ) || $offset + $sizes[ $info ] > strlen( $data ) ) {
			throw new \UnexpectedValueException( 'cbor' );
		}
		$value = 0;
		for ( $i = 0; $i < $sizes[ $info ]; $i++ ) {
			$value = ( $value << 8 ) | ord( $data[ $offset++ ] );
		}
		if ( $value < 0 || $value > 0x7fffffff ) {
			throw new \UnexpectedValueException( 'cbor' );
		}
		return $value;
	}
}
