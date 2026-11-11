<?php
/**
 * CSP Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

/**
 * CSP functionality class.
 */
class CSP {

	/**
	 * Validate a CSP (Content Security Policy) source value.
	 *
	 * Accepts standard CSP source expressions:
	 * - Quoted keywords: 'self', 'unsafe-inline', 'unsafe-eval', 'none', 'strict-dynamic', etc.
	 * - Nonce sources: 'nonce-<base64>'
	 * - Hash sources: 'sha256-<base64>', 'sha384-<base64>', 'sha512-<base64>'
	 * - Scheme sources: https:, http:, data:, blob:, mediastream:, filesystem:
	 * - Host sources: example.com, *.example.com, https://example.com, https://example.com/path
	 * - Wildcard: *
	 *
	 * @since 2.4.0
	 *
	 * @param string $value The CSP source value to validate.
	 * @return bool True if the value is a valid CSP source.
	 */
	public static function validate_csp_source( $value ) {

		// Reject policy delimiters before accepting any source expression.
		if ( ! is_string( $value ) || preg_match( '/[\x00-\x20\x7f;,]/', $value ) ) {

			return false;

		}

		// CSP quoted keywords.
		$csp_keywords = [
			"'self'",
			"'unsafe-inline'",
			"'unsafe-eval'",
			"'none'",
			"'strict-dynamic'",
			"'unsafe-hashes'",
			"'report-sample'",
			"'wasm-unsafe-eval'",
		];

		if ( in_array( $value, $csp_keywords, true ) ) {

			return true;

		}

		// Wildcard.
		if ( $value === '*' ) {

			return true;

		}

		// CSP nonce formats like nonce-base64.
		if ( preg_match( "/^'nonce-[A-Za-z0-9+\/=]+'$/", $value ) ) {

			return true;

		}

		// CSP hash formats like sha256-base64, sha384-base64, or sha512-base64.
		if ( preg_match( "/^'sha(256|384|512)-[A-Za-z0-9+\/=]+'$/", $value ) ) {

			return true;

		}

		// Scheme-only sources like https, http, data, blob, mediastream, filesystem.
		if ( preg_match( '/^[a-z][a-z0-9+\-.]*:$/i', $value ) ) {

			return true;

		}

		// Full URL with scheme (https://example.com, https://example.com/path).
		if ( preg_match( '#^(?:https?|wss?)://(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?::(?:[0-9]+|\*))?(?:/[^\s;,?\#]*)?$#i', $value ) ) {

			return true;

		}

		// Host source with optional wildcard subdomain: example.com, *.example.com.
		// Must not contain whitespace or semicolons.
		if ( ! preg_match( '/[\s;]/', $value ) && preg_match( '/^(\*\.)?[a-z0-9][a-z0-9.\-]*[a-z0-9]$/i', $value ) ) {

			return true;

		}

		return false;

	}

	/**
	 * Validate and deduplicate CSP sources without expanding their trust boundary.
	 *
	 * @since 2.4.0
	 *
	 * @param string $sources_string Space-separated list of CSP sources.
	 * @return string Normalized space-separated list of CSP sources.
	 */
	public static function normalize_csp_sources( $sources_string ) {

		if ( empty( trim( $sources_string ) ) ) {

			return '';

		}

		$sources    = preg_split( '/\s+/', trim( $sources_string ) );
		$normalized = [];

		foreach ( $sources as $source ) {

			if ( ! self::validate_csp_source( $source ) ) {

				continue;

			}

			$normalized[] = $source;

		}

		// Remove duplicates while keeping order.
		$normalized = array_values( array_unique( $normalized ) );

		return implode( ' ', $normalized );

	}

	/**
	 * Validate a source an administrator may add to an allow list.
	 *
	 * Hosts and schemes only: keywords such as 'unsafe-inline' are decided by the protection
	 * level, so a list can never contradict it.
	 *
	 * @param string $value Source value.
	 * @return bool
	 */
	public static function validate_host_source( $value ) {

		return self::validate_csp_source( $value ) && '*' !== $value && 0 !== strpos( $value, "'" );

	}

	/**
	 * Keep only allow-list entries from a saved source list.
	 *
	 * @param string $sources Saved value, separated by "|" or whitespace.
	 * @return string[]
	 */
	public static function host_list( $sources ) {

		$tokens = preg_split( '/[\s|]+/', (string) $sources, -1, PREG_SPLIT_NO_EMPTY );

		return array_values( array_unique( array_filter( (array) $tokens, [ __CLASS__, 'validate_host_source' ] ) ) );

	}

}
