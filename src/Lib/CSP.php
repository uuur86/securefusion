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
		// CSP quoted keywords.
		$csp_keywords = [
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
		if ( preg_match( '#^https?://.+#i', $value ) ) {
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
	 * Normalize CSP sources to automatically include both www and non-www versions of domains,
	 * and include the apex domain when wildcard is specified.
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

		// Keywords and schemes to ignore.
		$keywords = [
			"'self'",
			"'unsafe-inline'",
			"'unsafe-eval'",
			"'none'",
			"'strict-dynamic'",
			"'unsafe-hashes'",
			"'report-sample'",
			"'wasm-unsafe-eval'",
			'*',
			'data:',
			'blob:',
			'mediastream:',
			'filesystem:',
			'https:',
			'http:',
		];

		foreach ( $sources as $source ) {
			if ( empty( $source ) ) {
				continue;
			}

			// Add the original source.
			$normalized[] = $source;

			// Skip keywords, nonces, and hashes.
			if ( in_array( strtolower( $source ), $keywords, true ) ) {
				continue;
			}
			if ( strpos( $source, "'nonce-" ) === 0 || strpos( $source, "'sha" ) === 0 ) {
				continue;
			}

			// Parse scheme if present.
			$scheme      = '';
			$domain_part = $source;
			if ( preg_match( '#^([a-z][a-z0-9+\-.]*://)(.+)#i', $source, $matches ) ) {
				$scheme      = $matches[1];
				$domain_part = $matches[2];
			}

			// Process domain part.
			if ( strpos( $domain_part, 'www.' ) === 0 ) {
				// www.example.com -> example.com.
				$apex         = substr( $domain_part, 4 );
				$normalized[] = $scheme . $apex;
			} elseif ( strpos( $domain_part, '*.' ) === 0 ) {
				// *.example.com -> example.com.
				$apex         = substr( $domain_part, 2 );
				$normalized[] = $scheme . $apex;
			} elseif ( ! preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/', $domain_part ) && strpos( $domain_part, '.' ) !== false ) {
				// example.com -> www.example.com.
				$normalized[] = $scheme . 'www.' . $domain_part;
			}
		}

		// Remove duplicates while keeping order.
		$normalized = array_values( array_unique( $normalized ) );

		return implode( ' ', $normalized );
	}
}
