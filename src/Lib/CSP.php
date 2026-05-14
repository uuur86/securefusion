<?php
/**
 * CSP Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

/**
 * CSP Class
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

		// CSP nonce: 'nonce-<base64>'.
		if ( preg_match( "/^'nonce-[A-Za-z0-9+\/=]+'$/", $value ) ) {
			return true;
		}

		// CSP hash: 'sha256-<base64>', 'sha384-<base64>', 'sha512-<base64>'.
		if ( preg_match( "/^'sha(256|384|512)-[A-Za-z0-9+\/=]+'$/", $value ) ) {
			return true;
		}

		// Scheme-only sources: https:, http:, data:, blob:, mediastream:, filesystem:.
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
}