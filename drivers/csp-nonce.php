<?php
/**
 * SecureFusion CSP cache driver.
 *
 * Loaded from wp-config.php, before WordPress and before any page cache answers. A cached page
 * carries a placeholder instead of a nonce, plus a signed note of its policy. This file swaps the
 * placeholder for a fresh nonce on every response and sends the matching policy header, so a page
 * cache that answers through PHP can keep serving its stored copy.
 *
 * It depends on nothing but PHP. Without the key constant it does nothing.
 *
 * @package securefusion
 */

// PHP declares this file's functions before running it, so only a constant can tell a second load apart.
if ( ! defined( 'SECUREFUSION_CSP_DRIVER_KEY' ) || defined( 'SECUREFUSION_CSP_DRIVER_LIMIT' ) ) {

	return;

}

/**
 * Largest page the driver holds back, in bytes. Larger responses pass through untouched.
 */
define( 'SECUREFUSION_CSP_DRIVER_LIMIT', 3145728 );

/**
 * Rewrite a finished page: remove the signed note and replace its placeholder.
 *
 * @param string $html  Complete response body.
 * @param string $key   Signing key from wp-config.php.
 * @param string $nonce Fresh nonce for this response.
 * @return array|null Keys body, headers, nonce; null when the page carries no valid note.
 */
function securefusion_csp_driver_apply( $html, $key, $nonce ) {

	$tail = substr( $html, -20000 );

	// The note must close the document: only whitespace and comments, which caches append, may follow.
	if ( ! preg_match( '~<script\b[^>]{0,80}\bdata-securefusion-csp\b[^>]{0,80}>v1\.([a-f0-9]{32}|)\.([A-Za-z0-9+/=]{1,16000})\.([a-f0-9]{64})</script>(?>\s+|<!--(?:(?!-->).)*-->)*+$~Ds', $tail, $match, PREG_OFFSET_CAPTURE ) ) {

		return null;

	}

	$placeholder = $match[1][0];
	$payload     = $match[2][0];

	if ( ! hash_equals( hash_hmac( 'sha256', 'csp:v1.' . $placeholder . '.' . $payload, $key ), $match[3][0] ) ) {

		return null;

	}

	// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Transport encoding of our own signed header list.
	$decoded = json_decode( (string) base64_decode( $payload, true ), true, 3 );
	$headers = array();

	foreach ( array( 'Content-Security-Policy', 'Content-Security-Policy-Report-Only' ) as $name ) {

		if ( is_array( $decoded ) && isset( $decoded[ $name ] ) && is_string( $decoded[ $name ] ) && '' !== $decoded[ $name ] && ! preg_match( '/[\x00-\x1f\x7f]/', $decoded[ $name ] ) ) {

			$headers[ $name ] = $decoded[ $name ];

		}

	}

	$html = substr( $html, 0, strlen( $html ) - strlen( $tail ) + $match[0][1] );

	if ( '' !== $placeholder ) {

		$html = str_replace( $placeholder, $nonce, $html );

		foreach ( $headers as $name => $value ) {

			$headers[ $name ] = str_replace( $placeholder, $nonce, $value );

		}

	}

	return array(
		'body'    => $html,
		'headers' => $headers,
		'nonce'   => '' !== $placeholder,
	);

}



/**
 * Whether the response so far looks like an HTML page.
 *
 * @param string $body First part of the response body.
 * @return bool
 */
function securefusion_csp_driver_is_html( $body ) {

	foreach ( headers_list() as $header ) {

		if ( 0 === stripos( $header, 'content-type:' ) ) {

			return false !== stripos( $header, 'text/html' );

		}

	}

	$start = ltrim( substr( $body, 0, 256 ) );

	// Caches may hand over a page they compressed earlier.
	return '' === $start || '<' === $start[0] || 0 === strpos( $start, "\x1f\x8b" );

}



/**
 * Send the page with a fresh nonce and its policy.
 *
 * @param string $body Complete response body.
 * @return string
 */
function securefusion_csp_driver_finish( $body ) {

	if ( '' === $body || headers_sent() ) {

		return $body;

	}

	$gzip   = false;
	$length = false;

	foreach ( headers_list() as $header ) {

		if ( 0 === stripos( $header, 'content-length:' ) ) {

			$length = true;

		}

		if ( 0 === stripos( $header, 'content-encoding:' ) ) {

			// Only gzip can be reopened here; anything else is passed on as it is.
			if ( false === stripos( $header, 'gzip' ) || 0 !== strpos( $body, "\x1f\x8b" ) || ! function_exists( 'gzdecode' ) ) {

				return $body;

			}

			$gzip = true;

		}

	}

	$html = $gzip ? gzdecode( $body, SECUREFUSION_CSP_DRIVER_LIMIT * 4 ) : $body;

	if ( ! is_string( $html ) ) {

		return $body;

	}

	$result = securefusion_csp_driver_apply( $html, (string) constant( 'SECUREFUSION_CSP_DRIVER_KEY' ), bin2hex( random_bytes( 16 ) ) );

	if ( null === $result ) {

		return $body;

	}

	header_remove( 'Content-Security-Policy' );
	header_remove( 'Content-Security-Policy-Report-Only' );

	foreach ( $result['headers'] as $name => $value ) {

		header( $name . ': ' . $value );

	}

	if ( $result['nonce'] ) {

		// This copy belongs to one visitor. Caches between here and the browser must not keep it.
		header( 'Cache-Control: private, no-cache, max-age=0, must-revalidate' );
		header( 'X-LiteSpeed-Cache-Control: no-cache' );
		header( 'X-Accel-Expires: 0' );
		header( 'CDN-Cache-Control: no-store' );
		header( 'Surrogate-Control: no-store' );

	}

	$body = $gzip ? (string) gzencode( $result['body'], 6 ) : $result['body'];

	if ( $length ) {

		header( 'Content-Length: ' . strlen( $body ) );

	}

	return $body;

}



/**
 * Output handler: hold an HTML page until it is complete, pass everything else through.
 *
 * Memory is bounded by SECUREFUSION_CSP_DRIVER_LIMIT plus one 64 KB chunk.
 *
 * @param string $chunk Buffered output.
 * @param int    $phase Output handler flags.
 * @return string
 */
function securefusion_csp_driver_buffer( $chunk, $phase ) {

	static $held = '';
	static $pass = false;

	if ( $pass ) {

		return $chunk;

	}

	$held .= $chunk;

	if ( $phase & PHP_OUTPUT_HANDLER_FINAL ) {

		$body = $held;
		$held = '';
		$pass = true;

		return ( $phase & PHP_OUTPUT_HANDLER_CLEAN ) ? '' : securefusion_csp_driver_finish( $body );

	}

	// A deliberate flush means the response is streamed; downloads and oversized pages are not ours.
	if ( ( $phase & PHP_OUTPUT_HANDLER_FLUSH ) || strlen( $held ) > SECUREFUSION_CSP_DRIVER_LIMIT || ! securefusion_csp_driver_is_html( $held ) ) {

		$body = $held;
		$held = '';
		$pass = true;

		return $body;

	}

	return '';

}



/**
 * Begin on front-end page requests only.
 *
 * @return void
 */
function securefusion_csp_driver_start() {

	if ( 'cli' === PHP_SAPI || defined( 'SECUREFUSION_CSP_DRIVER' ) ) {

		return;

	}

	// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Runs before WordPress; values are only matched against fixed patterns.
	$method = isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '';
	$uri    = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
	$probe  = isset( $_SERVER['HTTP_X_SECUREFUSION_PROBE'] ) ? $_SERVER['HTTP_X_SECUREFUSION_PROBE'] : '';
	// phpcs:enable WordPress.Security.ValidatedSanitizedInput

	if ( 'GET' !== $method || ! is_string( $uri ) || preg_match( '#/wp-admin/|/wp-json/|/wp-login\.php|/wp-cron\.php|/xmlrpc\.php#', $uri ) ) {

		return;

	}

	// Answer the plugin's self-test: proof that this request passed through the driver.
	if ( is_string( $probe ) && preg_match( '/^[a-f0-9]{32}$/D', $probe ) ) {

		header( 'X-SecureFusion-Driver: ' . hash_hmac( 'sha256', 'probe:' . $probe, (string) constant( 'SECUREFUSION_CSP_DRIVER_KEY' ) ) );

	}

	define( 'SECUREFUSION_CSP_DRIVER', 1 );

	ob_start( 'securefusion_csp_driver_buffer', 65536 );

}

securefusion_csp_driver_start();
