<?php
/**
 * How a per-response nonce coexists with page caches.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Request-path half of the cache driver: cheap checks only, no file or network access.
 *
 * A nonce is only safe when every response gets its own. Either the driver in wp-config.php
 * replaces a placeholder on each response, or the page is kept out of shared caches.
 */
class CSPCache {

	/**
	 * Network-wide result of the driver self-test: ok, reason, checked.
	 */
	const STATUS_OPTION = 'securefusion_csp_driver';

	/**
	 * Short-lived token that marks the self-test's own requests.
	 */
	const PROBE_TRANSIENT = 'securefusion_csp_probe';

	/**
	 * Whether the driver wraps this response.
	 *
	 * @return bool
	 */
	public static function driver_loaded() {

		return defined( 'SECUREFUSION_CSP_DRIVER' ) && defined( 'SECUREFUSION_CSP_DRIVER_KEY' );

	}

	/**
	 * Read the last self-test result.
	 *
	 * @return array
	 */
	public static function status() {

		$status = get_site_option( self::STATUS_OPTION, [] );

		return is_array( $status ) ? $status : [];

	}

	/**
	 * Whether this request belongs to the running self-test.
	 *
	 * @return bool
	 */
	private static function probing() {

		$probe = isset( $_SERVER['HTTP_X_SECUREFUSION_PROBE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SECUREFUSION_PROBE'] ) ) : '';

		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $probe ) ) {

			return false;

		}

		$expected = get_site_transient( self::PROBE_TRANSIENT );

		return is_string( $expected ) && hash_equals( $expected, $probe );

	}

	/**
	 * Whether pages may carry a placeholder for the driver to replace.
	 *
	 * Loading the driver is not enough: a cache that answers without PHP would hand out the
	 * placeholder itself. Only a passed self-test, or the self-test's own request, enables it.
	 *
	 * @return bool
	 */
	public static function driver_ready() {

		if ( ! self::driver_loaded() ) {

			return false;

		}

		return ! empty( self::status()['ok'] ) || self::probing();

	}

	/**
	 * Whether a page cache is known to keep whole pages for more than one visitor.
	 *
	 * Cloudflare is left out on purpose: by default it does not keep HTML.
	 *
	 * @return bool
	 */
	public static function shared() {

		$found = ( defined( 'WP_CACHE' ) && WP_CACHE ) || isset( $_SERVER['HTTP_X_VARNISH'] );

		foreach ( [ 'LSCWP_V', 'KINSTAMU_VERSION', 'WPE_APIKEY', 'FLYWHEEL_CONFIG_DIR' ] as $constant ) {

			$found = $found || defined( $constant );

		}

		return (bool) apply_filters( 'securefusion_csp_page_cache', $found );

	}

	/**
	 * Build the signed note the driver reads at the end of a page.
	 *
	 * @param string               $placeholder Value standing in for the nonce, or empty.
	 * @param array<string,string> $headers     Policy headers for this page.
	 * @return string Empty when the driver is not loaded.
	 */
	public static function marker( $placeholder, $headers ) {

		if ( ! defined( 'SECUREFUSION_CSP_DRIVER_KEY' ) || ! $headers ) {

			return '';

		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Transport encoding; the driver verifies the signature before reading it.
		$payload = base64_encode( (string) wp_json_encode( $headers ) );
		$signed  = 'v1.' . $placeholder . '.' . $payload;

		return '<script type="text/plain" data-securefusion-csp>' . $signed . '.' . hash_hmac( 'sha256', 'csp:' . $signed, (string) constant( 'SECUREFUSION_CSP_DRIVER_KEY' ) ) . '</script>';

	}

	/**
	 * Whether WordPress is answering with an HTML document.
	 *
	 * @return bool
	 */
	public static function is_html_response() {

		foreach ( headers_list() as $header ) {

			if ( 0 === stripos( $header, 'content-type:' ) ) {

				return false !== stripos( $header, 'text/html' );

			}

		}

		return false;

	}

	/**
	 * Keep this response out of every shared cache we know how to address.
	 *
	 * Each header is read by one kind of cache and ignored by everything else, so sending all of
	 * them is safe on any server: page cache plugins (constant), browsers and standard proxies
	 * (Cache-Control), LiteSpeed, Nginx, Cloudflare and other CDNs, Varnish and Fastly.
	 *
	 * @return void
	 */
	public static function exclude() {

		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Standard response-cache bypass flag.
			define( 'DONOTCACHEPAGE', true );

		}

		if ( headers_sent() ) {

			return;

		}

		nocache_headers();

		header( 'X-LiteSpeed-Cache-Control: no-cache' );
		header( 'X-Accel-Expires: 0' );
		header( 'CDN-Cache-Control: no-store' );
		header( 'Surrogate-Control: no-store' );

	}

}
