<?php
/**
 * CSP integration module.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Resolve provider sources without changing administrator source lists.
 */
class CSPIntegrations {

	/**
	 * Time Cloudflare last forwarded a request to this site.
	 */
	const CLOUDFLARE_OPTION = 'securefusion_cloudflare_seen';

	/**
	 * Return the bundled catalog; extensions can register additional providers.
	 *
	 * @return array
	 */
	public static function catalog() {

		static $catalog;

		if ( null === $catalog ) {

			$catalog = require __DIR__ . '/CSP/Providers.php';

		}

		return apply_filters( 'securefusion_csp_providers', $catalog );

	}

	/**
	 * Detect SDKs and active plugin paths without loading gateway objects.
	 *
	 * @param array $catalog Catalog.
	 * @return array
	 */
	public static function detected( $catalog ) {

		$plugins = array_merge( (array) get_option( 'active_plugins', [] ), array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		$result  = [];

		foreach ( $catalog as $id => $provider ) {

			$result[ $id ] = (bool) array_intersect( $provider['plugins'] ?? [], $plugins );

		}

		// Site Kit can enable individual Google modules; installation alone is not consent.
		if ( in_array( 'google-site-kit/google-site-kit.php', $plugins, true ) ) {

			$modules       = (array) get_option( 'googlesitekit_active_modules', [] );
			$result['ga4'] = $result['ga4'] || in_array( 'analytics-4', $modules, true );
			$result['gtm'] = $result['gtm'] || in_array( 'tagmanager', $modules, true );

		}

		$result['cloudflare'] = ! empty( $result['cloudflare'] ) || self::behind_cloudflare();

		$result['freemius']  = function_exists( 'fs_dynamic_init' );
		$result['recaptcha'] = '1' === (string) Settings::get( 'recaptcha_enable' );

		return apply_filters( 'securefusion_csp_detected_providers', $result );

	}

	/**
	 * Whether requests reach this site through Cloudflare, which adds scripts no plugin announces.
	 *
	 * Cloudflare marks every request it forwards. Requests that skip it, such as a cache preloader
	 * calling the server directly, rely on the last sighting.
	 *
	 * @return bool
	 */
	public static function behind_cloudflare() {

		$ray  = isset( $_SERVER['HTTP_CF_RAY'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_RAY'] ) ) : '';
		$seen = (int) get_option( self::CLOUDFLARE_OPTION, 0 );

		if ( ! preg_match( '/^[0-9a-f]{16}-[A-Z]{3}$/D', $ray ) ) {

			return $seen > 0 && time() - $seen < 90 * DAY_IN_SECONDS;

		}

		if ( time() - $seen > WEEK_IN_SECONDS ) {

			update_option( self::CLOUDFLARE_OPTION, time(), true );

		}

		return true;

	}

	/**
	 * Whether a well-known service is allowed without being detected.
	 *
	 * Services whose hosts serve nothing but their own fixed code are always trusted. Hosts that
	 * serve code anyone may upload or configure (tag managers, public libraries) would let injected
	 * markup load it, so while inline code is verified they wait until they are found on the site
	 * or the owner allows them. With all inline code allowed that precaution gains nothing.
	 *
	 * @param array  $provider Catalog entry.
	 * @param string $level    Protection level.
	 * @return bool
	 */
	public static function trusted( $provider, $level ) {

		$trusted = $provider['trusted'] ?? '';

		return 'strict' === $trusted || ( 'basic' === $trusted && 'strict' !== $level );

	}

	/**
	 * Find the service that lists a blocked address for one resource type.
	 *
	 * @param string $url  Address without query, for example https://www.google.com/recaptcha/api.js.
	 * @param string $type Resource type, for example script.
	 * @return string Provider id, or empty.
	 */
	public static function provider_for( $url, $type ) {

		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );

		if ( '' === $host ) {

			return '';

		}

		foreach ( self::catalog() as $id => $provider ) {

			foreach ( [ $provider['sources'][ $type ] ?? [] ] as $sources ) {

				foreach ( $sources as $source ) {

					$allowed = strtolower( (string) wp_parse_url( str_replace( '*.', 'wildcard.', $source ), PHP_URL_HOST ) );
					$prefix  = (string) wp_parse_url( $source, PHP_URL_PATH );
					$match   = 0 === strpos( $allowed, 'wildcard.' )
						? substr( $host, -strlen( $allowed ) + 8 ) === substr( $allowed, 8 )
						: $host === $allowed;

					if ( $match && ( '' === $prefix || 0 === strpos( $path, $prefix ) ) ) {

						return (string) $id;

					}

				}

			}

		}

		return '';

	}

	/**
	 * Explicit on/off overrides detection; absent settings mean automatic.
	 *
	 * @param mixed $mode Setting.
	 * @param bool  $detected Detection result.
	 * @return bool
	 */
	public static function enabled( $mode, $detected ) {

		if ( '1' === (string) $mode ) {

			return true;

		}

		if ( '0' === (string) $mode ) {

			return false;

		}

		return (bool) $detected;

	}

	/**
	 * Resolve generated sources separately from manually entered sources.
	 *
	 * @param array $settings Settings.
	 * @return array
	 */
	public static function sources( $settings ) {

		$catalog  = self::catalog();
		$detected = self::detected( $catalog );
		$level    = CSPPolicy::level( $settings );
		$result   = [];

		foreach ( $catalog as $id => $provider ) {

			if ( ! self::enabled( $settings[ 'csp_service_' . $id ] ?? 'auto', ! empty( $detected[ $id ] ) || self::trusted( $provider, $level ) ) ) {

				continue;

			}

			foreach ( $provider['sources'] as $directive => $sources ) {

				$result[ $directive ] = array_merge( $result[ $directive ] ?? [], $sources );

			}

		}

		return $result;

	}

}
