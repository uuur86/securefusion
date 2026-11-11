<?php
/**
 * Work out which theme or plugin produced a piece of page code.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Source keys are "core", "plugin:slug", "theme:slug", "external" or "unknown".
 */
class CSPInlineSources {

	const CORE     = 'core';
	const EXTERNAL = 'external';
	const UNKNOWN  = 'unknown';

	/**
	 * Match a slash-normalized path against the WordPress code locations.
	 *
	 * @param string $path  URL path or file path.
	 * @param array  $roots Location => source prefix ("plugin", "theme").
	 * @return string
	 */
	public static function from_path( $path, $roots ) {

		$path = str_replace( '\\', '/', (string) $path );

		foreach ( $roots as $root => $kind ) {

			$start = '' === $root ? false : strpos( $path, $root );

			if ( false === $start ) {

				continue;

			}

			$rest = explode( '/', ltrim( substr( $path, $start + strlen( $root ) ), '/' ) );

			if ( count( $rest ) > 1 && '' !== $rest[0] ) {

				return $kind . ':' . $rest[0];

			}

			// A single-file plugin sits directly in the plugins folder.
			if ( 'plugin' === $kind && '' !== $rest[0] ) {

				return 'plugin:' . basename( $rest[0], '.php' );

			}

		}

		return preg_match( '#/(?:wp-includes|wp-admin)/#', $path ) ? self::CORE : self::UNKNOWN;

	}

	/**
	 * Resolve a script or style URL.
	 *
	 * @param string $url Asset URL.
	 * @return string
	 */
	public static function from_url( $url ) {

		$path = wp_parse_url( (string) $url, PHP_URL_PATH );

		if ( ! is_string( $path ) ) {

			return self::UNKNOWN;

		}

		return self::from_path(
			$path,
			[
				self::url_path( plugins_url() )        => 'plugin',
				self::url_path( plugins_url( '', WPMU_PLUGIN_DIR . '/index.php' ) ) => 'plugin',
				self::url_path( get_theme_root_uri() ) => 'theme',
			]
		);

	}

	/**
	 * Return a URL's path with a trailing slash.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	private static function url_path( $url ) {

		$path = wp_parse_url( (string) $url, PHP_URL_PATH );

		return is_string( $path ) ? trailingslashit( $path ) : '';

	}

	/**
	 * Resolve a PHP file.
	 *
	 * @param string $file Absolute file path.
	 * @return string
	 */
	public static function from_file( $file ) {

		return self::from_path(
			$file,
			[
				trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) )    => 'plugin',
				trailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) )  => 'plugin',
				trailingslashit( wp_normalize_path( get_theme_root() ) ) => 'theme',
			]
		);

	}

	/**
	 * Resolve the code behind a hook callback.
	 *
	 * @param callable $callback Hook callback.
	 * @return string
	 */
	public static function from_callback( $callback ) {

		try {

			if ( is_array( $callback ) ) {

				$reflection = new \ReflectionMethod( $callback[0], $callback[1] );

			} elseif ( is_string( $callback ) && false !== strpos( $callback, '::' ) ) {

				$reflection = new \ReflectionMethod( $callback );

			} elseif ( is_object( $callback ) && ! $callback instanceof \Closure ) {

				$reflection = new \ReflectionMethod( $callback, '__invoke' );

			} else {

				$reflection = new \ReflectionFunction( $callback );

			}

			$file = $reflection->getFileName();

			return is_string( $file ) ? self::from_file( $file ) : self::CORE;

		} catch ( \ReflectionException $e ) {

			return self::UNKNOWN;

		}

	}

	/**
	 * Slugs of the active theme and plugins.
	 *
	 * @return array<string,string> Slug => source key.
	 */
	private static function active_slugs() {

		static $slugs = null;

		if ( null !== $slugs ) {

			return $slugs;

		}

		$slugs = [
			get_stylesheet() => 'theme:' . get_stylesheet(),
			get_template()   => 'theme:' . get_template(),
		];

		$plugins = array_merge( (array) get_option( 'active_plugins', [] ), array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );

		foreach ( $plugins as $plugin ) {

			$slug = dirname( (string) $plugin );
			$slug = '.' === $slug ? basename( (string) $plugin, '.php' ) : $slug;

			$slugs[ $slug ] = 'plugin:' . $slug;

		}

		return $slugs;

	}

	/**
	 * Everything trusted automatically: WordPress, the active theme and active plugins.
	 *
	 * @return string[] Source keys.
	 */
	public static function installed() {

		return array_values( array_unique( array_merge( [ self::CORE ], array_values( self::active_slugs() ) ) ) );

	}

	/**
	 * Resolve a registered handle that has no file of its own.
	 *
	 * @param string $handle Script or style handle.
	 * @return string
	 */
	public static function from_handle_name( $handle ) {

		if ( preg_match( '/^(?:wp-|global-styles|core-block-supports|classic-theme-styles|admin-bar|dashicons|jquery)/', $handle ) ) {

			return self::CORE;

		}

		$best = '';

		foreach ( self::active_slugs() as $slug => $source ) {

			if ( ( $handle === $slug || 0 === strpos( $handle, $slug . '-' ) ) && strlen( $slug ) > strlen( $best ) ) {

				$best = (string) $slug;

			}

		}

		return '' !== $best ? self::active_slugs()[ $best ] : self::UNKNOWN;

	}

	/**
	 * Resolve a WordPress inline element id such as "theme-style-inline-css".
	 *
	 * @param string $type Script or style.
	 * @param string $id   Element id.
	 * @return string
	 */
	public static function for_element( $type, $id ) {

		$registry = 'script' === $type ? wp_scripts() : wp_styles();
		$handle   = preg_replace( '/-(?:js-before|js-after|js-extra|js-translations|inline-css)$/', '', (string) $id );

		if ( ! isset( $registry->registered[ $handle ] ) ) {

			return self::UNKNOWN;

		}

		$src = $registry->registered[ $handle ]->src;

		if ( is_string( $src ) && '' !== $src ) {

			$source = self::from_url( $src );

			if ( self::UNKNOWN !== $source ) {

				return $source;

			}

		}

		return self::from_handle_name( $handle );

	}

	/**
	 * Whether approving this source can cover its future output. External and unknown code cannot.
	 *
	 * @param string $source Source key.
	 * @return bool
	 */
	public static function trustable( $source ) {

		return self::CORE === $source || 0 === strpos( (string) $source, 'plugin:' ) || 0 === strpos( (string) $source, 'theme:' );

	}

	/**
	 * Category of a source, for filtering and display.
	 *
	 * @param string $source Source key.
	 * @return string core, theme, plugin, external or unknown.
	 */
	public static function kind( $source ) {

		$kind = strtok( (string) $source, ':' );

		return in_array( $kind, [ 'core', 'theme', 'plugin', 'external' ], true ) ? $kind : self::UNKNOWN;

	}

	/**
	 * Human name of a source. Admin screens only.
	 *
	 * @param string $source Source key.
	 * @return string
	 */
	public static function label( $source ) {

		$kind = self::kind( $source );

		if ( 'core' === $kind ) {

			return __( 'WordPress', 'secuplug' );

		}

		if ( 'external' === $kind ) {

			return __( 'External hosts', 'secuplug' );

		}

		if ( self::UNKNOWN === $kind ) {

			return __( 'Unknown or page content', 'secuplug' );

		}

		$slug = substr( (string) $source, strlen( $kind ) + 1 );

		if ( 'theme' === $kind ) {

			$theme = wp_get_theme( $slug );

			return $theme->exists() ? (string) $theme->get( 'Name' ) : $slug;

		}

		if ( ! function_exists( 'get_plugins' ) ) {

			require_once ABSPATH . 'wp-admin/includes/plugin.php';

		}

		foreach ( get_plugins() as $file => $data ) {

			if ( dirname( $file ) === $slug || basename( $file, '.php' ) === $slug ) {

				return (string) $data['Name'];

			}

		}

		return $slug;

	}

}
