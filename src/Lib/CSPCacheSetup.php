<?php
/**
 * Install, verify and remove the CSP cache driver. Admin requests only.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * The driver is one marked block in wp-config.php that loads drivers/csp-nonce.php.
 *
 * Nothing else is written anywhere, the block does nothing once the plugin folder is gone, and
 * removing it returns the file to its previous content.
 */
class CSPCacheSetup {

	const BLOCK_START = '// BEGIN SecureFusion CSP driver';
	const BLOCK_END   = '// END SecureFusion CSP driver';

	/**
	 * Self-test requests: the first may fill a cache, the later ones show how it answers.
	 */
	const PROBES = 3;

	/**
	 * Locate wp-config.php the way WordPress does.
	 *
	 * @return string Path, or empty when it cannot be found.
	 */
	public static function config_path() {

		if ( is_file( ABSPATH . 'wp-config.php' ) ) {

			return ABSPATH . 'wp-config.php';

		}

		$parent = dirname( ABSPATH );

		// One level up counts only when that folder is not another WordPress install.
		if ( is_file( $parent . '/wp-config.php' ) && ! is_file( $parent . '/wp-settings.php' ) ) {

			return $parent . '/wp-config.php';

		}

		return '';

	}

	/**
	 * Write a path as PHP code, relative to wp-config.php where possible so a moved site keeps working.
	 *
	 * @param string $config_dir Folder holding wp-config.php.
	 * @param string $target     Absolute file path.
	 * @return string PHP expression.
	 */
	public static function path_expression( $config_dir, $target ) {

		$base   = rtrim( str_replace( '\\', '/', $config_dir ), '/' ) . '/';
		$target = str_replace( '\\', '/', $target );

		if ( 0 === strpos( $target, $base ) ) {

			return '__DIR__ . ' . var_export( '/' . substr( $target, strlen( $base ) ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Generates a quoted PHP string literal.

		}

		return var_export( $target, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Generates a quoted PHP string literal.

	}

	/**
	 * Build the wp-config.php block.
	 *
	 * @param string $path_expression PHP expression for the driver file.
	 * @param string $key             Signing key, 64 hexadecimal characters.
	 * @return string
	 */
	public static function block( $path_expression, $key ) {

		return self::BLOCK_START . "\n"
			. "if ( ! defined( 'SECUREFUSION_CSP_DRIVER_KEY' ) && is_file( " . $path_expression . " ) ) {\n"
			. "\tdefine( 'SECUREFUSION_CSP_DRIVER_KEY', '" . preg_replace( '/[^a-f0-9]/', '', $key ) . "' );\n"
			. "\tinclude_once " . $path_expression . ";\n"
			. "}\n"
			. self::BLOCK_END;

	}

	/**
	 * Remove the block from wp-config.php content.
	 *
	 * @param string $contents File content.
	 * @return string
	 */
	public static function without_block( $contents ) {

		$pattern = '~' . preg_quote( self::BLOCK_START, '~' ) . '.*?' . preg_quote( self::BLOCK_END, '~' ) . '\r?\n?~s';
		$result  = preg_replace( $pattern, '', (string) $contents );

		return is_string( $result ) ? $result : (string) $contents;

	}

	/**
	 * Put the block directly after the opening tag, where nothing has run yet.
	 *
	 * @param string $contents File content.
	 * @param string $block    Block from block().
	 * @return string New content, or empty when the file is not safe to edit automatically.
	 */
	public static function with_block( $contents, $block ) {

		$contents = self::without_block( $contents );

		// A strict_types declaration must stay the first statement, and anything but a plain opening tag is unusual enough to leave alone.
		if ( ! preg_match( '/^<\?php(\r?\n|[ \t])/', $contents, $match ) || preg_match( '/\bdeclare\s*\(\s*strict_types/', substr( $contents, 0, 4096 ) ) ) {

			return '';

		}

		$eol    = false !== strpos( $contents, "\r\n" ) ? "\r\n" : "\n";
		$result = '<?php' . $eol . str_replace( "\n", $eol, $block ) . $eol . preg_replace( '/^[ \t]*\r?\n?/', '', substr( $contents, 5 ) );

		// Never write a file PHP cannot parse.
		if ( function_exists( 'token_get_all' ) && defined( 'TOKEN_PARSE' ) ) {

			try {

				token_get_all( $result, TOKEN_PARSE );

			} catch ( \ParseError $e ) {

				return '';

			}

		}

		return $result;

	}

	/**
	 * Whether this user and this host allow changing wp-config.php.
	 *
	 * @return bool
	 */
	public static function can_manage() {

		return current_user_can( is_multisite() ? 'manage_network_options' : 'manage_options' ) && wp_is_file_mod_allowed( 'securefusion_csp_driver' );

	}

	/**
	 * Whether wp-config.php holds the block.
	 *
	 * @return bool
	 */
	public static function installed() {

		$path = self::config_path();

		if ( '' === $path || ! is_readable( $path ) || filesize( $path ) > MB_IN_BYTES ) {

			return false;

		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file below 1 MB.
		return false !== strpos( (string) file_get_contents( $path ), self::BLOCK_START );

	}

	/**
	 * Replace wp-config.php in one step, so a failed write can never leave half a file.
	 *
	 * @param string $path     File path.
	 * @param string $contents New content.
	 * @return bool
	 */
	private static function write( $path, $contents ) {

		global $wp_filesystem;

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Checked before WP_Filesystem is loaded, to fail without side effects.
		if ( '' === $contents || ! is_writable( $path ) || ! is_writable( dirname( $path ) ) ) {

			return false;

		}

		require_once ABSPATH . 'wp-admin/includes/file.php';

		if ( ! WP_Filesystem() || ! is_object( $wp_filesystem ) || 'direct' !== $wp_filesystem->method ) {

			return false;

		}

		// A .php name, so the copy could never be served as readable text.
		$temporary = dirname( $path ) . '/wp-config-securefusion-' . bin2hex( random_bytes( 16 ) ) . '.php';
		$mode      = fileperms( $path ) & 0777;

		if ( ! $wp_filesystem->put_contents( $temporary, $contents, $mode ) || $wp_filesystem->get_contents( $temporary ) !== $contents ) {

			$wp_filesystem->delete( $temporary );

			return false;

		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replace; WP_Filesystem::move() deletes the destination first.
		if ( ! rename( $temporary, $path ) ) {

			$wp_filesystem->delete( $temporary );

			return false;

		}

		// Servers that cache compiled PHP would keep running the old file.
		if ( function_exists( 'opcache_invalidate' ) ) {

			opcache_invalidate( $path, true );

		}

		return true;

	}

	/**
	 * Read wp-config.php when it is small enough to be a real one.
	 *
	 * @param string $path File path.
	 * @return string Content, or empty.
	 */
	private static function read( $path ) {

		if ( '' === $path || ! is_readable( $path ) || filesize( $path ) > MB_IN_BYTES ) {

			return '';

		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file below 1 MB.
		return (string) file_get_contents( $path );

	}

	/**
	 * Lines an administrator can paste when the file cannot be changed automatically.
	 *
	 * @return string
	 */
	public static function manual_block() {

		$path = self::config_path();

		return self::block(
			self::path_expression( '' !== $path ? dirname( $path ) : ABSPATH, SECUREFUSION_PATH . 'drivers/csp-nonce.php' ),
			bin2hex( random_bytes( 32 ) )
		);

	}

	/**
	 * Add the block to wp-config.php and test it.
	 *
	 * @return bool False when the file could not be changed.
	 */
	public static function install() {

		$path     = self::config_path();
		$contents = self::read( $path );
		$key      = bin2hex( random_bytes( 32 ) );

		if ( '' === $contents ) {

			return false;

		}

		$block = self::block( self::path_expression( dirname( $path ), SECUREFUSION_PATH . 'drivers/csp-nonce.php' ), $key );

		if ( ! self::write( $path, self::with_block( $contents, $block ) ) ) {

			return false;

		}

		self::verify( $key );

		return true;

	}

	/**
	 * Take the block out of wp-config.php.
	 *
	 * @return bool False when the block is still there.
	 */
	public static function remove() {

		delete_site_option( CSPCache::STATUS_OPTION );

		$path     = self::config_path();
		$contents = self::read( $path );

		if ( '' === $contents || false === strpos( $contents, self::BLOCK_START ) ) {

			return true;

		}

		$removed = self::write( $path, self::without_block( $contents ) );

		self::purge();

		return $removed;

	}

	/**
	 * Forget the self-test when the caching setup may have changed; pages fall back to no-cache until it passes again.
	 *
	 * @return void
	 */
	public static function invalidate() {

		delete_site_option( CSPCache::STATUS_OPTION );

	}

	/**
	 * Ask for the home page like a visitor and check that every answer passed through the driver.
	 *
	 * A cache that answers without PHP returns no proof, or an old one. Bounded: PROBES requests, 5 seconds each.
	 *
	 * @param string $key Signing key when it was written during this request.
	 * @return array Saved status: ok, reason, checked.
	 */
	public static function verify( $key = '' ) {

		if ( '' === $key && defined( 'SECUREFUSION_CSP_DRIVER_KEY' ) ) {

			$key = (string) constant( 'SECUREFUSION_CSP_DRIVER_KEY' );

		}

		$previous = CSPCache::status();
		$reason   = '' === $key ? 'pending' : 'ok';

		for ( $i = 0; $i < self::PROBES && 'ok' === $reason; $i++ ) {

			$probe = bin2hex( random_bytes( 16 ) );

			set_site_transient( CSPCache::PROBE_TRANSIENT, $probe, MINUTE_IN_SECONDS );

			$response = wp_remote_get(
				network_home_url( '/' ),
				[
					'timeout'             => 5,
					'redirection'         => 3,
					'limit_response_size' => 64 * KB_IN_BYTES,
					'cookies'             => [],
					/** This filter is documented in wp-includes/class-wp-http-streams.php */
					'sslverify'           => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for loopback requests.
					'headers'             => [ 'X-SecureFusion-Probe' => $probe ],
				]
			);

			if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {

				$reason = 'unreachable';

			} elseif ( ! hash_equals( hash_hmac( 'sha256', 'probe:' . $probe, $key ), (string) wp_remote_retrieve_header( $response, 'x-securefusion-driver' ) ) ) {

				// The first request already failing usually means the new wp-config.php is not running yet.
				$reason = 0 === $i && ! defined( 'SECUREFUSION_CSP_DRIVER_KEY' ) ? 'pending' : 'bypassed';

			}

		}

		delete_site_transient( CSPCache::PROBE_TRANSIENT );

		$status = [
			'ok'      => 'ok' === $reason,
			'reason'  => $reason,
			'checked' => time(),
		];

		update_site_option( CSPCache::STATUS_OPTION, $status );

		// Pages cached before a change of verdict were built for the other mode, and a failed test
		// may have left its own request in a cache.
		if ( ! $status['ok'] || empty( $previous['ok'] ) ) {

			self::purge();

		}

		return $status;

	}

	/**
	 * Repeat the self-test from the daily cleanup, so a cache added later cannot go unnoticed.
	 *
	 * @return void
	 */
	public static function recheck() {

		// Only a passing driver is in use; a failing one waits for "Check again".
		if ( ! empty( CSPCache::status()['ok'] ) ) {

			self::verify();

		}

	}

	/**
	 * Name the page caches that can be recognised from inside WordPress.
	 *
	 * @return string[]
	 */
	public static function detect() {

		$found     = [];
		$constants = [
			'WP_ROCKET_VERSION'     => 'WP Rocket',
			'LSCWP_V'               => 'LiteSpeed Cache',
			'W3TC'                  => 'W3 Total Cache',
			'WPCACHEHOME'           => 'WP Super Cache',
			'WPFC_MAIN_PATH'        => 'WP Fastest Cache',
			'CACHE_ENABLER_VERSION' => 'Cache Enabler',
			'BREEZE_VERSION'        => 'Breeze',
			'KINSTAMU_VERSION'      => 'Kinsta',
			'WPE_APIKEY'            => 'WP Engine',
			'FLYWHEEL_CONFIG_DIR'   => 'Flywheel',
		];

		foreach ( $constants as $constant => $label ) {

			if ( defined( $constant ) ) {

				$found[] = $label;

			}

		}

		$headers = [
			'HTTP_CF_RAY'    => 'Cloudflare',
			'HTTP_X_VARNISH' => 'Varnish',
			'X-LSCACHE'      => 'LiteSpeed',
		];

		foreach ( $headers as $name => $label ) {

			if ( isset( $_SERVER[ $name ] ) ) {

				$found[] = $label;

			}

		}

		if ( ! $found && defined( 'WP_CACHE' ) && WP_CACHE ) {

			$found[] = __( 'a page cache plugin', 'secuplug' );

		}

		return array_values( array_unique( $found ) );

	}

	/**
	 * Ask the known page caches to drop their stored pages. Each call is one the cache plugin documents.
	 *
	 * @return void
	 */
	public static function purge() {

		foreach ( [ 'rocket_clean_domain', 'w3tc_flush_posts', 'wp_cache_clear_cache', 'wpfc_clear_all_cache', 'sg_cachepress_purge_cache', 'wpo_cache_flush' ] as $function ) {

			if ( function_exists( $function ) ) {

				call_user_func( $function );

			}

		}

		foreach ( [ 'litespeed_purge_all', 'cache_enabler_clear_complete_cache', 'breeze_clear_all_cache', 'wphb_clear_page_cache', 'swcfpc_purge_cache' ] as $hook ) {

			if ( has_action( $hook ) ) {

				do_action( $hook ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- Purge hooks owned by cache plugins.

			}

		}

		/**
		 * Fires when stored pages no longer match the Content Security Policy settings.
		 */
		do_action( 'securefusion_csp_purge_cache' );

	}

	/**
	 * React to saved settings: purge only when a policy setting changed.
	 *
	 * @param mixed $old   Previous values.
	 * @param mixed $saved Saved values.
	 * @return void
	 */
	public static function settings_changed( $old, $saved ) {

		$filter = static function ( $values ) {

			return array_filter(
				is_array( $values ) ? $values : [],
				static function ( $name ) {

					return 0 === strpos( (string) $name, 'csp_' ) || 0 === strpos( (string) $name, 'enable_csp_' );

				},
				ARRAY_FILTER_USE_KEY
			);

		};

		if ( $filter( $old ) === $filter( $saved ) ) {

			return;

		}

		delete_transient( CSPInline::NOTE );

		self::purge();

	}

	/**
	 * Adapter for update_site_option_{option}, which passes the new value first.
	 *
	 * @param string $option Option name.
	 * @param mixed  $saved  Saved values.
	 * @param mixed  $old    Previous values.
	 * @return void
	 */
	public static function network_settings_changed( $option, $saved, $old ) {

		self::settings_changed( $old, $saved );

	}

}
