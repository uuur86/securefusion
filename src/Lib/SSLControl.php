<?php
/**
 * SSLControl Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * SSL Control functionality class.
 */
class SSLControl {

	use WPCommon;



	/**
	 * Initialize SSL control.
	 */
	public function init() {
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			return;
		}

		if ( ! is_admin() && $this->get_settings( 'enable_https' ) !== 'https' ) {
			return;
		}

		$new_base_url = $this->do_ssl( site_url() );

		if ( is_admin() ) {
			if ( $this->ssl_available( $new_base_url ) === false ) {
				return;
			}
		} else {
			$cert_data = \get_transient( 'securefusion_ssl_cert_data' );
			if ( $cert_data === 'not-valid' ) {
				return;
			}
		}

		// If SSL is enabled.
		if ( $this->get_settings( 'enable_https' ) === 'https' ) {
			$this->force_ssl_redirect();

			if ( $this->get_https_status() ) {
				// Force to HTTPS.
				if ( ! isset( $_SERVER['HTTPS'] ) ) {
					$_SERVER['HTTPS'] = 'on';
				}

				add_action( 'admin_enqueue_scripts', [ $this, 'admin_ssl_fix_frontend' ] );

				add_filter( 'get_user_option_use_ssl', '__return_true' );
				add_filter( 'secure_signon_cookie', '__return_true' );

				add_filter( 'upload_dir', [ $this, 'do_ssl' ] );
			}
		}
	}



	/**
	 * SSL error handling.
	 *
	 * @param int    $errno   Error number.
	 * @param string $errstr  Error message.
	 * @param string $errfile Error file.
	 * @param int    $errline Error line.
	 */
	public function ssl_error_handling( $errno, $errstr, $errfile, $errline ) {
		// on errors.
	}



	/**
	 * Check if SSL is available for the given URL.
	 *
	 * @param string $url URL to check.
	 * @return bool True if SSL is available, false otherwise.
	 */
	protected function ssl_available( $url ) {
		$cert_data = \get_transient( 'securefusion_ssl_cert_data' );

		if ( is_array( $cert_data ) && ! empty( $cert_data ) ) {
			return $cert_data;
		}
		// Cache failures separately: false is also WordPress's cache-miss value.
		if ( get_transient( 'securefusion_ssl_check_failed' ) ) {
			return false;
		}

		$host   = wp_parse_url( $url, PHP_URL_HOST );
		$port   = wp_parse_url( $url, PHP_URL_PORT );
		$port   = null === $port ? 443 : $port;
		$result = false;

		if ( $host && 'localhost' !== $host ) {
			$result = $this->probe_certificate( $host, $port );
		}

		if ( is_array( $result ) && ! empty( $result ) ) {
			set_transient( 'securefusion_ssl_cert_data', $result, DAY_IN_SECONDS );
			delete_transient( 'securefusion_ssl_check_failed' );
			return $result;
		}

		delete_transient( 'securefusion_ssl_cert_data' );
		set_transient( 'securefusion_ssl_check_failed', 1, 300 );

		return false;
	}



	/**
	 * Probe a certificate with a short connection timeout and guaranteed cleanup.
	 *
	 * @param string $host Host.
	 * @param int    $port Port.
	 * @return array|false Parsed certificate or unavailable result.
	 */
	protected function probe_certificate( $host, $port ) {
		$context = stream_context_create(
			[
				'ssl' => [
					'capture_peer_cert' => true,
					'verify_peer'       => true,
					'verify_peer_name'  => true,
					'peer_name'         => trim( $host, '[]' ),
				],
			]
		);

		$stream = false;

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Capture expected TLS connection warnings; restored in finally.
		set_error_handler( [ $this, 'ssl_error_handling' ] );

		try {
			$stream = stream_socket_client( 'ssl://' . $host . ':' . (int) $port, $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $context );

			if ( ! $stream ) {
				return false;
			}

			$params = stream_context_get_params( $stream );
			$peer   = $params['options']['ssl']['peer_certificate'] ?? null;

			return $peer ? openssl_x509_parse( $peer ) : false;
		} finally {
			if ( is_resource( $stream ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- This is a TLS socket, not a filesystem file.
				fclose( $stream );
			}

			restore_error_handler();
		}
	}


	/**
	 * Check if site is using HTTPS.
	 *
	 * @return bool True if site is using HTTPS, false otherwise.
	 */
	protected function get_https_status() {
		$server_var = wp_unslash( $_SERVER );

		if ( isset( $server_var['REQUEST_SCHEME'] ) && $server_var['REQUEST_SCHEME'] === 'https' ) {
			return true;
		}

		if ( isset( $server_var['HTTPS'] ) && $server_var['HTTPS'] === 'on' ) {
			return true;
		}

		if ( isset( $_ENV['HTTPS'] ) && $_ENV['HTTPS'] === 'on' ) {
			return true;
		}

		if ( isset( $server_var['HTTP_X_FORWARDED_SSL'] ) && ( strpos( $server_var['HTTP_X_FORWARDED_SSL'], 'on' ) !== false || strpos( $server_var['HTTP_X_FORWARDED_SSL'], '1' ) !== false ) ) {
			return true;
		}

		if ( isset( $server_var['HTTP_X_FORWARDED_PROTO'] ) && strpos( $server_var['HTTP_X_FORWARDED_PROTO'], 'https' ) !== false ) {
			return true;
		}

		if ( isset( $server_var['HTTP_CF_VISITOR'] ) && strpos( $server_var['HTTP_CF_VISITOR'], 'https' ) !== false ) {
			return true;
		}

		if ( isset( $server_var['HTTP_CLOUDFRONT_FORWARDED_PROTO'] ) && strpos( $server_var['HTTP_CLOUDFRONT_FORWARDED_PROTO'], 'https' ) !== false ) {
			return true;
		}

		if ( isset( $server_var['HTTP_X_PROTO'] ) && strpos( $server_var['HTTP_X_PROTO'], 'SSL' ) !== false ) {
			return true;
		}

		return false;
	}



	/**
	 * Force SSL on the given URL.
	 *
	 * @param string|array $url URL to force SSL on.
	 * @return string|array URL with SSL forced.
	 */
	public function do_ssl( $url ) {
		if ( is_array( $url ) ) {
			$new_url = [];

			foreach ( $url as $url_key => $url_val ) {
				$new_url[ $url_key ] = $this->do_ssl( $url_val );
			}

			return $new_url;
		}

		if ( substr( $url, 0, 7 ) === 'http://' ) {
			$url = 'https://' . substr( $url, 7 );
		}

		return $url;
	}



	/**
	 * Enqueue SSL fix script for admin area.
	 */
	public function admin_ssl_fix_frontend() {
		wp_enqueue_script(
			'securefusion-admin-ssl-fix-js',
			plugins_url( 'assets/js/fix-ssl.js', SECUREFUSION_BASENAME ),
			'jquery',
			'1.02',
			true
		);
	}



	/**
	 * Force SSL redirect on the given URL.
	 */
	protected function force_ssl_redirect() {
		global $pagenow;

		$https = $this->get_https_status();

		if ( ! $https ) {
			$redirect    = false;
			$url_parts   = wp_parse_url( home_url() );
			$current_url = 'https://' . $url_parts['host'] . add_query_arg( [] );

			// All pages will redirect to https.
			if ( $this->get_settings( 'force_site_https' ) ) {
				$redirect = true;
			} else {
				// Redirect control for login pages.
				if ( ( $this->is_login_page() || $this->is_login_page( false ) ) && $this->get_settings( 'force_login_https' ) ) {
					$redirect = true;
				}

				// Redirect control for admin pages.
				if ( is_admin() && $this->get_settings( 'force_admin_https' ) ) {
					$redirect = true;

					// Except admin-ajax.php.
					if ( $pagenow === 'admin-ajax.php' ) {
						$redirect = false;
					}
				}

				// Redirect control for front pages.
				if ( $this->get_settings( 'force_front_https' ) ) {
					if ( ( ! $this->is_login_page( false ) ) && ( ! is_admin() ) ) {
						$redirect = true;
					}
				}
			}

			if ( $redirect ) {
				if ( function_exists( 'wp_redirect' ) ) {
					wp_safe_redirect( $this->do_ssl( $current_url ), 302 );
				} else {
					header( 'location: ' . $this->do_ssl( $current_url ), true, 302 );
				}

				exit;
			}
		}
	}
}
