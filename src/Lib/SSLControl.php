<?php
/**
 * SSLControl Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

/**
 * SSL Control
 */
class SSLControl {

	use WPCommon;



	/**
	 * Initialize SSL control.
	 */
	public function init() {
		$new_base_url = $this->do_ssl( site_url() );

		// Check SSL Support.
		if ( $this->ssl_available( $new_base_url ) === false ) {
			return;
		}

		// If SSL Enables.
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

		if ( ! $cert_data ) {
			$url_parse = parse_url( $url, PHP_URL_HOST );

			if ( $url_parse === 'localhost' ) {
				$cert_data = 'not-valid';
			} elseif ( $url_parse ) {
				$get_context = stream_context_create(
					[
						'ssl' => [ 'capture_peer_cert' => true ],
					]
				);
				$socket_url  = 'ssl://' . $url_parse . ':443';

				if ( $get_context ) {
					set_error_handler( [ $this, 'ssl_error_handling' ] );
					$stream = stream_socket_client(
						$socket_url,
						$errno,
						$errstr,
						30,
						STREAM_CLIENT_CONNECT,
						$get_context
					);
					restore_error_handler();

					if ( $errno == 0 && $stream ) {
						$cert_params = stream_context_get_params( $stream );
						$cert_peer   = $cert_params['options']['ssl']['peer_certificate'];

						if ( isset( $cert_peer ) ) {
							$cert_data = openssl_x509_parse( $cert_peer );
						}
					}
				}
			}

			\set_transient( 'securefusion_ssl_cert_data', $cert_data, DAY_IN_SECONDS );
		}

		if ( $cert_data === 'not-valid' ) {
			return false;
		}

		if ( ! empty( $cert_data ) ) {
			return $cert_data;
		}

		return false;
	}



	/**
	 * Check if site is using HTTPS.
	 *
	 * @return bool True if site is using HTTPS, false otherwise.
	 */
	protected function get_https_status() {
		$server_var = wp_unslash( $_SERVER );

		if ( isset( $server_var['REQUEST_SCHEME'] ) && $server_var['REQUEST_SCHEME'] == 'https' ) {
			return true;
		}

		if ( isset( $server_var['HTTPS'] ) && $server_var['HTTPS'] === 'on' ) {
			return true;
		}

		if ( isset( $_ENV['HTTPS'] ) && $_ENV['HTTPS'] === 'on' ) {
			return true;
		}

		if ( isset( $server_var['HTTP_X_FORWARDED_SSL'] ) || strpos( $server_var['HTTP_X_FORWARDED_SSL'], 'on' ) !== false || strpos( $server_var['HTTP_X_FORWARDED_SSL'], '1' ) !== false ) {
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
			'1.02'
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
			$url_parts   = parse_url( home_url() );
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
					wp_redirect( $this->do_ssl( $current_url ), 302 );
				} else {
					header( 'location: ' . $this->do_ssl( $current_url ), true, 302 );
				}

				exit;
			}
		}
	}
}
