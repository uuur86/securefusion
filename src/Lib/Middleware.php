<?php
/**
 * Middleware Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

/**
 * Middleware functionality class.
 */
class Middleware {


	use WPCommon;


	/**
	 * Brute force database service instance.
	 *
	 * @var BruteForceDB
	 */
	private $brute_force_db;


	/**
	 * Initialize middleware.
	 *
	 * @return void
	 */
	public function init() {
		global $wp;

		$this->brute_force_db = new BruteForceDB();

		if ( ! function_exists( 'wp_get_current_user' ) ) {
			include ABSPATH . '/wp-includes/pluggable.php';
		}

		// Get client IP early for blocking checks.
		$ip = $this->get_client_ip();

		// Block check: deny blocked IPs before any processing.
		if ( $ip && $this->brute_force_db->is_ip_blocked( $ip ) ) {
			status_header( 403 );
			exit( 'Access Denied' );
		}

		if ( \current_user_can( 'manage_options' ) ) {
			// Automatically whitelist admin IPs.
			if ( $ip ) {
				$this->brute_force_db->whitelist_ip( $ip );
			}
			return;
		}

		// Payload size limit check (excluding multipart/form-data uploads).
		$this->check_payload_size_limit( $ip );

		if ( $this->get_settings( 'filter_bad_requests' ) ) {
			$this->filter_bad_requests();
		}

		if ( $this->get_settings( 'disable_rest_api' ) ) {
			$service_regex = 'users';
			$request_uri   = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			$controlling   = \preg_match( '#(^\/?wp\-json\/wp\/v[12]\/?$|^\/?wp\-json\/wp\/v[12]\/?(' . $service_regex . ')\/?.*$)#siu', $request_uri );

			if ( $controlling ) {
				if ( version_compare( get_bloginfo( 'version' ), '4.7', '>=' ) ) {
					add_filter( 'rest_authentication_errors', [ $this, 'disable_rest_api' ] );
				} else {
					$this->disable_rest_api_manually();
				}
			}
		}
	}


	/**
	 * Check payload size limit and block IP if exceeded.
	 *
	 * Skips multipart/form-data requests (file uploads) to avoid
	 * interfering with legitimate upload operations.
	 *
	 * @param string|false $ip Client IP address.
	 * @return void
	 */
	private function check_payload_size_limit( $ip ) {
		if ( ! $ip ) {
			return;
		}

		$max_payload_size = (int) $this->get_settings( 'max_payload_size' );

		if ( $max_payload_size <= 0 ) {
			return;
		}

		// Skip multipart uploads entirely.
		$content_type = isset( $_SERVER['CONTENT_TYPE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) : '';

		if ( stripos( $content_type, 'multipart/form-data' ) !== false ) {
			return;
		}

		// Calculate total payload: query string + request body.
		$query_string_size = isset( $_SERVER['QUERY_STRING'] ) ? strlen( $_SERVER['QUERY_STRING'] ) : 0;
		$body_size         = isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
		$total_size        = $query_string_size + $body_size;

		if ( $total_size > $max_payload_size ) {
			$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			$payload_info = sprintf( 'Size: %d bytes (limit: %d) | URI: %s', $total_size, $max_payload_size, $request_uri );

			$this->brute_force_db->block_ip( $ip );
			$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_REQUEST, $user_agent, $payload_info );

			wp_die(
				esc_html__( 'SecureFusion: Request payload exceeds the allowed limit. Your IP has been blocked.', 'securefusion' ),
				esc_html__( 'Payload Too Large', 'securefusion' ),
				[
					'response'  => 403,
					'back_link' => false,
				]
			);
		}
	}


	/**
	 * Apply security headers.
	 *
	 * @return void
	 */
	public function headers() {
		// Do not apply security headers in the admin area to avoid conflicts with plugins.
		if ( is_admin() ) {
			return;
		}

		$hide_versions = $this->get_settings( 'hide_versions' );
		$bad_bots      = $this->get_settings( 'bad_bots' );
		$http_headers  = $this->get_settings( 'http_headers' );

		// Helper to resolve null to a default for backward compatibility before settings are re-saved.
		$resolve_csp_toggle = function ( $key, $fallback ) {
			$val = $this->get_settings( $key );
			return ( null === $val ) ? $fallback : $val;
		};

		$enable_csp_style              = $resolve_csp_toggle( 'enable_csp_style', '0' );
		$enable_csp_script             = $resolve_csp_toggle( 'enable_csp_script', '0' );
		$enable_csp_font               = $resolve_csp_toggle( 'enable_csp_font', '0' );
		$enable_csp_frame              = $resolve_csp_toggle( 'enable_csp_frame', '0' );
		$enable_csp_worker             = $resolve_csp_toggle( 'enable_csp_worker', '0' );
		$enable_csp_img                = $resolve_csp_toggle( 'enable_csp_img', '0' );
		$csp_upgrade_insecure_requests = $resolve_csp_toggle( 'csp_upgrade_insecure_requests', '1' );
		$csp_block_all_mixed_content   = $resolve_csp_toggle( 'csp_block_all_mixed_content', '1' );
		$csp_sandbox                   = $resolve_csp_toggle( 'csp_sandbox', '0' );

		// CSP Sources.
		$csp_allowed_style_sources  = $this->get_settings( 'csp_allowed_style_sources' );
		$csp_allowed_style_sources  = str_replace( '|', ' ', $csp_allowed_style_sources );
		$csp_allowed_script_sources = $this->get_settings( 'csp_allowed_script_sources' );
		$csp_allowed_script_sources = str_replace( '|', ' ', $csp_allowed_script_sources );
		$csp_allowed_font_sources   = $this->get_settings( 'csp_allowed_font_sources' );
		$csp_allowed_font_sources   = str_replace( '|', ' ', $csp_allowed_font_sources );
		$csp_allowed_frame_sources  = $this->get_settings( 'csp_allowed_frame_sources' );
		$csp_allowed_frame_sources  = str_replace( '|', ' ', $csp_allowed_frame_sources );
		$csp_allowed_worker_sources = $this->get_settings( 'csp_allowed_worker_sources' );
		$csp_allowed_worker_sources = str_replace( '|', ' ', $csp_allowed_worker_sources );
		$csp_allowed_img_sources    = $this->get_settings( 'csp_allowed_img_sources' );
		$csp_allowed_img_sources    = str_replace( '|', ' ', $csp_allowed_img_sources );

		if ( $bad_bots ) {
			$bad_bots   = get_option( 'bad_bots_list', '^libwww-perl.*' );
			$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

			if ( preg_match( "/{$bad_bots}/i", $user_agent ) ) {
				// Log the bad bot event with details.
				$ip = $this->get_client_ip();
				if ( $ip ) {
					$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
					$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_BOT, $user_agent, $request_uri );
				}

				status_header( 403 );
				exit( 'Access Denied' );
			}
		}

		if ( $hide_versions ) {
			header( 'Server: ' );
			header_remove( 'X-Powered-By' );
		}

		if ( $http_headers ) {
			// Cross-Origin Opener Policy (COOP).
			header( 'Cross-Origin-Opener-Policy: same-origin' );

			// Clickjacking Mitigation & Other Headers.
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'X-Content-Type-Options: nosniff' );
			header( 'Referrer-Policy: no-referrer-when-downgrade' );
			header( 'X-XSS-Protection: 1; mode=block' );
			header( 'Strict-Transport-Security: max-age=31536000' );
			header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );

			/**
			 * Content Security Policy (CSP)
			 * Helps prevent Cross-Site Scripting (XSS) and data injection attacks.
			 * This policy is more specific to reduce risks highlighted by security scanners.
			 */
			$csp_policy = '';

			if ( $enable_csp_frame ) {
				$csp_policy .= "frame-src 'self' " . $csp_allowed_frame_sources . '; ';
			}

			if ( $enable_csp_worker ) {
				$csp_policy .= "worker-src 'self' " . $csp_allowed_worker_sources . '; ';
			}

			if ( $enable_csp_script ) {
				$csp_policy .= "script-src 'self' " . $csp_allowed_script_sources . '; ';
			}

			if ( $enable_csp_style ) {
				$csp_policy .= "style-src 'self' " . $csp_allowed_style_sources . '; ';
			}

			if ( $enable_csp_img ) {
				$csp_policy .= "img-src 'self' " . $csp_allowed_img_sources . '; ';
			}

			if ( $enable_csp_font ) {
				$csp_policy .= "font-src 'self' " . $csp_allowed_font_sources . '; ';
			}

			if ( ! empty( $csp_policy ) ) {
				if ( $csp_upgrade_insecure_requests ) {
					$csp_policy .= 'upgrade-insecure-requests; ';
				}

				if ( $csp_block_all_mixed_content ) {
					$csp_policy .= 'block-all-mixed-content; ';
				}

				if ( $csp_sandbox ) {
					$csp_policy .= 'sandbox; ';
				}

				$csp_policy = str_replace( array( "\r\n", "\r", "\n", "\t" ), '', $csp_policy );

				// Disallows plugins like Flash.
				$csp_policy .= "object-src 'none'; ";

				// Mitigates clickjacking.
				$csp_policy .= "frame-ancestors 'self'; ";

				$csp_policy = "default-src 'self'; " . $csp_policy;

				header( 'Content-Security-Policy: ' . $csp_policy );
			}

			/**
			 * HTTP Strict Transport Security (HSTS)
			 * Enforces secure (HTTPS) connections.
			 * To fix the "No 'preload' directive found" warning, you can add the 'preload' directive.
			 * WARNING: Only add 'preload' if you understand the consequences and are certain
			 * that your entire site and ALL its subdomains can be served over HTTPS permanently.
			 * This cannot be easily undone. More info: https://hstspreload.org/
			 */
			$hsts_max_age = 60 * 60 * 24 * 30 * 24; // 2 year

			header( 'Strict-Transport-Security: max-age=' . $hsts_max_age . '; includeSubDomains; preload' );
		}
	}


	/**
	 * Filter bad requests.
	 *
	 * @return void
	 */
	public function filter_bad_requests() {
		global $wp, $pagenow;

		// http://vulnsite.com/script.php etc.
		// wp-config.php etc.
		// ../../../../etc/pwd etc.
		// ../../../unwanted.php.

		if ( ! $this->get_settings( 'filter_bad_requests' ) ) {
			return;
		}

		if ( current_user_can( 'manage_options' ) ) {
			return;
		}

		// If REQUEST_METHOD is not set or empty, it means there is no security concern.
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || empty( $_SERVER['REQUEST_METHOD'] ) ) {
			return;
		}

		// All HTTP Methods: GET / POST / PUT / HEAD / DELETE / PATCH / OPTIONS / CONNECT / TRACE.
		$method = \in_array(
			$_SERVER['REQUEST_METHOD'],
			// Methods that have the same function as POST.
			array( 'POST', 'PUT', 'PATCH' ),
			true
		) ? 'POST' : 'GET';

		$custom_cookie_patterns  = $this->get_settings( 'cookie_patterns' );
		$custom_request_patterns = $this->get_settings( 'request_patterns' );

		$pattern_arr = array( '/[\#]/', '/[\|]/' );
		$replace_arr = array( '\\\\#', '\\\\|' );

		if ( $custom_cookie_patterns ) {
			$custom_cookie_patterns = preg_split( '/\r\n|\n/', $custom_cookie_patterns );
			$custom_cookie_patterns = array_map(
				function ( $val ) use ( $pattern_arr, $replace_arr ) {
					return preg_replace( $pattern_arr, $replace_arr, $val );
				},
				$custom_cookie_patterns
			);
		}

		if ( $custom_request_patterns ) {
			$custom_request_patterns = preg_split( '/\r\n|\n/', $custom_request_patterns );
			$custom_request_patterns = array_map(
				function ( $val ) use ( $pattern_arr, $replace_arr ) {
					return preg_replace( $pattern_arr, $replace_arr, $val );
				},
				$custom_request_patterns
			);
		}

		$custom_cookie_patterns  = is_array( $custom_cookie_patterns ) ? $custom_cookie_patterns : array();
		$custom_request_patterns = is_array( $custom_request_patterns ) ? $custom_request_patterns : array();

		// Cookie security.
		$cookie_filter_items = apply_filters( 'securefusion_cookie_filter_items', $custom_cookie_patterns );

		if ( ! empty( $cookie_filter_items ) ) {
			$cookie_pattern = '#' . implode( '|', $cookie_filter_items ) . '#siu';
		}

		if ( ! empty( $_COOKIE ) ) {
			if ( ! empty( $cookie_pattern ) ) {
				if ( $this->bad_request_control( $_COOKIE, $cookie_pattern ) ) {
					// Log bad cookie with details.
					$ip = $this->get_client_ip();
					if ( $ip ) {
						$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
						$cookie_data = http_build_query( $_COOKIE );
						$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_COOKIE, $user_agent, $cookie_data );
					}

					wp_die(
						esc_html__( 'SecureFusion Firewall has been denied this cookie request.', 'securefusion' ),
						esc_html__( 'Cookie Failure', 'securefusion' ),
						[
							'response'  => 403,
							'back_link' => true,
						]
					);
				}
			}
		}

		// phpcs:ignore -- No validation needed.
		if ( $method === 'GET' && empty( $_GET ) ) {
			return;
		}

		// GET and POST security.
		$http_pattern = '(?:(?:http|https)?\:\/\/)?';
		$url_pattern  = $http_pattern . '(?:[a-z0-9_\-\.]+\/+)([a-z0-9_\-\.\/]+)?';

		$default_regex_arr = [
			// SQL Global Variables.
			'@@[\w\.\$]+',
			'eval\(\s*[\'\"][\w\s\(\)]+[\'\"]\s*\)',
			'base64_(encode|decode)\s*\(',
			'shell_exec\(\s*[\'\"][\w\s\-\.\/]+[\'\"]\s*\)',
			'phpinfo\(\s*\)',
			'^file_get_contents\(\s*[\'\"][\w\s\-\.\/]+[\'\"]\s*\)',
			$url_pattern . '\.(htaccess|exe|run|cgi)',
			$url_pattern . '(config|boot|vuln|load)\.(php|ini)',
			'mosConfig_[a-zA-Z_]{1,20}',
			// sql injections.
			'(union\s+)?(select|insert|delete)\s+\w+(\s*,\s*\w+)*\s+from\s+\w+(\s+where\s+\w+\s*(=|<|>|\!=)\s*[\w\'\"]+)?',
			// special characters " ' < > \ { |.
			'.*(&\#x22;|&\#x27;|&\#x3C;|&\#x3E;|&\#x5C;|&\#x7B;|&\#x7C;).*',
			// prevents ../ url patterns.
			$http_pattern . '(\/*[a-z0-9_\-\.]+)?(\.\.\/)+([a-z0-9_\-\.])*',
		];

		$request_regex_arr = array_merge( $default_regex_arr, $custom_request_patterns );

		$request_filter_items = apply_filters( 'securefusion_request_filter_items', $request_regex_arr );

		$request_pattern = '#' . implode( '|', $request_filter_items ) . '#siu';

		// phpcs:ignore -- Input is validated in bad_request_control().
		if ( $method === 'POST' && ! empty( $_POST ) ) {
			// phpcs:ignore -- Input is validated in bad_request_control().
			$input = $_POST;
		} else {
			// phpcs:ignore -- Input is validated in bad_request_control().
			$input = $_SERVER['QUERY_STRING'];
		}

		if ( $this->bad_request_control( $input, $request_pattern ) ) {
			// Log bad request with details.
			$ip = $this->get_client_ip();
			if ( $ip ) {
				$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
				$payload     = is_array( $input ) ? http_build_query( $input ) : $input;
				$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_REQUEST, $user_agent, $request_uri . ' | ' . $payload );
			}

			// Comments.
			if ( $pagenow === 'wp-comments-post.php' ) {
				wp_die(
					esc_html__( 'SecureFusion Firewall has been denied this comment submission.', 'securefusion' ),
					esc_html__( 'Comment Submission Failure', 'securefusion' ),
					[
						'response'  => 403,
						'back_link' => true,
					]
				);
			}

			wp_die(
				esc_html__( 'SecureFusion Firewall has been denied this request.', 'securefusion' ),
				esc_html__( 'Request Failure', 'securefusion' ),
				[
					'response'  => 403,
					'back_link' => true,
				]
			);
		}

		if ( empty( $wp->query_vars ) ) {
			return;
		}

		// WP Query security.
		if ( $this->bad_request_control( $wp->query_vars, $request_pattern ) ) {
			// Log bad query with details.
			$ip = $this->get_client_ip();
			if ( $ip ) {
				$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$payload     = http_build_query( $wp->query_vars );
				$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_QUERY, $user_agent, $payload );
			}

			wp_die(
				esc_html__( 'SecureFusion Firewall has been denied this WP Queries.', 'securefusion' ),
				esc_html__( 'WP Query Failure', 'securefusion' ),
				[
					'response'  => 403,
					'back_link' => true,
				]
			);
		}
	}


	/**
	 * Filter out bad requests based on the given pattern.
	 *
	 * @param array|string $input  The input to filter out.
	 * @param string       $pattern The pattern to filter out.
	 * @return bool Whether the input should be filtered out.
	 */
	private function bad_request_control( $input, $pattern ) {
		if ( is_array( $input ) ) {
			$input = http_build_query( $input );
		}

		$input = urldecode( $input );

		$checker = preg_match( $pattern, $input );

		// detect unwanted requests.
		if ( $checker === 1 ) {
			return true;
		}

		return false;
	}


	/**
	 * Disable the REST API.
	 *
	 * @param array $access The access to the REST API.
	 * @return \WP_Error The access to the REST API.
	 */
	public function disable_rest_api( $access ) {
		return new \WP_Error(
			'rest_disabled',
			esc_html__( 'The REST API on this site has been disabled.', 'securefusion' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}


	/**
	 * Disable the REST API manually.
	 *
	 * @return void
	 */
	public function disable_rest_api_manually() {
		// v 1.x .
		add_filter( 'json_enabled', '__return_false' );
		add_filter( 'json_jsonp_enabled', '__return_false' );

		// v 2.x .
		add_filter( 'rest_enabled', '__return_false' );
		add_filter( 'rest_jsonp_enabled', '__return_false' );
	}


	/**
	 * Track failed login attempts.
	 *
	 * Fired on 'wp_login_failed' action.
	 *
	 * @param string $username Username attempted.
	 * @param \WP_Error|null $error Optional. Error object.
	 * @return void
	 */
	public function track_login_failed( $username, $error = null ) {
		$ip = $this->get_client_ip();

		if ( ! $ip ) {
			return;
		}

		// Log with full details (IP, UA, payload).
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		// Construct payload: username and sanitized POST data excluding passwords
		$post_data = wp_unslash( $_POST );
		if ( isset( $post_data['pwd'] ) ) {
			$post_data['pwd'] = '******';
		}
		if ( isset( $post_data['password'] ) ) {
			$post_data['password'] = '******';
		}

		// Serialize payload safely
		$payload = 'Username: ' . sanitize_text_field( $username );
		if ( ! empty( $post_data ) && is_array( $post_data ) ) {
			$payload .= ' | POST: ' . http_build_query( $post_data );
		}

		$this->brute_force_db->log_attempt_with_details(
			$ip,
			BruteForceDB::TYPE_FAILED_LOGIN,
			$user_agent,
			$payload
		);
	}

	/**
	 * Limit login attempts.
	 *
	 * @param string $username Username.
	 *
	 * @return string Username.
	 */
	public function track_limit_login_attempts( $username ) {
		// Get client IP.
		$ip = $this->get_client_ip();

		if ( ! $ip ) {
			return $username;
		}

		$ip_time_limit  = $this->get_settings( 'ip_time_limit' );
		$ip_login_limit = $this->get_settings( 'ip_login_limit' );

		if ( ! $ip_login_limit || ! $ip_time_limit ) {
			return $username;
		}

		$window_seconds = $ip_time_limit * HOUR_IN_SECONDS;
		$attempts       = $this->brute_force_db->get_failed_login_attempts_in_window( $ip, $window_seconds );

		// Failed login attempts.
		if ( $attempts >= $ip_login_limit ) {
			wp_die(
				esc_html__( '<strong>ERROR</strong>: You have reached the login attempts limit.', 'securefusion' ),
				esc_html__( 'Too many failed login attempts', 'securefusion' ),
				[
					'response'  => 403,
					'back_link' => true,
				]
			);
		}

		return $username;
	}
}
