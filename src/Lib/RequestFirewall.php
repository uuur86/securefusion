<?php
/**
 * RequestFirewall responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * RequestFirewall methods.
 *
 * @mixin Middleware
 * @property BruteForceDB $brute_force_db Created in Middleware::__construct().
 * @method string get_client_ip() Resolved client IP, or empty.
 * @method array|string|null get_settings( string|null $name = null ) Resolved settings.
 */
trait RequestFirewall {

	/**
	 * Check the payload size limit for anonymous requests.
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

		// Skip if IP is whitelisted (exact or range).
		if ( $this->brute_force_db->is_ip_whitelisted( $ip ) ) {

			return;

		}

		// The limit targets anonymous floods; WordPress has verified signed-in users here.
		if ( is_user_logged_in() ) {

			return;

		}

		// API clients authenticate after this hook, so only their real endpoints are exempt.
		if ( $this->has_api_credentials() && $this->is_api_endpoint() ) {

			return;

		}

		// Skip multipart uploads entirely.
		$content_type = isset( $_SERVER['CONTENT_TYPE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) : '';

		if ( stripos( $content_type, 'multipart/form-data' ) !== false ) {

			return;

		}

		// Calculate total payload: query string + request body.

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Inspect original request bytes; transforming them would change attack detection or size measurement.
		$query_string_size = isset( $_SERVER['QUERY_STRING'] ) ? strlen( $_SERVER['QUERY_STRING'] ) : 0;
		$body_size         = isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
		$total_size        = $query_string_size + $body_size;

		if ( $total_size > $max_payload_size ) {

			$this->handle_oversized_request( $ip, $total_size, $max_payload_size );

		}

	}


	/**
	 * Log an oversized request and, if the site owner opted in, block repeat senders.
	 *
	 * Long comments and checkout forms can exceed the limit once, so a single request
	 * never blocks an address and every block expires.
	 *
	 * @param string $ip               Client IP address.
	 * @param int    $total_size       Request size in bytes.
	 * @param int    $max_payload_size Configured limit in bytes.
	 * @return void
	 */
	private function handle_oversized_request( $ip, $total_size, $max_payload_size ) {

		$user_agent   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$payload_info = sprintf( 'Size: %d bytes (limit: %d) | Path: %s', $total_size, $max_payload_size, $this->request_path_for_log() );

		$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_OVERSIZED_REQUEST, $user_agent, $payload_info );

		if ( ! $this->get_settings( 'block_oversized_requests' ) ) {

			return;

		}

		$threshold = max( 1, absint( $this->get_settings( 'oversized_block_threshold' ) ) );
		$attempts  = $this->brute_force_db->count_attempts_in_window( $ip, BruteForceDB::TYPE_OVERSIZED_REQUEST, Middleware::OVERSIZED_WINDOW );

		if ( $attempts < $threshold ) {

			return;

		}

		$minutes = min( Middleware::OVERSIZED_MAX_BLOCK_MINUTES, max( 1, absint( $this->get_settings( 'oversized_block_minutes' ) ) ) );

		$this->brute_force_db->block_ip( $ip, $minutes * MINUTE_IN_SECONDS );

		if ( ! headers_sent() ) {

			header( 'X-LiteSpeed-Cache-Control: no-cache' );

		}

		wp_die(
			esc_html(
				sprintf(
					/* translators: %s: number of minutes. */
					_n( 'This address sent too many oversized requests. Try again in %s minute.', 'This address sent too many oversized requests. Try again in %s minutes.', $minutes, 'secuplug' ),
					number_format_i18n( $minutes )
				)
			),
			esc_html__( 'Too many oversized requests', 'secuplug' ),
			[
				'response'  => 403,
				'back_link' => false,
			]
		);

	}


	/**
	 * Whether the request carries API credentials.
	 *
	 * @return bool
	 */
	private function has_api_credentials() {

		if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) || ! empty( $_SERVER['PHP_AUTH_USER'] ) || ! empty( $_SERVER['PHP_AUTH_PW'] ) ) {

			return true;

		}

		// Use filter_input() to avoid direct superglobal processing for WooCommerce API keys.
		return ! empty( filter_input( INPUT_GET, 'consumer_key', FILTER_UNSAFE_RAW ) ) || ! empty( filter_input( INPUT_POST, 'consumer_key', FILTER_UNSAFE_RAW ) );

	}


	/**
	 * Whether the request path is a REST or XML-RPC endpoint.
	 *
	 * Only the path is matched, so text placed in the query string cannot claim an endpoint.
	 *
	 * @return bool
	 */
	private function is_api_endpoint() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Presence check only; this does not authorize an action.
		if ( isset( $_GET['rest_route'] ) ) {

			return true;

		}

		$path = $this->request_path_for_log();

		return strpos( $path, '/' . trim( rest_get_url_prefix(), '/' ) . '/' ) !== false || 'xmlrpc.php' === basename( $path );

	}


	/**
	 * Request path without the query string, which can hold tokens and personal data.
	 *
	 * @return string
	 */
	private function request_path_for_log() {

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = wp_parse_url( $uri, PHP_URL_PATH );

		return is_string( $path ) ? $path : '';

	}


	/**
	 * Summarize request fields for the log without keeping secrets.
	 *
	 * Sensitive and nested fields keep their name only; other values are shortened.
	 *
	 * @param array|string $input Request fields, or a raw query string.
	 * @return string
	 */
	private function redact_for_log( $input ) {

		$fields = $input;

		if ( ! is_array( $fields ) ) {

			parse_str( (string) $fields, $fields );

		}

		$parts = [];

		foreach ( array_slice( $fields, 0, 50, true ) as $name => $value ) {

			$name      = substr( (string) $name, 0, 64 );
			$sensitive = preg_match( '/pass|pwd|token|secret|auth|nonce|session|cookie|card|cvv|cvc|ssn|otp|key|mail|phone/i', $name );
			$parts[]   = $name . '=' . ( $sensitive || ! is_scalar( $value ) ? '[redacted]' : substr( (string) $value, 0, 200 ) );

		}

		return implode( '&', $parts );

	}


	/**
	 * Keep the patterns that compile, so one bad custom rule cannot disable the firewall.
	 *
	 * Empty patterns are dropped too: an empty alternative would match every request.
	 *
	 * @param mixed $patterns Filtered pattern list.
	 * @return string[]
	 */
	private function usable_patterns( $patterns ) {

		return array_values(
			array_filter(
				(array) $patterns,
				static function ( $pattern ) {

					// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A failed compile is the condition being tested.
					return is_string( $pattern ) && '' !== $pattern && false !== @preg_match( '#' . $pattern . '#siu', '' );

				}
			)
		);

	}


	/**
	 * Check requested path for malicious or sensitive files.
	 *
	 * Detects scanner bots probing for exposed configuration files,
	 * shell scripts, backups, and backdoor PHP scripts. Only intercepts
	 * requests already routed through WordPress (non-existent files on disk).
	 * Does NOT modify .htaccess or interfere with server configuration.
	 *
	 * @return void
	 */
	private function check_malicious_path() {

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$url_path    = wp_parse_url( $request_uri, PHP_URL_PATH );

		if ( empty( $url_path ) ) {

			return;

		}

		// Decode URL-encoded characters to prevent bypass via %2e (%2eenv becomes .env).
		$url_path = urldecode( $url_path );

		$malicious_path_patterns = [
			// Exposed configuration and hidden files.
			'\.(env|git|htaccess|htpasswd|gitignore|gitattributes|dockerignore|editorconfig|npmrc)(?:\.|$|\/|\?)',
			// Shell scripts, SQL dumps, backups, CGI, executables.
			'\.(sh|bash|sql|bak|log|cgi|exe|pl|py)$',
			// WordPress config backups.
			'wp-config\.(bak|old|txt|temp|tmp|zip)$',
			// Common backup archives.
			'backup\.(zip|tar|gz|sql|rar|bak)$',
			// Known backdoor / webshell PHP filenames.
			'(malicious-script|shell|webshell|c99|r57|cmd|backdoor|eval-stdin|wp-theme-check|alfashell|0x|01xa|adminer)\.php$',
		];

		$malicious_path_pattern = '#(' . implode( '|', $malicious_path_patterns ) . ')#siu';

		if ( preg_match( $malicious_path_pattern, $url_path ) ) {

			$ip = $this->get_client_ip();

			if ( $ip ) {

				$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_REQUEST, $user_agent, $url_path );

			}

			wp_die(
				esc_html__( 'SecureFusion Firewall has denied access to this resource.', 'secuplug' ),
				esc_html__( 'Access Denied', 'secuplug' ),
				[
					'response'  => 403,
					'back_link' => false,
				]
			);

		}

	}


	/**
	 * Built-in request rules.
	 *
	 * SQL rules require statement syntax, so sentences such as "select items from list"
	 * in comments and searches pass. Quantifiers are bounded to limit backtracking.
	 *
	 * @return string[]
	 */
	private function default_request_patterns() {

		$http_pattern = '(?:(?:http|https)?\:\/\/)?';
		$url_pattern  = $http_pattern . '(?:[a-z0-9_\-\.]+\/+)([a-z0-9_\-\.\/]+)?';
		$sql_compare  = '[\w.`]+\s*(?:=|<|>|\!=|\blike\b|\bin\s*\()';

		return [
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
			'\bunion\s+(?:all\s+|distinct\s+)?select\s+[^;]{0,200}?(?:,|\*|\(|\d|\bnull\b|\bfrom\b)',
			'\bselect\s+\*\s+from\s+[\w.`]+',
			'\bselect\b[^;]{1,200}?\bfrom\s+[\w.`]+\s+where\s+' . $sql_compare,
			'\binsert\s+into\s+[\w.`]+\s*(?:\(|values\b|select\b|set\b)',
			'\bdelete\s+from\s+[\w.`]+\s+where\s+' . $sql_compare,
			// special characters " ' < > \ { |.
			'.*(&\#x22;|&\#x27;|&\#x3C;|&\#x3E;|&\#x5C;|&\#x7B;|&\#x7C;).*',
			// prevents ../ url patterns.
			$http_pattern . '(\/*[a-z0-9_\-\.]+)?(\.\.\/)+([a-z0-9_\-\.])*',
		];

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

		// Check requested path for malicious/sensitive files (e.g. .env, .sh, backdoor .php scripts).
		// Only intercepts requests already routed through WordPress (non-existent files);
		// does NOT modify .htaccess or interfere with files physically served by the web server.
		$this->check_malicious_path();

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
		$cookie_filter_items = $this->usable_patterns( apply_filters( 'securefusion_cookie_filter_items', $custom_cookie_patterns ) );

		if ( ! empty( $cookie_filter_items ) ) {

			$cookie_pattern = '#' . implode( '|', $cookie_filter_items ) . '#siu';

		}

		if ( ! empty( $_COOKIE ) ) {

			if ( ! empty( $cookie_pattern ) ) {

				if ( $this->bad_request_control( $_COOKIE, $cookie_pattern ) ) {

					// Log bad cookie with details.
					$ip = $this->get_client_ip();

					if ( $ip ) {

						$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

						// Cookie values include session credentials, so only the names are kept.
						$cookie_data = 'Cookies: ' . implode( ', ', array_map( 'sanitize_key', array_slice( array_keys( $_COOKIE ), 0, 50 ) ) );
						$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_COOKIE, $user_agent, $cookie_data );

					}

					wp_die(
						esc_html__( 'SecureFusion Firewall has denied this cookie request.', 'secuplug' ),
						esc_html__( 'Cookie Failure', 'secuplug' ),
						[
							'response'  => 403,
							'back_link' => true,
						]
					);

				}

			}

		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Presence check only; the firewall inspects unauthenticated requests.
		if ( $method === 'GET' && empty( $_GET ) ) {

			return;

		}

		// GET and POST security.
		$request_regex_arr = array_merge( $this->default_request_patterns(), $custom_request_patterns );

		$request_filter_items = $this->usable_patterns( apply_filters( 'securefusion_request_filter_items', $request_regex_arr ) );

		$request_pattern = '#' . implode( '|', $request_filter_items ) . '#siu';

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Firewall inspection must also handle requests without form nonces; this does not authorize a form action.
		if ( $method === 'POST' && ! empty( $_POST ) ) {

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Firewall inspection must also handle requests without form nonces; this does not authorize a form action.
			$input = $_POST;

		} else {

			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Inspect original request bytes; transforming them would change attack detection or size measurement.
			$input = isset( $_SERVER['QUERY_STRING'] ) && is_string( $_SERVER['QUERY_STRING'] ) ? $_SERVER['QUERY_STRING'] : '';

		}

		if ( $this->bad_request_control( $input, $request_pattern ) ) {

			// Log bad request with details.
			$ip = $this->get_client_ip();

			if ( $ip ) {

				$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_REQUEST, $user_agent, $this->request_path_for_log() . ' | ' . $this->redact_for_log( $input ) );

			}

			// Comments.
			if ( $pagenow === 'wp-comments-post.php' ) {

				wp_die(
					esc_html__( 'SecureFusion Firewall has denied this comment submission.', 'secuplug' ),
					esc_html__( 'Comment Submission Failure', 'secuplug' ),
					[
						'response'  => 403,
						'back_link' => true,
					]
				);

			}

			wp_die(
				esc_html__( 'SecureFusion Firewall has denied this request.', 'secuplug' ),
				esc_html__( 'Request Failure', 'secuplug' ),
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

				$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_QUERY, $user_agent, $this->redact_for_log( $wp->query_vars ) );

			}

			wp_die(
				esc_html__( 'SecureFusion Firewall has denied this WP Query.', 'secuplug' ),
				esc_html__( 'WP Query Failure', 'secuplug' ),
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

		$input  = urldecode( (string) $input );
		$length = strlen( $input );

		// Input that cannot be inspected must not pass as clean. Signed-in users are spared
		// because page builders can legitimately save very large fields.
		if ( $length > 1048576 ) {

			return ! is_user_logged_in();

		}

		$chunk_size = 32768;
		$overlap    = 4096;

		// Invalid UTF-8 would make a /u pattern fail, and chunks can split a character.
		// Built-in rules are ASCII, so masking the high bytes keeps them effective.
		if ( $length > $chunk_size || 1 !== preg_match( '//u', $input ) ) {

			$input = (string) preg_replace( '/[\x80-\xFF]/', '?', $input );

		}

		$offset = 0;

		// Bounded by the size check above: at most about 37 chunks.
		do {

			$checker = preg_match( $pattern, substr( $input, $offset, $chunk_size ) );

			// detect unwanted requests.
			if ( $checker === 1 ) {

				return true;

			}

			if ( $checker === false ) {

				return ! is_user_logged_in();

			}

			$offset += $chunk_size - $overlap;

		} while ( $offset + $overlap < $length );

		return false;

	}

}
