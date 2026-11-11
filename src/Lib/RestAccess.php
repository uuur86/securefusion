<?php
/**
 * RestAccess responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * RestAccess methods.
 *
 * @mixin Middleware
 * @method string get_client_ip() Resolved client IP, or empty.
 */
trait RestAccess {

	/**
	 * True between authentication and dispatch of the HTTP REST request, so only that
	 * request is checked and server-side rest_do_request() calls keep working.
	 *
	 * @var bool
	 */
	private $rest_check_armed = false;

	/**
	 * Arms the route check for the HTTP REST request.
	 *
	 * Fired on 'rest_authentication_errors', which WordPress runs only for REST requests
	 * served over HTTP, right before dispatching them. The value is passed through untouched.
	 *
	 * @param \WP_Error|null|true $errors Authentication result so far.
	 * @return \WP_Error|null|true Unchanged result.
	 */
	public function arm_rest_route_check( $errors ) {

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {

			$this->rest_check_armed = true;

		}

		return $errors;

	}


	/**
	 * Blocks anonymous access to the protected core REST services.
	 *
	 * Fired on 'rest_pre_dispatch'. Only the request armed by arm_rest_route_check() is
	 * checked, so internal rest_do_request() calls made by themes and plugins are not affected.
	 *
	 * @param mixed            $result  Response to replace the requested version with.
	 * @param \WP_REST_Server  $server  Server instance.
	 * @param \WP_REST_Request $request Request used to generate the response.
	 * @return mixed Unchanged result, or a WP_Error when the request is blocked.
	 */
	public function restrict_rest_route( $result, $server, $request ) {

		if ( ! $this->rest_check_armed ) {

			return $result;

		}

		$this->rest_check_armed = false;

		if ( is_wp_error( $result ) || ! $request instanceof \WP_REST_Request ) {

			return $result;

		}

		// CORS preflight requests never carry credentials; blocking them would break
		// authenticated cross-origin clients (application passwords).
		if ( 'OPTIONS' === $request->get_method() ) {

			return $result;

		}

		if ( ! self::is_protected_rest_route( $request->get_route() ) ) {

			return $result;

		}

		if ( $this->is_rest_api_access_allowed( $request ) ) {

			return $result;

		}

		return new \WP_Error(
			'rest_disabled',
			esc_html__( 'The REST API on this site has been disabled.', 'secuplug' ),
			array( 'status' => rest_authorization_required_code() )
		);

	}


	/**
	 * Whether a REST route belongs to a protected core service.
	 *
	 * Matches the wp/v1 and wp/v2 namespace indexes and every route of the services in
	 * REST_PROTECTED_SERVICES, case-insensitively, as WordPress routes do.
	 *
	 * @param string $route Route as returned by WP_REST_Request::get_route(), e.g. "/wp/v2/users/1".
	 * @return bool
	 */
	public static function is_protected_rest_route( $route ) {

		if ( ! is_string( $route ) || '' === $route ) {

			return false;

		}

		// Only the prefix matters, so long routes are cut before any regex runs.
		$route = substr( $route, 0, Middleware::REST_ROUTE_MAX_LENGTH );
		$route = '/' . trim( (string) preg_replace( '#/{2,}#', '/', $route ), '/' );

		/**
		 * Filters the core REST services (under wp/v1 and wp/v2) blocked for anonymous visitors.
		 *
		 * @param string[] $services Service names, e.g. "users", "posts".
		 */
		$services = apply_filters( 'securefusion_rest_protected_services', Middleware::REST_PROTECTED_SERVICES );

		$quoted = [];

		foreach ( (array) $services as $service ) {

			if ( is_string( $service ) && '' !== $service ) {

				$quoted[] = preg_quote( $service, '#' );

			}

		}

		$pattern = empty( $quoted )
			? '#^/wp/v[12]$#i'
			: '#^/wp/v[12](?:$|/(?:' . implode( '|', $quoted ) . ')(?:/|$))#i';

		$matched = preg_match( $pattern, $route );

		// A regex failure must not open the API silently.
		return false === $matched ? true : 1 === $matched;

	}


	/**
	 * Verify if the current REST API request should be allowed based on security bypass rules.
	 *
	 * Runs only for protected routes, after WordPress has authenticated the request
	 * (cookie + nonce, application passwords), so is_user_logged_in() is reliable here.
	 *
	 * @param \WP_REST_Request|null $request Current request.
	 * @return bool True if allowed, false if blocked.
	 */
	private function is_rest_api_access_allowed( $request = null ) {

		// 1. Allow authenticated users.
		if ( is_user_logged_in() ) {

			return true;

		}

		// 2. Allow internal WordPress executions (Admin dashboard, AJAX, Cron, WP-CLI).
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'WP_CLI' ) && \WP_CLI ) ) {

			return true;

		}

		// 3. Allow loopback requests from the server itself. No DNS lookup here: it would
		// run on visitor requests and slow down or stall the site when DNS is slow.
		$ip        = $this->get_client_ip();
		$server_ip = isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '';

		$is_loopback = (
			'127.0.0.1' === $ip ||
			'::1' === $ip ||
			( ! empty( $server_ip ) && $ip === $server_ip )
		);

		if ( $is_loopback ) {

			$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

			if ( 0 === strpos( $user_agent, 'WordPress/' ) ) {

				return true;

			}

		}

		// 4. Allow requests with a valid REST API Nonce (e.g. from legitimate forms on the site).
		$nonce = null;

		if ( isset( $_SERVER['HTTP_X_WP_NONCE'] ) ) {

			$nonce = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_WP_NONCE'] ) );

		} elseif ( isset( $_REQUEST['_wpnonce'] ) ) {

			$nonce = sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) );

		}

		if ( $nonce && wp_verify_nonce( $nonce, 'wp_rest' ) ) {

			return true;

		}

		/**
		 * Filters whether an anonymous request to a protected REST route is allowed.
		 *
		 * Use it for trusted integrations, e.g. a monitoring service or a server whose
		 * loopback requests arrive from a public IP behind NAT.
		 *
		 * @param bool                  $allowed Default false.
		 * @param \WP_REST_Request|null $request Current request.
		 * @param string|false          $ip      Client IP.
		 */
		return (bool) apply_filters( 'securefusion_rest_allow_request', false, $request, $ip );

	}

}
