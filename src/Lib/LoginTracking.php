<?php
/**
 * LoginTracking responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * LoginTracking methods.
 *
 * @mixin Middleware
 * @property BruteForceDB $brute_force_db Created in Middleware::__construct().
 * @method string get_client_ip() Resolved client IP, or empty.
 * @method array|string|null get_settings( string|null $name = null ) Resolved settings.
 */
trait LoginTracking {

	/**
	 * Register the login hooks.
	 *
	 * The lockout runs on the 'authenticate' filter, which wp_authenticate() applies for every
	 * password login: the login form (wp_signon()), XML-RPC (wp_xmlrpc_server::login()) and any
	 * plugin that calls wp_authenticate(). The 'wp_authenticate' action used before is fired by
	 * wp_signon() only.
	 *
	 * @return void
	 */
	public function register_login_tracking() {

		add_action( 'wp_login_failed', [ $this, 'track_login_failed' ], 10, 2 );
		add_filter( 'authenticate', [ $this, 'check_login_lockout' ], Middleware::LOGIN_LOCKOUT_PRIORITY, 3 );
		add_action( 'wp_login', [ $this, 'track_login_successful' ], 10, 2 );

	}


	/**
	 * Refuse a password check from a locked-out address before WordPress verifies the password.
	 *
	 * Runs ahead of every core 'authenticate' callback. Core checks a password only when both
	 * fields are filled (wp_authenticate_username_password() and its email and application
	 * password siblings answer empty fields without hashing), so calls without credentials,
	 * such as every view of wp-login.php, cost no query here. A locked-out address is answered
	 * by wp_die(), which ends the request: no later callback can turn the refusal into a login
	 * and no password hash is computed.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result of earlier callbacks.
	 * @param string                  $username Username or email address.
	 * @param string                  $password Password.
	 * @return \WP_User|\WP_Error|null
	 */
	public function check_login_lockout(
		$user,
		$username = '',
		#[\SensitiveParameter]
		$password = ''
	) {

		if ( empty( $username ) || empty( $password ) ) {

			return $user;

		}

		if ( $this->track_limit_login_attempts() ) {

			// Reached only if a wp_die() handler returns instead of ending the request.
			return new \WP_Error( 'securefusion_locked_out', esc_html__( 'You have reached the login attempts limit. Your IP has been locked out.', 'secuplug' ) );

		}

		return $user;

	}


	/**
	 * Track failed login attempts.
	 *
	 * Fired on 'wp_login_failed' action.
	 *
	 * @param string         $username Username attempted.
	 * @param \WP_Error|null $error Optional. Error object.
	 * @return void
	 */
	public function track_login_failed( $username, $error = null ) {
		// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by hook action.
		unset( $error );

		$ip = $this->get_client_ip();

		if ( ! $ip ) {

			return;

		}

		// Log with full details (IP, UA, payload).
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		// Do not retain arbitrary login form fields, credentials or tokens.
		$payload = 'Username: ' . sanitize_text_field( $username );

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
	 * Called from check_login_lockout() before a password is verified. Blocks the address
	 * and ends the request once it reached the limit within the window.
	 *
	 * @return bool True when the address is locked out and wp_die() returned.
	 */
	public function track_limit_login_attempts() {

		// Get client IP.
		$ip = $this->get_client_ip();

		if ( ! $ip ) {

			return false;

		}

		if ( $this->brute_force_db->is_ip_whitelisted( $ip ) ) {

			return false;

		}

		$ip_login_limit    = $this->get_settings( 'ip_login_limit' );
		$ip_attempt_window = $this->get_settings( 'ip_attempt_window' );
		$ip_time_limit     = $this->get_settings( 'ip_time_limit' );

		if ( ! $ip_login_limit ) {

			return false;

		}

		$ip_attempt_window = ! empty( $ip_attempt_window ) ? absint( $ip_attempt_window ) : 1;
		$ip_time_limit     = ! empty( $ip_time_limit ) ? absint( $ip_time_limit ) : 2;

		$window_seconds = $ip_attempt_window * MINUTE_IN_SECONDS;
		$attempts       = $this->brute_force_db->get_failed_login_attempts_in_window( $ip, $window_seconds );

		// Failed login attempts.
		if ( $attempts >= $ip_login_limit ) {

			$duration_seconds = $ip_time_limit * HOUR_IN_SECONDS;
			$this->brute_force_db->block_ip( $ip, $duration_seconds );

			if ( ! headers_sent() ) {

				header( 'X-LiteSpeed-Cache-Control: no-cache' );

				// The XML-RPC handler of wp_die() prints a fault but sets no status of its own.
				status_header( 403 );

			}

			// wp_die() picks the answer for the request: the HTML page on the login form, an
			// XML-RPC fault for XML-RPC, JSON for REST and AJAX; all with status 403 and no-cache.
			wp_die(
				esc_html__( 'You have reached the login attempts limit. Your IP has been locked out.', 'secuplug' ),
				esc_html__( 'Too many failed login attempts', 'secuplug' ),
				[
					'response'  => 403,
					'back_link' => false,
				]
			);

			return true;

		}

		return false;

	}


	/**
	 * Track successful login attempts.
	 *
	 * Fired on 'wp_login' action.
	 *
	 * @param string   $user_login Username.
	 * @param \WP_User $user       User object.
	 * @return void
	 */
	public function track_login_successful( $user_login, $user ) {

		$ip = $this->get_client_ip();

		if ( ! $ip ) {

			return;

		}

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		// Construct payload safely (Username & User ID).
		$payload = sprintf( 'User: %s (ID: %d)', sanitize_text_field( $user_login ), $user->ID );

		$this->brute_force_db->log_attempt_with_details(
			$ip,
			BruteForceDB::TYPE_SUCCESSFUL_LOGIN,
			$user_agent,
			$payload
		);

	}

}
