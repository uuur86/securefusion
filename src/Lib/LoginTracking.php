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
	 * Fired on the 'wp_authenticate' action.
	 *
	 * @return void
	 */
	public function track_limit_login_attempts() {

		// Get client IP.
		$ip = $this->get_client_ip();

		if ( ! $ip ) {

			return;

		}

		if ( $this->brute_force_db->is_ip_whitelisted( $ip ) ) {

			return;

		}

		$ip_login_limit    = $this->get_settings( 'ip_login_limit' );
		$ip_attempt_window = $this->get_settings( 'ip_attempt_window' );
		$ip_time_limit     = $this->get_settings( 'ip_time_limit' );

		if ( ! $ip_login_limit ) {

			return;

		}

		$ip_attempt_window = ! empty( $ip_attempt_window ) ? absint( $ip_attempt_window ) : 1;
		$ip_time_limit     = ! empty( $ip_time_limit ) ? absint( $ip_time_limit ) : 2;

		$window_seconds = $ip_attempt_window * MINUTE_IN_SECONDS;
		$attempts       = $this->brute_force_db->get_failed_login_attempts_in_window( $ip, $window_seconds );

		// Failed login attempts.
		if ( $attempts >= $ip_login_limit ) {

			$duration_seconds = $ip_time_limit * HOUR_IN_SECONDS;
			$this->brute_force_db->block_ip( $ip, $duration_seconds );

			wp_die(
				esc_html__( 'You have reached the login attempts limit. Your IP has been locked out.', 'secuplug' ),
				esc_html__( 'Too many failed login attempts', 'secuplug' ),
				[
					'response'  => 403,
					'back_link' => false,
				]
			);

		}

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
