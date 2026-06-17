<?php
/**
 * ReCaptcha Class
 * Handles Google reCAPTCHA integrations and validation.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

use SecureFusion\Lib\Traits\WPCommon;
use WP_Error;

/**
 * ReCaptcha functionality class.
 */
class ReCaptcha {

	use WPCommon;

	/**
	 * Initialize reCAPTCHA.
	 *
	 * Registers actions and filters for form integration.
	 *
	 * @return void
	 */
	public function init() {
		if ( ! $this->get_settings( 'recaptcha_enable' ) ) {
			return;
		}

		// Register lazyload script.
		add_action( 'wp_enqueue_scripts', [ $this, 'register_assets' ] );
		add_action( 'login_enqueue_scripts', [ $this, 'register_assets' ] );

		// WP Login Form.
		if ( $this->get_settings( 'recaptcha_login' ) ) {
			add_action( 'login_form', [ $this, 'render_captcha_placeholder' ] );
			add_filter( 'wp_authenticate_user', [ $this, 'validate_login' ], 30, 1 );
		}

		// WP Registration Form.
		if ( $this->get_settings( 'recaptcha_register' ) ) {
			add_action( 'register_form', [ $this, 'render_captcha_placeholder' ] );
			add_filter( 'registration_errors', [ $this, 'validate_registration' ], 10, 1 );
		}

		// WP Lost Password Form.
		if ( $this->get_settings( 'recaptcha_lostpassword' ) ) {
			add_action( 'lostpassword_form', [ $this, 'render_captcha_placeholder' ] );
			add_action( 'lostpassword_post', [ $this, 'validate_lostpassword' ], 10, 0 );
		}

		// WP Comment Form.
		if ( $this->get_settings( 'recaptcha_comment' ) ) {
			add_action( 'comment_form_after_fields', [ $this, 'render_captcha_placeholder' ] );
			add_action( 'comment_form_logged_in_after', [ $this, 'render_captcha_placeholder' ] );
			add_filter( 'preprocess_comment', [ $this, 'validate_comment' ] );
		}

		// Contact Form 7 Integration.
		if ( $this->get_settings( 'recaptcha_cf7' ) ) {
			add_filter( 'wpcf7_form_elements', [ $this, 'cf7_inject_placeholder' ] );
			add_filter( 'wpcf7_validate', [ $this, 'cf7_validate_captcha' ], 10, 1 );
		}

		// Mailchimp for WP (MC4WP) Integration.
		if ( $this->get_settings( 'recaptcha_mc4wp' ) ) {
			add_action( 'mc4wp_form_before_fields', [ $this, 'render_captcha_placeholder' ] );
			add_filter( 'mc4wp_form_errors', [ $this, 'mc4wp_validate_captcha' ], 10, 1 );
		}
	}

	/**
	 * Register lazyload recaptcha assets.
	 *
	 * @return void
	 */
	public function register_assets() {
		wp_register_script(
			'securefusion-recaptcha-lazyload',
			plugins_url( 'assets/js/recaptcha.js', SECUREFUSION_BASENAME ),
			[],
			SECUREFUSION_VERSION,
			true
		);
	}

	/**
	 * Render the placeholder for reCAPTCHA widget.
	 *
	 * @return void
	 */
	public function render_captcha_placeholder() {
		$site_key = $this->get_settings( 'recaptcha_site_key' );
		$version  = $this->get_settings( 'recaptcha_version' );

		if ( empty( $site_key ) ) {
			return;
		}

		wp_enqueue_script( 'securefusion-recaptcha-lazyload' );

		echo '<div class="securefusion-recaptcha-placeholder" data-sitekey="' . esc_attr( $site_key ) . '" data-version="' . esc_attr( $version ) . '" style="margin: 10px 0;"></div>';
	}

	/**
	 * Verification via Google API.
	 *
	 * @return bool True if verification succeeds, false otherwise.
	 */
	public function verify_recaptcha_token() {
		$secret_key = $this->get_settings( 'recaptcha_secret_key' );
		if ( empty( $secret_key ) ) {
			return true; // Assume pass if not configured.
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked via the parent forms' own built-in nonces.
		$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';
		if ( empty( $token ) ) {
			return false;
		}

		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			[
				'body' => [
					'secret'   => $secret_key,
					'response' => $token,
					'remoteip' => $this->get_client_ip(),
				],
			]
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! isset( $body['success'] ) || ! $body['success'] ) {
			return false;
		}

		// For v3, check score.
		if ( $this->get_settings( 'recaptcha_version' ) === 'v3' ) {
			$score = isset( $body['score'] ) ? (float) $body['score'] : 0.0;
			if ( $score < 0.5 ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Validate login form submission.
	 *
	 * @param WP_User|WP_Error $user WP_User or WP_Error object.
	 * @return WP_User|WP_Error
	 */
	public function validate_login( $user ) {
		// If authentication already failed, skip captcha validation.
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		if ( ! $this->verify_recaptcha_token() ) {
			return new WP_Error( 'recaptcha_failed', '<strong>' . esc_html__( 'Error:', 'secuplug' ) . '</strong> ' . esc_html__( 'Please complete the reCAPTCHA.', 'secuplug' ) );
		}

		return $user;
	}

	/**
	 * Validate registration form submission.
	 *
	 * @param WP_Error $errors WP_Error object.
	 * @return WP_Error
	 */
	public function validate_registration( $errors ) {
		if ( ! $this->verify_recaptcha_token() ) {
			$errors->add( 'recaptcha_failed', '<strong>' . esc_html__( 'Error:', 'secuplug' ) . '</strong> ' . esc_html__( 'Please complete the reCAPTCHA.', 'secuplug' ) );
		}
		return $errors;
	}

	/**
	 * Validate lost password form submission.
	 *
	 * @return void
	 */
	public function validate_lostpassword() {
		if ( ! $this->verify_recaptcha_token() ) {
			wp_die(
				'<strong>' . esc_html__( 'Error:', 'secuplug' ) . '</strong> ' . esc_html__( 'Please complete the reCAPTCHA.', 'secuplug' ),
				esc_html__( 'reCAPTCHA Failed', 'secuplug' ),
				[
					'response'  => 400,
					'back_link' => true,
				]
			);
		}
	}

	/**
	 * Validate comment submission.
	 *
	 * @param array $commentdata Comment data.
	 * @return array
	 */
	public function validate_comment( $commentdata ) {
		// Skip for logged in admin to prevent frustration if configured.
		if ( current_user_can( 'manage_options' ) ) {
			return $commentdata;
		}

		if ( ! $this->verify_recaptcha_token() ) {
			wp_die(
				'<strong>' . esc_html__( 'Error:', 'secuplug' ) . '</strong> ' . esc_html__( 'Please complete the reCAPTCHA.', 'secuplug' ),
				esc_html__( 'reCAPTCHA Failed', 'secuplug' ),
				[
					'response'  => 400,
					'back_link' => true,
				]
			);
		}

		return $commentdata;
	}

	/**
	 * Inject placeholder in Contact Form 7 elements.
	 *
	 * @param string $elements Form elements HTML.
	 * @return string
	 */
	public function cf7_inject_placeholder( $elements ) {
		// Only inject if there isn't already a securefusion placeholder.
		if ( strpos( $elements, 'securefusion-recaptcha-placeholder' ) === false ) {
			$site_key = $this->get_settings( 'recaptcha_site_key' );
			$version  = $this->get_settings( 'recaptcha_version' );

			if ( ! empty( $site_key ) ) {
				wp_enqueue_script( 'securefusion-recaptcha-lazyload' );
				$placeholder = '<div class="securefusion-recaptcha-placeholder" data-sitekey="' . esc_attr( $site_key ) . '" data-version="' . esc_attr( $version ) . '" style="margin: 10px 0;"></div>';

				// Inject just before the submit button if possible, otherwise at the end.
				if ( preg_match( '/<input[^>]+type=["\']submit["\']/i', $elements ) ) {
					$elements = preg_replace( '/(<input[^>]+type=["\']submit["\'])/i', $placeholder . '$1', $elements, 1 );
				} else {
					$elements .= $placeholder;
				}
			}
		}
		return $elements;
	}

	/**
	 * Validate Contact Form 7 submission.
	 *
	 * @param WPCF7_Validation $result Validation result object.
	 * @return WPCF7_Validation
	 */
	public function cf7_validate_captcha( $result ) {
		if ( ! $this->verify_recaptcha_token() ) {
			$result->invalidate( 'g-recaptcha-response', esc_html__( 'Please complete the reCAPTCHA.', 'secuplug' ) );
		}
		return $result;
	}

	/**
	 * Validate Mailchimp for WP submission.
	 *
	 * @param array $errors Form errors.
	 * @return array
	 */
	public function mc4wp_validate_captcha( $errors ) {
		if ( ! $this->verify_recaptcha_token() ) {
			$errors[] = esc_html__( 'Please complete the reCAPTCHA.', 'secuplug' );
		}
		return $errors;
	}
}
