<?php
/**
 * Recaptcha Settings
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	// Section info.
	'name'  => 'recaptcha_settings',
	'title' => esc_html__( 'reCAPTCHA', 'secuplug' ),
	'desc'  => esc_html__( 'Adds a Google reCAPTCHA check to the forms you choose. The script loads lazily to keep pages fast.', 'secuplug' ),
	// Form items.
	'items' => [
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_enable',
			'default' => $this->default_settings['recaptcha_enable'] ?? '0',
			'label'   => esc_html__( 'Use reCAPTCHA', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Create the site key and the secret key in the Google reCAPTCHA admin console for this domain.', 'secuplug' ) . '</span>',
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'Disable', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Enable', 'secuplug' ),
				],
			],
		],
		[
			'type'        => 'text_input',
			'name'        => 'recaptcha_site_key',
			'label'       => esc_html__( 'Site key', 'secuplug' ),
			'placeholder' => esc_html__( 'reCAPTCHA site key', 'secuplug' ),
		],
		[
			'type'        => 'text_input',
			'name'        => 'recaptcha_secret_key',
			'label'       => esc_html__( 'Secret key', 'secuplug' ),
			'placeholder' => esc_html__( 'reCAPTCHA secret key', 'secuplug' ),
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_version',
			'default' => $this->default_settings['recaptcha_version'] ?? 'v2_checkbox',
			'label'   => esc_html__( 'reCAPTCHA type', 'secuplug' ),
			'options' => [
				[
					'value' => 'v2_checkbox',
					'label' => esc_html__( 'reCAPTCHA v2 (Checkbox)', 'secuplug' ),
				],
				[
					'value' => 'v2_invisible',
					'label' => esc_html__( 'reCAPTCHA v2 (Invisible)', 'secuplug' ),
				],
				[
					'value' => 'v3',
					'label' => esc_html__( 'reCAPTCHA v3', 'secuplug' ),
				],
			],
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_login',
			'default' => $this->default_settings['recaptcha_login'] ?? '0',
			'label'   => esc_html__( 'Login form', 'secuplug' ),
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'No', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Yes', 'secuplug' ),
				],
			],
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_register',
			'default' => $this->default_settings['recaptcha_register'] ?? '0',
			'label'   => esc_html__( 'Registration form', 'secuplug' ),
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'No', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Yes', 'secuplug' ),
				],
			],
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_lostpassword',
			'default' => $this->default_settings['recaptcha_lostpassword'] ?? '0',
			'label'   => esc_html__( 'Lost password form', 'secuplug' ),
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'No', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Yes', 'secuplug' ),
				],
			],
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_comment',
			'default' => $this->default_settings['recaptcha_comment'] ?? '0',
			'label'   => esc_html__( 'Comment form', 'secuplug' ),
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'No', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Yes', 'secuplug' ),
				],
			],
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_cf7',
			'default' => $this->default_settings['recaptcha_cf7'] ?? '0',
			'label'   => esc_html__( 'Contact Form 7 forms', 'secuplug' ),
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'No', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Yes', 'secuplug' ),
				],
			],
		],
		[
			'type'    => 'radio',
			'name'    => 'recaptcha_mc4wp',
			'default' => $this->default_settings['recaptcha_mc4wp'] ?? '0',
			'label'   => esc_html__( 'Mailchimp for WP forms', 'secuplug' ),
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'No', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'Yes', 'secuplug' ),
				],
			],
		],
	],
];
