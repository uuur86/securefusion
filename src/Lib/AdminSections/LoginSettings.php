<?php
/**
 * Login Settings
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	// Section info.
	'name'  => 'login_settings',
	'title' => esc_html__( 'Login', 'secuplug' ),
	'desc'  => esc_html__( 'Limits password guessing and can move the login page to an address only you know. Write down a new login address before you save it.', 'secuplug' ),
	// Form items.
	'items' => [
		[
			'type'   => 'text_input',
			'name'   => 'ip_time_limit',
			'label'  => esc_html__( 'Lockout duration', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' hour(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'How long an IP stays blocked after too many failed logins.', 'secuplug' ) . '</span>',
		],
		[
			'type'   => 'text_input',
			'name'   => 'ip_attempt_window',
			'label'  => esc_html__( 'Counting window', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' minute(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Failed logins are counted within this period.', 'secuplug' ) . '</span>',
		],
		[
			'type'   => 'text_input',
			'name'   => 'ip_login_limit',
			'label'  => esc_html__( 'Failed logins allowed', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' attempts', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'An IP is blocked after this many failed logins within the counting window.', 'secuplug' ) . '</span>',
		],
		[
			'type'   => 'text_input',
			'name'   => 'cleanup_ip_days',
			'label'  => esc_html__( 'Forget IPs after', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' day(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Removes IP records that were inactive for this many days. 0 keeps them.', 'secuplug' ) . '</span>',
		],
		[
			'type'   => 'text_input',
			'name'   => 'cleanup_ip_attempts',
			'label'  => esc_html__( 'Forget only IPs with fewer than', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' failed logins', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'IPs with this many failed logins or more are kept.', 'secuplug' ) . '</span>',
		],
		[
			'type'   => 'text_input',
			'name'   => 'custom_login_url',
			'label'  => esc_html__( 'Login page address', 'secuplug' ),
			'before' => '<span class="url-text">' . ( 'network' === $this->context ? esc_html__( '(site address)', 'secuplug' ) : esc_html( \get_home_url() ) ) . '/</span>',
			'after'  => '<span class="url-text">/</span><span class="field-tip">' . esc_html__( 'Example: hidden-login. Leave it empty to keep the standard wp-login.php address.', 'secuplug' ) . '</span>',
		],
		[
			'type'  => 'text_input',
			'name'  => 'change_login_error',
			'label' => esc_html__( 'Login error message', 'secuplug' ),
			'after' => '<span class="description">' . esc_html__( 'Shown instead of the WordPress message, which tells attackers whether a username exists. Leave it empty to keep the WordPress message.', 'secuplug' ) . '</span>',
		],
	],
];
