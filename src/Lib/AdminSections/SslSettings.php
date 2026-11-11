<?php
/**
 * Ssl Settings
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	// Section info.
	'name'  => 'ssl_settings',
	'title' => esc_html__( 'HTTPS', 'secuplug' ),
	'desc'  => esc_html__( 'Moves logins, the admin area and visitors to HTTPS.', 'secuplug' ),
	// Form items.
	'items' => [
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'enable_https',
			'default' => '',
			'label'   => esc_html__( 'HTTPS support', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Turn this on after your SSL certificate works. The options below need it.', 'secuplug' ) . '</span>',
			'options' => [
				[
					'label' => esc_html__( 'Disabled', 'secuplug' ),
					'value' => '',
				],
				[
					'label' => esc_html__( 'Enabled', 'secuplug' ),
					'value' => 'https',
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'force_login_https',
			'default' => '',
			'label'   => esc_html__( 'Use HTTPS on the login page', 'secuplug' ),
			'options' => [
				[
					'label' => esc_html__( 'Disabled', 'secuplug' ),
					'value' => '',
				],
				[
					'label' => esc_html__( 'Enabled', 'secuplug' ),
					'value' => 'https',
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'force_admin_https',
			'default' => '',
			'label'   => esc_html__( 'Use HTTPS in the admin area', 'secuplug' ),
			'options' => [
				[
					'label' => esc_html__( 'Disabled', 'secuplug' ),
					'value' => '',
				],
				[
					'label' => esc_html__( 'Enabled', 'secuplug' ),
					'value' => 'https',
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'force_front_https',
			'default' => '',
			'label'   => esc_html__( 'Use HTTPS on the front page', 'secuplug' ),
			'options' => [
				[
					'label' => esc_html__( 'Disabled', 'secuplug' ),
					'value' => '',
				],
				[
					'label' => esc_html__( 'Enabled', 'secuplug' ),
					'value' => 'https',
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'force_site_https',
			'default' => '',
			'label'   => esc_html__( 'Use HTTPS on the whole site', 'secuplug' ),
			'options' => [
				[
					'label' => esc_html__( 'Disabled', 'secuplug' ),
					'value' => '',
				],
				[
					'label' => esc_html__( 'Enabled', 'secuplug' ),
					'value' => 'https',
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'enable_hsts',
			'default' => '0',
			'label'   => esc_html__( 'Strict HTTPS in browsers (HSTS)', 'secuplug' ),
			'after'   => '<span class="fsf-field-warning"><span class="fsf-field-warning__label">' . esc_html__( 'Can make the site unreachable.', 'secuplug' ) . '</span> ' . esc_html__( 'Browsers that see this refuse plain HTTP and refuse to bypass certificate errors for the duration below. If your certificate expires or HTTPS stops working, those visitors cannot open the site, and turning this off does not reach them. Use it only when renewal is automatic and every page works over HTTPS.', 'secuplug' ) . '</span>',
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'Off', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'On', 'secuplug' ),
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'hsts_max_age',
			'default' => '86400',
			'label'   => esc_html__( 'How long browsers remember HSTS', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Start with 1 day. Raise it step by step once the site has run without HTTPS problems.', 'secuplug' ) . '</span>',
			'options' => [
				[
					'value' => '86400',
					'label' => esc_html__( '1 day (test)', 'secuplug' ),
				],
				[
					'value' => '2592000',
					'label' => esc_html__( '30 days', 'secuplug' ),
				],
				[
					'value' => '31536000',
					'label' => esc_html__( '1 year', 'secuplug' ),
				],
				[
					'value' => '63072000',
					'label' => esc_html__( '2 years', 'secuplug' ),
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'enable_hsts_subdomains',
			'default' => '0',
			'label'   => esc_html__( 'HSTS: include subdomains', 'secuplug' ),
			'after'   => '<span class="fsf-field-warning"><span class="fsf-field-warning__label">' . esc_html__( 'Affects every subdomain.', 'secuplug' ) . '</span> ' . esc_html__( 'Any subdomain without working HTTPS, such as mail, staging or a shop on another server, becomes unreachable. On a subdomain network this covers every site.', 'secuplug' ) . '</span>',
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'Off', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'On', 'secuplug' ),
				],
			],
		],
		[
			'cond'    => $ssl_cond,
			'type'    => 'radio',
			'name'    => 'enable_hsts_preload',
			'default' => '0',
			'label'   => esc_html__( 'HSTS: allow preloading', 'secuplug' ),
			'after'   => '<span class="fsf-field-warning"><span class="fsf-field-warning__label">' . esc_html__( 'Removal takes months.', 'secuplug' ) . '</span> ' . esc_html__( 'Only sent with subdomains on and a duration of at least 1 year. Once your domain is on the browser preload lists it must stay HTTPS-only.', 'secuplug' ) . '</span>',
			'options' => [
				[
					'value' => '0',
					'label' => esc_html__( 'Off', 'secuplug' ),
				],
				[
					'value' => '1',
					'label' => esc_html__( 'On', 'secuplug' ),
				],
			],
		],
	],
];
