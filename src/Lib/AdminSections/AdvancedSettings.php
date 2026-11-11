<?php
/**
 * Advanced Settings
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	// Section info.
	'name'  => 'advanced_settings',
	'title' => esc_html__( 'Advanced', 'secuplug' ),
	'desc'  => esc_html__( 'Patterns used by "Filter malicious requests" on the Firewall tab.', 'secuplug' ),
	// Form items.
	'items' => [
		[
			'type'              => 'taginput',
			'name'              => 'cookie_patterns',
			'label'             => esc_html__( 'Cookie patterns', 'secuplug' ),
			'placeholder'       => '[a-z0-9]+',
			'field_type'        => 'regex',
			'sanitize_callback' => function ( $value ) {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				return @preg_match( '/' . $value . '/', '' ) !== false;

			},
			'presets'           => [
				'[a-z0-9]+'                => __( 'Alphanumeric', 'secuplug' ),
				'[a-zA-Z0-9_\-]+'          => __( 'Safe Chars', 'secuplug' ),
				'[^\x27\x22\x3c\x3e\x5c]+' => __( 'No Special Chars', 'secuplug' ),
				'^PHPSESSID$'              => __( 'PHPSESSID', 'secuplug' ),
			],
		],
		[
			'type'              => 'taginput',
			'name'              => 'request_patterns',
			'label'             => esc_html__( 'Request patterns (GET and POST)', 'secuplug' ),
			'placeholder'       => '(union|select|insert)\s+\w+',
			'field_type'        => 'regex',
			'sanitize_callback' => function ( $value ) {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				return @preg_match( '/' . $value . '/', '' ) !== false;

			},
			'presets'           => [
				'@@[\w\.\$]+'              => __( 'SQL Vars', 'secuplug' ),
				'(union|select|insert)\s+' => __( 'SQL Keywords', 'secuplug' ),
				'base64_\w+\('             => __( 'Base64 Func', 'secuplug' ),
				'<script[^>]*>'            => __( 'XSS Script Tag', 'secuplug' ),
				'\bon\w+\s*=\s*[\x27\x22]' => __( 'XSS Event Handler', 'secuplug' ),
				'\.\.[\\/]'                => __( 'LFI Traversal', 'secuplug' ),
			],
		],
	],
];
