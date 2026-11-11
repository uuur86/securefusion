<?php
/**
 * Active Guard Settings
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	// Section info.
	'name'  => 'active_guard_settings',
	'title' => esc_html__( 'Firewall', 'secuplug' ),
	'desc'  => esc_html__( 'Checks requests before WordPress handles them and hides details that attackers look for. The request filter is in beta.', 'secuplug' ),
	// Form items.
	'items' => [
		[
			'type'    => 'radio',
			'name'    => 'filter_bad_requests',
			'default' => '0',
			'label'   => esc_html__( 'Filter malicious requests', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Blocks requests that contain common attack patterns such as code injection and cross-site scripting. The patterns are on the Advanced tab.', 'secuplug' ) . '</span>',
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
			'name'    => 'disable_rest_api',
			'default' => '0',
			'label'   => esc_html__( 'Close the REST API to visitors', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Visitors who are not logged in cannot read posts, pages, users or settings through /wp-json/wp/v2/. The API index and the endpoints of other plugins stay open.', 'secuplug' ) . '</span>',
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
			'name'    => 'hide_usernames',
			'default' => '1',
			'label'   => esc_html__( 'Hide usernames from visitors', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Stops the common ways to find login names: ?author=1 links, the REST users list, administrators in the users sitemap and oEmbed author data. Author pages keep working.', 'secuplug' ) . '</span>',
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
			'name'    => 'hide_versions',
			'default' => '0',
			'label'   => esc_html__( 'Hide server and PHP versions', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Removes the Server and X-Powered-By response headers that reveal software versions.', 'secuplug' ) . '</span>',
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
			'name'    => 'bad_bots',
			'default' => '0',
			'label'   => esc_html__( 'Block bad bots', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Blocks requests whose user agent matches the bad bot list (by default libwww-perl).', 'secuplug' ) . '</span>',
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
			'name'    => 'http_headers',
			'default' => $this->default_settings['http_headers'] ?? '1',
			'label'   => esc_html__( 'Send browser security headers', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Sends X-Frame-Options, X-Content-Type-Options and Referrer-Policy. Content Security Policy and HSTS have their own settings.', 'secuplug' ) . '</span>',
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
			'name'    => 'enable_coop',
			'default' => '0',
			'label'   => esc_html__( 'Isolate pages from other windows (COOP)', 'secuplug' ),
			'after'   => '<span class="description">' . esc_html__( 'Sends Cross-Origin-Opener-Policy: same-origin. This blocks some cross-site leaks but breaks sign-in pop-ups such as "Sign in with Google". Leave it off if you use them.', 'secuplug' ) . '</span>',
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
			'type'   => 'text_input',
			'name'   => 'max_payload_size',
			'label'  => esc_html__( 'Maximum request size', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' bytes', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Larger requests from visitors (file uploads excluded) are written to the Security Log. 0 turns the check off. Default: 4096.', 'secuplug' ) . '</span>',
		],
		[
			'type'    => 'radio',
			'name'    => 'block_oversized_requests',
			'default' => '0',
			'label'   => esc_html__( 'Block oversized requests', 'secuplug' ),
			'after'   => '<span class="fsf-field-warning"><span class="fsf-field-warning__label">' . esc_html__( 'Check the Security Log first.', 'secuplug' ) . '</span> ' . esc_html__( 'Long comments and checkout forms can go over the limit. A blocked address cannot open any page of this site until the block ends.', 'secuplug' ) . ' ' . esc_html( $this->oversized_request_summary() ) . '</span>',
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
			'type'   => 'text_input',
			'name'   => 'oversized_block_threshold',
			'label'  => esc_html__( 'Oversized requests allowed', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' requests', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'An address is blocked when it reaches this many oversized requests within 10 minutes. A single request never blocks anyone unless this is 1. Default: 5.', 'secuplug' ) . '</span>',
		],
		[
			'type'   => 'text_input',
			'name'   => 'oversized_block_minutes',
			'label'  => esc_html__( 'Oversized request block time', 'secuplug' ),
			'before' => '',
			'after'  => esc_html__( ' minute(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'The block ends by itself after this time, 10080 minutes (7 days) at most. You can unblock an address sooner on the Security Log page. Default: 30.', 'secuplug' ) . '</span>',
		],
	],

];
