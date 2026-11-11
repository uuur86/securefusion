<?php
/**
 * Xmlrpc Settings
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	// Section info.
	'name'  => 'xmlrpc_settings',
	'title' => esc_html__( 'XML-RPC', 'secuplug' ),
	'desc'  => esc_html__( 'XML-RPC is an older remote publishing interface. Attackers use it to try many passwords in a single request. Most sites do not need it.', 'secuplug' ),
	// Form items.
	'items' => [
		[
			'type'    => 'radio',
			'name'    => 'disable_xmlrpc',
			'default' => '0',
			'label'   => esc_html__( 'Turn off XML-RPC completely', 'secuplug' ),
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
			'after'   => '<span class="description">' . esc_html__( 'Blocks every XML-RPC request. Apps that publish through XML-RPC (older mobile apps, some Jetpack features) stop working.', 'secuplug' ) . '</span>',
		],
		[
			'type'    => 'radio',
			'name'    => 'disable_xmlrpc_user_login',
			'default' => '0',
			'label'   => esc_html__( 'Block logins through XML-RPC', 'secuplug' ),
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
			'after'   => '<span class="description">' . esc_html__( 'Stops password guessing through XML-RPC. Leave this on unless an app signs in to your site through XML-RPC.', 'secuplug' ) . '</span>',
		],
		[
			'type'    => 'radio',
			'name'    => 'disable_xmlrpc_pingback',
			'default' => '0',
			'label'   => esc_html__( 'Block pingbacks', 'secuplug' ),
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
			'after'   => '<span class="description">' . esc_html__( 'Attackers can use pingbacks to make your site send traffic floods to other sites.', 'secuplug' ) . '</span>',
		],
		[
			'type'    => 'radio',
			'name'    => 'disable_self_pingback',
			'default' => '0',
			'label'   => esc_html__( 'Block pingbacks to your own posts', 'secuplug' ),
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
			'after'   => '<span class="description">' . esc_html__( 'WordPress pings your own posts when you link between them. This only adds noise to your comments.', 'secuplug' ) . '</span>',
		],
	],
];
