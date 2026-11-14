<?php
/**
 * Notification settings.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

$securefusion_notify_switch = [
	[
		'value' => '0',
		'label' => esc_html__( 'Off', 'secuplug' ),
	],
	[
		'value' => '1',
		'label' => esc_html__( 'On', 'secuplug' ),
	],
];

$securefusion_notify_field = static function ( $name, $label, $description ) use ( $securefusion_notify_switch ) {

	return [
		'type'    => 'radio',
		'name'    => $name,
		'default' => '1',
		'label'   => $label,
		'options' => $securefusion_notify_switch,
		'after'   => '<span class="description">' . esc_html( $description ) . '</span>',
	];

};

return [
	// Section info.
	'name'  => 'notification_settings',
	'title' => esc_html__( 'Notifications', 'secuplug' ),
	'desc'  => esc_html__( 'Visitors and other users never see them.', 'secuplug' ),
	// Form items.
	'items' => [
		$securefusion_notify_field(
			'notify_enable',
			esc_html__( 'Show notifications', 'secuplug' ),
			__( 'Turns every kind below on or off at once.', 'secuplug' )
		),
		$securefusion_notify_field(
			'notify_csp',
			esc_html__( 'Blocked content', 'secuplug' ),
			__( 'When the Content Security Policy blocks something on the page you are viewing, or would block it while testing. Everything blocked on one page is gathered in one box, with a button to allow it. Also works when the policy does not apply to administrators.', 'secuplug' )
		),
		$securefusion_notify_field(
			'notify_status',
			esc_html__( 'Protection status', 'secuplug' ),
			__( 'Only things that need a decision, such as a tested policy that is ready to be turned on or a cache driver that stopped working.', 'secuplug' )
		),
		$securefusion_notify_field(
			'notify_activity',
			esc_html__( 'Activity summary', 'secuplug' ),
			__( 'At most once a week, in the dashboard only: how many addresses were stopped or logged since the last summary.', 'secuplug' )
		),
	],
];
