<?php
/**
 * Content Security Policy settings.
 *
 * Protection is on or off. Fields below it only add hosts or change one thing, so no two
 * fields can contradict each other.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

$securefusion_csp_values = 'network' === $this->context ? Settings::inherited_values() : Settings::all();

$securefusion_csp_description = static function ( $text, $class_name = 'description' ) {

	return '<span class="' . esc_attr( $class_name ) . '">' . esc_html( $text ) . '</span>';

};

$securefusion_csp_warning = static function ( $lead, $text, $class_name = '' ) {

	return '<span class="fsf-field-warning ' . esc_attr( $class_name ) . '"><span class="fsf-field-warning__label">' . esc_html( $lead ) . '</span> ' . esc_html( $text ) . '</span>';

};

$securefusion_csp_switch = static function ( $off, $on ) {

	return [
		[
			'value' => '0',
			'label' => $off,
		],
		[
			'value' => '1',
			'label' => $on,
		],
	];

};

/**
 * One host list per resource type. There is no switch: a list that adds to a rule the policy
 * already has takes a note, a list that creates the limit takes the warning of what then breaks.
 */
$securefusion_csp_list = static function ( $type, $label, $placeholder, $presets, $note, $breaks = '' ) use ( $securefusion_csp_description, $securefusion_csp_warning ) {

	return [
		[
			'type'              => 'taginput',
			'name'              => 'csp_allowed_' . $type . '_sources',
			'label'             => $label,
			'placeholder'       => $placeholder,
			'field_type'        => 'url',
			'sanitize_callback' => [ CSP::class, 'validate_host_source' ],
			'presets'           => $presets,
			'after'             => $securefusion_csp_description( $note ) . ( '' !== $breaks ? $securefusion_csp_warning( __( 'Limits as soon as it holds a host.', 'secuplug' ), $breaks ) : '' ),
		],
	];

};

return [
	// Section info.
	'name'  => 'security_policies_settings',
	'title' => esc_html__( 'Content Security Policy', 'secuplug' ),
	'desc'  => esc_html__( 'Tells browsers what your pages may load and run. The admin area is never restricted, and the login page only gets the framing and base URL rules.', 'secuplug' ),
	// Form items.
	'items' => array_merge(
		[
			[
				'type'    => 'radio',
				'name'    => 'csp_level',
				'default' => 'off' === CSPPolicy::level( $securefusion_csp_values ) ? 'off' : 'basic',
				'label'   => __( 'Protection', 'secuplug' ),
				'options' => [
					[
						'value' => 'off',
						'label' => __( 'Off', 'secuplug' ),
					],
					[
						'value' => 'basic',
						'label' => __( 'On (recommended)', 'secuplug' ),
					],
				],
				'after'   => $securefusion_csp_description( __( 'A script only runs when it comes from your own site, from a host your theme or plugins load, from a service allowed below, or when it was approved for the page. Code that WordPress, your theme and active plugins print is approved while the page is built. Injected code has none of these, so browsers refuse it. Framing by other sites and changed base URLs are blocked too.', 'secuplug' ), 'description fsf-csp-note' )
					. $securefusion_csp_description( __( 'Anything blocked on a page you visit shows up as a notification at the bottom right, with a button to allow it.', 'secuplug' ), 'description fsf-csp-note' ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_mode',
				'default' => CSPPolicy::mode( $securefusion_csp_values ),
				'label'   => __( 'When a rule is broken', 'secuplug' ),
				'options' => [
					[
						'value' => 'report',
						'label' => __( 'Test: block nothing, only report', 'secuplug' ),
					],
					[
						'value' => 'enforce',
						'label' => __( 'Enforce: block it', 'secuplug' ),
					],
				],
				'after'   => $securefusion_csp_description( __( 'While you test, visitors are not protected against injected scripts. Notifications show what would be blocked. Framing and base URL rules are enforced either way.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_scope_members',
				'default' => $securefusion_csp_values['csp_scope_members'] ?? '1',
				'label'   => __( 'Apply to logged-in members', 'secuplug' ),
				'options' => $securefusion_csp_switch( __( 'Off', 'secuplug' ), __( 'On', 'secuplug' ) ),
				'after'   => $securefusion_csp_description( __( 'When off, members only get the framing and base URL rules. Account and cart pages can print code of their own, so visit them once as a member.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_scope_admins',
				'default' => $securefusion_csp_values['csp_scope_admins'] ?? '1',
				'label'   => __( 'Apply to administrators', 'secuplug' ),
				'options' => $securefusion_csp_switch( __( 'Off', 'secuplug' ), __( 'On', 'secuplug' ) ),
				'after'   => $securefusion_csp_description( __( 'When off, nothing is blocked for you, and notifications still show what visitors lose. Page builder editors and the Customizer are left alone either way.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_inline_method',
				'default' => in_array( $securefusion_csp_values['csp_inline_method'] ?? 'auto', [ 'nonce', 'hash' ], true ) ? $securefusion_csp_values['csp_inline_method'] : 'auto',
				'label'   => __( 'How inline code is verified', 'secuplug' ),
				'options' => [
					[
						'value' => 'auto',
						'label' => __( 'Automatic (recommended)', 'secuplug' ),
					],
					[
						'value' => 'nonce',
						'label' => __( 'Nonce', 'secuplug' ),
					],
					[
						'value' => 'hash',
						'label' => __( 'Hash', 'secuplug' ),
					],
				],
				'after'   => $securefusion_csp_description( __( 'A nonce is one token that is new on every visit. A page cache would hand the same token to everyone, so behind a page cache Automatic lists a hash for each piece of approved code instead and pages stay cached. With the cache driver installed it uses the nonce there too. The Page cache box below shows what applies to this site.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_allow_inline',
				'default' => $securefusion_csp_values['csp_allow_inline'] ?? '0',
				'label'   => __( 'Allow all inline code', 'secuplug' ),
				'options' => $securefusion_csp_switch( __( 'Off', 'secuplug' ), __( 'On', 'secuplug' ) ),
				'after'   => $securefusion_csp_warning( __( 'Lowers protection.', 'secuplug' ), __( 'Code written into the page itself then runs without being checked, including code an attacker manages to inject. Only the hosts scripts load from stay limited. Use it only when a page cannot work otherwise.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_block_event_handlers',
				'default' => $securefusion_csp_values['csp_block_event_handlers'] ?? '0',
				'label'   => __( 'Block inline event handlers', 'secuplug' ),
				'options' => $securefusion_csp_switch( __( 'Off', 'secuplug' ), __( 'On', 'secuplug' ) ),
				'after'   => $securefusion_csp_warning( __( 'Can break pages.', 'secuplug' ), __( 'Stops attributes such as onclick, onload and onerror, which cannot be approved one by one. It closes a common injection route, but many themes and speed plugins rely on them. A notification offers to switch this off again when a page needs it.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_allow_eval',
				'default' => $securefusion_csp_values['csp_allow_eval'] ?? '0',
				'label'   => __( 'Allow code built at runtime (eval) on every page', 'secuplug' ),
				'options' => $securefusion_csp_switch( __( 'Off', 'secuplug' ), __( 'On', 'secuplug' ) ),
				'after'   => $securefusion_csp_warning( __( 'Lowers protection.', 'secuplug' ), __( 'Pages that load WordPress templates, such as product variations and playlists, need this and get it on their own. Turn it on only when a notification says another script needs it.', 'secuplug' ) ),
			],
			[
				'type'    => 'radio',
				'name'    => 'csp_upgrade_insecure_requests',
				'default' => $securefusion_csp_values['csp_upgrade_insecure_requests'] ?? '1',
				'label'   => __( 'Upgrade HTTP requests to HTTPS', 'secuplug' ),
				'options' => $securefusion_csp_switch( __( 'Off', 'secuplug' ), __( 'On', 'secuplug' ) ),
				'after'   => $securefusion_csp_description( __( 'Sent only on HTTPS pages. Turn it off only if a resource exists solely over plain HTTP.', 'secuplug' ) ),
			],
			[
				'type'        => 'text_input',
				'name'        => 'csp_report_uri',
				'label'       => __( 'Report URL', 'secuplug' ),
				'placeholder' => 'https://report-uri.com/example',
				'after'       => $securefusion_csp_description( __( 'Optional address where browsers send violation reports as JSON.', 'secuplug' ) ),
			],
		],
		CSPIntegrationSettings::fields(),
		[
			[
				'type'              => 'taginput',
				'name'              => 'csp_allowed_script_sources',
				'label'             => __( 'Allowed script (JS) hosts', 'secuplug' ),
				'placeholder'       => 'cdn.example.com',
				'field_type'        => 'url',
				'sanitize_callback' => [ CSP::class, 'validate_host_source' ],
				'presets'           => [],
				'after'             => $securefusion_csp_description( __( 'Hosts of scripts that your theme and plugins register are allowed automatically, and Services above cover the common providers. Other hosts belong here. The quickest way to add one is the Allow button on the notification that reports it.', 'secuplug' ) ),
			],
		],
		$securefusion_csp_list(
			'style',
			__( 'Additional style hosts', 'secuplug' ),
			'fonts.googleapis.com',
			[
				'https://use.fontawesome.com' => __( 'FontAwesome', 'secuplug' ),
			],
			__( 'Added to the style rule, which exists while inline code is verified. Stylesheets your theme and plugins register are allowed automatically.', 'secuplug' )
		),
		$securefusion_csp_list(
			'worker',
			__( 'Additional worker hosts', 'secuplug' ),
			'worker.example.com',
			[],
			__( 'Background workers may always come from your own site and from blob: addresses. Hosts listed here are added.', 'secuplug' )
		),
		$securefusion_csp_list(
			'font',
			__( 'Allowed font hosts', 'secuplug' ),
			'fonts.gstatic.com',
			[
				'data:'                       => __( 'data:', 'secuplug' ),
				'https://fonts.gstatic.com'   => __( 'Google Fonts', 'secuplug' ),
				'https://use.fontawesome.com' => __( 'FontAwesome', 'secuplug' ),
			],
			__( 'Empty: fonts are not limited.', 'secuplug' ),
			__( 'Fonts then load only from your own site and the hosts listed. Icons and text fall back to system fonts if a host is missing.', 'secuplug' )
		),
		$securefusion_csp_list(
			'frame',
			__( 'Allowed embed hosts', 'secuplug' ),
			'youtube.com',
			[
				'https://www.youtube.com'  => __( 'YouTube', 'secuplug' ),
				'https://www.google.com'   => __( 'Google Maps', 'secuplug' ),
				'https://open.spotify.com' => __( 'Spotify', 'secuplug' ),
			],
			__( 'Empty: embeds are not limited.', 'secuplug' ),
			__( 'Videos, maps and payment forms from hosts not listed then stay blank.', 'secuplug' )
		),
		$securefusion_csp_list(
			'img',
			__( 'Allowed image hosts', 'secuplug' ),
			'example.com',
			[
				'data:'                       => __( 'data:', 'secuplug' ),
				'https:'                      => __( 'https:', 'secuplug' ),
				'https://secure.gravatar.com' => __( 'Gravatar', 'secuplug' ),
				'https://i0.wp.com'           => __( 'Jetpack CDN', 'secuplug' ),
			],
			__( 'Empty: images are not limited.', 'secuplug' ),
			__( 'Images from any host not listed then disappear, including ones pasted into posts.', 'secuplug' )
		),
		$securefusion_csp_list(
			'connect',
			__( 'Allowed connection hosts', 'secuplug' ),
			'api.example.com',
			[],
			__( 'Empty: connections are not limited.', 'secuplug' ),
			__( 'Analytics, live search and payment requests to hosts not listed then fail silently.', 'secuplug' )
		),
		$securefusion_csp_list(
			'media',
			__( 'Allowed audio and video hosts', 'secuplug' ),
			'media.example.com',
			[
				'https:' => __( 'https:', 'secuplug' ),
			],
			__( 'Empty: audio and video are not limited.', 'secuplug' ),
			__( 'Audio and video files on hosts not listed then do not play.', 'secuplug' )
		),
		$securefusion_csp_list(
			'form_action',
			__( 'Allowed form targets', 'secuplug' ),
			'www.paypal.com',
			[],
			__( 'Empty: forms may post anywhere.', 'secuplug' ),
			__( 'Forms that post to another site, such as payment gateways and newsletter services, then stop submitting.', 'secuplug' )
		)
	),
];
