<?php
/**
 * Progressive disclosure for existing settings; does not change saved values.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/** Present technical controls only when requested. */
class SettingsExperience {

	/**
	 * Split display sections without changing field definitions.
	 *
	 * @param array $sections Registered sections.
	 * @return array
	 */
	public static function sections( $sections ) {

		$primary = [
			'security_policies_settings' => [ 'csp_level', 'csp_mode', 'csp_scope_members', 'csp_scope_admins' ],
			'active_guard_settings'      => [ 'filter_bad_requests', 'http_headers' ],
			'ssl_settings'               => [ 'enable_https', 'force_site_https' ],
			'recaptcha_settings'         => [ 'recaptcha_enable', 'recaptcha_site_key', 'recaptcha_secret_key', 'recaptcha_version' ],
			'notification_settings'      => [ 'notify_enable', 'notify_csp', 'notify_status', 'notify_activity' ],
			'network_policy_settings'    => [ Settings::POLICY_SITE_ADMINS ],
		];

		$result = [];

		foreach ( $sections as $section ) {

			$advanced          = $section;
			$advanced['name'] .= '_advanced';
			$advanced['title'] = '';
			$advanced['desc']  = '';
			$advanced['items'] = [];
			$services          = array_merge( $advanced, [ 'name' => $section['name'] . '_services' ] );
			$limits            = array_merge( $advanced, [ 'name' => $section['name'] . '_limits' ] );
			$items             = $section['items'];
			$section['items']  = [];

			foreach ( $items as $item ) {

				$name = $item['name'] ?? '';

				if ( in_array( $name, $primary[ $section['name'] ] ?? [], true ) ) {

					$section['items'][] = $item;

				} elseif ( 'security_policies_settings' === $section['name'] && 0 === strpos( $name, 'csp_service_' ) ) {

					$services['items'][] = $item;

				} elseif ( 'security_policies_settings' === $section['name'] && self::is_limit( $name ) ) {

					$limits['items'][] = $item;

				} else {

					$advanced['items'][] = $item;

				}

			}

			$result[] = $section;
			$result[] = $advanced;

			if ( $services['items'] ) {

				$services['title'] = esc_html__( 'Services', 'secuplug' );
				$services['desc']  = esc_html__( 'Hosts these services need are added for you. Auto allows a service that is found on this site, and a few that only ever serve their own code. Services that serve code from any account, such as tag managers and public libraries, wait until they are found or you allow them.', 'secuplug' );
				$result[]          = $services;

			}

			if ( $limits['items'] ) {

				$limits['title'] = esc_html__( 'Host lists', 'secuplug' );
				$limits['desc']  = esc_html__( 'The script, style and worker lists only add hosts to rules the policy already has. Every other list is empty by default and limits its resource type as soon as it holds a host, so test before you enforce it.', 'secuplug' );
				$result[]        = $limits;

			}

		}

		return $result;

	}

	/**
	 * Whether a field is one of the per-type host lists.
	 *
	 * @param string $name Field name.
	 * @return bool
	 */
	private static function is_limit( $name ) {

		return 0 === strpos( $name, 'csp_allowed_' );

	}

	/**
	 * Render plain-language guidance.
	 *
	 * @param string $tab Current tab.
	 * @return void
	 */
	public static function summary( $tab ) {

		$messages = [
			'xmlrpc'            => __( 'Remote publishing and pingbacks. Review advanced settings only if an app or service needs a different access rule.', 'secuplug' ),
			'login'             => __( 'Repeated failed logins are limited using your saved thresholds. Adjust timing or the login address only when needed.', 'secuplug' ),
			'active_guard'      => __( 'Manage request filtering and browser protection here. Access restrictions, limits and compatibility options are under Advanced settings.', 'secuplug' ),
			'ssl'               => __( 'Use an encrypted connection after your certificate is ready. Extra redirects and strict browser HTTPS (HSTS) are under Advanced settings.', 'secuplug' ),
			'security_policies' => __( 'One switch. Scripts from your site, your plugins and trusted services run, injected ones do not, and a notification asks you about anything else. Choices that lower protection or can break pages are marked and live under Advanced settings.', 'secuplug' ),
			'notifications'     => __( 'Small messages at the bottom right of your pages and the admin area, shown only to administrators. They say what was blocked and offer the fix.', 'secuplug' ),
			'recaptcha'         => __( 'An optional extra check for forms. Set up your keys before enabling it; choose individual forms under Advanced settings.', 'secuplug' ),
			'advanced'          => __( 'Custom request and cookie rules are optional. Leave them unchanged unless this site needs a specific exception.', 'secuplug' ),
			'network_policy'    => __( 'Choose whether individual site administrators may customize the network defaults.', 'secuplug' ),
		];

		echo '<p class="fsf-settings-summary">' . esc_html( $messages[ $tab ] ?? '' ) . '</p>';

	}

}
