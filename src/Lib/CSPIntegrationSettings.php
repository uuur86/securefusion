<?php
/**
 * Compact CSP provider controls.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Build provider controls using the existing settings save and permission flow.
 */
class CSPIntegrationSettings {

	/**
	 * Build compact auto/on/off controls with read-only source provenance.
	 *
	 * @return array
	 */
	public static function fields() {

		$catalog  = CSPIntegrations::catalog();
		$detected = CSPIntegrations::detected( $catalog );
		$level    = CSPPolicy::level( Settings::all() );
		$fields   = [];
		$states   = [
			'detected' => esc_html__( 'Auto: allowed, found on this site', 'secuplug' ),
			'trusted'  => esc_html__( 'Auto: allowed as a well-known service', 'secuplug' ),
			''         => esc_html__( 'Auto: not found on this site. Switch it on if you use it, or press Allow when a notification asks', 'secuplug' ),
		];

		foreach ( $catalog as $id => $provider ) {

			$details = '<div class="fsf-csp-sources"><button type="button" class="fsf-link fsf-csp-toggle">' . esc_html__( 'Included sources', 'secuplug' ) . '</button><div class="fsf-csp-content">';

			foreach ( $provider['sources'] as $directive => $sources ) {

				$details .= '<div class="fsf-csp-directive"><span class="fsf-csp-directive-name">' . esc_html( $directive ) . '</span><br>' . esc_html( implode( ', ', $sources ) ) . '</div>';

			}

			$details .= '<div class="fsf-csp-doc"><a href="' . esc_url( $provider['documentation'] ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Provider documentation', 'secuplug' ) . '</a></div></div></div>';
			$fields[] = [
				'type'    => 'radio',
				'name'    => 'csp_service_' . $id,
				'default' => 'auto',
				'label'   => esc_html( $provider['label'] ),
				'options' => [
					[
						'value' => 'auto',
						'label' => esc_html__( 'Auto', 'secuplug' ),
					],
					[
						'value' => '1',
						'label' => esc_html__( 'On', 'secuplug' ),
					],
					[
						'value' => '0',
						'label' => esc_html__( 'Off', 'secuplug' ),
					],
				],
				'after'   => '<span class="fsf-csp-detection">' . $states[ ! empty( $detected[ $id ] ) ? 'detected' : ( CSPIntegrations::trusted( $provider, $level ) ? 'trusted' : '' ) ] . '</span>' . $details,
			];

		}

		return $fields;

	}

}
