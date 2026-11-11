<?php
/**
 * Render declarative tag-input presets at the form boundary.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Adapt preset configuration to the form library's HTML interface.
 */
class TagInputPresets {

	/**
	 * Render preset maps without changing the source configuration.
	 *
	 * @param array $sections Form section definitions.
	 * @return array
	 */
	public static function prepare( $sections ) {

		foreach ( $sections as $section_key => $section ) {

			foreach ( $section['items'] ?? [] as $field_key => $field ) {

				if ( isset( $field['presets'] ) && is_array( $field['presets'] ) ) {

					$sections[ $section_key ]['items'][ $field_key ]['presets'] = self::render( $field['presets'] );

				}

			}

		}

		return $sections;

	}

	/**
	 * Escape values and labels in their respective output contexts.
	 *
	 * @param array $presets Map of preset values to display labels.
	 * @return string
	 */
	public static function render( $presets ) {

		$html = '';

		foreach ( $presets as $value => $label ) {

			if ( ! is_string( $label ) ) {

				continue;

			}

			$html .= sprintf(
				'<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="%s">%s</button>',
				esc_attr( $value ),
				esc_html( $label )
			);

		}

		return $html;

	}

}
