<?php
/**
 * Bastion theme for the wasp form library.
 *
 * Only the templates that differ from wasp's default theme are listed; every other
 * field type falls back to the default templates and is styled by bastion.css.
 *
 * @package securefusion
 */

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

return [
	// Radio groups render as a segmented control.
	'Radio'   => [
		'main'   => '<fieldset id="[id]" class="fsf-seg">[options]</fieldset>',
		'option' => '<span><input type="radio" name="[name]" id="[id]" value="[value]" [checked]/><label for="[id]">[label]</label></span>',
	],

	// Source line under an inheritable field: where the value comes from and the way back.
	// The override checkbox stays in the form (wasp saves only overridden fields) but is
	// switched automatically, so it is hidden.
	'Inherit' => [
		'main' => '<div class="wasp-inherit fsf-source" data-wasp-inherit="[state]">
					<input type="checkbox" class="wasp-inherit-checkbox fsf-source__toggle" name="[name]" id="[id]" value="1" tabindex="-1" aria-hidden="true" [checked][disabled]/>
					<span class="fsf-source__state fsf-source__state--inherited">' . esc_html__( 'Follows the network setting', 'secuplug' ) . '</span>
					<span class="fsf-source__state fsf-source__state--overridden">' . esc_html__( 'Customized for this site', 'secuplug' ) . '</span>
					<span class="fsf-source__state fsf-source__state--locked"><span class="dashicons dashicons-lock" aria-hidden="true"></span>[label]</span>
					<span class="fsf-source__network">[source_label]: <span class="fsf-source__value">[inherited]</span></span>
					<button type="button" class="fsf-link fsf-source__revert" data-wasp-inherit-revert>[revert_label]</button>
				</div>',
	],
];
