<?php
/**
 * Install the trusted inline style renderer without touching page HTML.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * WordPress style-renderer adapter.
 */
class CSPNonce {

	/**
	 * Preserve registered handles and queues in a nonce-aware renderer.
	 *
	 * @return void
	 */
	public static function install_styles() {

		// Preserve registered handles and queues while adapting the trusted renderer.
		global $wp_styles;

		$styles = wp_styles();

		if ( get_class( $styles ) === 'WP_Styles' ) {

			$replacement = new CSPNonceStyles();

			foreach ( get_object_vars( $styles ) as $key => $value ) {

				$replacement->$key = $value;

			}

			$replacement->do_concat = false;

			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Preserve queue state in a nonce-aware WP_Styles renderer.
			$wp_styles = $replacement;

		}

	}

}
