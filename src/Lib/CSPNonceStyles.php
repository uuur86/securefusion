<?php
/**
 * Nonce-aware renderer for registered WordPress inline styles.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Keep the WordPress queue and style order; authorize only its inline CSS.
 */
class CSPNonceStyles extends \WP_Styles {

	/**
	 * Render one handle and authorize its inline style element.
	 *
	 * Core builds the inline tag itself for handles with a stylesheet, so the finished markup
	 * is the only place a nonce can be added for both kinds of handle.
	 *
	 * @param string   $handle Registered stylesheet handle.
	 * @param int|bool $group Dependency group.
	 * @return bool
	 */
	public function do_item( $handle, $group = false ) {

		$this->do_concat = false;

		ob_start();

		$done = parent::do_item( $handle, $group );
		$html = (string) ob_get_clean();

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Markup produced by WP_Styles; only a nonce attribute is added.
		echo CSPInline::stamp_style( $handle, $html );

		return $done;

	}

}
