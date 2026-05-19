<?php
/**
 * XMLRPC Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

/**
 * XMLRPC Class
 */
class XMLRPC {

	use WPCommon;

	/**
	 * Filter XMLRPC calls.
	 *
	 * @param string $call XMLRPC call.
	 * @return string Filtered XMLRPC call.
	 */
	public function filter_xmlrpc( $call ) {
		return 'SecureFusion_' . $call . '_debug';
	}



	/**
	 * Initialize XMLRPC.
	 */
	public function init() {
		if ( $this->get_settings( 'disable_xmlrpc' ) === '1' ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
		}

		if ( $this->get_settings( 'disable_self_pingback' ) === '1' ) {
			add_action( 'pre_ping', [ $this, 'disable_self_pingback' ], 1, 1 );
		}

		add_filter( 'wp_xmlrpc_server_class', array( $this, 'filter_xmlrpc' ) );
	}



	/**
	 * Disable self pingback.
	 *
	 * @param array &$links Array of links.
	 * @return void
	 */
	public function disable_self_pingback( &$links ) {
		$home = get_option( 'home' );

		foreach ( $links as $key => $link_txt ) {
			if ( 0 === strpos( $link_txt, $home ) ) {
				unset( $links[ $key ] );
			}
		}
	}
}
