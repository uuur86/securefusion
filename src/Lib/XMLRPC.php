<?php

/**
 * XMLRPC Class
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

class XMLRPC {

	use WPCommon;

	function filter_xmlrpc( $call )
	{
		return 'SecureFusion_' . $call . '_debug';
	}



	function init()
	{
		if ( $this->get_settings( 'disable_xmlrpc' ) === '1' ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
		}

		if ( $this->get_settings( 'disable_self_pingback' ) === '1' ) {
			add_action( 'pre_ping', [$this, 'disable_self_pingback'], 1, 1 );
		}

		add_filter( 'wp_xmlrpc_server_class', array( $this, 'filter_xmlrpc' ) );
	}



	// Disable self pingback
	function disable_self_pingback( &$links )
	{
		$home = get_option( 'home' );

		foreach ( $links as $key => $link_txt ) {
			if ( 0 === strpos( $link_txt, $home ) ) {
				unset( $links[ $key ] );
			}
		}
	}
}
