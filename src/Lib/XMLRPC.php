<?php
/**
 * XMLRPC Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * XMLRPC functionality class.
 */
class XMLRPC {

	use WPCommon;

	/**
	 * Filter XMLRPC calls.
	 *
	 * WordPress applies this filter only while it serves an XML-RPC request, right before it
	 * creates the server. The subclass and the core classes it extends are loaded here, so other
	 * requests never parse them.
	 *
	 * @param string $call XMLRPC call.
	 * @return string Filtered XMLRPC call.
	 */
	public function filter_xmlrpc( $call ) {

		require_once dirname( __DIR__, 2 ) . '/xmlrpc_server.php';

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
