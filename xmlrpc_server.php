<?php

/**
 * XMLRPC SERVER Class
 * @package securefusion
*/

if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

require_once( ABSPATH . '/wp-includes/class-IXR.php' );
require_once( ABSPATH . '/wp-includes/class-wp-xmlrpc-server.php' );

use SecureFusion\Lib\Traits\WPCommon;

class SecureFusion_wp_xmlrpc_server_debug extends \wp_xmlrpc_server {
	public $error, $auth_failed, $get_options;

	use WPCommon;



	/**
 	* securefusion_wp_xmlrpc_server_debug constructor.
 	*/
	public function __construct()
	{
		$this->get_options = $this->get_settings();

		if ( $this->get_options[ 'disable_xmlrpc' ] ) {
			return;
		}

		parent::__construct();
	}



	/**
 	* @param string $user
 	* @param string $pass
 	*
 	* @return bool|WP_User
 	*/
	public function login( $user, $pass )
	{
		if ( $this->get_options[ 'disable_xmlrpc_user_login' ] ) {
			$this->auth_failed = true;
			$this->error( '404', esc_html__( 'XMLRPC login disabled', 'securefusion' ) );
			exit;
		}

		return parent::login( $user, $pass );
	}



	/**
 	* @param array $args
 	*
 	* @return bool|IXR_Error|string
 	*/
	public function pingback_ping( $args )
	{
		if ( $this->get_options[ 'disable_xmlrpc_pingback' ] ) {
			$this->error( '404', esc_html__( 'XMLRPC pingback disabled', 'securefusion' ) );
			exit;
		}

		return parent::pingback_ping( $args );
	}
}
