<?php
/**
 * XMLRPC SERVER Class
 *
 * @package securefusion
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

require_once ABSPATH . '/wp-includes/class-IXR.php';
require_once ABSPATH . '/wp-includes/class-wp-xmlrpc-server.php';

use SecureFusion\Lib\Traits\WPCommon;

/**
 * This function replaces the default WordPress XML-RPC server class with our custom class that includes security features.
 */
// phpcs:ignore
class SecureFusion_wp_xmlrpc_server_debug extends \wp_xmlrpc_server {

	/**
	 * Variables
	 *
	 * @var bool  $auth_failed Indicates if authentication has failed.
	 */
	public $auth_failed;

	/**
	 * Variables
	 *
	 * @var array $get_options Plugin settings.
	 */
	public $get_options;

	use WPCommon;



	/**
	 * This method is called when the XML-RPC server receives a request.
	 * It checks if the request is for a method that should be disabled based on the plugin settings.
	 */
	public function __construct() {
		$this->get_options = $this->get_settings();

		if ( $this->get_options['disable_xmlrpc'] ) {
			return;
		}

		parent::__construct();
	}



	/**
	 * Login method override to block XML-RPC logins if the option is enabled.
	 *
	 * @param string $user Username.
	 * @param string $pass Password.
	 *
	 * @return bool|WP_User
	 */
	public function login( $user, $pass ) {
		if ( $this->get_options['disable_xmlrpc_user_login'] ) {
			$this->auth_failed = true;
			$brute_force_db    = new \SecureFusion\Lib\BruteForceDB();
			$ip                = $this->get_client_ip();

			if ( $ip ) {
				$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$brute_force_db->log_attempt_with_details(
					$ip,
					\SecureFusion\Lib\BruteForceDB::TYPE_FAILED_LOGIN,
					$user_agent,
					'XML-RPC Login Blocked | Username: ' . sanitize_text_field( $user )
				);
			}

			$this->error( '404', esc_html__( 'XMLRPC login disabled', 'secuplug' ) );

			exit;
		}

		return parent::login( $user, $pass );
	}



	/**
	 * Pingback method override to block XML-RPC pingbacks if the option is enabled.
	 *
	 * @param array $args Pingback arguments.
	 *
	 * @return bool|IXR_Error|string
	 */
	public function pingback_ping( $args ) {
		if ( $this->get_options['disable_xmlrpc_pingback'] ) {
			$this->error( '404', esc_html__( 'XMLRPC pingback disabled', 'secuplug' ) );
			exit;
		}

		return parent::pingback_ping( $args );
	}
}
