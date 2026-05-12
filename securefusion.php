<?php

/**
 * @package SecureFusion
 * @license GPL v3
 * Plugin Name: SecureFusion
 * Plugin URI: https://codeplus.dev/securefusion
 * Description: SecureFusion is a lightweight, robust security plugin for WordPress.
 *  It gives you the ability to disable specific XML-RPC services, alter the login page address, and force SSL on pages.
 * Version: 1.4.4
 * Author: codeplusdev <contact@codeplus.dev>
 * Author URI: https://profiles.wordpress.org/codeplusdev/
 * License: GPL v3 or later
 * Text Domain : securefusion
 * Domain Path:  /languages
 * Requires PHP: 7.4 or later
 */

if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

if ( ! defined( 'SECUREFUSION_VERSION' ) ) {
	define( 'SECUREFUSION_VERSION', '1.4.4' );
}

if ( ! defined( 'SECUREFUSION_PATH' ) ) {
	define( 'SECUREFUSION_PATH', plugin_dir_path( __FILE__ ) );
}

if ( ! defined( 'SECUREFUSION_BASENAME' ) ) {
	define( 'SECUREFUSION_BASENAME', plugin_basename( __FILE__ ) );
}

if ( ! defined( 'SECUREFUSION_HIDE_LOGIN_DISABLE' ) ) {
	define( 'SECUREFUSION_HIDE_LOGIN_DISABLE', false );
}

require_once( SECUREFUSION_PATH . 'vendor/autoload.php' );
require_once( SECUREFUSION_PATH . 'xmlrpc_server.php' );

use SecureFusion\Lib\Main;

$args = array();

$securefusion = new Main();

load_textdomain('securefusion', SECUREFUSION_PATH . 'languages/' . get_locale() . '.mo');

register_activation_hook( __FILE__, array( $securefusion, 'activate' ) );
register_deactivation_hook( __FILE__, array( $securefusion, 'deactivate' ) );
