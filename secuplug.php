<?php
/**
 * Plugin Name: SecureFusion
 * Plugin URI: https://fyndsoft.com/digital-products/securefusion/
 * Description: Firewall, login protection, Content Security Policy, security headers, XML-RPC and REST API hardening, HTTPS enforcement and a security log, built to stay light on every request.
 * Version: 3.0.0
 * Author: codeplusdev
 * Author URI: https://profiles.wordpress.org/codeplusdev/
 * License: GPLv3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: secuplug
 * Domain Path:  /languages
 * Requires at least: 6.6
 * Requires PHP: 7.4
 *
 * @package secuplug
 * @license GPL v3
 */

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

if ( ! defined( 'SECUREFUSION_VERSION' ) ) {

	define( 'SECUREFUSION_VERSION', '3.0.0' );

}

if ( ! defined( 'SECUREFUSION_PATH' ) ) {

	define( 'SECUREFUSION_PATH', plugin_dir_path( __FILE__ ) );

}

if ( ! defined( 'SECUREFUSION_URL' ) ) {

	define( 'SECUREFUSION_URL', plugin_dir_url( __FILE__ ) );

}

if ( ! defined( 'SECUREFUSION_BASENAME' ) ) {

	define( 'SECUREFUSION_BASENAME', plugin_basename( __FILE__ ) );

}

if ( ! defined( 'SECUREFUSION_HIDE_LOGIN_DISABLE' ) ) {

	define( 'SECUREFUSION_HIDE_LOGIN_DISABLE', false );

}

require_once SECUREFUSION_PATH . 'vendor/autoload.php';

use SecureFusion\Lib\Main;

$securefusion = new Main();

/**
 * Load translations in the language of the current user.
 *
 * The bundled files are named after the locale alone (tr_TR.mo), which load_plugin_textdomain()
 * never finds: it only looks for secuplug-tr_TR.mo. They are loaded by path, first, because they
 * match this version's strings. A locale without its own file uses the file of its language
 * (de.mo for de_AT, de_CH or de_DE_formal). A language pack from WordPress.org fills in what they lack.
 *
 * @return void
 */
function securefusion_load_translations() {

	$locale  = determine_locale();
	$bundled = SECUREFUSION_PATH . 'languages/' . $locale . '.mo';

	if ( ! is_readable( $bundled ) ) {

		$bundled = SECUREFUSION_PATH . 'languages/' . strtok( $locale, '_' ) . '.mo';

	}

	unload_textdomain( 'secuplug', true );

	foreach ( array( $bundled, WP_LANG_DIR . '/plugins/secuplug-' . $locale . '.mo' ) as $file ) {

		if ( is_readable( $file ) ) {

			// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_textdomainFound -- Bundled translations use their own file names.
			load_textdomain( 'secuplug', $file, $locale );

		}

	}

}

// Not before WordPress knows the user, and again whenever it switches language (emails to other users).
add_action( 'init', 'securefusion_load_translations', 0 );
add_action( 'change_locale', 'securefusion_load_translations' );

register_activation_hook( __FILE__, array( $securefusion, 'activate' ) );
register_deactivation_hook( __FILE__, array( $securefusion, 'deactivate' ) );
