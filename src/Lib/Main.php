<?php
/**
 * Main Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

use SecureFusion\Lib as Sources;
use SecureFusion\Lib\Traits\WPCommon;


/**
 * Main functionality class.
 */
class Main {

	use WPCommon;

	/**
	 * Protected variables
	 *
	 * @access  protected
	 * @var     object
	 */
	protected $login;
	/**
	 * Protected variables
	 *
	 * @access  protected
	 * @var     object
	 */
	protected $admin;
	/**
	 * Protected variables
	 *
	 * @access  protected
	 * @var     object
	 */
	protected $xmlrpc;
	/**
	 * Protected variables
	 *
	 * @access  protected
	 * @var     object
	 */
	protected $ssl_control;
	/**
	 * Protected variables
	 *
	 * @access  protected
	 * @var     object
	 */
	protected $middleware;

	/**
	 * Protected variables
	 *
	 * @access  protected
	 * @var     array
	 */
	protected $default_settings;



	/**
	 * Constructor
	 */
	public function __construct() {
		// Default values.
		$default_settings = array(
			'disable_xmlrpc'                => '0',
			'disable_xmlrpc_user_login'     => '1',
			'disable_xmlrpc_pingback'       => '1',
			'disable_self_pingback'         => '1',
			'ip_time_limit'                 => '2',
			'ip_login_limit'                => '5',
			'ip_attempt_window'             => '10',
			'cleanup_ip_days'               => '30',
			'cleanup_ip_attempts'           => '10',
			'custom_login_url'              => '',
			'change_login_error'            => '',
			'change_admin_id'               => '',
			'filter_bad_requests'           => '1',
			'disable_rest_api'              => '1',
			'hide_versions'                 => '1',
			'bad_bots'                      => '1',
			'http_headers'                  => '1',
			'cookie_patterns'               => '',
			'request_patterns'              => '',
			'max_payload_size'              => '4096',

			'enable_csp_style'              => '0',
			'enable_csp_script'             => '0',
			'enable_csp_font'               => '0',
			'enable_csp_img'                => '0',
			'enable_csp_frame'              => '0',
			'enable_csp_worker'             => '0',
			'csp_upgrade_insecure_requests' => '0',
			'csp_block_all_mixed_content'   => '0',
			'csp_sandbox'                   => '0',

			/**
			 * WARNING: 'unsafe-inline' is needed for compatibility with many WordPress plugins,
			 * but it is a security risk. The ideal solution is a nonce-based policy,
			 * which is complex to implement across a theme and plugins.
			 */
			'csp_allowed_style_sources'     => '\'unsafe-inline\'' . PHP_EOL .
				'https://fonts.googleapis.com' . PHP_EOL .
				'https://cdnjs.cloudflare.com' . PHP_EOL .
				'https://www.googletagmanager.com',
			'csp_allowed_script_sources'    => '\'unsafe-inline\'' . PHP_EOL .
				'https://www.googletagmanager.com',
			'csp_allowed_font_sources'      => 'data:' . PHP_EOL .
				'https://fonts.gstatic.com' . PHP_EOL .
				'https://cdnjs.cloudflare.com',
			'csp_allowed_img_sources'       => 'data:' . PHP_EOL .
				'https://secure.gravatar.com' . PHP_EOL .
				'https://s.w.org',
			'csp_allowed_frame_sources'     => 'data:' . PHP_EOL .
				'https://youtube.com' . PHP_EOL .
				'https://www.youtube.com',
			'csp_allowed_worker_sources'    => 'blob:',
		);

		$this->default_settings = $default_settings;

		$this->admin       = new Sources\Admin( $default_settings );
		$this->login       = new Sources\Login();
		$this->ssl_control = new Sources\SSLControl();
		$this->xmlrpc      = new Sources\XMLRPC();
		$this->middleware  = new Sources\Middleware();
		$comments_block    = new Sources\CommentsBlock();

		add_action( 'admin_init', array( 'PAnD', 'init' ) );

		// COMMENTS BLOCK.
		add_action( 'init', array( $comments_block, 'init' ) );

		// ADMIN.
		add_action( 'init', array( $this->admin, 'init' ) );

		// XMLRPC.
		add_action( 'init', array( $this->xmlrpc, 'init' ) );

		// LOGIN.
		add_action( 'init', array( $this->login, 'init' ) );

		// SSL CONTROL.
		add_action( 'plugin_loaded', array( $this->ssl_control, 'init' ) );

		// MIDDLEWARE.
		add_action( 'plugin_loaded', array( $this->middleware, 'init' ) );
		add_action( 'init', array( $this->middleware, 'filter_bad_requests' ), 10 );
		add_action( 'wp_login_failed', array( $this->middleware, 'track_login_failed' ), 10, 2 );
		add_action( 'wp_authenticate', array( $this->middleware, 'track_limit_login_attempts' ), 10, 2 );
		add_action( 'wp_login', array( $this->middleware, 'track_login_successful' ), 10, 2 );
		add_action( 'init', array( $this->middleware, 'headers' ), 9 );

		// SECURITY LOG — AJAX handlers.
		$security_log = new Sources\SecurityLog();
		$security_log->register_ajax();

		// IP RULES — AJAX handlers.
		$ip_rules = new Sources\IPRules();
		$ip_rules->register_ajax();

		// ADMIN IP WHITELIST on successful login.
		add_action( 'wp_login', array( $this, 'whitelist_admin_ip_on_login' ), 10, 2 );

		// CRON JOB FOR IP CLEANUP.
		add_action( 'securefusion_cleanup_ips_cron', array( $this, 'cron_cleanup_old_ips' ) );

		// MIGRATION & UPDATE DETECTOR.
		// Run update migrations synchronously during plugin load to prevent race conditions
		// with Middleware::init() which runs early on 'plugin_loaded' and queries the database.
		$this->maybe_update_plugin();
	}

	/**
	 * Whitelist admin IP on successful login.
	 *
	 * @param string   $user_login Username.
	 * @param \WP_User $user       User object.
	 * @return void
	 */
	public function whitelist_admin_ip_on_login( $user_login, $user ) {
		if ( ! $user instanceof \WP_User || ! $user->has_cap( 'manage_options' ) ) {
			return;
		}

		$ip = $this->get_client_ip();

		if ( $ip && $this->is_public_ip( $ip ) ) {
			$brute_force_db = new BruteForceDB();
			$brute_force_db->whitelist_ip( $ip );
		}
	}


	/**
	 * Cron callback to clean up old IP records.
	 */
	public function cron_cleanup_old_ips() {
		$settings = get_option( 'securefusion_settings', array() );
		$days     = isset( $settings['cleanup_ip_days'] ) ? absint( $settings['cleanup_ip_days'] ) : 0;
		$attempts = isset( $settings['cleanup_ip_attempts'] ) ? absint( $settings['cleanup_ip_attempts'] ) : 0;

		if ( $days > 0 && $attempts > 0 ) {
			$brute_force_db = new BruteForceDB();
			$brute_force_db->cleanup_old_ips( $days, $attempts );
		}
	}


	/**
	 * Activate plugin.
	 */
	public function activate() {
		$old_settings = get_option( 'secuplug_settings' );
		$new_settings = get_option( 'securefusion_settings', array() );

		// Update new slug in option table.
		if ( $old_settings !== false ) {

			delete_option( 'secuplug_settings' );
			$new_settings = $old_settings;

		}

		// Override existing settings.
		$new_settings = array_merge( $this->default_settings, $new_settings );

		// Update final settings.
		update_option( 'securefusion_settings', $new_settings );

		// Database schema operations via centralized service.
		$brute_force_db = new BruteForceDB();
		$brute_force_db->maybe_migrate_old_table();
		$brute_force_db->create_table();
		$brute_force_db->maybe_add_database_indexes();
		$brute_force_db->migrate_existing_rows_to_failed_login();

		update_option( 'securefusion_db_version', SECUREFUSION_VERSION );

		if ( ! wp_next_scheduled( 'securefusion_cleanup_ips_cron' ) ) {
			wp_schedule_event( time(), 'daily', 'securefusion_cleanup_ips_cron' );
		}
	}


	/**
	 * Run updates if the plugin version has changed.
	 *
	 * Runs synchronously during plugin load.
	 *
	 * @return void
	 */
	public function maybe_update_plugin() {
		$installed_version = get_option( 'securefusion_db_version' );
		if ( $installed_version !== SECUREFUSION_VERSION ) {
			// Merge default settings to ensure new options exist.
			$settings = get_option( 'securefusion_settings', array() );
			$settings = array_merge( $this->default_settings, $settings );
			update_option( 'securefusion_settings', $settings );

			// Run database schema updates.
			$brute_force_db = new BruteForceDB();
			$brute_force_db->maybe_migrate_old_table();
			$brute_force_db->create_table();
			$brute_force_db->maybe_add_database_indexes();
			$brute_force_db->migrate_existing_rows_to_failed_login();

			update_option( 'securefusion_db_version', SECUREFUSION_VERSION );
		}
	}


	/**
	 * Deactivate plugin.
	 */
	public function deactivate() {
		wp_clear_scheduled_hook( 'securefusion_cleanup_ips_cron' );
	}
}
