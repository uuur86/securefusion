<?php
/**
 * Main Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib as Sources;


/**
 * Main Class
 *
 * @package securefusion
 */
class Main {

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
			'disable_xmlrpc'             => '0',
			'disable_xmlrpc_user_login'  => '1',
			'disable_xmlrpc_pingback'    => '1',
			'disable_self_pingback'      => '1',
			'ip_time_limit'              => '10',
			'ip_login_limit'             => '5',
			'custom_login_url'           => '',
			'change_login_error'         => '',
			'change_admin_id'            => '',
			'filter_bad_requests'        => '1',
			'disable_rest_api'           => '1',
			'hide_versions'              => '1',
			'bad_bots'                   => '1',
			'http_headers'               => '1',
			'cookie_patterns'            => '',
			'request_patterns'           => '',

			/**
			 * WARNING: 'unsafe-inline' is needed for compatibility with many WordPress plugins,
			 * but it is a security risk. The ideal solution is a nonce-based policy,
			 * which is complex to implement across a theme and plugins.
			 */
			'csp_allowed_style_sources'  => '\'unsafe-inline\'' . PHP_EOL .
				'https://fonts.googleapis.com' . PHP_EOL .
				'https://cdnjs.cloudflare.com' . PHP_EOL .
				'https://www.googletagmanager.com',
			'csp_allowed_script_sources' => '\'unsafe-inline\'' . PHP_EOL .
				'https://www.googletagmanager.com',
			'csp_allowed_font_sources'   => 'data:' . PHP_EOL .
				'https://fonts.gstatic.com' . PHP_EOL .
				'https://cdnjs.cloudflare.com',
			'csp_allowed_img_sources'    => 'data:' . PHP_EOL .
				'https://secure.gravatar.com' . PHP_EOL .
				'https://s.w.org',
			'csp_allowed_frame_sources'  => 'data:' . PHP_EOL .
				'https://youtube.com' . PHP_EOL .
				'https://www.youtube.com',
			'csp_allowed_worker_sources' => 'blob:',
		);

		$this->default_settings = $default_settings;

		$this->admin       = new Sources\Admin( $default_settings );
		$this->login       = new Sources\Login();
		$this->ssl_control = new Sources\SSLControl();
		$this->xmlrpc      = new Sources\XMLRPC();
		$this->middleware  = new Sources\Middleware();

		add_action( 'admin_init', array( 'PAnD', 'init' ) );

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
		add_filter( 'wp_authenticate_user', array( $this->middleware, 'track_authenticate_user' ), 30, 2 );
		add_action( 'wp_authenticate', array( $this->middleware, 'track_limit_login_attempts' ), 10, 2 );
		add_action( 'init', array( $this->middleware, 'headers' ), 9 );

		// LOGIN LOG — AJAX handlers.
		$login_log = new Sources\LoginLog();
		$login_log->register_ajax();
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

		// Override exists settings.
		$new_settings = array_merge( $this->default_settings, $new_settings );

		// Update final settings.
		update_option( 'securefusion_settings', $new_settings );

		// Database schema operations via centralized service.
		$brute_force_db = new BruteForceDB();
		$brute_force_db->maybe_migrate_old_table();
		$brute_force_db->create_table();
	}


	/**
	 * Deactivate plugin.
	 */
	public function deactivate() {
		delete_option( 'secuplug_settings' );
		delete_option( 'securefusion_settings' );
	}
}
