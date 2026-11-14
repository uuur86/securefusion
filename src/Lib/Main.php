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
	 * @var     object
	 */
	protected $recaptcha;

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
			'disable_xmlrpc'                  => '0',
			'disable_xmlrpc_user_login'       => '0',
			'disable_xmlrpc_pingback'         => '1',
			'disable_self_pingback'           => '1',
			'ip_time_limit'                   => '2',
			'ip_login_limit'                  => '5',
			'ip_attempt_window'               => '10',
			'cleanup_ip_days'                 => '30',
			'cleanup_ip_attempts'             => '10',
			'custom_login_url'                => '',
			'change_login_error'              => '',
			'filter_bad_requests'             => '1',
			'disable_rest_api'                => '0',
			'hide_usernames'                  => '1',
			'hide_versions'                   => '1',
			'bad_bots'                        => '1',
			'http_headers'                    => '1',
			'cookie_patterns'                 => '',
			'request_patterns'                => '',
			'max_payload_size'                => '4096',
			'block_oversized_requests'        => '0',
			'oversized_block_threshold'       => '5',
			'oversized_block_minutes'         => '30',

			'csp_level'                       => 'basic',
			'csp_mode'                        => 'enforce',
			'csp_scope_members'               => '1',
			'csp_scope_admins'                => '1',
			'csp_inline_method'               => 'auto',
			'csp_block_event_handlers'        => '0',
			'csp_allow_eval'                  => '0',
			'csp_allow_inline'                => '0',
			'csp_upgrade_insecure_requests'   => '1',

			// Lists that limit their resource type once they hold a host. Empty: no limit.
			'csp_allowed_connect_sources'     => '',
			'csp_allowed_media_sources'       => '',
			'csp_allowed_form_action_sources' => '',
			'csp_allowed_font_sources'        => '',
			'csp_allowed_img_sources'         => '',
			'csp_allowed_frame_sources'       => '',

			// CSP Reporting.
			'csp_report_uri'                  => '',

			// Advanced HTTP Headers.
			'enable_coop'                     => '0',
			'enable_hsts'                     => '0',
			'hsts_max_age'                    => '86400',
			'enable_hsts_preload'             => '0',
			'enable_hsts_subdomains'          => '0',

			// reCAPTCHA.
			'recaptcha_enable'                => '0',
			'recaptcha_site_key'              => '',
			'recaptcha_secret_key'            => '',
			'recaptcha_version'               => 'v2_checkbox',
			'recaptcha_login'                 => '0',
			'recaptcha_register'              => '0',
			'recaptcha_lostpassword'          => '0',
			'recaptcha_comment'               => '0',
			'recaptcha_cf7'                   => '0',
			'recaptcha_mc4wp'                 => '0',

			'csp_allowed_style_sources'       => 'https://fonts.googleapis.com' . PHP_EOL .
				'https://cdnjs.cloudflare.com',
			'csp_allowed_script_sources'      => '',
			'csp_allowed_worker_sources'      => '',

			// Notifications for administrators.
			'notify_enable'                   => '1',
			'notify_csp'                      => '1',
			'notify_status'                   => '1',
			'notify_activity'                 => '1',
		);

		foreach ( array_keys( CSPIntegrations::catalog() ) as $provider ) {

			$default_settings[ 'csp_service_' . $provider ] = 'auto';

		}

		$this->default_settings = $default_settings;

		// Settings must be resolvable before any module reads them.
		Settings::boot( $default_settings );

		// The settings form reads the option itself, so it must see older policy settings as a level too.
		add_filter( 'option_' . Settings::SITE_OPTION, [ CSPPolicy::class, 'upgrade_values' ] );

		// Every write stores the translated form, so settings of older versions are converted once.
		add_filter( 'pre_update_option_' . Settings::SITE_OPTION, [ CSPPolicy::class, 'upgrade_values' ] );
		add_filter( 'pre_update_site_option_' . Settings::NETWORK_OPTION, [ CSPPolicy::class, 'upgrade_values' ] );

		// Network mode: convert this site's stored copy to overrides once (bounded: one site).
		Settings::maybe_migrate_site();

		$this->admin       = new Sources\Admin( $default_settings );
		$this->login       = new Sources\Login();
		$this->ssl_control = new Sources\SSLControl();
		$this->xmlrpc      = new Sources\XMLRPC();
		$this->middleware  = new Sources\Middleware();
		$this->recaptcha   = new Sources\ReCaptcha();
		$comments_block    = new Sources\CommentsBlock();
		$user_enumeration  = new Sources\UserEnumeration();

		add_action( 'admin_init', array( 'PAnD', 'init' ) );

		// COMMENTS BLOCK.
		add_action( 'init', array( $comments_block, 'init' ) );

		// USER ENUMERATION.
		add_action( 'init', array( $user_enumeration, 'init' ) );

		// ADMIN.
		add_action( 'init', array( $this->admin, 'init' ) );
		CSPInlineAdmin::register();
		Notifier::register();
		add_action( 'template_redirect', [ CSPInline::class, 'discover' ], 0 );

		// XMLRPC.
		add_action( 'init', array( $this->xmlrpc, 'init' ) );

		// LOGIN.
		add_action( 'init', array( $this->login, 'init' ) );

		// RECAPTCHA.
		add_action( 'init', array( $this->recaptcha, 'init' ) );

		// SSL CONTROL.
		add_action( 'plugins_loaded', array( $this->ssl_control, 'init' ) );

		// MIDDLEWARE.
		add_action( 'plugins_loaded', array( $this->middleware, 'init' ) );
		add_action( 'init', array( $this->middleware, 'filter_bad_requests' ), 10 );
		add_action( 'init', array( $this->middleware, 'headers' ), 9 );

		$this->middleware->register_login_tracking();

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
		// with Middleware::init() which runs early on 'plugins_loaded' and queries the database.
		add_action( 'admin_notices', [ $this, 'database_notice' ] );
		add_action( 'admin_init', [ $this, 'redact_legacy_logs' ] );

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

		$settings = Settings::all();
		$days     = isset( $settings['cleanup_ip_days'] ) ? absint( $settings['cleanup_ip_days'] ) : 0;
		$attempts = isset( $settings['cleanup_ip_attempts'] ) ? absint( $settings['cleanup_ip_attempts'] ) : 0;

		if ( $days > 0 && $attempts > 0 ) {

			$brute_force_db = new BruteForceDB();
			$brute_force_db->cleanup_old_ips( $days, $attempts );

		}

		$this->cleanup_expired_ip_rules();

	}


	/**
	 * Delete expired IP blocks, on every site of a network.
	 *
	 * The cleanup cron runs on the main site only, while every site keeps its own rules table.
	 * Bounded by half of max_execution_time (15 seconds when unlimited), by 100 sites per run
	 * with the position kept in a network option, and by the batch limits of
	 * BruteForceDB::cleanup_expired_ip_rules().
	 *
	 * @return void
	 */
	private function cleanup_expired_ip_rules() {

		$max_time = (int) ini_get( 'max_execution_time' );
		$deadline = microtime( true ) + ( $max_time > 0 ? $max_time : 30 ) / 2;

		if ( ! is_multisite() ) {

			( new BruteForceDB() )->cleanup_expired_ip_rules( $deadline );

			return;

		}

		$offset = absint( get_site_option( 'securefusion_rule_cleanup_offset', 0 ) );
		$sites  = get_sites(
			[
				'fields'     => 'ids',
				'number'     => 100,
				'offset'     => $offset,
				'network_id' => get_current_network_id(),
				'orderby'    => 'id',
				'order'      => 'ASC',
			]
		);

		$done = 0;

		foreach ( $sites as $site_id ) {

			if ( microtime( true ) >= $deadline ) {

				break;

			}

			switch_to_blog( $site_id );

			// Sites that never finished installing have no rules table to clean.
			if ( get_option( 'securefusion_db_verified' ) ) {

				( new BruteForceDB() )->cleanup_expired_ip_rules( $deadline );

			}

			restore_current_blog();

			++$done;

		}

		$finished = $done === count( $sites ) && count( $sites ) < 100;

		update_site_option( 'securefusion_rule_cleanup_offset', $finished ? 0 : $offset + $done );

	}


	/**
	 * Activate plugin.
	 *
	 * @param bool $network_wide Whether to activate the plugin network-wide.
	 */
	public function activate( $network_wide = false ) {

		$old_settings = get_option( 'secuplug_settings' );
		$new_settings = get_option( Settings::SITE_OPTION, array() );

		// Update new slug in option table.
		if ( $old_settings !== false ) {

			delete_option( 'secuplug_settings' );

			$new_settings = $old_settings;

		}

		// Read older policy settings as a level before the defaults fill in a level of their own.
		$new_settings = CSPPolicy::upgrade_values( is_array( $new_settings ) ? $new_settings : array() );

		if ( $network_wide && is_multisite() ) {

			// WordPress records the plugin as network-active only after this hook runs.
			Settings::set_network_mode( true );

			if ( ! empty( $new_settings ) ) {

				update_option( Settings::SITE_OPTION, $new_settings );

			}

			// Seeds network settings from the main site and converts this site to overrides.
			// Other sites convert themselves on their next request.
			Settings::maybe_seed_network();
			Settings::maybe_migrate_site();

		} else {

			// Override existing settings.
			$new_settings = array_merge( $this->default_settings, $new_settings );

			// Update final settings.
			update_option( Settings::SITE_OPTION, $new_settings );

		}

		// Database schema operations via centralized service.
		$this->install_database();

		if ( ! wp_next_scheduled( 'securefusion_cleanup_ips_cron' ) ) {

			wp_schedule_event( time(), 'daily', 'securefusion_cleanup_ips_cron' );

		}

	}


	/**
	 * Install and verify the schema before recording a successful version.
	 *
	 * @return bool Success.
	 */
	public function install_database() {

		$db = new BruteForceDB();

		$db->maybe_migrate_old_table();

		global $wpdb;

		if ( $wpdb->last_error ) {

			update_option( 'securefusion_db_error', 1, false );
			set_transient( 'securefusion_db_retry', 1, 300 );

			return false;

		}

		$db->create_table();
		$db->maybe_add_database_indexes();

		if ( ! $db->schema_is_ready() ) {

			update_option( 'securefusion_db_error', 1, false );
			set_transient( 'securefusion_db_retry', 1, 300 );

			return false;

		}

		$db->migrate_existing_rows_to_failed_login();

		if ( ! $wpdb->last_error ) {

			$db->flag_range_rules();

		}

		if ( $wpdb->last_error ) {

			update_option( 'securefusion_db_error', 1, false );
			set_transient( 'securefusion_db_retry', 1, 300 );

			return false;

		}

		update_option( 'securefusion_db_version', SECUREFUSION_VERSION );
		update_option( 'securefusion_db_verified', BruteForceDB::SCHEMA_REVISION, false );
		delete_option( 'securefusion_db_error' );
		delete_transient( 'securefusion_db_retry' );

		return true;

	}

	/**
	 * Surface incomplete installation to administrators without exposing SQL.
	 */
	public function database_notice() {

		if ( current_user_can( 'manage_options' ) && get_option( 'securefusion_db_error' ) ) {

			echo '<div class="notice notice-error"><p>' . esc_html__( 'SecureFusion database setup is incomplete. Logging and IP protection may not work correctly. Check database permissions and server logs. Setup will retry on a request after five minutes.', 'secuplug' ) . '</p></div>';

		}

	}


	/**
	 * Clear credentials stored by older versions, one bounded batch per admin request.
	 *
	 * Bounded by the batch size; progress is kept so a large log finishes over several requests.
	 *
	 * @return void
	 */
	public function redact_legacy_logs() {

		$state = get_option( 'securefusion_log_redaction', 0 );

		if ( 'done' === $state || ! current_user_can( 'manage_options' ) ) {

			return;

		}

		global $wpdb;

		$last_id = ( new BruteForceDB() )->redact_legacy_payloads( absint( $state ) );

		// Keep the position after a failure, such as a table that is not created yet.
		if ( $wpdb->last_error ) {

			return;

		}

		update_option( 'securefusion_log_redaction', $last_id > 0 ? $last_id : 'done', false );

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

		// A new schema revision reruns the install once, also on sites already at this version.
		$verified = BruteForceDB::SCHEMA_REVISION === get_option( 'securefusion_db_verified' );

		if ( ( $installed_version !== SECUREFUSION_VERSION || ! $verified ) && ! get_transient( 'securefusion_db_retry' ) ) {

			if ( Settings::is_network_mode() ) {

				// New keys are added to the network layer; sites keep only their overrides.
				$network = CSPPolicy::upgrade_values( Settings::maybe_seed_network() );
				$merged  = array_merge( $this->default_settings, $network );

				if ( $merged !== $network ) {

					update_site_option( Settings::NETWORK_OPTION, $merged );

				}

			} else {

				// Merge default settings to ensure new options exist.
				$settings = get_option( Settings::SITE_OPTION, array() );
				$settings = array_merge( $this->default_settings, CSPPolicy::upgrade_values( is_array( $settings ) ? $settings : array() ) );

				update_option( Settings::SITE_OPTION, $settings );

			}

			// Run database schema updates.
			$this->install_database();

		}

	}


	/**
	 * Deactivate the plugin.
	 *
	 * @param bool $network_wide Whether the plugin is being deactivated for the whole network.
	 * @return void
	 */
	public function deactivate( $network_wide = false ) {

		wp_clear_scheduled_hook( 'securefusion_cleanup_ips_cron' );

		// The driver serves every site of a network, so one site leaving must not remove it.
		if ( ! is_multisite() || $network_wide ) {

			CSPCacheSetup::remove();

		}

	}

}
