<?php
/**
 * Admin Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

use WaspCreators\Wasp;
use SecureFusion\Lib\Traits\WPCommon;

/**
 * Admin functionality class.
 */
class Admin {

	use AdminDashboardWidgets;
	use AdminSettingsView;
	use WPCommon;
	use AdminDashboard;


	/**
	 * Settings page instance.
	 *
	 * @var Wasp
	 */
	protected $settings_page;

	/**
	 * Menu pages.
	 *
	 * @var array
	 */
	protected $menu_pages;

	/**
	 * Admin link.
	 *
	 * @var string
	 */
	protected $admin_link;

	/**
	 * Plugin URL.
	 *
	 * @var string
	 */
	protected $plugin_url;

	/**
	 * Default settings.
	 *
	 * @var array
	 */
	protected $default_settings;

	/**
	 * Which settings form this request uses: 'site' or 'network'.
	 *
	 * @var string
	 */
	protected $context = 'site';

	/**
	 * Whether network defaults with per-site overrides are active.
	 *
	 * @var bool
	 */
	protected $layered = false;

	/**
	 * Setting keys of every settings section, keyed by section name.
	 *
	 * @var array<string,string[]>
	 */
	protected $section_keys = array();


	/**
	 * Constructor.
	 *
	 * @param array $default_settings Default settings.
	 */
	public function __construct( $default_settings = array() ) {

		$this->default_settings = $default_settings;

		if ( function_exists( 'admin_url' ) ) {

			$this->admin_link = \admin_url( 'admin.php' );
			$this->plugin_url = \plugins_url( '/', SECUREFUSION_BASENAME );

		}

	}



	/**
	 * Add a link to your settings page in your plugin.
	 *
	 * @param array $links Links.
	 *
	 * @return array
	 */
	public function add_settings_link( $links ) {

		$settings_link  = '<a href="admin.php?page=securefusion-settings">';
		$settings_link .= esc_html__( 'Settings', 'secuplug' );
		$settings_link .= '</a>';

		$links[] = $settings_link;

		return $links;

	}


	/**
	 * Describe recent oversized requests so the owner can judge the block setting.
	 *
	 * The log belongs to each site, so the network screen has nothing to report.
	 *
	 * @return string Plain text, or empty on the network screen.
	 */
	protected function oversized_request_summary() {

		if ( 'network' === $this->context ) {

			return '';

		}

		$summary = get_transient( 'securefusion_oversized_summary' );

		if ( ! is_array( $summary ) ) {

			$summary = ( new BruteForceDB() )->get_oversized_request_summary( 7 );

			set_transient( 'securefusion_oversized_summary', $summary, 10 * MINUTE_IN_SECONDS );

		}

		if ( 0 === $summary['requests'] ) {

			return __( 'No requests went over the limit in the last 7 days.', 'secuplug' );

		}

		return sprintf(
			/* translators: 1: number of requests, 2: number of IP addresses. */
			_n( '%1$s request went over the limit in the last 7 days, from %2$s IP address(es).', '%1$s requests went over the limit in the last 7 days, from %2$s IP address(es).', $summary['requests'], 'secuplug' ),
			number_format_i18n( $summary['requests'] ),
			number_format_i18n( $summary['addresses'] )
		);

	}


	/**
	 * Explain the native WordPress account transition without mutating users.
	 *
	 * @return void
	 */
	protected function get_account_transition_html() {

		if ( ! current_user_can( 'manage_options' ) ) {

			wp_die( esc_html__( 'You do not have permission to view this page.', 'secuplug' ) );

		}

		echo '<div class="fsf-account-guide">';

		echo '<p>' . esc_html__( 'If you choose to replace this account, use WordPress user management and verify each step before removing the original account.', 'secuplug' ) . '</p>';

		echo '<p>' . esc_html__( 'A different user ID is not protection against SQL injection or privilege escalation. Keep strong passwords, login protection and software updates in place.', 'secuplug' ) . '</p>';

		if ( is_multisite() ) {

			echo '<p>' . esc_html__( 'Multisite accounts are shared across sites. Ask a network administrator to review site memberships, super administrator access and content ownership on every affected site before replacing an account. Removing a user from one site is different from deleting the network account.', 'secuplug' ) . '</p>';

		} else {

			echo '<ol>';

			foreach ( [
				__( 'Back up the site and review data owned by the old account, including orders, memberships and records stored by other plugins. WordPress content reassignment does not guarantee migration of those records.', 'secuplug' ),
				__( 'Create a new user with a distinct username, an accessible email address, a strong password and the Administrator role.', 'secuplug' ),
				__( 'Sign in with the new account in a separate browser session and verify access before changing the old account.', 'secuplug' ),
				__( 'From the new account, open Users. Only after checking plugin-owned data, delete the old account and select Attribute all content to the new account. If ownership is uncertain, postpone deletion and review the old account permissions instead.', 'secuplug' ),
				__( 'Verify content authorship, media, plugin records and administrator access after the transition.', 'secuplug' ),
			] as $step ) {

				echo '<li>' . esc_html( $step ) . '</li>';

			}

			echo '</ol>';

			if ( current_user_can( 'create_users' ) ) {

				echo '<p><a class="button button-primary" href="' . esc_url( admin_url( 'user-new.php' ) ) . '">' . esc_html__( 'Create a new user', 'secuplug' ) . '</a></p>';

			}

		}

		if ( current_user_can( 'list_users' ) ) {

			echo '<p><a class="button" href="' . esc_url( admin_url( 'users.php' ) ) . '">' . esc_html__( 'Review site users', 'secuplug' ) . '</a></p>';

		}

		echo '</div>';

	}


	/**
	 * Add admin menu pages.
	 *
	 * @return void
	 */
	public function admin_menu() {

		$this->menu_pages['main'] = \add_menu_page(
			esc_html__( 'SecureFusion', 'secuplug' ),
			esc_html__( 'SecureFusion', 'secuplug' ),
			'manage_options',
			'secuplug',
			array( $this, 'get_dashboard_html' ),
			'dashicons-shield'
		);

		$this->menu_pages['dashboard'] = \add_submenu_page(
			'secuplug',
			esc_html__( 'SecureFusion Dashboard', 'secuplug' ),
			esc_html__( 'Dashboard', 'secuplug' ),
			'manage_options',
			'secuplug',
			array( $this, 'get_dashboard_html' )
		);

		$this->menu_pages['settings'] = \add_submenu_page(
			'secuplug',
			esc_html__( 'SecureFusion Settings', 'secuplug' ),
			esc_html__( 'Settings', 'secuplug' ),
			$this->layered ? Settings::site_capability() : 'manage_options',
			'securefusion-settings',
			array( $this, 'get_settings_html' )
		);

		$this->menu_pages['security_log'] = \add_submenu_page(
			'secuplug',
			esc_html__( 'SecureFusion Security Log', 'secuplug' ),
			esc_html__( 'Security Log', 'secuplug' ),
			'manage_options',
			'securefusion-security-log',
			array( $this, 'get_security_log_html' )
		);

		$this->menu_pages['ip_rules'] = \add_submenu_page(
			'secuplug',
			esc_html__( 'SecureFusion IP Rules', 'secuplug' ),
			esc_html__( 'IP Rules', 'secuplug' ),
			'manage_options',
			'securefusion-ip-rules',
			array( $this, 'get_ip_rules_html' )
		);

		$this->menu_pages['ip_ranges'] = \add_submenu_page(
			'secuplug',
			esc_html__( 'SecureFusion IP Ranges', 'secuplug' ),
			esc_html__( 'IP Ranges', 'secuplug' ),
			'manage_options',
			'securefusion-ip-ranges',
			array( $this, 'get_ip_ranges_html' )
		);

	}


	/**
	 * Get security log HTML.
	 *
	 * Delegates rendering to the SecurityLog class.
	 *
	 * @return void
	 */
	public function get_security_log_html() {

		$log = new SecurityLog();
		$log->render();

	}


	/**
	 * Get IP rules HTML.
	 *
	 * Delegates rendering to the IPRules class.
	 *
	 * @return void
	 */
	public function get_ip_rules_html() {

		$rules = new IPRules();
		$rules->render();

	}


	/**
	 * Get IP ranges HTML.
	 *
	 * Delegates rendering to the IPRanges class.
	 *
	 * @return void
	 */
	public function get_ip_ranges_html() {

		$ranges = new IPRanges();
		$ranges->render();

	}


	/**
	 * Welcome notice.
	 *
	 * @return void
	 */
	public function welcome_notice() {

		if ( ! \PAnD::is_admin_notice_active( 'do-securefusion-settings-forever' ) ) {

			return;

		}

		$settings_menu = $this->admin_link . '?page=securefusion-settings';
		?>
		<div data-dismissible="do-securefusion-settings-forever" class="notice is-dismissible fynd-sf-welcome-notice">
			<div class="fynd-sf-welcome-inner">
				<span class="dashicons dashicons-shield-alt fynd-sf-welcome-icon"></span>
				<div class="fynd-sf-welcome-text">
					<strong><?php esc_html_e( 'SecureFusion is active!', 'secuplug' ); ?></strong>
					<span><?php esc_html_e( 'Configure your security settings to protect your site.', 'secuplug' ); ?></span>
				</div>
				<a href="<?php echo esc_url( $settings_menu ); ?>" class="fynd-sf-btn fynd-sf-btn-primary fynd-sf-welcome-btn">
					<?php esc_html_e( 'Go to Settings', 'secuplug' ); ?>
				</a>
			</div>
		</div>
		<?php
	}


	/**
	 * Load settings.
	 *
	 * @return void
	 */
	public function load() {

		$current_user = \wp_get_current_user();

		$ssl_cond = is_array( get_transient( 'securefusion_ssl_cert_data' ) );

		$conf = [
			require __DIR__ . '/AdminSections/XmlrpcSettings.php',
			require __DIR__ . '/AdminSections/ActiveGuardSettings.php',
			require __DIR__ . '/AdminSections/SecurityPoliciesSettings.php',
			require __DIR__ . '/AdminSections/LoginSettings.php',
			require __DIR__ . '/AdminSections/SslSettings.php',
			require __DIR__ . '/AdminSections/RecaptchaSettings.php',
			require __DIR__ . '/AdminSections/NotificationSettings.php',
			require __DIR__ . '/AdminSections/AdvancedSettings.php',
		];

		if ( 'network' === $this->context ) {

			$conf[] = $this->get_network_policy_section();

		} elseif ( $this->layered ) {

			// Sub-site: show network values, save only what this site customizes.
			$this->settings_page->set_fallback_values(
				Settings::inherited_values(),
				[
					'locked'        => Settings::NETWORK_ONLY,
					'label'         => esc_html__( 'Customize for this site', 'secuplug' ),
					'source_label'  => esc_html__( 'Network setting', 'secuplug' ),
					'locked_label'  => esc_html__( 'Set by the network administrator', 'secuplug' ),
					'empty_label'   => esc_html__( '(empty)', 'secuplug' ),
					'revert_label'  => esc_html__( 'Use network setting', 'secuplug' ),
					'auto_override' => true,
				]
			);

		}

		foreach ( $conf as $section ) {

			if ( empty( $section['name'] ) || empty( $section['items'] ) || ! is_array( $section['items'] ) ) {

				continue;

			}

			$this->section_keys[ $section['name'] ] = array_values( array_filter( wp_list_pluck( $section['items'], 'name' ) ) );

		}

		$this->settings_page->load_form( TagInputPresets::prepare( SettingsExperience::sections( $conf ) ) );
		$this->settings_page->register();

	}



	/**
	 * Network admin menu (network-activated multisite).
	 *
	 * @return void
	 */
	public function network_admin_menu() {

		$hook = \add_menu_page(
			esc_html__( 'SecureFusion Network Settings', 'secuplug' ),
			esc_html__( 'SecureFusion', 'secuplug' ),
			'manage_network_options',
			'securefusion-network-settings',
			array( $this, 'get_settings_html' ),
			'dashicons-shield'
		);

		// Network admin screen IDs carry a "-network" suffix.
		$this->menu_pages['network_settings'] = $hook . '-network';

	}



	/**
	 * Settings link on the network Plugins screen.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public function add_network_settings_link( $links ) {

		$links[] = '<a href="' . esc_url( \network_admin_url( 'admin.php?page=securefusion-network-settings' ) ) . '">' . esc_html__( 'Network Settings', 'secuplug' ) . '</a>';

		return $links;

	}



	/**
	 * Notice shown when an older wasp library (loaded by another plugin) lacks network support.
	 *
	 * @return void
	 */
	public function old_wasp_notice() {

		if ( ! \current_user_can( 'manage_network_options' ) ) {

			return;

		}

		echo '<div class="notice notice-warning"><p>' . esc_html__( 'SecureFusion: another plugin loads an older version of the wasp settings library, so network defaults are not available. Each site uses its own settings until that plugin is updated.', 'secuplug' ) . '</p></div>';

	}


	/**
	 * Admin menu screen.
	 *
	 * @return void
	 */
	public function admin_menu_screen() {

		if ( $this->check_admin_menu_screen( $this->menu_pages ) ) {

			$this->admin_menu_zone();

		} else {

			// Only show the welcome notice on the main WordPress Dashboard page.
			$screen = get_current_screen();

			if ( $screen && $screen->id === 'dashboard' && \current_user_can( $this->layered ? Settings::site_capability() : 'manage_options' ) ) {

				\add_action( 'admin_notices', [ $this, 'welcome_notice' ] );

			}

		}

	}


	/**
	 * Admin menu zone.
	 *
	 * @return void
	 */
	public function admin_menu_zone() {

		\add_action( 'admin_enqueue_scripts', array( $this, 'admin_theme_styles' ), 1 );

	}


	/**
	 * Admin theme styles.
	 *
	 * @return void
	 */
	public function admin_theme_styles() {

		\wp_enqueue_style( 'securefusion-admin-theme-main-css', \plugins_url( 'assets/css/admin.css', SECUREFUSION_BASENAME ), array(), (string) filemtime( SECUREFUSION_PATH . 'assets/css/admin.css' ) );
		\wp_enqueue_style( 'securefusion-bastion', \plugins_url( 'assets/css/bastion.css', SECUREFUSION_BASENAME ), array( 'securefusion-admin-theme-main-css' ), (string) filemtime( SECUREFUSION_PATH . 'assets/css/bastion.css' ) );
		\wp_enqueue_script( 'securefusion-admin-js', \plugins_url( 'assets/js/admin.js', SECUREFUSION_BASENAME ), array( 'jquery' ), (string) filemtime( SECUREFUSION_PATH . 'assets/js/admin.js' ), true );
		\wp_localize_script(
			'securefusion-admin-js',
			'securefusionAdmin',
			[
				'hostsOnly'    => __( 'Hosts only: inline code and keywords are set by the protection level.', 'secuplug' ),
				'invalidUrl'   => __( 'Invalid URL format', 'secuplug' ),
				'invalidRegex' => __( 'Invalid regex pattern', 'secuplug' ),
			]
		);

		\wp_enqueue_script( 'securefusion-inline-manager', \plugins_url( 'assets/js/inline-manager.js', SECUREFUSION_BASENAME ), [ 'jquery' ], (string) filemtime( SECUREFUSION_PATH . 'assets/js/inline-manager.js' ), true );
		\wp_localize_script(
			'securefusion-inline-manager',
			'securefusionInline',
			[
				'url'         => admin_url( 'admin-ajax.php' ),
				'saved'       => __( 'Saved.', 'secuplug' ),
				'saving'      => __( 'Working…', 'secuplug' ),
				'error'       => __( 'The request failed. Your changes were not confirmed.', 'secuplug' ),
				'needsLevel'  => __( 'Not used while protection is Off', 'secuplug' ),
				'needsStrict' => __( 'Not used while all inline code is allowed', 'secuplug' ),
			]
		);

		\wp_enqueue_script( 'securefusion-unsaved-settings', \plugins_url( 'assets/js/unsaved-settings.js', SECUREFUSION_BASENAME ), array( 'jquery', 'securefusion-admin-js' ), (string) filemtime( SECUREFUSION_PATH . 'assets/js/unsaved-settings.js' ), true );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-state-changing query parameter check.
		if ( isset( $_GET['page'] ) && 'secuplug' === $_GET['page'] ) {

			\wp_enqueue_script( 'securefusion-chartjs', \plugins_url( 'assets/lib/chartjs/chart.umd.min.js', SECUREFUSION_BASENAME ), array( 'jquery' ), (string) filemtime( SECUREFUSION_PATH . 'assets/js/admin.js' ), true );
			\wp_enqueue_script( 'securefusion-dashboard-js', \plugins_url( 'assets/js/dashboard.js', SECUREFUSION_BASENAME ), array( 'securefusion-chartjs' ), SECUREFUSION_VERSION, true );

			$chart_data = $this->get_dashboard_chart_data();

			\wp_localize_script( 'securefusion-dashboard-js', 'securefusionChartData', $chart_data );

		}

	}


	/**
	 * Init.
	 *
	 * @return void
	 */
	public function init() {

		// Settings link.
		$filter_name = 'plugin_action_links_' . \plugin_basename( SECUREFUSION_BASENAME );

		\add_filter( $filter_name, array( $this, 'add_settings_link' ) );

		// wasp serves its scripts from its own folder; tell it the URL, which plugins_url()
		// cannot work out when vendor/ is a symlink or junction (development setups).
		if ( method_exists( Wasp::class, 'set_assets_url' ) && is_dir( SECUREFUSION_PATH . 'vendor/uuur86/wasp/assets' ) ) {

			Wasp::set_assets_url( SECUREFUSION_URL . 'vendor/uuur86/wasp/' );

		}

		// Network defaults need wasp 3.1+. Another plugin may have loaded an older copy first.
		$wasp_supports_layers = method_exists( Wasp::class, 'set_fallback_values' );
		$this->layered        = Settings::is_network_mode() && $wasp_supports_layers;

		if ( Settings::is_network_mode() && ! $wasp_supports_layers ) {

			\add_action( 'network_admin_notices', array( $this, 'old_wasp_notice' ) );

		}

		// AJAX does not retain the network admin screen context.
		$network_reset = wp_doing_ajax()
			&& isset( $_POST['nonce'] ) && is_string( $_POST['nonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( $_POST['nonce'] ) ), 'wasp_reset_field_nonce' )
			&& current_user_can( 'manage_network_options' )
			&& isset( $_POST['action'], $_POST['settings_name'] )
			&& is_string( $_POST['action'] ) && is_string( $_POST['settings_name'] )
			&& in_array( wp_unslash( $_POST['action'] ), [ 'wasp_reset_field', 'wasp_reset_all_fields' ], true )
			&& 'securefusion_network' === sanitize_key( wp_unslash( $_POST['settings_name'] ) );

		$this->context = ( $this->layered && ( \is_network_admin() || $network_reset ) ) ? 'network' : 'site';

		// Settings Page Form.
		if ( 'network' === $this->context ) {

			$this->settings_page = new Wasp(
				'securefusion-network-settings',
				'securefusion_network',
				'secuplug',
				null,
				[ 'storage' => 'network' ]
			);

			\add_action( 'network_admin_menu', array( $this, 'network_admin_menu' ) );
			\add_filter( 'network_admin_plugin_action_links_' . \plugin_basename( SECUREFUSION_BASENAME ), array( $this, 'add_network_settings_link' ) );

		} elseif ( $this->layered ) {

			$this->settings_page = new Wasp(
				'securefusion-settings',
				'securefusion',
				'secuplug',
				null,
				[ 'capability' => Settings::site_capability() ]
			);

		} else {

			$this->settings_page = new Wasp(
				'securefusion-settings',
				'securefusion',
				'secuplug'
			);

		}

		if ( $this->settings_page instanceof Wasp ) {

			// Bastion templates; field types the theme does not list use wasp's defaults.
			if ( method_exists( $this->settings_page, 'set_theme' ) ) {

				$this->settings_page->set_theme( SECUREFUSION_PATH . 'assets/wasp/bastion.wasp.php' );

			}

			$this->settings_page->wp_form_init( [ $this, 'load' ] );

			// On a sub-site "Use network setting" is the way back, so there is no factory reset.
			if ( ! ( $this->layered && 'site' === $this->context ) ) {

				$this->settings_page->enable_reset(
					[
						'confirm_message' => esc_html__( 'Restore the default value of this setting?', 'secuplug' ),
						'button_text'     => esc_html__( 'Restore default', 'secuplug' ),
						'button_class'    => 'fsf-link',
						'wrapper_class'   => 'wasp-reset-wrapper',
					],
					$this->default_settings
				);

			}

		}

		\add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		\add_action( 'current_screen', array( $this, 'admin_menu_screen' ) );

	}

}
