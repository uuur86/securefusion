<?php
/**
 * Admin Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use WaspCreators\Wasp;
use SecureFusion\Lib\Traits\WPCommon;

/**
 * Admin Class
 *
 * @package securefusion
 */
class Admin {

	/**
	 * Filesystem instance.
	 *
	 * @var \WP_Filesystem
	 */
	protected $filesystem;

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

	use WPCommon;


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
		$settings_link .= esc_html__( 'Settings', 'securefusion' );
		$settings_link .= '</a>';

		$links[] = $settings_link;

		return $links;
	}


	/**
	 * Add admin menu pages.
	 *
	 * @return void
	 */
	public function admin_menu() {
		$this->menu_pages['main'] = \add_menu_page(
			esc_html__( 'SecureFusion', 'securefusion' ),
			esc_html__( 'SecureFusion', 'securefusion' ),
			'manage_options',
			'securefusion',
			array( $this, 'get_dashboard_html' ),
			'dashicons-shield'
		);

		$this->menu_pages['dashboard'] = \add_submenu_page(
			'securefusion',
			esc_html__( 'SecureFusion Dashboard', 'securefusion' ),
			esc_html__( 'Dashboard', 'securefusion' ),
			'manage_options',
			'securefusion',
			array( $this, 'get_dashboard_html' )
		);

		$this->menu_pages['settings'] = \add_submenu_page(
			'securefusion',
			esc_html__( 'SecureFusion Settings', 'securefusion' ),
			esc_html__( 'Settings', 'securefusion' ),
			'manage_options',
			'securefusion-settings',
			array( $this, 'get_settings_html' )
		);

		$this->menu_pages['login_log'] = \add_submenu_page(
			'securefusion',
			esc_html__( 'Login Log', 'securefusion' ),
			esc_html__( 'Login Log', 'securefusion' ),
			'manage_options',
			'securefusion-login-log',
			array( $this, 'get_login_log_html' )
		);
	}


	/**
	 * Get dashboard HTML.
	 *
	 * @return void
	 */
	public function get_dashboard_html() {
		global $wp_version;

		$settings = $this->settings_page;

		$disable_all_xmlrpc = $settings->get_setting( 'disable_xmlrpc', false );
		$force_all_https    = $settings->get_setting( 'force_site_https', false );

		$enable_https = $settings->get_setting( 'enable_https', null );

		// login.
		$login_url          = $settings->get_setting( 'custom_login_url', null );
		$change_admin_id    = $settings->get_setting( 'change_admin_id', null ) > 1 ? 1 : 0;
		$change_login_error = empty( $settings->get_setting( 'change_login_error', null ) ) ? 0 : 1;

		// firewall.
		$filter_bad_requests = $settings->get_setting( 'filter_bad_requests', null );
		$disable_rest_api    = $settings->get_setting( 'disable_rest_api', null );

		if ( $disable_all_xmlrpc ) {
			$xmlrpc_login    = 1;
			$xmlrpc_pingback = 1;
			$self_pingback   = 1;
		} else {
			// Gets xml-rpc settings when all xml-rpc services are disabled.
			$xmlrpc_login    = $settings->get_setting( 'disable_xmlrpc_user_login', null );
			$xmlrpc_pingback = $settings->get_setting( 'disable_xmlrpc_pingback', null );
			$self_pingback   = $settings->get_setting( 'disable_self_pingback', null );
		}

		if ( $force_all_https ) {
			$force_front_https = 1;
			$force_admin_https = 1;
			$force_login_https = 1;
		} else {
			$force_front_https = $settings->get_setting( 'force_front_https', null );
			$force_admin_https = $settings->get_setting( 'force_admin_https', null );
			$force_login_https = $settings->get_setting( 'force_login_https', null );
		}

		$security_pass = true;

		$brute_force_db   = new BruteForceDB();
		$total_attempts   = $brute_force_db->get_total_attempts();
		$unique_ips_count = $brute_force_db->get_unique_ips_count();

		?>
		<div class="securefusion-dashboard container">
			<header class="dashboard-header">
				<img src="<?php echo esc_url( $this->plugin_url ); ?>assets/icon.svg" alt="SecureFusion Logo" class="dashboard-logo">
				<div class="dashboard-title">
					<h1>
						<?php esc_html_e( 'SecureFusion Dashboard', 'securefusion' ); ?>
					</h1>
					<p class="description">
						<?php esc_html_e( 'You could monitoring your WordPress security settings.', 'securefusion' ); ?>
					</p>
				</div>
			</header>
			<section class="dashboard-overview">
				<div class="dashboard-item">
					<h2><?php esc_html_e( 'Security Status', 'securefusion' ); ?></h2>

					<p>
					<?php
					esc_html_e( 'WordPress Version:', 'securefusion' );
					echo ' ' . esc_html( $wp_version );
					?>
					</p>

					<?php
					if ( version_compare( $wp_version, '6.7.0', '<' ) ) :
						$security_pass = false;
						?>
						<p class="status disabled">
							<?php esc_html_e( 'Your WordPress version has security vulnerabilities.', 'securefusion' ); ?>
						</p>
					<?php endif; ?>

					<p>
					<?php
					esc_html_e( 'PHP Version:', 'securefusion' );
					echo ' ' . esc_html( phpversion() );
					?>
					</p>

					<?php
					if ( version_compare( phpversion(), '8.2.0', '<' ) ) :
						$security_pass = false;
						?>
						<p class="status disabled">
							<?php esc_html_e( 'Your PHP version has security vulnerabilities.', 'securefusion' ); ?>
						</p>
					<?php endif; ?>

					<p>
					<?php
					esc_html_e( 'Failed login attempts:', 'securefusion' );
					echo ' ' . (int) $total_attempts;
					?>
					</p>
					<p>
					<?php
					esc_html_e( 'IPs of Failed Attempts:', 'securefusion' );
					echo ' ' . (int) $unique_ips_count;
					?>
					</p>
					<p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=securefusion-login-log' ) ); ?>" class="button button-secondary">
							<span class="dashicons dashicons-list-view" style="vertical-align:text-top;font-size:16px;width:16px;height:16px;margin-right:4px;"></span>
							<?php esc_html_e( 'View Login Log', 'securefusion' ); ?>
						</a>
					</p>
					<?php if ( $security_pass ) : ?>
						<p class="status enabled">
							<?php esc_html_e( 'Everything is running smoothly. No security issues have been detected.', 'securefusion' ); ?>
						</p>
					<?php endif; ?>
				</div>
				<?php
				$settings_link = \add_query_arg(
					array(
						'page' => 'securefusion-settings',
					),
					$this->admin_link
				);

				$this->add_status_box(
					esc_html__( 'XML-RPC FULL PROTECTION', 'securefusion' ),
					$disable_all_xmlrpc,
					esc_html__( 'Blocks all remote requests. Most commonly used to prevent all types of remote attacks.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'XML-RPC LOGIN PROTECTION', 'securefusion' ),
					$xmlrpc_login,
					esc_html__( 'Blocks remote login requests. Most commonly used to prevent brute force login attempts.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'XML-RPC PINGBACK PROTECTION', 'securefusion' ),
					$xmlrpc_pingback,
					esc_html__( 'Blocks remote pingback requests. Most commonly used to prevent DDoS attacks.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'SELF PINGBACK PROTECTION', 'securefusion' ),
					$self_pingback,
					esc_html__( 'Blocks remote self-pingback requests. Most commonly used to prevent DDoS attacks.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'New Custom Login URL', 'securefusion' ),
					$login_url,
					esc_html__( 'Hides login url from the attackers.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'Enable HTTPS / SSL', 'securefusion' ),
					$enable_https,
					esc_html__( 'SSL automatically encrypts your privileged information data.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'Force HTTPS Login', 'securefusion' ),
					$force_login_https,
					esc_html__( 'Redirect login page protocol HTTP to HTTPS', 'securefusion' )
				);
				$this->add_status_box(
					esc_html__( 'Change Login Error', 'securefusion' ),
					$change_login_error,
					esc_html__( 'Disable default login errors and provide attackers with less than what they need.', 'securefusion' )
				);
				$this->add_status_box(
					esc_html__( 'Change Admin ID', 'securefusion' ),
					$change_admin_id,
					esc_html__( "It's not difficult to predict your Admin ID if it's set to `1`. Secure your site against simple SQL vulnerabilities.", 'securefusion' )
				);
				$this->add_status_box(
					esc_html__( 'Forge HTTPS Admin', 'securefusion' ),
					$force_admin_https,
					esc_html__( 'Redirects the admin page protocol from HTTP to HTTPS', 'securefusion' )
				);
				$this->add_status_box(
					esc_html__( 'Force HTTPS Front Page', 'securefusion' ),
					$force_front_https,
					esc_html__( 'Redirects the front page protocol from HTTP to HTTPS.', 'securefusion' )
				);
				$this->add_status_box(
					esc_html__( 'Filter Bad Requests', 'securefusion' ),
					$filter_bad_requests,
					esc_html__( 'Helps secure your site against attacks like XSS, CSRF, and Code Injections.', 'securefusion' )
				);
				$this->add_status_box(
					esc_html__( 'Disable Rest API', 'securefusion' ),
					$disable_rest_api,
					esc_html__( 'Conceals sensitive information from attackers, such as Admin user IDs, user lists, and their IDs.', 'securefusion' )
				);

				$this->add_status_box(
					esc_html__( 'Settings', 'securefusion' ),
					false,
					esc_html__( 'Manage your security features', 'securefusion' ),
					[
						esc_html__( 'Go to settings', 'securefusion' ),
						$settings_link,
					]
				);
				?>
			</section>
		</div>
		<?php
	}


	/**
	 * Get login log HTML.
	 *
	 * Delegates rendering to the LoginLog class.
	 *
	 * @return void
	 */
	public function get_login_log_html() {
		$log = new LoginLog();
		$log->render();
	}


	/**
	 * Get settings HTML.
	 *
	 * @return void
	 */
	public function get_settings_html() {
		$ssl_cond  = empty( get_transient( 'securefusion_ssl_cert_data' ) );
		$ssl_error = esc_html__( 'Only use this if you have an SSL certificate; otherwise, it cannot be enabled.', 'securefusion' );

		if ( $ssl_cond ) {
			$ssl_error = '<p style="color:red">' .
					esc_html__( 'ERROR! You don’t have any valid SSL certificate. ', 'securefusion' ) .
				'</p>' .

				'<p>' .

					'<b>' . esc_html__( 'Free SSL certificate providers', 'securefusion' ) . '</b> : ' .

					'<a href="https://letsencrypt.org/" target="_blank">' .
					esc_html__( 'Let’s Encrypt', 'securefusion' ) .
					'</a>' .

					' or <a href="https://www.cloudflare.com/" target="_blank">' .
					esc_html__( 'Cloudflare', 'securefusion' ) .
					'</a>' .

					'<br />' .

					'<b>Paid SSL certificate providers</b> : ' .

					'<a href="https://sectigo.com/" target="_blank">' .
					esc_html__( 'Comodo / Sectigo', 'securefusion' ) .
					'</a>' .

					' or <a href="https://www.digicert.com" target="_blank">' .
					esc_html__( 'Digicert', 'securefusion' ) .
					'</a>' .

				'</p>';
		}

		?>
		<div class="secure-fusion-settings container" style="position: relative;float: left;width: 100%;">
			<div class="header">
				<img src="<?php echo esc_url( $this->plugin_url ); ?>assets/icon.svg" alt="SecureFusion Logo">
				<div class="header-title">
					<h1><?php esc_html_e( 'SecureFusion Security Settings', 'securefusion' ); ?></h1>
					<p class="version-info">
						<?php
							/* translators: %s: Version number */
							printf( esc_html__( 'Version %s - Check out.', 'securefusion' ), esc_html( SECUREFUSION_VERSION ) );
						?>
						<a href="https://codeplus.dev/securefusion/changelog" target="_blank" rel="noopener">
							<?php esc_html_e( 'What\'s New', 'securefusion' ); ?>
						</a>
					</p>
				</div>
				<div class="plugin-links">
					<a href="#">
						<?php esc_html_e( 'Additional Plugins', 'securefusion' ); ?>
					</a>
				</div>
			</div>
			<p class="description">
				<?php esc_html_e( 'You could manage your WordPress security settings.', 'securefusion' ); ?>
			</p>
			<div class="clear"></div>
			<?php
			if ( $this->settings_page->is_ready() ) {
				?>
				<h2 class="nav-tab-wrapper">
					<a href="#xmlrpc" class="nav-tab">
						<span class="dashicons dashicons-networking"></span>
						<?php esc_html_e( 'XMLRPC', 'securefusion' ); ?>
					</a>
					<a href="#login" class="nav-tab">
						<span class="dashicons dashicons-admin-users"></span>
						<?php esc_html_e( 'Login', 'securefusion' ); ?>
					</a>
					<a href="#ssl" class="nav-tab">
						<span class="dashicons dashicons-admin-network"></span>
						<?php esc_html_e( 'SSL', 'securefusion' ); ?>
					</a>
					<a href="#firewall" class="nav-tab">
						<span class="dashicons dashicons-hidden"></span>
						<?php esc_html_e( 'Firewall', 'securefusion' ); ?>
					</a>
					<a href="#advanced" class="nav-tab">
						<span class="dashicons dashicons-warning"></span>
						<?php esc_html_e( 'Advanced', 'securefusion' ); ?>
					</a>
				</h2>
				<div class="content-box">
					<?php $this->settings_page->form_start(); ?>
					<div class="content-tab-wrapper">
						<div class="tab-content" id="securefusion-xmlrpc">
							<?php $this->settings_page->run_section( 'xmlrpc_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="securefusion-login">
							<?php $this->settings_page->run_section( 'login_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="securefusion-ssl">
							<?php $this->settings_page->run_section( 'ssl_settings' ); ?>
							<div class="notice notice-error">
								<p><?php echo wp_kses_post( $ssl_error ); ?></p>
							</div>
						</div>
						<div class="tab-content hidden" id="securefusion-firewall">
							<?php $this->settings_page->run_section( 'firewall_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="securefusion-advanced">
							<?php $this->settings_page->run_section( 'advanced_settings' ); ?>
							<div class="notice notice-error">
								<p>
									<?php esc_html_e( "If you don't have experience in cybersecurity or regular expressions, do not modify these areas.", 'securefusion' ); ?>
								</p>
							</div>
						</div>
					</div>
					<?php $this->settings_page->form_end(); ?>
				</div>
			</div>
				<?php
			}
	}


	/**
	 * Welcome notice.
	 *
	 * @return void
	 */
	public function welcome_notice() {
		$settings = $this->get_settings();

		if ( ! empty( $settings ) ) {
			return;
		}

		if ( ! \PAnD::is_admin_notice_active( 'do-securefusion-settings-forever' ) ) {
			return;
		}

		$settings_menu = $this->admin_link . '?page=securefusion-settings';
		?>
		<div data-dismissible="do-securefusion-settings-forever" class="welcome-panel notice is-dismissible">
			<div class="welcome-panel-content">
				<h2>
					<?php esc_html_e( 'Welcome to SecureFusion', 'securefusion' ); ?>
				</h2>
				<p class="about-description">
					<?php
						printf(
							/* translators: %s: Plugin Settings URL */
							esc_html__(
								'Thank you for installing SecureFusion! Check out <a href="%s">the Plugin Settings</a>',
								'securefusion'
							),
							esc_url( $settings_menu )
						);
					?>
				</p>
				<div class="welcome-panel-column-container">
					<div class="welcome-panel-column">
						<p>
							<a href="<?php echo esc_url( $settings_menu ); ?>" class="button button-primary button-hero">
								<?php esc_html_e( 'Get started', 'securefusion' ); ?>
							</a>
						</p>
					</div>
				</div>
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

		$ssl_cond = ! empty( get_transient( 'securefusion_ssl_cert_data' ) );

		$conf = [
			[
				// Section info.
				'name'  => 'xmlrpc_settings',
				'title' => esc_html__( 'XML-RPC SETTINGS', 'securefusion' ),
				'desc'  => esc_html__( 'You can prevent to xmlrpc attacks.', 'securefusion' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc',
						'default' => '0',
						'label'   => esc_html__( 'Disable All XML-RPC Services', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'Enabling this option will completely disable XML-RPC functionality, which can prevent certain types of attacks but may affect integrations with other systems and applications.', 'securefusion' ) . '</p>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc_user_login',
						'default' => '0',
						'label'   => esc_html__( 'Disable XML-RPC Login Service', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'If checked, this will disable login capability through XML-RPC. This helps prevent brute force attacks but may affect some legitimate XML-RPC uses.', 'securefusion' ) . '</p>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc_pingback',
						'default' => '0',
						'label'   => esc_html__( 'Disable XML-RPC Pingback Service', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'Pingbacks can be abused for DDoS attacks. Disabling this will prevent pingbacks, improving security.', 'securefusion' ) . '</p>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_self_pingback',
						'default' => '0',
						'label'   => esc_html__( 'Disable Self Pingback Service', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'WordPress generates pingbacks to its own posts by default. This option disables such self-pingbacks.', 'securefusion' ) . '</p>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'firewall_settings',
				'title' => esc_html__( 'FIREWALL SETTINGS', 'securefusion' ),
				'desc'  => esc_html__( 'Firewall security settings. (Beta)', 'securefusion' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'filter_bad_requests',
						'default' => '0',
						'label'   => esc_html__( 'Filter Bad Requests', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_rest_api',
						'default' => '0',
						'label'   => esc_html__( 'Disable Rest API for Visitors', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'hide_versions',
						'default' => '0',
						'label'   => esc_html__( 'Hide apache and PHP version', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'bad_bots',
						'default' => '0',
						'label'   => esc_html__( 'Block bad bots', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'http_headers',
						'default' => '0',
						'label'   => esc_html__( 'Add HTTP Headers for Browser Security', 'securefusion' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'securefusion' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'securefusion' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_style_sources',
						'label'             => esc_html__( 'CSP Allowed Style Sources', 'securefusion' ),
						'placeholder'       => 'fonts.googleapis.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="\'unsafe-inline\'">unsafe-inline</button><button type="button" class="taginput-preset-btn" data-preset="https://fonts.googleapis.com">Google Fonts</button><button type="button" class="taginput-preset-btn" data-preset="https://cdnjs.cloudflare.com">Cloudflare</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_script_sources',
						'label'             => esc_html__( 'CSP Allowed Script Sources', 'securefusion' ),
						'placeholder'       => 'googletagmanager.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="\'unsafe-inline\'">unsafe-inline</button><button type="button" class="taginput-preset-btn" data-preset="https://www.googletagmanager.com">Google Tag Manager</button><button type="button" class="taginput-preset-btn" data-preset="https://www.google-analytics.com">GA4</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_font_sources',
						'label'             => esc_html__( 'CSP Allowed Font Sources', 'securefusion' ),
						'placeholder'       => 'fonts.gstatic.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="data:">data:</button><button type="button" class="taginput-preset-btn" data-preset="https://fonts.gstatic.com">Google Fonts</button><button type="button" class="taginput-preset-btn" data-preset="https://cdnjs.cloudflare.com">Cloudflare</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_frame_sources',
						'label'             => esc_html__( 'CSP Frame Sources (iframe embed)', 'securefusion' ),
						'placeholder'       => 'youtube.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="https://www.youtube.com">YouTube</button><button type="button" class="taginput-preset-btn" data-preset="https://www.google.com">Google</button><button type="button" class="taginput-preset-btn" data-preset="https://maps.google.com">Google Maps</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_worker_sources',
						'label'             => esc_html__( 'CSP Worker Sources', 'securefusion' ),
						'placeholder'       => 'blob:',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="blob:">blob:</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_img_sources',
						'label'             => esc_html__( 'CSP Image Sources', 'securefusion' ),
						'placeholder'       => 'example.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="data:">data:</button><button type="button" class="taginput-preset-btn" data-preset="https:">https:</button>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'login_settings',
				'title' => esc_html__( 'LOGIN SETTINGS - BE CAREFUL!', 'securefusion' ),
				'desc'  => esc_html__( 'You can hide or secure your login page against the attackers. Please save your new login url before you change it.', 'securefusion' ),
				// Form items.
				'items' => [
					[
						'type'   => 'text_input',
						'name'   => 'ip_time_limit',
						'label'  => esc_html__( 'Min. Wait Time', 'securefusion' ),
						'before' => '',
						'after'  => esc_html__( ' hour(s)', 'securefusion' ) . '<span class="field-tip"> ' . esc_html__( 'Minimum Wait Time After Failed Attempt', 'securefusion' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'ip_login_limit',
						'label'  => esc_html__( 'Max. Attempt Limit', 'securefusion' ),
						'before' => '',
						'after'  => esc_html__( ' time(s)', 'securefusion' ) . '<span class="field-tip"> ' . esc_html__( 'Maksimum Failed Login Attempt Limit', 'securefusion' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'custom_login_url',
						'label'  => esc_html__( 'Custom Login Path', 'securefusion' ),
						'before' => '<span class="url-text">' . \get_home_url() . '/</span>',
						'after'  => '<span class="field-tip">/ (For exam. : hidden-login)</span>',
					],
					[
						'type'  => 'text_input',
						'name'  => 'change_login_error',
						'label' => esc_html__( 'Custom Login Error Message', 'securefusion' ),
					],
					[
						'type'   => 'text_input',
						'name'   => 'change_admin_id',
						'label'  => esc_html__( 'Your Admin ID', 'securefusion' ),
						'before' => 'Your current ID is ',
						'after'  => ' for "' . $current_user->user_login . '". ' .
							'<span class="field-tip">' .
							'	We recommended to change this field for each user by one by' .
							'</span>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'ssl_settings',
				'title' => esc_html__( 'SSL SETTINGS', 'securefusion' ),
				'desc'  => esc_html__( 'HTTPS/SSL security settings.', 'securefusion' ),
				// Form items.
				'items' => [
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'enable_https',
						'default' => '',
						'label'   => esc_html__( 'HTTPS Support', 'securefusion' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_login_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS on login page', 'securefusion' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_admin_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS on admin page', 'securefusion' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_front_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS on front page', 'securefusion' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_site_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS site-wide', 'securefusion' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
				],
			],
			[
				// Section info.
				'name'  => 'advanced_settings',
				'title' => esc_html__( 'ADVANCED SETTINGS', 'securefusion' ),
				'desc'  => esc_html__( 'Advanced security settings. `Filter Bad Requests` must be active for it to work.', 'securefusion' ),
				// Form items.
				'items' => [
					[
						'type'              => 'taginput',
						'name'              => 'cookie_patterns',
						'label'             => esc_html__( 'Cookie Regex Patterns', 'securefusion' ),
						'placeholder'       => '[a-z0-9]+',
						'field_type'        => 'regex',
						'sanitize_callback' => function ( $value ) {
							// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
							return @preg_match( '/' . $value . '/', '' ) !== false;
						},
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="[a-z0-9]+">Alphanumeric</button><button type="button" class="taginput-preset-btn" data-preset="[a-zA-Z0-9_\-]+">Safe Chars</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'request_patterns',
						'label'             => esc_html__( 'Get/Post Request Regex Patterns', 'securefusion' ),
						'placeholder'       => '(union|select|insert)\s+\w+',
						'field_type'        => 'regex',
						'sanitize_callback' => function ( $value ) {
							// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
							return @preg_match( '/' . $value . '/', '' ) !== false;
						},
						'presets'           => '<button type="button" class="taginput-preset-btn" data-preset="@@[\w\.\$]+">SQL Vars</button><button type="button" class="taginput-preset-btn" data-preset="(union|select|insert)\s+">SQL Keywords</button><button type="button" class="taginput-preset-btn" data-preset="base64_\w+\(">Base64 Func</button>',
					],
				],
			],
		];

		$this->settings_page->loadForm( $conf );
		$this->settings_page->register();
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
			\add_action( 'admin_notices', [ $this, 'welcome_notice' ] );
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
		\wp_enqueue_style( 'securefusion-admin-theme-main-css', \plugins_url( 'assets/css/admin.css', SECUREFUSION_BASENAME ), array(), '1.1.14' );
		\wp_enqueue_script( 'securefusion-admin-js', \plugins_url( 'assets/js/admin.js', SECUREFUSION_BASENAME ), array(), '1.1.25', true );
	}



	/**
	 * Add status box.
	 *
	 * @param string $title   Title.
	 * @param mixed  $status  Status.
	 * @param string $desc    Description.
	 * @param array  $button  Button array.
	 *
	 * @return void
	 */
	public function add_status_box( $title, $status = false, $desc = '', $button = [] ) {
		?>
		<div class="dashboard-item">
			<h2>
				<?php echo esc_html( $title ); ?>
			</h2>
			<?php
			if ( ! empty( $desc ) ) :
				?>
				<p class="description">
					<?php echo esc_html( $desc ); ?>
				</p>
				<?php
			endif;

			if ( $status !== false ) :
				?>
				<p class="status <?php echo esc_attr( $status ? 'enabled' : 'disabled' ); ?>">
					<?php $status ? esc_html_e( 'enabled', 'securefusion' ) : esc_html_e( 'disabled', 'securefusion' ); ?>
				</p>
				<?php
			endif;

			if ( ! empty( $button ) ) :
				?>
				<a href="<?php echo esc_attr( $button[1] ); ?>">
					<?php echo esc_html( $button[0] ); ?>
				</a>
				<?php
			endif;
			?>
		</div>
		<?php
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

		// Settings Page Form.
		$this->settings_page = new Wasp(
			'securefusion-settings',
			'securefusion',
			'securefusion'
		);

		if ( $this->settings_page instanceof Wasp ) {
			$this->settings_page->wp_form_init( [ $this, 'load' ] );

			// Enable reset feature with factory defaults.
			$this->settings_page->enable_reset(
				[
					'confirm_message' => esc_html__( 'Are you sure you want to reset this field to its default value?', 'securefusion' ),
					'button_text'     => esc_html__( 'Reset', 'securefusion' ),
					'button_class'    => 'button button-secondary button-small',
					'wrapper_class'   => 'wasp-reset-wrapper',
				],
				$this->default_settings
			);
		}

		\add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		\add_action( 'current_screen', array( $this, 'admin_menu_screen' ) );
	}
}
