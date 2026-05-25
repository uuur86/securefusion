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
		$settings_link .= esc_html__( 'Settings', 'secuplug' );
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
			'manage_options',
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
		<div class="wrap fynd-sf-dashboard">

			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'SecureFusion Dashboard', 'secuplug' ); ?></h1>

			<?php
			$this->render_header(
				esc_html__( 'SecureFusion Dashboard', 'secuplug' ),
				esc_html__( 'You can monitor your WordPress security settings.', 'secuplug' )
			);
			?>

			<section class="fynd-sf-charts-section">
				<div class="fynd-sf-chart-container">
					<div class="fynd-sf-chart-header">
						<h3><?php esc_html_e( 'Daily Security Events (Last 30 Days)', 'secuplug' ); ?></h3>
						<span class="fynd-sf-chart-badge"><?php esc_html_e( 'Real-time', 'secuplug' ); ?></span>
					</div>
					<div class="fynd-sf-chart-body">
						<canvas id="fynd-sf-daily-chart"></canvas>
					</div>
				</div>
				<div class="fynd-sf-chart-container">
					<div class="fynd-sf-chart-header">
						<h3><?php esc_html_e( 'Monthly Security Events (Last 12 Months)', 'secuplug' ); ?></h3>
						<span class="fynd-sf-chart-badge"><?php esc_html_e( 'Overview', 'secuplug' ); ?></span>
					</div>
					<div class="fynd-sf-chart-body">
						<canvas id="fynd-sf-monthly-chart"></canvas>
					</div>
				</div>
			</section>

			<section class="dashboard-overview">
				<div class="dashboard-item fynd-sf-security-status-card <?php echo esc_attr( $security_pass ? 'fynd-sf-status-enabled' : 'fynd-sf-status-disabled' ); ?>">
					<div class="fynd-sf-card-header-row">
						<h2><?php esc_html_e( 'Security Status', 'secuplug' ); ?></h2>
						
						<div class="fynd-sf-system-badges">
							<div class="fynd-sf-system-badge">
								<span class="dashicons dashicons-wordpress"></span>
								<span>WordPress: <strong><?php echo esc_html( $wp_version ); ?></strong></span>
								<?php if ( version_compare( $wp_version, '6.7.0', '<' ) ) : ?>
									<span class="fynd-sf-badge-warning" title="<?php esc_attr_e( 'Vulnerable version', 'secuplug' ); ?>">!</span>
								<?php endif; ?>
							</div>
							<div class="fynd-sf-system-badge">
								<span class="dashicons dashicons-admin-settings"></span>
								<span>PHP: <strong><?php echo esc_html( phpversion() ); ?></strong></span>
								<?php if ( version_compare( phpversion(), '8.2.0', '<' ) ) : ?>
									<span class="fynd-sf-badge-warning" title="<?php esc_attr_e( 'Outdated version', 'secuplug' ); ?>">!</span>
								<?php endif; ?>
							</div>
						</div>
					</div>

					<div class="fynd-sf-metrics-grid">
						<div class="fynd-sf-metric-widget fynd-sf-metric-total">
							<span class="dashicons dashicons-shield"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $total_attempts; ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Total Attacks', 'secuplug' ); ?></span>
							</div>
						</div>
						<div class="fynd-sf-metric-widget fynd-sf-metric-failed-login">
							<span class="dashicons dashicons-lock"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $brute_force_db->get_total_attempts_by_type( 'failed_login' ); ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Failed Logins', 'secuplug' ); ?></span>
							</div>
						</div>
						<div class="fynd-sf-metric-widget fynd-sf-metric-bad-request">
							<span class="dashicons dashicons-warning"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $brute_force_db->get_total_attempts_by_type( 'bad_request' ); ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Bad Requests', 'secuplug' ); ?></span>
							</div>
						</div>
						<div class="fynd-sf-metric-widget fynd-sf-metric-bad-cookie">
							<span class="dashicons dashicons-excerpt-view"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $brute_force_db->get_total_attempts_by_type( 'bad_cookie' ); ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Bad Cookies', 'secuplug' ); ?></span>
							</div>
						</div>
						<div class="fynd-sf-metric-widget fynd-sf-metric-bad-bot">
							<span class="dashicons dashicons-networking"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $brute_force_db->get_total_attempts_by_type( 'bad_bot' ); ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Bad Bots', 'secuplug' ); ?></span>
							</div>
						</div>
						<div class="fynd-sf-metric-widget fynd-sf-metric-bad-query">
							<span class="dashicons dashicons-search"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $brute_force_db->get_total_attempts_by_type( 'bad_query' ); ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Bad Queries', 'secuplug' ); ?></span>
							</div>
						</div>
						<div class="fynd-sf-metric-widget fynd-sf-metric-unique-ips">
							<span class="dashicons dashicons-admin-site-alt3"></span>
							<div class="fynd-sf-metric-info">
								<span class="fynd-sf-metric-value"><?php echo (int) $unique_ips_count; ?></span>
								<span class="fynd-sf-metric-label"><?php esc_html_e( 'Unique IPs', 'secuplug' ); ?></span>
							</div>
						</div>
					</div>

					<?php if ( ! $security_pass ) : ?>
						<div class="fynd-sf-status-alert fynd-sf-status-alert-danger">
							<span class="dashicons dashicons-dismiss"></span>
							<div class="fynd-sf-alert-content">
								<strong><?php esc_html_e( 'System Security Warnings:', 'secuplug' ); ?></strong>
								<ul style="margin: 4px 0 0 16px; padding: 0;">
									<?php if ( version_compare( $wp_version, '6.7.0', '<' ) ) : ?>
										<li><?php esc_html_e( 'Your WordPress version has security vulnerabilities. Please update WordPress.', 'secuplug' ); ?></li>
									<?php endif; ?>
									<?php if ( version_compare( phpversion(), '8.2.0', '<' ) ) : ?>
										<li><?php esc_html_e( 'Your PHP version has security vulnerabilities. Please upgrade PHP.', 'secuplug' ); ?></li>
									<?php endif; ?>
								</ul>
							</div>
						</div>
					<?php else : ?>
						<div class="fynd-sf-status-alert fynd-sf-status-alert-success">
							<span class="dashicons dashicons-yes-alt"></span>
							<span class="fynd-sf-alert-text"><?php esc_html_e( 'Everything is running smoothly. No security issues have been detected.', 'secuplug' ); ?></span>
						</div>
					<?php endif; ?>

					<div class="fynd-sf-card-actions">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=securefusion-security-log' ) ); ?>" class="fynd-sf-btn fynd-sf-btn-primary">
							<span class="dashicons dashicons-list-view"></span>
							<?php esc_html_e( 'View Security Log', 'secuplug' ); ?>
						</a>
					</div>
				</div>
				<?php
				$settings_link = \add_query_arg(
					array(
						'page' => 'securefusion-settings',
					),
					$this->admin_link
				);

				$this->add_status_box(
					esc_html__( 'XML-RPC FULL PROTECTION', 'secuplug' ),
					$disable_all_xmlrpc,
					esc_html__( 'Blocks all remote requests. Most commonly used to prevent all types of remote attacks.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'XML-RPC LOGIN PROTECTION', 'secuplug' ),
					$xmlrpc_login,
					esc_html__( 'Blocks remote login requests. Most commonly used to prevent brute force login attempts.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'XML-RPC PINGBACK PROTECTION', 'secuplug' ),
					$xmlrpc_pingback,
					esc_html__( 'Blocks remote pingback requests. Most commonly used to prevent DDoS attacks.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'SELF PINGBACK PROTECTION', 'secuplug' ),
					$self_pingback,
					esc_html__( 'Blocks remote self-pingback requests. Most commonly used to prevent DDoS attacks.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'New Custom Login URL', 'secuplug' ),
					$login_url,
					esc_html__( 'Hides login url from the attackers.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'Enable HTTPS / SSL', 'secuplug' ),
					$enable_https,
					esc_html__( 'SSL automatically encrypts your privileged information data.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'Force HTTPS Login', 'secuplug' ),
					$force_login_https,
					esc_html__( 'Redirect login page protocol HTTP to HTTPS', 'secuplug' )
				);
				$this->add_status_box(
					esc_html__( 'Change Login Error', 'secuplug' ),
					$change_login_error,
					esc_html__( 'Disable default login errors and provide attackers with less than what they need.', 'secuplug' )
				);
				$this->add_status_box(
					esc_html__( 'Change Admin ID', 'secuplug' ),
					$change_admin_id,
					esc_html__( "It's not difficult to predict your Admin ID if it's set to `1`. Secure your site against simple SQL vulnerabilities.", 'secuplug' )
				);
				$this->add_status_box(
					esc_html__( 'Force HTTPS Admin', 'secuplug' ),
					$force_admin_https,
					esc_html__( 'Redirects the admin page protocol from HTTP to HTTPS', 'secuplug' )
				);
				$this->add_status_box(
					esc_html__( 'Force HTTPS Front Page', 'secuplug' ),
					$force_front_https,
					esc_html__( 'Redirects the front page protocol from HTTP to HTTPS.', 'secuplug' )
				);
				$this->add_status_box(
					esc_html__( 'Filter Bad Requests', 'secuplug' ),
					$filter_bad_requests,
					esc_html__( 'Helps secure your site against attacks like XSS, CSRF, and Code Injections.', 'secuplug' )
				);
				$this->add_status_box(
					esc_html__( 'Disable Rest API', 'secuplug' ),
					$disable_rest_api,
					esc_html__( 'Conceals sensitive information from attackers, such as Admin user IDs, user lists, and their IDs.', 'secuplug' )
				);

				$this->add_status_box(
					esc_html__( 'Settings', 'secuplug' ),
					false,
					esc_html__( 'Manage your security features', 'secuplug' ),
					[
						esc_html__( 'Go to settings', 'secuplug' ),
						$settings_link,
					]
				);
				?>
			</section>
		</div>
		<?php
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
	 * Get settings HTML.
	 *
	 * @return void
	 */
	public function get_settings_html() {
		$ssl_cond  = empty( get_transient( 'securefusion_ssl_cert_data' ) );
		$ssl_error = esc_html__( 'Only use this if you have an SSL certificate; otherwise, it cannot be enabled.', 'secuplug' );

		if ( $ssl_cond ) {
			$ssl_error = '<p style="color:red">' .
					esc_html__( 'ERROR! You don’t have any valid SSL certificate. ', 'secuplug' ) .
				'</p>' .

				'<p>' .

					'<b>' . esc_html__( 'Free SSL certificate providers', 'secuplug' ) . '</b> : ' .

					'<a href="https://letsencrypt.org/" target="_blank">' .
					esc_html__( 'Let’s Encrypt', 'secuplug' ) .
					'</a>' .

					' or <a href="https://www.cloudflare.com/" target="_blank">' .
					esc_html__( 'Cloudflare', 'secuplug' ) .
					'</a>' .

					'<br />' .

					'<b>Paid SSL certificate providers</b> : ' .

					'<a href="https://sectigo.com/" target="_blank">' .
					esc_html__( 'Comodo / Sectigo', 'secuplug' ) .
					'</a>' .

					' or <a href="https://www.digicert.com" target="_blank">' .
					esc_html__( 'Digicert', 'secuplug' ) .
					'</a>' .

				'</p>';
		}

		?>
		<div class="wrap fynd-sf-settings">

			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'SecureFusion Security Settings', 'secuplug' ); ?></h1>

			<?php
			$this->render_header(
				esc_html__( 'SecureFusion Security Settings', 'secuplug' ),
				esc_html__( 'You can manage your WordPress security settings.', 'secuplug' )
			);
			?>
			<?php
			if ( $this->settings_page->is_ready() ) {
				?>
				<h2 class="nav-tab-wrapper">
					<a href="#xmlrpc" class="nav-tab">
						<span class="dashicons dashicons-networking"></span>
						<?php esc_html_e( 'XMLRPC', 'secuplug' ); ?>
					</a>
					<a href="#login" class="nav-tab">
						<span class="dashicons dashicons-admin-users"></span>
						<?php esc_html_e( 'Login', 'secuplug' ); ?>
					</a>
					<a href="#ssl" class="nav-tab">
						<span class="dashicons dashicons-admin-network"></span>
						<?php esc_html_e( 'SSL', 'secuplug' ); ?>
					</a>
					<a href="#active_guard" class="nav-tab">
						<span class="dashicons dashicons-shield"></span>
						<?php esc_html_e( 'Active Guard', 'secuplug' ); ?>
					</a>
					<a href="#security_policies" class="nav-tab">
						<span class="dashicons dashicons-clipboard"></span>
						<?php esc_html_e( 'Security Policies', 'secuplug' ); ?>
					</a>
					<a href="#advanced" class="nav-tab">
						<span class="dashicons dashicons-warning"></span>
						<?php esc_html_e( 'Advanced', 'secuplug' ); ?>
					</a>
				</h2>
				<div class="content-box">
					<?php $this->settings_page->form_start(); ?>
					<div class="content-tab-wrapper">
						<div class="tab-content" id="fynd-sf-xmlrpc">
							<?php $this->settings_page->run_section( 'xmlrpc_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="fynd-sf-login">
							<?php $this->settings_page->run_section( 'login_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="fynd-sf-ssl">
							<?php $this->settings_page->run_section( 'ssl_settings' ); ?>
							<div class="fynd-sf-tab-notice fynd-sf-tab-notice-error">
								<p><?php echo wp_kses_post( $ssl_error ); ?></p>
							</div>
						</div>
						<div class="tab-content hidden" id="fynd-sf-active_guard">
							<?php $this->settings_page->run_section( 'active_guard_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="fynd-sf-security_policies">
							<?php $this->settings_page->run_section( 'security_policies_settings' ); ?>
						</div>
						<div class="tab-content hidden" id="fynd-sf-advanced">
							<?php $this->settings_page->run_section( 'advanced_settings' ); ?>
							<div class="fynd-sf-tab-notice fynd-sf-tab-notice-error">
								<p>
									<?php esc_html_e( "If you don't have experience in cybersecurity or regular expressions, do not modify these areas.", 'secuplug' ); ?>
								</p>
							</div>
						</div>
					<?php
					$submit_text = esc_html__( 'Save Settings', 'secuplug' );
					?>
					<p class="submit">
						<input type="submit" name="submit" id="submit" class="fynd-sf-btn fynd-sf-btn-primary" value="<?php echo esc_attr( $submit_text ); ?>" style="height: auto; padding: 8px 20px; font-size: 14px;">
					</p>
					</form>
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

		$ssl_cond = ! empty( get_transient( 'securefusion_ssl_cert_data' ) );

		$conf = [
			[
				// Section info.
				'name'  => 'xmlrpc_settings',
				'title' => esc_html__( 'XML-RPC SETTINGS', 'secuplug' ),
				'desc'  => esc_html__( 'You can prevent XML-RPC attacks.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc',
						'default' => '0',
						'label'   => esc_html__( 'Disable All XML-RPC Services', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'Enabling this option will completely disable XML-RPC functionality, which can prevent certain types of attacks but may affect integrations with other systems and applications.', 'secuplug' ) . '</p>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc_user_login',
						'default' => '0',
						'label'   => esc_html__( 'Disable XML-RPC Login Service', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'If checked, this will disable login capability through XML-RPC. This helps prevent brute force attacks but may affect some legitimate XML-RPC uses.', 'secuplug' ) . '</p>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc_pingback',
						'default' => '0',
						'label'   => esc_html__( 'Disable XML-RPC Pingback Service', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'Pingbacks can be abused for DDoS attacks. Disabling this will prevent pingbacks, improving security.', 'secuplug' ) . '</p>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_self_pingback',
						'default' => '0',
						'label'   => esc_html__( 'Disable Self Pingback Service', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
						'after'   => '<p class="description">' . esc_html__( 'WordPress generates pingbacks to its own posts by default. This option disables such self-pingbacks.', 'secuplug' ) . '</p>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'active_guard_settings',
				'title' => esc_html__( 'ACTIVE GUARD SETTINGS', 'secuplug' ),
				'desc'  => esc_html__( 'Active guard and firewall settings. (Beta)', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'filter_bad_requests',
						'default' => '0',
						'label'   => esc_html__( 'Filter Bad Requests', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_rest_api',
						'default' => '0',
						'label'   => esc_html__( 'Disable Rest API for Visitors', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'hide_versions',
						'default' => '0',
						'label'   => esc_html__( 'Hide apache and PHP version', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'bad_bots',
						'default' => '0',
						'label'   => esc_html__( 'Block bad bots', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'http_headers',
						'default' => '0',
						'label'   => esc_html__( 'Add HTTP Headers for Browser Security', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'No', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Yes', 'secuplug' ),
							],
						],
					],
					[
						'type'   => 'text_input',
						'name'   => 'max_payload_size',
						'label'  => esc_html__( 'Max Payload Size (Bytes)', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' bytes', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Maximum allowed request payload size (excluding file uploads). IPs exceeding this limit will be permanently blocked. Set 0 to disable. Default: 4096.', 'secuplug' ) . '</span>',
					],
				],

			],
			[
				// Section info.
				'name'  => 'security_policies_settings',
				'title' => esc_html__( 'SECURITY POLICIES', 'secuplug' ),
				'desc'  => esc_html__( 'Content Security Policy (CSP) configurations.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_style',
						'default' => $this->default_settings['enable_csp_style'] ?? '0',
						'label'   => esc_html__( 'Enable CSP Style Sources', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_style_sources',
						'label'             => esc_html__( 'CSP Allowed Style Sources', 'secuplug' ),
						'placeholder'       => 'fonts.googleapis.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'unsafe-inline\'">unsafe-inline</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://fonts.googleapis.com">Google Fonts</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdnjs.cloudflare.com">Cloudflare CDN</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdn.jsdelivr.net">jsDelivr</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://use.fontawesome.com">FontAwesome</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_script',
						'default' => $this->default_settings['enable_csp_script'] ?? '0',
						'label'   => esc_html__( 'Enable CSP Script Sources', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_script_sources',
						'label'             => esc_html__( 'CSP Allowed Script Sources', 'secuplug' ),
						'placeholder'       => 'googletagmanager.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'unsafe-inline\'">unsafe-inline</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.googletagmanager.com">Google Tag Manager</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google-analytics.com">GA4</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google.com/recaptcha">reCAPTCHA</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://js.stripe.com">Stripe</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdn.jsdelivr.net">jsDelivr</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://unpkg.com">UNPKG</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_font',
						'default' => $this->default_settings['enable_csp_font'] ?? '0',
						'label'   => esc_html__( 'Enable CSP Font Sources', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_font_sources',
						'label'             => esc_html__( 'CSP Allowed Font Sources', 'secuplug' ),
						'placeholder'       => 'fonts.gstatic.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="data:">data:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://fonts.gstatic.com">Google Fonts</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdnjs.cloudflare.com">Cloudflare CDN</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://use.fontawesome.com">FontAwesome</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdn.jsdelivr.net">jsDelivr</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_frame',
						'default' => $this->default_settings['enable_csp_frame'] ?? '0',
						'label'   => esc_html__( 'Enable CSP Frame Sources', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_frame_sources',
						'label'             => esc_html__( 'CSP Frame Sources (iframe embed)', 'secuplug' ),
						'placeholder'       => 'youtube.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.youtube.com">YouTube</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google.com">Google</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://maps.google.com">Google Maps</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://player.vimeo.com">Vimeo</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://js.stripe.com">Stripe</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google.com/recaptcha">reCAPTCHA</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_worker',
						'default' => $this->default_settings['enable_csp_worker'] ?? '0',
						'label'   => esc_html__( 'Enable CSP Worker Sources', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_worker_sources',
						'label'             => esc_html__( 'CSP Worker Sources', 'secuplug' ),
						'placeholder'       => 'blob:',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="blob:">blob:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="data:">data:</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_img',
						'default' => $this->default_settings['enable_csp_img'] ?? '0',
						'label'   => esc_html__( 'Enable CSP Image Sources', 'secuplug' ),
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'              => 'taginput',
						'name'              => 'csp_allowed_img_sources',
						'label'             => esc_html__( 'CSP Image Sources', 'secuplug' ),
						'placeholder'       => 'example.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="data:">data:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https:">https:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://secure.gravatar.com">Gravatar</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://s.w.org">WordPress.org</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://i0.wp.com">Jetpack CDN</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'csp_upgrade_insecure_requests',
						'default' => $this->default_settings['csp_upgrade_insecure_requests'] ?? '0',
						'label'   => esc_html__( 'Upgrade Insecure Requests', 'secuplug' ),
						'after'   => '<p class="description">' . esc_html__( 'Instructs the browser to upgrade all HTTP requests to HTTPS.', 'secuplug' ) . '</p>',
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'csp_block_all_mixed_content',
						'default' => $this->default_settings['csp_block_all_mixed_content'] ?? '0',
						'label'   => esc_html__( 'Block All Mixed Content', 'secuplug' ),
						'after'   => '<p class="description">' . esc_html__( 'Prevents loading any HTTP content on an HTTPS page.', 'secuplug' ) . '</p>',
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'csp_sandbox',
						'default' => $this->default_settings['csp_sandbox'] ?? '0',
						'label'   => esc_html__( 'Sandbox', 'secuplug' ),
						'after'   => '<p class="description">' . esc_html__( 'Enables a sandbox for the requested resource similar to the iframe sandbox attribute. This can block some features of your website (like payment gateway integration). Use with caution!', 'secuplug' ) . '</p>',
						'options' => [
							[
								'value' => '0',
								'label' => esc_html__( 'Disable', 'secuplug' ),
							],
							[
								'value' => '1',
								'label' => esc_html__( 'Enable', 'secuplug' ),
							],
						],
					],
				],
			],
			[
				// Section info.
				'name'  => 'login_settings',
				'title' => esc_html__( 'LOGIN SETTINGS - BE CAREFUL!', 'secuplug' ),
				'desc'  => esc_html__( 'You can hide or secure your login page against attackers. Please save your new login url before you change it.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'   => 'text_input',
						'name'   => 'ip_time_limit',
						'label'  => esc_html__( 'Min. Wait Time', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' hour(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Minimum Wait Time After Failed Attempt', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'ip_attempt_window',
						'label'  => esc_html__( 'Attempt Tracking Window', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' minute(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Time frame to track failed login attempts', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'ip_login_limit',
						'label'  => esc_html__( 'Max. Attempt Limit', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' time(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Maximum Failed Login Attempt Limit', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'cleanup_ip_days',
						'label'  => esc_html__( 'Auto-Delete IPs: Older Than', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' day(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Delete IPs inactive for this many days (0 to disable).', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'cleanup_ip_attempts',
						'label'  => esc_html__( 'Auto-Delete IPs: Fewer Than', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' attempt(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Only delete IPs that have fewer than this many total attempts.', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'custom_login_url',
						'label'  => esc_html__( 'Custom Login Path', 'secuplug' ),
						'before' => '<span class="url-text">' . \get_home_url() . '/</span>',
						'after'  => '<span class="field-tip">/ (For exam. : hidden-login)</span>',
					],
					[
						'type'  => 'text_input',
						'name'  => 'change_login_error',
						'label' => esc_html__( 'Custom Login Error Message', 'secuplug' ),
					],
					[
						'type'   => 'text_input',
						'name'   => 'change_admin_id',
						'label'  => esc_html__( 'Your Admin ID', 'secuplug' ),
						'before' => 'Your current ID is ',
						'after'  => ' for "' . $current_user->user_login . '". ' .
							'<span class="field-tip">' .
							'	We recommend changing this field for each user one by one' .
							'</span>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'ssl_settings',
				'title' => esc_html__( 'SSL SETTINGS', 'secuplug' ),
				'desc'  => esc_html__( 'HTTPS/SSL security settings.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'enable_https',
						'default' => '',
						'label'   => esc_html__( 'HTTPS Support', 'secuplug' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'secuplug' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'secuplug' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_login_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS on login page', 'secuplug' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'secuplug' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'secuplug' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_admin_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS on admin page', 'secuplug' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'secuplug' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'secuplug' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_front_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS on front page', 'secuplug' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'secuplug' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'secuplug' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'force_site_https',
						'default' => '',
						'label'   => esc_html__( 'Force HTTPS site-wide', 'secuplug' ),
						'options' => [
							[
								'label' => esc_html__( 'Disabled', 'secuplug' ),
								'value' => '',
							],
							[
								'label' => esc_html__( 'Enabled', 'secuplug' ),
								'value' => 'https',
							],
						],
					],
				],
			],
			[
				// Section info.
				'name'  => 'advanced_settings',
				'title' => esc_html__( 'ADVANCED SETTINGS', 'secuplug' ),
				'desc'  => esc_html__( 'Advanced security settings. `Filter Bad Requests` must be active for it to work.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'              => 'taginput',
						'name'              => 'cookie_patterns',
						'label'             => esc_html__( 'Cookie Regex Patterns', 'secuplug' ),
						'placeholder'       => '[a-z0-9]+',
						'field_type'        => 'regex',
						'sanitize_callback' => function ( $value ) {
							// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
							return @preg_match( '/' . $value . '/', '' ) !== false;
						},
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="[a-z0-9]+">Alphanumeric</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="[a-zA-Z0-9_\-]+">Safe Chars</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="[^\x27\x22\x3c\x3e\x5c]+">No Special Chars</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="^PHPSESSID$">PHPSESSID</button>',
					],
					[
						'type'              => 'taginput',
						'name'              => 'request_patterns',
						'label'             => esc_html__( 'Get/Post Request Regex Patterns', 'secuplug' ),
						'placeholder'       => '(union|select|insert)\s+\w+',
						'field_type'        => 'regex',
						'sanitize_callback' => function ( $value ) {
							// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
							return @preg_match( '/' . $value . '/', '' ) !== false;
						},
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="@@[\w\.\$]+">SQL Vars</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="(union|select|insert)\s+">SQL Keywords</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="base64_\w+\(">Base64 Func</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="<script[^>]*>">XSS Script Tag</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\bon\w+\s*=\s*[\x27\x22]">XSS Event Handler</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\.\.[\\/]">LFI Traversal</button>',
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
			// Only show the welcome notice on the main WordPress Dashboard page.
			$screen = get_current_screen();
			if ( $screen && $screen->id === 'dashboard' ) {
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
		\wp_enqueue_style( 'securefusion-admin-theme-main-css', \plugins_url( 'assets/css/admin.css', SECUREFUSION_BASENAME ), array(), SECUREFUSION_VERSION );
		\wp_enqueue_script( 'securefusion-admin-js', \plugins_url( 'assets/js/admin.js', SECUREFUSION_BASENAME ), array(), SECUREFUSION_VERSION, true );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-state-changing query parameter check.
		if ( isset( $_GET['page'] ) && 'secuplug' === $_GET['page'] ) {
			\wp_enqueue_script( 'securefusion-chartjs', \plugins_url( 'assets/lib/chartjs/chart.umd.min.js', SECUREFUSION_BASENAME ), array(), SECUREFUSION_VERSION, true );
			\wp_enqueue_script( 'securefusion-dashboard-js', \plugins_url( 'assets/js/dashboard.js', SECUREFUSION_BASENAME ), array( 'securefusion-chartjs' ), SECUREFUSION_VERSION, true );

			$chart_data = $this->get_dashboard_chart_data();
			\wp_localize_script( 'securefusion-dashboard-js', 'securefusionChartData', $chart_data );
		}
	}


	/**
	 * Prepare the security log statistics for Chart.js rendering.
	 *
	 * @return array Multi-dimensional array of chart data.
	 */
	protected function get_dashboard_chart_data() {
		$db = new BruteForceDB();

		// 1. Daily Stats (Last 30 days)
		$daily_raw    = $db->get_daily_attempts_stats( 30 );
		$daily_labels = array();
		for ( $i = 29; $i >= 0; $i-- ) {
			$timestamp      = time() - ( $i * DAY_IN_SECONDS );
			$daily_labels[] = function_exists( 'wp_date' ) ? wp_date( 'Y-m-d', $timestamp ) : gmdate( 'Y-m-d', $timestamp );
		}

		// Initialize datasets for each type.
		$types = array(
			BruteForceDB::TYPE_FAILED_LOGIN,
			BruteForceDB::TYPE_BAD_REQUEST,
			BruteForceDB::TYPE_BAD_COOKIE,
			BruteForceDB::TYPE_BAD_BOT,
			BruteForceDB::TYPE_BAD_QUERY,
			BruteForceDB::TYPE_BLOCKED,
		);

		$daily_data = array();
		foreach ( $types as $type ) {
			$daily_data[ $type ] = array_fill( 0, 30, 0 );
		}

		if ( is_array( $daily_raw ) ) {
			foreach ( $daily_raw as $row ) {
				$label_index = array_search( $row->date_str, $daily_labels, true );
				if ( false !== $label_index && isset( $daily_data[ $row->log_type ] ) ) {
					$daily_data[ $row->log_type ][ $label_index ] = (int) $row->count;
				}
			}
		}

		// 2. Monthly Stats (Last 12 months)
		$monthly_raw    = $db->get_monthly_attempts_stats( 12 );
		$monthly_labels = array();
		for ( $i = 11; $i >= 0; $i-- ) {
			$timestamp        = strtotime( gmdate( 'Y-m-01' ) . " -{$i} months" );
			$monthly_labels[] = function_exists( 'wp_date' ) ? wp_date( 'Y-m', $timestamp ) : gmdate( 'Y-m', $timestamp );
		}

		$monthly_data = array();
		foreach ( $types as $type ) {
			$monthly_data[ $type ] = array_fill( 0, 12, 0 );
		}

		if ( is_array( $monthly_raw ) ) {
			foreach ( $monthly_raw as $row ) {
				$label_index = array_search( $row->month_str, $monthly_labels, true );
				if ( false !== $label_index && isset( $monthly_data[ $row->log_type ] ) ) {
					$monthly_data[ $row->log_type ][ $label_index ] = (int) $row->count;
				}
			}
		}

		// Human readable labels for types.
		$type_labels = array(
			BruteForceDB::TYPE_FAILED_LOGIN => __( 'Failed Login', 'secuplug' ),
			BruteForceDB::TYPE_BAD_REQUEST  => __( 'Bad Request', 'secuplug' ),
			BruteForceDB::TYPE_BAD_COOKIE   => __( 'Bad Cookie', 'secuplug' ),
			BruteForceDB::TYPE_BAD_BOT      => __( 'Bad Bot', 'secuplug' ),
			BruteForceDB::TYPE_BAD_QUERY    => __( 'Bad Query', 'secuplug' ),
			BruteForceDB::TYPE_BLOCKED      => __( 'Blocked Request', 'secuplug' ),
		);

		return array(
			'daily'       => array(
				'labels'   => $daily_labels,
				'datasets' => $daily_data,
			),
			'monthly'     => array(
				'labels'   => $monthly_labels,
				'datasets' => $monthly_data,
			),
			'type_labels' => $type_labels,
		);
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
		$card_class = 'dashboard-item';
		if ( $status !== false ) {
			$card_class .= $status ? ' fynd-sf-status-enabled' : ' fynd-sf-status-disabled';
		} else {
			$card_class .= ' fynd-sf-status-neutral';
		}
		?>
		<div class="<?php echo esc_attr( $card_class ); ?>">
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
				<div class="status-wrapper" style="margin-top: 10px;">
					<span class="status <?php echo esc_attr( $status ? 'enabled' : 'disabled' ); ?>">
						<?php $status ? esc_html_e( 'enabled', 'secuplug' ) : esc_html_e( 'disabled', 'secuplug' ); ?>
					</span>
				</div>
				<?php
			endif;

			if ( ! empty( $button ) ) :
				?>
				<p style="margin-top: 15px; margin-bottom: 0;">
					<a href="<?php echo esc_attr( $button[1] ); ?>" class="fynd-sf-btn fynd-sf-btn-secondary">
						<?php echo esc_html( $button[0] ); ?>
					</a>
				</p>
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
			'secuplug'
		);

		if ( $this->settings_page instanceof Wasp ) {
			$this->settings_page->wp_form_init( [ $this, 'load' ] );

			// Enable reset feature with factory defaults.
			$this->settings_page->enable_reset(
				[
					'confirm_message' => esc_html__( 'Are you sure you want to reset this field to its default value?', 'secuplug' ),
					'button_text'     => esc_html__( 'Reset', 'secuplug' ),
					'button_class'    => 'fynd-sf-btn fynd-sf-btn-secondary',
					'wrapper_class'   => 'wasp-reset-wrapper',
				],
				$this->default_settings
			);
		}

		\add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		\add_action( 'current_screen', array( $this, 'admin_menu_screen' ) );
	}
}
