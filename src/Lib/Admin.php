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
	 * Get dashboard HTML.
	 *
	 * @return void
	 */
	public function get_dashboard_html() {
		global $wp_version;

		$disable_all_xmlrpc = $this->get_settings( 'disable_xmlrpc' );
		$force_all_https    = $this->get_settings( 'force_site_https' );

		$enable_https = $this->get_settings( 'enable_https' );

		// login.
		$login_url          = $this->get_settings( 'custom_login_url' );
		$change_login_error = empty( $this->get_settings( 'change_login_error' ) ) ? 0 : 1;

		// firewall.
		$filter_bad_requests = $this->get_settings( 'filter_bad_requests' );
		$disable_rest_api    = $this->get_settings( 'disable_rest_api' );

		if ( $disable_all_xmlrpc ) {
			$xmlrpc_login    = 1;
			$xmlrpc_pingback = 1;
			$self_pingback   = 1;
		} else {
			// Gets xml-rpc settings when all xml-rpc services are disabled.
			$xmlrpc_login    = $this->get_settings( 'disable_xmlrpc_user_login' );
			$xmlrpc_pingback = $this->get_settings( 'disable_xmlrpc_pingback' );
			$self_pingback   = $this->get_settings( 'disable_self_pingback' );
		}

		if ( $force_all_https ) {
			$force_front_https = 1;
			$force_admin_https = 1;
			$force_login_https = 1;
		} else {
			$force_front_https = $this->get_settings( 'force_front_https' );
			$force_admin_https = $this->get_settings( 'force_admin_https' );
			$force_login_https = $this->get_settings( 'force_login_https' );
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

				$first_user = get_userdata( 1 );

				if ( $first_user && in_array( 'administrator', (array) $first_user->roles, true ) ) {
					ob_start();
					$this->get_account_transition_html();
					$account_guide = ob_get_clean();
					$this->add_status_box(
						esc_html__( 'Administrator account review', 'secuplug' ),
						false,
						esc_html__( 'An administrator on this site uses ID 1. This alone is not a vulnerability. Review the account before deciding whether to replace it.', 'secuplug' ),
						[],
						$account_guide
					);
				}

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
					esc_html__( 'Filter malicious requests', 'secuplug' ),
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
		$has_ssl     = is_array( get_transient( 'securefusion_ssl_cert_data' ) );
		$sub_site    = $this->layered && 'site' === $this->context;
		$customized  = $this->customized_counts();
		$total       = array_sum( $customized );
		$allowed_ssl = array(
			'a'      => array(
				'href'   => array(),
				'target' => array(),
				'rel'    => array(),
			),
			'strong' => array(),
		);

		if ( $has_ssl ) {
			$ssl_notice = esc_html__( 'Turn these on only after your site opens without warnings at https://.', 'secuplug' );
		} else {
			$ssl_notice = '<strong>' . esc_html__( 'No valid SSL certificate was found for this site, so HTTPS options cannot be turned on.', 'secuplug' ) . '</strong> ' .
				esc_html__( 'Many hosts install a free certificate for you. Free providers:', 'secuplug' ) . ' ' .
				'<a href="https://letsencrypt.org/" target="_blank" rel="noopener">Let&#8217;s Encrypt</a>, ' .
				'<a href="https://www.cloudflare.com/" target="_blank" rel="noopener">Cloudflare</a>. ' .
				esc_html__( 'Paid providers:', 'secuplug' ) . ' ' .
				'<a href="https://sectigo.com/" target="_blank" rel="noopener">Sectigo</a>, ' .
				'<a href="https://www.digicert.com/" target="_blank" rel="noopener">DigiCert</a>.';
		}

		$tabs = array(
			'xmlrpc'            => array( 'xmlrpc_settings', esc_html__( 'XML-RPC', 'secuplug' ) ),
			'login'             => array( 'login_settings', esc_html__( 'Login', 'secuplug' ) ),
			'ssl'               => array( 'ssl_settings', esc_html__( 'HTTPS', 'secuplug' ) ),
			'active_guard'      => array( 'active_guard_settings', esc_html__( 'Firewall', 'secuplug' ) ),
			'security_policies' => array( 'security_policies_settings', esc_html__( 'Content Security Policy', 'secuplug' ) ),
			'recaptcha'         => array( 'recaptcha_settings', esc_html__( 'reCAPTCHA', 'secuplug' ) ),
			'advanced'          => array( 'advanced_settings', esc_html__( 'Advanced', 'secuplug' ) ),
		);

		if ( 'network' === $this->context ) {
			$tabs['network_policy'] = array( 'network_policy_settings', esc_html__( 'Network policy', 'secuplug' ) );
		}

		?>
		<div class="wrap fynd-sf-settings fsf">

			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'SecureFusion settings', 'secuplug' ); ?></h1>

			<?php
			if ( 'network' === $this->context ) {
				$this->render_header(
					esc_html__( 'Network security settings', 'secuplug' ),
					esc_html__( 'Defaults for every site in the network.', 'secuplug' )
				);
			} else {
				$this->render_header(
					esc_html__( 'Security settings', 'secuplug' ),
					esc_html__( 'Choose which protections run on this site.', 'secuplug' )
				);
			}

			if ( $sub_site ) {
				?>
				<div class="fsf-context" role="note">
					<span class="fsf-context__title"><?php esc_html_e( 'This site follows the network settings.', 'secuplug' ); ?></span>
					<span class="fsf-context__text">
						<?php
						if ( $total > 0 ) {
							/* translators: %s: number of settings customized for this site. */
							echo esc_html( sprintf( _n( '%s setting is customized for this site.', '%s settings are customized for this site.', $total, 'secuplug' ), number_format_i18n( $total ) ) ) . ' ';
						}
						esc_html_e( 'Change a value to customize it for this site only. "Use network setting" brings the network value back.', 'secuplug' );
						?>
					</span>
				</div>
				<?php
			}

			if ( $this->settings_page->is_ready() ) {
				?>
				<div class="fsf-panel">
					<h2 class="nav-tab-wrapper fsf-tabs">
						<?php foreach ( $tabs as $tab_id => $tab ) : ?>
							<a href="#<?php echo esc_attr( $tab_id ); ?>" class="nav-tab">
								<?php echo esc_html( $tab[1] ); ?>
								<?php if ( ! empty( $customized[ $tab[0] ] ) ) : ?>
									<span class="fsf-tab__count" title="<?php esc_attr_e( 'Customized for this site', 'secuplug' ); ?>">
										<?php echo esc_html( number_format_i18n( $customized[ $tab[0] ] ) ); ?>
										<span class="screen-reader-text"><?php esc_html_e( 'customized for this site', 'secuplug' ); ?></span>
									</span>
								<?php endif; ?>
							</a>
						<?php endforeach; ?>
					</h2>

					<div class="content-box" data-fsf-unsaved>
						<?php $this->settings_page->form_start(); ?>
						<div class="content-tab-wrapper">
							<?php foreach ( $tabs as $tab_id => $tab ) : ?>
								<div class="tab-content hidden" id="fynd-sf-<?php echo esc_attr( $tab_id ); ?>">
									<?php $this->settings_page->run_section( $tab[0] ); ?>

									<?php if ( 'ssl' === $tab_id ) : ?>
										<div class="<?php echo esc_attr( $has_ssl ? 'fynd-sf-tab-notice' : 'fynd-sf-tab-notice fynd-sf-tab-notice-error' ); ?>">
											<p><?php echo wp_kses( $ssl_notice, $allowed_ssl ); ?></p>
										</div>
									<?php elseif ( 'advanced' === $tab_id ) : ?>
										<div class="fynd-sf-tab-notice fynd-sf-tab-notice-error">
											<p><?php esc_html_e( 'Wrong patterns can block normal visitors or let attacks through. Change them only if you know regular expressions.', 'secuplug' ); ?></p>
										</div>
									<?php endif; ?>
								</div>
							<?php endforeach; ?>
						</div>

						<div class="fsf-foot">
							<button type="submit" name="submit" id="submit" class="fsf-btn fsf-btn--primary"><?php esc_html_e( 'Save settings', 'secuplug' ); ?></button>
							<span class="fsf-foot__hint">
								<?php
								if ( $sub_site ) {
									esc_html_e( 'Saves every tab. Settings that follow the network are not stored for this site.', 'secuplug' );
								} else {
									esc_html_e( 'Saves every tab.', 'secuplug' );
								}
								?>
							</span>
						</div>
						</form>
					</div>
				</div>
				<?php
			}
			?>
		</div>
		<?php
	}


	/**
	 * Number of settings this site customizes, per settings section.
	 *
	 * Only meaningful on a sub-site of a network; empty otherwise. Bounded by the
	 * number of settings (a few dozen keys).
	 *
	 * @return array<string,int> Section name => count.
	 */
	protected function customized_counts() {
		$counts = array();

		if ( ! $this->layered || 'site' !== $this->context ) {
			return $counts;
		}

		$own = array_diff( array_keys( Settings::site_values() ), Settings::NETWORK_ONLY );

		foreach ( $this->section_keys as $section => $keys ) {
			$counts[ $section ] = count( array_intersect( $keys, $own ) );
		}

		return $counts;
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
			[
				// Section info.
				'name'  => 'xmlrpc_settings',
				'title' => esc_html__( 'XML-RPC', 'secuplug' ),
				'desc'  => esc_html__( 'XML-RPC is an older remote publishing interface. Attackers use it to try many passwords in a single request. Most sites do not need it.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc',
						'default' => '0',
						'label'   => esc_html__( 'Turn off XML-RPC completely', 'secuplug' ),
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
						'after'   => '<span class="description">' . esc_html__( 'Blocks every XML-RPC request. Apps that publish through XML-RPC (older mobile apps, some Jetpack features) stop working.', 'secuplug' ) . '</span>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc_user_login',
						'default' => '0',
						'label'   => esc_html__( 'Block logins through XML-RPC', 'secuplug' ),
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
						'after'   => '<span class="description">' . esc_html__( 'Stops password guessing through XML-RPC. Leave this on unless an app signs in to your site through XML-RPC.', 'secuplug' ) . '</span>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_xmlrpc_pingback',
						'default' => '0',
						'label'   => esc_html__( 'Block pingbacks', 'secuplug' ),
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
						'after'   => '<span class="description">' . esc_html__( 'Attackers can use pingbacks to make your site send traffic floods to other sites.', 'secuplug' ) . '</span>',
					],
					[
						'type'    => 'radio',
						'name'    => 'disable_self_pingback',
						'default' => '0',
						'label'   => esc_html__( 'Block pingbacks to your own posts', 'secuplug' ),
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
						'after'   => '<span class="description">' . esc_html__( 'WordPress pings your own posts when you link between them. This only adds noise to your comments.', 'secuplug' ) . '</span>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'active_guard_settings',
				'title' => esc_html__( 'Firewall', 'secuplug' ),
				'desc'  => esc_html__( 'Checks requests before WordPress handles them and hides details that attackers look for. The request filter is in beta.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'filter_bad_requests',
						'default' => '0',
						'label'   => esc_html__( 'Filter malicious requests', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Blocks requests that contain common attack patterns such as code injection and cross-site scripting. The patterns are on the Advanced tab.', 'secuplug' ) . '</span>',
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
						'label'   => esc_html__( 'Close the REST API to visitors', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Visitors who are not logged in cannot read posts, pages, users or settings through /wp-json/wp/v2/. The API index and the endpoints of other plugins stay open.', 'secuplug' ) . '</span>',
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
						'name'    => 'hide_usernames',
						'default' => '1',
						'label'   => esc_html__( 'Hide usernames from visitors', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Stops the common ways to find login names: ?author=1 links, the REST users list, administrators in the users sitemap and oEmbed author data. Author pages keep working.', 'secuplug' ) . '</span>',
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
						'label'   => esc_html__( 'Hide server and PHP versions', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Removes the Server and X-Powered-By response headers that reveal software versions.', 'secuplug' ) . '</span>',
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
						'after'   => '<span class="description">' . esc_html__( 'Blocks requests whose user agent matches the bad bot list (by default libwww-perl).', 'secuplug' ) . '</span>',
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
						'label'   => esc_html__( 'Send browser security headers', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Sends X-Frame-Options, X-Content-Type-Options, Referrer-Policy and HSTS (2 years). HSTS makes browsers refuse plain HTTP for your domain, so turn this on only if HTTPS works on your site.', 'secuplug' ) . '</span>',
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
						'name'    => 'enable_coop',
						'default' => '0',
						'label'   => esc_html__( 'Isolate pages from other windows (COOP)', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Sends Cross-Origin-Opener-Policy: same-origin. This blocks some cross-site leaks but breaks sign-in pop-ups such as "Sign in with Google". Leave it off if you use them.', 'secuplug' ) . '</span>',
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
						'name'    => 'enable_hsts_subdomains',
						'default' => '0',
						'label'   => esc_html__( 'HSTS: include subdomains', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Tells browsers to use HTTPS on every subdomain too. Turn this on only if all your subdomains work over HTTPS.', 'secuplug' ) . '</span>',
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
						'name'    => 'enable_hsts_preload',
						'default' => '0',
						'label'   => esc_html__( 'HSTS: allow preloading', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Adds the preload directive. Once your domain is on the browser preload lists, removal takes months and the site must stay HTTPS-only.', 'secuplug' ) . '</span>',
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
						'label'  => esc_html__( 'Maximum request size', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' bytes', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Requests with a larger body (file uploads excluded) are rejected and their IP is blocked permanently. 0 turns the check off. Default: 4096.', 'secuplug' ) . '</span>',
					],
				],

			],
			[
				// Section info.
				'name'  => 'security_policies_settings',
				'title' => esc_html__( 'Content Security Policy', 'secuplug' ),
				'desc'  => esc_html__( 'Tells browsers which sources may load styles, scripts, fonts, images and frames on your pages. Needs "Send browser security headers" on the Firewall tab. Test a policy in report-only mode before you enforce it.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_style',
						'default' => $this->default_settings['enable_csp_style'] ?? '0',
						'label'   => esc_html__( 'Limit style sources', 'secuplug' ),
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
						'label'             => esc_html__( 'Allowed style sources', 'secuplug' ),
						'placeholder'       => 'fonts.googleapis.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'unsafe-inline\'">unsafe-inline</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://fonts.googleapis.com">Google Fonts</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdnjs.cloudflare.com">Cloudflare CDN</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdn.jsdelivr.net">jsDelivr</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://use.fontawesome.com">FontAwesome</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_script',
						'default' => $this->default_settings['enable_csp_script'] ?? '0',
						'label'   => esc_html__( 'Limit script sources', 'secuplug' ),
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
						'label'             => esc_html__( 'Allowed script sources', 'secuplug' ),
						'placeholder'       => 'googletagmanager.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'unsafe-inline\'">unsafe-inline</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.googletagmanager.com">Google Tag Manager</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google-analytics.com">GA4</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google.com/recaptcha">reCAPTCHA</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://js.stripe.com">Stripe</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdn.jsdelivr.net">jsDelivr</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://unpkg.com">UNPKG</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_font',
						'default' => $this->default_settings['enable_csp_font'] ?? '0',
						'label'   => esc_html__( 'Limit font sources', 'secuplug' ),
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
						'label'             => esc_html__( 'Allowed font sources', 'secuplug' ),
						'placeholder'       => 'fonts.gstatic.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="data:">data:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://fonts.gstatic.com">Google Fonts</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdnjs.cloudflare.com">Cloudflare CDN</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://use.fontawesome.com">FontAwesome</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://cdn.jsdelivr.net">jsDelivr</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_frame',
						'default' => $this->default_settings['enable_csp_frame'] ?? '0',
						'label'   => esc_html__( 'Limit frame sources (embeds)', 'secuplug' ),
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
						'label'             => esc_html__( 'Allowed frame sources', 'secuplug' ),
						'placeholder'       => 'youtube.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.youtube.com">YouTube</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google.com">Google</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://maps.google.com">Google Maps</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://player.vimeo.com">Vimeo</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://js.stripe.com">Stripe</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google.com/recaptcha">reCAPTCHA</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_worker',
						'default' => $this->default_settings['enable_csp_worker'] ?? '0',
						'label'   => esc_html__( 'Limit worker sources', 'secuplug' ),
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
						'label'             => esc_html__( 'Allowed worker sources', 'secuplug' ),
						'placeholder'       => 'blob:',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="blob:">blob:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="data:">data:</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_img',
						'default' => $this->default_settings['enable_csp_img'] ?? '0',
						'label'   => esc_html__( 'Limit image sources', 'secuplug' ),
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
						'label'             => esc_html__( 'Allowed image sources', 'secuplug' ),
						'placeholder'       => 'example.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="data:">data:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https:">https:</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://secure.gravatar.com">Gravatar</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://s.w.org">WordPress.org</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://i0.wp.com">Jetpack CDN</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'csp_upgrade_insecure_requests',
						'default' => $this->default_settings['csp_upgrade_insecure_requests'] ?? '0',
						'label'   => esc_html__( 'Upgrade HTTP requests to HTTPS', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Browsers load every http:// resource on your pages over https:// instead.', 'secuplug' ) . '</span>',
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
						'label'   => esc_html__( 'Block mixed content', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Browsers refuse to load http:// resources on https:// pages.', 'secuplug' ) . '</span>',
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
						'label'   => esc_html__( 'Sandbox pages', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Applies the restrictions of a sandboxed iframe to your pages. This breaks forms, pop-ups and payment gateways on most sites. Use it only if you know you need it.', 'secuplug' ) . '</span>',
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
						'name'    => 'enable_csp_connect',
						'default' => $this->default_settings['enable_csp_connect'] ?? '0',
						'label'   => esc_html__( 'Limit connection sources', 'secuplug' ),
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
						'name'              => 'csp_allowed_connect_sources',
						'label'             => esc_html__( 'Allowed connection sources', 'secuplug' ),
						'placeholder'       => 'google-analytics.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.google-analytics.com">GA4</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://*.google-analytics.com">GA4 Wildcard</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://*.googletagmanager.com">Google Tag Manager</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://stats.g.doubleclick.net">DoubleClick</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://api.stripe.com">Stripe API</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://*.wordpress.org">WordPress.org</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_media',
						'default' => $this->default_settings['enable_csp_media'] ?? '0',
						'label'   => esc_html__( 'Limit audio and video sources', 'secuplug' ),
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
						'name'              => 'csp_allowed_media_sources',
						'label'             => esc_html__( 'Allowed media sources', 'secuplug' ),
						'placeholder'       => 'youtube.com',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.youtube.com">YouTube</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://player.vimeo.com">Vimeo</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https:">https:</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_form_action',
						'default' => $this->default_settings['enable_csp_form_action'] ?? '0',
						'label'   => esc_html__( 'Limit form targets', 'secuplug' ),
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
						'name'              => 'csp_allowed_form_action_sources',
						'label'             => esc_html__( 'Allowed form targets', 'secuplug' ),
						'placeholder'       => '\'self\'',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'self\'">\'self\'</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://js.stripe.com">Stripe</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="https://www.paypal.com">PayPal</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_base_uri',
						'default' => $this->default_settings['enable_csp_base_uri'] ?? '0',
						'label'   => esc_html__( 'Limit the base URL', 'secuplug' ),
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
						'name'              => 'csp_allowed_base_uri_sources',
						'label'             => esc_html__( 'Allowed base URLs', 'secuplug' ),
						'placeholder'       => '\'self\'',
						'field_type'        => 'url',
						'sanitize_callback' => [ CSP::class, 'validate_csp_source' ],
						'presets'           => '<button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'self\'">\'self\'</button><button type="button" class="fynd-sf-taginput-preset-btn" data-preset="\'none\'">\'none\'</button>',
					],
					[
						'type'    => 'radio',
						'name'    => 'enable_csp_report_only',
						'default' => $this->default_settings['enable_csp_report_only'] ?? '0',
						'label'   => esc_html__( 'Report-only mode', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Browsers report policy violations in the console (and to the report URL) but block nothing. Use it to test a policy before you enforce it.', 'secuplug' ) . '</span>',
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
						'type'        => 'text_input',
						'name'        => 'csp_report_uri',
						'label'       => esc_html__( 'Report URL', 'secuplug' ),
						'placeholder' => 'https://report-uri.com/example',
						'after'       => '<span class="description">' . esc_html__( 'Address where browsers send violation reports as JSON. Leave it empty to skip reporting.', 'secuplug' ) . '</span>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'login_settings',
				'title' => esc_html__( 'Login', 'secuplug' ),
				'desc'  => esc_html__( 'Limits password guessing and can move the login page to an address only you know. Write down a new login address before you save it.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'   => 'text_input',
						'name'   => 'ip_time_limit',
						'label'  => esc_html__( 'Lockout duration', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' hour(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'How long an IP stays blocked after too many failed logins.', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'ip_attempt_window',
						'label'  => esc_html__( 'Counting window', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' minute(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Failed logins are counted within this period.', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'ip_login_limit',
						'label'  => esc_html__( 'Failed logins allowed', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' attempts', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'An IP is blocked after this many failed logins within the counting window.', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'cleanup_ip_days',
						'label'  => esc_html__( 'Forget IPs after', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' day(s)', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'Removes IP records that were inactive for this many days. 0 keeps them.', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'cleanup_ip_attempts',
						'label'  => esc_html__( 'Forget only IPs with fewer than', 'secuplug' ),
						'before' => '',
						'after'  => esc_html__( ' failed logins', 'secuplug' ) . '<span class="field-tip"> ' . esc_html__( 'IPs with this many failed logins or more are kept.', 'secuplug' ) . '</span>',
					],
					[
						'type'   => 'text_input',
						'name'   => 'custom_login_url',
						'label'  => esc_html__( 'Login page address', 'secuplug' ),
						'before' => '<span class="url-text">' . ( 'network' === $this->context ? esc_html__( '(site address)', 'secuplug' ) : esc_html( \get_home_url() ) ) . '/</span>',
						'after'  => '<span class="url-text">/</span><span class="field-tip">' . esc_html__( 'Example: hidden-login. Leave it empty to keep the standard wp-login.php address.', 'secuplug' ) . '</span>',
					],
					[
						'type'  => 'text_input',
						'name'  => 'change_login_error',
						'label' => esc_html__( 'Login error message', 'secuplug' ),
						'after' => '<span class="description">' . esc_html__( 'Shown instead of the WordPress message, which tells attackers whether a username exists. Leave it empty to keep the WordPress message.', 'secuplug' ) . '</span>',
					],
				],
			],
			[
				// Section info.
				'name'  => 'ssl_settings',
				'title' => esc_html__( 'HTTPS', 'secuplug' ),
				'desc'  => esc_html__( 'Moves logins, the admin area and visitors to HTTPS.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'cond'    => $ssl_cond,
						'type'    => 'radio',
						'name'    => 'enable_https',
						'default' => '',
						'label'   => esc_html__( 'HTTPS support', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Turn this on after your SSL certificate works. The options below need it.', 'secuplug' ) . '</span>',
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
						'label'   => esc_html__( 'Use HTTPS on the login page', 'secuplug' ),
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
						'label'   => esc_html__( 'Use HTTPS in the admin area', 'secuplug' ),
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
						'label'   => esc_html__( 'Use HTTPS on the front page', 'secuplug' ),
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
						'label'   => esc_html__( 'Use HTTPS on the whole site', 'secuplug' ),
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
				'name'  => 'recaptcha_settings',
				'title' => esc_html__( 'reCAPTCHA', 'secuplug' ),
				'desc'  => esc_html__( 'Adds a Google reCAPTCHA check to the forms you choose. The script loads lazily to keep pages fast.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'    => 'radio',
						'name'    => 'recaptcha_enable',
						'default' => $this->default_settings['recaptcha_enable'] ?? '0',
						'label'   => esc_html__( 'Use reCAPTCHA', 'secuplug' ),
						'after'   => '<span class="description">' . esc_html__( 'Create the site key and the secret key in the Google reCAPTCHA admin console for this domain.', 'secuplug' ) . '</span>',
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
						'type'        => 'text_input',
						'name'        => 'recaptcha_site_key',
						'label'       => esc_html__( 'Site key', 'secuplug' ),
						'placeholder' => esc_html__( 'reCAPTCHA site key', 'secuplug' ),
					],
					[
						'type'        => 'text_input',
						'name'        => 'recaptcha_secret_key',
						'label'       => esc_html__( 'Secret key', 'secuplug' ),
						'placeholder' => esc_html__( 'reCAPTCHA secret key', 'secuplug' ),
					],
					[
						'type'    => 'radio',
						'name'    => 'recaptcha_version',
						'default' => $this->default_settings['recaptcha_version'] ?? 'v2_checkbox',
						'label'   => esc_html__( 'reCAPTCHA type', 'secuplug' ),
						'options' => [
							[
								'value' => 'v2_checkbox',
								'label' => esc_html__( 'reCAPTCHA v2 (Checkbox)', 'secuplug' ),
							],
							[
								'value' => 'v2_invisible',
								'label' => esc_html__( 'reCAPTCHA v2 (Invisible)', 'secuplug' ),
							],
							[
								'value' => 'v3',
								'label' => esc_html__( 'reCAPTCHA v3', 'secuplug' ),
							],
						],
					],
					[
						'type'    => 'radio',
						'name'    => 'recaptcha_login',
						'default' => $this->default_settings['recaptcha_login'] ?? '0',
						'label'   => esc_html__( 'Login form', 'secuplug' ),
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
						'name'    => 'recaptcha_register',
						'default' => $this->default_settings['recaptcha_register'] ?? '0',
						'label'   => esc_html__( 'Registration form', 'secuplug' ),
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
						'name'    => 'recaptcha_lostpassword',
						'default' => $this->default_settings['recaptcha_lostpassword'] ?? '0',
						'label'   => esc_html__( 'Lost password form', 'secuplug' ),
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
						'name'    => 'recaptcha_comment',
						'default' => $this->default_settings['recaptcha_comment'] ?? '0',
						'label'   => esc_html__( 'Comment form', 'secuplug' ),
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
						'name'    => 'recaptcha_cf7',
						'default' => $this->default_settings['recaptcha_cf7'] ?? '0',
						'label'   => esc_html__( 'Contact Form 7 forms', 'secuplug' ),
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
						'name'    => 'recaptcha_mc4wp',
						'default' => $this->default_settings['recaptcha_mc4wp'] ?? '0',
						'label'   => esc_html__( 'Mailchimp for WP forms', 'secuplug' ),
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
				],
			],
			[
				// Section info.
				'name'  => 'advanced_settings',
				'title' => esc_html__( 'Advanced', 'secuplug' ),
				'desc'  => esc_html__( 'Patterns used by "Filter malicious requests" on the Firewall tab.', 'secuplug' ),
				// Form items.
				'items' => [
					[
						'type'              => 'taginput',
						'name'              => 'cookie_patterns',
						'label'             => esc_html__( 'Cookie patterns', 'secuplug' ),
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
						'label'             => esc_html__( 'Request patterns (GET and POST)', 'secuplug' ),
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

		$this->settings_page->load_form( $conf );
		$this->settings_page->register();
	}



	/**
	 * Network-only settings section.
	 *
	 * @return array
	 */
	protected function get_network_policy_section() {
		return [
			'name'  => 'network_policy_settings',
			'title' => esc_html__( 'Network policy', 'secuplug' ),
			'desc'  => esc_html__( 'Settings on this page are the defaults for every site in the network.', 'secuplug' ),
			'items' => [
				[
					'type'    => 'radio',
					'name'    => Settings::POLICY_SITE_ADMINS,
					'label'   => esc_html__( 'Site administrators can customize their site', 'secuplug' ),
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
					'after'   => '<span class="description">' . esc_html__( 'When off, only network administrators can change settings for a single site. Brute-force limits are always set here, for all sites.', 'secuplug' ) . '</span>',
				],
			],
		];
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
		\wp_enqueue_script( 'securefusion-admin-js', \plugins_url( 'assets/js/admin.js', SECUREFUSION_BASENAME ), array(), SECUREFUSION_VERSION, true );
		\wp_enqueue_script( 'securefusion-unsaved-settings', \plugins_url( 'assets/js/unsaved-settings.js', SECUREFUSION_BASENAME ), array( 'jquery', 'securefusion-admin-js' ), (string) filemtime( SECUREFUSION_PATH . 'assets/js/unsaved-settings.js' ), true );

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
	 * @param string $details Optional expanded guidance HTML.
	 *
	 * @return void
	 */
	public function add_status_box( $title, $status = false, $desc = '', $button = [], $details = '' ) {
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

			if ( ! empty( $details ) ) :
				?>
				<details class="fsf-card-details">
					<summary><?php esc_html_e( 'Review guidance', 'secuplug' ); ?></summary>
					<div class="fsf-card-details__body"><?php echo wp_kses_post( $details ); ?></div>
				</details>
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

		$this->context = ( $this->layered && \is_network_admin() ) ? 'network' : 'site';

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
