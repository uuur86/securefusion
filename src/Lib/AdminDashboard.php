<?php
/**
 * AdminDashboard responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * AdminDashboard methods.
 *
 * @mixin Admin
 * @property string $admin_link Admin URL, set in Admin::__construct().
 * @method array|string|null get_settings( string|null $name = null ) Resolved settings.
 * @method void render_header( string $title, string $description, array $custom_actions = [] ) Page header.
 * @method void add_status_box( string $title, bool $status = false, string $desc = '', array $button = [], string $details = '' ) Dashboard status row.
 * @method void get_account_transition_html() Account transition guide.
 */
trait AdminDashboard {

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

}
