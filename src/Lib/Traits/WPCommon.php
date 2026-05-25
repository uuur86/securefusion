<?php
/**
 * WPCommon Trait
 * Common WordPress methods
 *
 * @package securefusion
 */

namespace SecureFusion\Lib\Traits;

use Exception;


/**
 * WPCommon trait with common WordPress methods.
 */
trait WPCommon {


	/**
	 * WP settings
	 *
	 * @var array
	 */
	protected $wp_settings = false;


	/**
	 * Check admin menu screen
	 *
	 * @param array $menu_pages Admin menu pages.
	 *
	 * @return bool True if the current screen is in the menu pages, false otherwise.
	 */
	public function check_admin_menu_screen( $menu_pages ) {
		$screen = get_current_screen();

		if ( ! is_array( $menu_pages ) ) {
			return false;
		}

		if ( \in_array( $screen->id, $menu_pages, true ) ) {
			return true;
		}

		return false;
	}



	/**
	 * Get plugin settings
	 *
	 * @param string|null $name Plugin setting name.
	 *
	 * @return array|string|null Plugin settings or specific setting value.
	 */
	public function get_settings( $name = null ) {
		$value = null;

		if ( $this->wp_settings === false ) {
			$this->wp_settings = get_option( 'securefusion_settings', null );
		}

		if ( ! empty( $name ) ) {
			if ( isset( $this->wp_settings[ $name ] ) ) {
				$value = $this->wp_settings[ $name ];
			}
		} else {
			$value = $this->wp_settings;
		}

		return $value;
	}



	/**
	 * Set plugin settings
	 *
	 * @param string|array $name   Plugin setting name or array of settings.
	 * @param mixed        $value  Plugin setting value if $name is a string.
	 *
	 * @return bool True if settings were updated, false otherwise.
	 */
	public function set_settings( $name, $value ) {
		$settings          = $this->get_settings();
		$settings[ $name ] = $value;

		return update_option( 'securefusion_settings', $settings );
	}




	/**
	 * Get requested page
	 *
	 * @return string Requested page.
	 */
	public function get_requested_page() {
		if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}

		$requests       = wp_parse_url( sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
		$requested_page = trim( basename( $requests['path'] ), '\\/' );

		return $requested_page;
	}



	/**
	 * Get new login URL
	 *
	 * @return string New login URL.
	 */
	public function get_new_login_url() {
		return trim( $this->get_settings( 'custom_login_url' ), '\\/' );
	}



	/**
	 * Check if it's a login page
	 *
	 * @param bool $old Whether to check old login pages.
	 *
	 * @return bool True if it's a login page, false otherwise.
	 */
	public function is_login_page( $old = true ) {
		global $pagenow;

		$login_dir      = [ 'wp-admin', 'admin', 'login' ];
		$requested_page = $this->get_requested_page();

		$wp_login      = strpos( $pagenow, 'wp-login.php' ) !== false;
		$is_login_page = in_array( $requested_page, $login_dir );
		$is_login_page = ( $wp_login || $is_login_page );

		if ( $old ) {
			return $is_login_page;
		}

		return ( $requested_page == $this->get_new_login_url() );
	}




	/**
	 * Get WordPress filesystem
	 *
	 * @return \WP_Filesystem_Base WordPress filesystem object.
	 * @throws Exception If there is no filesystem in this WordPress version.
	 */
	protected function filesystem() {
		global $wp_filesystem;

		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			\WP_Filesystem();
		}

		if ( empty( $wp_filesystem ) ) {
			throw new Exception( 'There is no filesystem in this WordPress version' );
		}

		return $wp_filesystem;
	}



	/**
	 * Array merge values
	 *
	 * @param array $arrays Array of arrays to merge.

	 * @return array Merged array.
	 */
	protected function array_merge_values( array $arrays ) {
		$result = [];

		foreach ( $arrays as $array ) {
			$result = array_merge( $result, $array );
		}

		return $result;
	}



	/**
	 * Get client IP

	 * @return string Client IP.
	 */
	protected function get_client_ip() {
		$ipaddress = '';

		$server_var = wp_unslash( $_SERVER );

		if ( isset( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ipaddress = $server_var['HTTP_CLIENT_IP'];
		} elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ipaddress = $server_var['HTTP_X_FORWARDED_FOR'];
		} elseif ( isset( $_SERVER['HTTP_X_FORWARDED'] ) ) {
			$ipaddress = $server_var['HTTP_X_FORWARDED'];
		} elseif ( isset( $_SERVER['HTTP_FORWARDED_FOR'] ) ) {
			$ipaddress = $server_var['HTTP_FORWARDED_FOR'];
		} elseif ( isset( $_SERVER['HTTP_FORWARDED'] ) ) {
			$ipaddress = $server_var['HTTP_FORWARDED'];
		} else {
			$ipaddress = $server_var['REMOTE_ADDR'];
		}

		// Multiple IP addresses can be returned, so let's take the first one.
		if ( strpos( $ipaddress, ',' ) !== false ) {
			$ipaddress = explode( ',', $ipaddress );
			$ipaddress = $ipaddress[0] ?? false;
		}

		$ipaddress = filter_var( $ipaddress, FILTER_VALIDATE_IP );

		return $ipaddress;
	}
	/**
	 * Render the unified plugin page header.
	 *
	 * Outputs a consistent header component with logo, title, description,
	 * version info, changelog link, and Fyndsoft product/service links.
	 *
	 * @param string $title          Page title.
	 * @param string $description    Page description.
	 * @param array  $custom_actions Optional. Array of custom action button HTML strings.
	 *
	 * @return void
	 */
	public function render_header( $title, $description, $custom_actions = [] ) {
		$plugin_url    = \plugins_url( '/', SECUREFUSION_BASENAME );
		$changelog_url = 'https://fyndsoft.com/portfolio/securefusion/#changelog';
		$products_url  = 'https://fyndsoft.com/portfolio/';
		$services_url  = 'https://fyndsoft.com/services/';
		?>
		<header class="fynd-sf-log-header">
			<img src="<?php echo esc_url( $plugin_url ); ?>assets/icon.svg" alt="SecureFusion Logo" class="fynd-sf-log-logo">
			<div class="fynd-sf-log-header-text" style="flex-grow: 1;">
				<h2 class="fynd-sf-log-title"><?php echo esc_html( $title ); ?></h2>
				<p class="fynd-sf-log-desc">
					<?php echo esc_html( $description ); ?>
					<span class="version-info" style="margin-left: 10px; color: #646970;">
						<?php
						/* translators: %s: Version number */
						printf( esc_html__( 'Version %s - Check out.', 'securefusion' ), esc_html( SECUREFUSION_VERSION ) );
						?>
						<a href="<?php echo esc_url( $changelog_url ); ?>" target="_blank" rel="noopener" style="color: #01b9ba; text-decoration: none; font-weight: 500;">
							<?php esc_html_e( 'What\'s New', 'securefusion' ); ?>
						</a>
					</span>
				</p>
			</div>
			<div class="plugin-links">
				<?php if ( ! empty( $custom_actions ) ) : ?>
					<?php foreach ( $custom_actions as $action_html ) : ?>
						<?php
						// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Pre-escaped action HTML from caller.
						echo $action_html;
						?>
					<?php endforeach; ?>
				<?php endif; ?>
				<a href="<?php echo esc_url( $products_url ); ?>" target="_blank" rel="noopener" class="fynd-sf-btn fynd-sf-btn-secondary">
					<?php esc_html_e( 'Products', 'securefusion' ); ?>
				</a>
				<a href="<?php echo esc_url( $services_url ); ?>" target="_blank" rel="noopener" class="fynd-sf-btn fynd-sf-btn-secondary">
					<?php esc_html_e( 'Services', 'securefusion' ); ?>
				</a>
			</div>
		</header>
		<?php
	}
}
