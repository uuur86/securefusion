<?php
/**
 * WPCommon Trait
 * Common WordPress methods
 *
 * @package securefusion
 */

namespace SecureFusion\Lib\Traits;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

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
		$is_login_page = in_array( $requested_page, $login_dir, true );
		$is_login_page = ( $wp_login || $is_login_page );

		if ( $old ) {
			return $is_login_page;
		}

		return ( $requested_page === $this->get_new_login_url() );
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
	 * Check if an IP address is a private, loopback, or link-local IP.
	 *
	 * @param string $ip The IP address to check.
	 * @return bool True if private/local, false otherwise.
	 */
	public function is_private_ip( $ip ) {
		return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false;
	}



	/**
	 * Check if an IP address is a public IP.
	 *
	 * @param string $ip The IP address to check.
	 * @return bool True if public, false otherwise.
	 */
	public function is_public_ip( $ip ) {
		return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false;
	}



	/**
	 * Calculate the smallest CIDR block for a /24 prefix given the min and max last octet.
	 *
	 * If the min and max are equal (single IP), it returns the exact IP address.
	 *
	 * @param string $range_prefix   The first 3 octets (e.g. '192.168.1').
	 * @param int    $min_last_octet The minimum last octet.
	 * @param int    $max_last_octet The maximum last octet.
	 * @return string The CIDR notation (e.g. '192.168.1.0/28') or exact IP (e.g. '192.168.1.5').
	 */
	public function calculate_cidr( $range_prefix, $min_last_octet, $max_last_octet ) {
		$min = (int) $min_last_octet;
		$max = (int) $max_last_octet;

		if ( $min === $max ) {
			return $range_prefix . '.' . $min;
		}

		$diff = $min ^ $max;
		$mask = 32;

		while ( $diff > 0 ) {
			$diff >>= 1;
			--$mask;
		}

		$shift_amount       = 32 - $mask;
		$network_last_octet = $min & ( ~ ( ( 1 << $shift_amount ) - 1 ) & 0xFF );

		return $range_prefix . '.' . $network_last_octet . '/' . $mask;
	}



	/**
	 * Get client IP
	 *
	 * @return string Client IP.
	 */
	protected function get_client_ip() {
		$server_var  = wp_unslash( $_SERVER );
		$remote_addr = isset( $server_var['REMOTE_ADDR'] ) ? trim( $server_var['REMOTE_ADDR'] ) : '';

		// If REMOTE_ADDR is a public IP, trust it directly to prevent spoofing via custom headers.
		if ( ! empty( $remote_addr ) && $this->is_public_ip( $remote_addr ) ) {
			return $remote_addr;
		}

		// Otherwise, if REMOTE_ADDR is a private IP (e.g. Docker proxy, local env), check forwarding headers.
		$ipaddress = '';

		if ( isset( $server_var['HTTP_CLIENT_IP'] ) ) {
			$ipaddress = $server_var['HTTP_CLIENT_IP'];
		} elseif ( isset( $server_var['HTTP_X_FORWARDED_FOR'] ) ) {
			$ipaddress = $server_var['HTTP_X_FORWARDED_FOR'];
		} elseif ( isset( $server_var['HTTP_X_FORWARDED'] ) ) {
			$ipaddress = $server_var['HTTP_X_FORWARDED'];
		} elseif ( isset( $server_var['HTTP_FORWARDED_FOR'] ) ) {
			$ipaddress = $server_var['HTTP_FORWARDED_FOR'];
		} elseif ( isset( $server_var['HTTP_FORWARDED'] ) ) {
			$ipaddress = $server_var['HTTP_FORWARDED'];
		} else {
			$ipaddress = $remote_addr;
		}

		// Multiple IP addresses can be returned, so let's take the first one.
		if ( strpos( $ipaddress, ',' ) !== false ) {
			$ipaddress = explode( ',', $ipaddress );
			$ipaddress = $ipaddress[0] ?? '';
		}

		$ipaddress = trim( $ipaddress );
		$ipaddress = filter_var( $ipaddress, FILTER_VALIDATE_IP );

		return $ipaddress ? $ipaddress : $remote_addr;
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
						printf( esc_html__( 'Version %s - Check out.', 'secuplug' ), esc_html( SECUREFUSION_VERSION ) );
						?>
						<a href="<?php echo esc_url( $changelog_url ); ?>" target="_blank" rel="noopener" style="color: #01b9ba; text-decoration: none; font-weight: 500;">
							<?php esc_html_e( 'What\'s New', 'secuplug' ); ?>
						</a>
					</span>
				</p>
			</div>
			<div class="plugin-links">
				<?php if ( ! empty( $custom_actions ) ) : ?>
					<?php foreach ( $custom_actions as $action_html ) : ?>
						<?php
						$allowed_tags = [
							'button' => [
								'type'  => [],
								'id'    => [],
								'class' => [],
							],
							'span'   => [
								'class' => [],
							],
							'a'      => [
								'href'   => [],
								'class'  => [],
								'id'     => [],
								'target' => [],
								'rel'    => [],
							],
						];
						echo wp_kses( $action_html, $allowed_tags );
						?>
					<?php endforeach; ?>
				<?php endif; ?>
				<a href="<?php echo esc_url( $products_url ); ?>" target="_blank" rel="noopener" class="fynd-sf-btn fynd-sf-btn-secondary">
					<?php esc_html_e( 'Products', 'secuplug' ); ?>
				</a>
				<a href="<?php echo esc_url( $services_url ); ?>" target="_blank" rel="noopener" class="fynd-sf-btn fynd-sf-btn-secondary">
					<?php esc_html_e( 'Services', 'secuplug' ); ?>
				</a>
			</div>
		</header>
		<?php
	}
}
