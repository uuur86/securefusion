<?php
/**
 * IPRules Class
 *
 * Handles the IP rules management page listing blocked/whitelisted IPs,
 * manually adding new rules, and deleting them via AJAX.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * IPRules functionality class.
 */
class IPRules {

	use WPCommon;

	/**
	 * Nonce action for AJAX operations.
	 *
	 * @var string
	 */
	const NONCE_ACTION = 'securefusion_ip_rules';

	/**
	 * Rows per page.
	 *
	 * @var int
	 */
	const PER_PAGE = 20;


	/**
	 * Register AJAX handlers.
	 *
	 * @return void
	 */
	public function register_ajax() {
		add_action( 'wp_ajax_securefusion_add_ip_rule', [ $this, 'ajax_add_rule' ] );
		add_action( 'wp_ajax_securefusion_delete_ip_rule', [ $this, 'ajax_delete_rule' ] );
	}


	/**
	 * Enqueue page-specific assets.
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		wp_enqueue_style(
			'securefusion-security-log-css',
			plugins_url( 'assets/css/security-log.css', SECUREFUSION_BASENAME ),
			[],
			SECUREFUSION_VERSION
		);

		wp_enqueue_script(
			'securefusion-security-log-js',
			plugins_url( 'assets/js/security-log.js', SECUREFUSION_BASENAME ),
			[ 'jquery' ],
			SECUREFUSION_VERSION,
			true
		);

		wp_localize_script(
			'securefusion-security-log-js',
			'securefusionRules',
			[
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( self::NONCE_ACTION ),
				'confirmDelete' => esc_html__( 'Are you sure you want to delete this rule?', 'secuplug' ),
				'addSuccess'    => esc_html__( 'Rule has been added successfully.', 'secuplug' ),
				'deleteSuccess' => esc_html__( 'Rule has been deleted successfully.', 'secuplug' ),
				'addFailed'     => esc_html__( 'Failed to add rule.', 'secuplug' ),
				'deleteFailed'  => esc_html__( 'Failed to delete rule.', 'secuplug' ),
				'invalidFormat' => esc_html__( 'Invalid IP address or CIDR range format.', 'secuplug' ),
			]
		);
	}


	/**
	 * Validate IP or CIDR range format.
	 *
	 * @param string $value The IP or CIDR string.
	 * @return bool True if valid format.
	 */
	private function validate_ip_or_cidr( $value ) {
		if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
			return true;
		}

		if ( preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $value ) ) {
			list( $subnet, $mask ) = explode( '/', $value );
			if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				$mask = (int) $mask;
				if ( $mask >= 0 && $mask <= 32 ) {
					return true;
				}
			}
		}

		return false;
	}


	/**
	 * AJAX: Add a new IP rule.
	 *
	 * @return void
	 */
	public function ajax_add_rule() {
		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['nonce'] ) ), self::NONCE_ACTION ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Security check failed.', 'secuplug' ) ] );
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Permission denied.', 'secuplug' ) ] );
			return;
		}

		$ip        = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$rule_type = isset( $_POST['rule_type'] ) ? sanitize_text_field( wp_unslash( $_POST['rule_type'] ) ) : '';

		if ( ! $this->validate_ip_or_cidr( $ip ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid IP address or CIDR range format.', 'secuplug' ) ] );
			return;
		}

		if ( ! in_array( $rule_type, [ 'blocked', 'whitelisted' ], true ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid rule type.', 'secuplug' ) ] );
			return;
		}

		$db = new BruteForceDB();

		if ( $rule_type === 'blocked' ) {
			if ( $db->is_ip_whitelisted( $ip ) ) {
				wp_send_json_error( [ 'message' => esc_html__( 'This IP/range is whitelisted and cannot be blocked.', 'secuplug' ) ] );
				return;
			}
			$success = $db->block_ip( $ip );
		} else {
			$success = $db->whitelist_ip( $ip );
		}

		if ( $success ) {
			wp_send_json_success( [ 'message' => esc_html__( 'Rule has been added successfully.', 'secuplug' ) ] );
		} else {
			wp_send_json_error( [ 'message' => esc_html__( 'Failed to add rule.', 'secuplug' ) ] );
		}
	}


	/**
	 * AJAX: Delete an IP rule.
	 *
	 * @return void
	 */
	public function ajax_delete_rule() {
		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['nonce'] ) ), self::NONCE_ACTION ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Security check failed.', 'secuplug' ) ] );
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Permission denied.', 'secuplug' ) ] );
			return;
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

		if ( empty( $ip ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid IP or range.', 'secuplug' ) ] );
			return;
		}

		$db      = new BruteForceDB();
		$success = $db->delete_ip_rule( $ip );

		if ( $success ) {
			wp_send_json_success( [ 'message' => esc_html__( 'Rule has been deleted successfully.', 'secuplug' ) ] );
		} else {
			wp_send_json_error( [ 'message' => esc_html__( 'Failed to delete rule.', 'secuplug' ) ] );
		}
	}


	/**
	 * Normalize sorting order.
	 *
	 * @param string $order Raw sorting order.
	 * @return string 'ASC' or 'DESC'.
	 */
	private function normalize_order( $order ) {
		return strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
	}


	/**
	 * Render the IP Rules page.
	 *
	 * @return void
	 */
	public function render() {
		$db = new BruteForceDB();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$current_page = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( $_GET['orderby'] ) : 'created_at';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$order = isset( $_GET['order'] ) ? $this->normalize_order( sanitize_key( $_GET['order'] ) ) : 'DESC';

		$offset      = ( $current_page - 1 ) * self::PER_PAGE;
		$total_rows  = $db->get_total_rules_count();
		$total_pages = (int) ceil( $total_rows / self::PER_PAGE );

		$rows = $db->get_all_rules( self::PER_PAGE, $offset, $orderby, $order );

		$page_url = admin_url( 'admin.php?page=securefusion-ip-rules' );

		$this->enqueue_assets();
		?>
		<div class="wrap fynd-sf-login-log fynd-sf-ip-rules-page">
			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'IP Rules', 'secuplug' ); ?></h1>

			<?php
			$this->render_header(
				esc_html__( 'IP Rules Management', 'secuplug' ),
				esc_html__( 'Manually block or whitelist specific IP addresses and range blocks.', 'secuplug' )
			);
			?>

			<div id="fynd-sf-rules-notice" class="fynd-sf-log-notice" style="display:none;"></div>

			<!-- Add New Rule Card -->
			<div class="fynd-sf-card fynd-sf-rules-form-card">
				<h3><?php esc_html_e( 'Add New Rule', 'secuplug' ); ?></h3>
				<form id="fynd-sf-add-rule-form" class="fynd-sf-rules-form">
					<div class="fynd-sf-form-group-ip">
						<label for="fynd-sf-rule-ip"><?php esc_html_e( 'IP Address or Subnet (CIDR)', 'secuplug' ); ?></label>
						<input type="text" id="fynd-sf-rule-ip" name="ip" required placeholder="e.g. 192.168.1.1 or 192.168.1.0/24">
					</div>
					<div class="fynd-sf-form-group-type">
						<label for="fynd-sf-rule-type"><?php esc_html_e( 'Rule Type', 'secuplug' ); ?></label>
						<select id="fynd-sf-rule-type" name="rule_type">
							<option value="blocked"><?php esc_html_e( 'Blocked', 'secuplug' ); ?></option>
							<option value="whitelisted"><?php esc_html_e( 'Whitelisted', 'secuplug' ); ?></option>
						</select>
					</div>
					<div class="fynd-sf-form-group-submit">
						<button type="submit" class="fynd-sf-btn fynd-sf-btn-primary">
							<span class="dashicons dashicons-plus"></span>
							<?php esc_html_e( 'Add Rule', 'secuplug' ); ?>
						</button>
					</div>
				</form>
			</div>

			<div class="fynd-sf-log-table-wrap" style="margin-top: 20px;">
				<?php if ( $total_rows > 0 ) : ?>
					<table class="wp-list-table widefat fixed striped fynd-sf-log-table">
						<thead>
							<tr>
								<?php
								$columns = [
									'ip'         => esc_html__( 'IP / Subnet (CIDR)', 'secuplug' ),
									'rule_type'  => esc_html__( 'Rule Type', 'secuplug' ),
									'duration'   => esc_html__( 'Duration', 'secuplug' ),
									'created_at' => esc_html__( 'Created At', 'secuplug' ),
								];

								foreach ( $columns as $col_key => $col_label ) :
									$sort_key   = ( $col_key === 'duration' ) ? 'expiration' : $col_key;
									$is_sorted  = ( $orderby === $sort_key );
									$next_order = $is_sorted && $order === 'ASC' ? 'DESC' : 'ASC';
									$sort_url   = add_query_arg(
										[
											'orderby' => $sort_key,
											'order'   => $next_order,
											'paged'   => 1,
										],
										$page_url
									);
									$sort_class = $is_sorted ? 'sorted ' . strtolower( $order ) : 'sortable desc';
									?>
									<th scope="col" class="manage-column column-<?php echo esc_attr( $col_key ); ?> <?php echo esc_attr( $sort_class ); ?>">
										<a href="<?php echo esc_url( $sort_url ); ?>">
											<span><?php echo esc_html( $col_label ); ?></span>
											<span class="sorting-indicators">
												<span class="sorting-indicator asc" aria-hidden="true"></span>
												<span class="sorting-indicator desc" aria-hidden="true"></span>
											</span>
										</a>
									</th>
								<?php endforeach; ?>
								<th scope="col" class="manage-column column-actions"><?php esc_html_e( 'Actions', 'secuplug' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $rows as $row ) : ?>
								<tr data-ip="<?php echo esc_attr( $row->ip ); ?>">
									<td class="column-ip">
										<code><?php echo esc_html( $row->ip ); ?></code>
									</td>
									<td class="column-rule_type">
										<?php if ( $row->rule_type === 'whitelisted' ) : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-whitelisted"><?php esc_html_e( 'Whitelisted', 'secuplug' ); ?></span>
										<?php else : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-blocked"><?php esc_html_e( 'Blocked', 'secuplug' ); ?></span>
										<?php endif; ?>
									</td>
									<td class="column-duration">
										<?php
										if ( $row->rule_type === 'whitelisted' ) {
											echo esc_html__( 'Permanent', 'secuplug' );
										} else {
											$expiration = isset( $row->expiration ) ? (int) $row->expiration : 0;
											if ( $expiration === 0 ) {
												echo esc_html__( 'Permanent', 'secuplug' );
											} else {
												/* translators: %s: Formatted expiration date and time */
												printf( esc_html__( 'Until %s', 'secuplug' ), esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $expiration ) ) );
											}
										}
										?>
									</td>
									<td class="column-created_at">
										<?php
										$timestamp = (int) $row->created_at;
										if ( $timestamp > 0 ) {
											echo esc_html(
												wp_date(
													get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
													$timestamp
												)
											);
											echo '<br><small class="fynd-sf-time-ago">';
											echo esc_html( human_time_diff( $timestamp, time() ) . ' ' . __( 'ago', 'secuplug' ) );
											echo '</small>';
										} else {
											echo '—';
										}
										?>
									</td>
									<td class="column-actions">
										<button type="button" class="fynd-sf-btn fynd-sf-btn-sm fynd-sf-btn-danger fynd-sf-remove-rule-btn" data-ip="<?php echo esc_attr( $row->ip ); ?>">
											<span class="dashicons dashicons-trash"></span>
											<?php esc_html_e( 'Remove', 'secuplug' ); ?>
										</button>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>

					<?php if ( $total_pages > 1 ) : ?>
						<div class="fynd-sf-log-pagination">
							<span class="fynd-sf-pagination-info">
								<?php
								$current_page_f = number_format_i18n( $current_page );
								$total_pages_f  = number_format_i18n( $total_pages );
								$total_rows_f   = number_format_i18n( $total_rows );

								printf(
									/* translators: 1: Current page, 2: Total pages, 3: Total items. */
									esc_html__( 'Page %1$s of %2$s (%3$s items)', 'secuplug' ),
									esc_html( $current_page_f ),
									esc_html( $total_pages_f ),
									esc_html( $total_rows_f )
								);
								?>
							</span>
							<span class="fynd-sf-pagination-links">
								<?php
								// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links() returns safe HTML.
								echo str_replace(
									'page-numbers',
									'fynd-sf-page-number',
									paginate_links(
										[
											'base'      => add_query_arg( 'paged', '%#%', $page_url ),
											'format'    => '',
											'prev_text' => '&lsaquo;',
											'next_text' => '&rsaquo;',
											'total'     => $total_pages,
											'current'   => $current_page,
											'end_size'  => 1,
											'mid_size'  => 2,
											'add_args'  => [
												'orderby' => $orderby,
												'order'   => $order,
											],
										]
									)
								);
								?>
							</span>
						</div>
					<?php endif; ?>

				<?php else : ?>
					<div class="fynd-sf-log-empty">
						<span class="dashicons dashicons-shield-alt"></span>
						<p><?php esc_html_e( 'No IP rules defined yet.', 'secuplug' ); ?></p>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}
