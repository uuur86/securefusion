<?php
/**
 * LoginLog Class
 *
 * Handles the failed login attempts log page with
 * listing, reset (truncate), JSON export, import, and IP range analysis.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

/**
 * LoginLog Class
 *
 * @package securefusion
 */
class LoginLog {

	/**
	 * Nonce action for AJAX operations.
	 *
	 * @var string
	 */
	const NONCE_ACTION = 'securefusion_login_log';

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
		add_action( 'wp_ajax_securefusion_log_reset', [ $this, 'ajax_reset' ] );
		add_action( 'wp_ajax_securefusion_log_export', [ $this, 'ajax_export' ] );
		add_action( 'wp_ajax_securefusion_log_import', [ $this, 'ajax_import' ] );
		add_action( 'wp_ajax_securefusion_log_range_ips', [ $this, 'ajax_range_ips' ] );
	}


	/**
	 * Enqueue page-specific assets.
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		wp_enqueue_style(
			'securefusion-login-log-css',
			plugins_url( 'assets/css/login-log.css', SECUREFUSION_BASENAME ),
			[],
			SECUREFUSION_VERSION
		);

		wp_enqueue_script(
			'securefusion-login-log-js',
			plugins_url( 'assets/js/login-log.js', SECUREFUSION_BASENAME ),
			[ 'jquery' ],
			SECUREFUSION_VERSION,
			true
		);

		wp_localize_script(
			'securefusion-login-log-js',
			'securefusionLog',
			[
				'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
				'nonce'          => wp_create_nonce( self::NONCE_ACTION ),
				'confirmReset'   => esc_html__( 'WARNING: This action is irreversible! All failed login attempt data will be permanently deleted. Are you absolutely sure?', 'securefusion' ),
				'confirmImport'  => esc_html__( 'Importing data will add records to the existing table. Continue?', 'securefusion' ),
				'resetSuccess'   => esc_html__( 'All data has been deleted successfully.', 'securefusion' ),
				'exportEmpty'    => esc_html__( 'No data to export.', 'securefusion' ),
				'importSuccess'  => esc_html__( 'Import completed successfully.', 'securefusion' ),
				'importError'    => esc_html__( 'Import failed. Please check the file format.', 'securefusion' ),
				'invalidFile'    => esc_html__( 'Please select a valid JSON file.', 'securefusion' ),
				'processing'     => esc_html__( 'Processing...', 'securefusion' ),
				'copied'         => esc_html__( 'Copied to clipboard!', 'securefusion' ),
				'copyFailed'     => esc_html__( 'Copy failed. Please select and copy manually.', 'securefusion' ),
			]
		);
	}


	/**
	 * Validate AJAX request (nonce + capability).
	 *
	 * @return bool
	 */
	private function validate_ajax_request() {
		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['nonce'] ) ), self::NONCE_ACTION ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Security check failed.', 'securefusion' ) ] );
			return false;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Permission denied.', 'securefusion' ) ] );
			return false;
		}

		return true;
	}


	/**
	 * AJAX: Reset (truncate) all log data.
	 *
	 * @return void
	 */
	public function ajax_reset() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		$db      = new BruteForceDB();
		$success = $db->truncate_table();

		if ( $success ) {
			wp_send_json_success( [ 'message' => esc_html__( 'All data has been deleted.', 'securefusion' ) ] );
		} else {
			wp_send_json_error( [ 'message' => esc_html__( 'Failed to delete data.', 'securefusion' ) ] );
		}
	}


	/**
	 * AJAX: Export all log data as JSON.
	 *
	 * @return void
	 */
	public function ajax_export() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		$db   = new BruteForceDB();
		$rows = $db->get_all_rows_for_export();

		$export = [];
		foreach ( $rows as $row ) {
			$export[] = [
				'ip'           => $row->ip,
				'attempts'     => (int) $row->attempts,
				'last_attempt' => (int) $row->last_attempt,
			];
		}

		wp_send_json_success(
			[
				'data'     => $export,
				'filename' => 'securefusion-login-log-' . gmdate( 'Y-m-d' ) . '.json',
			]
		);
	}


	/**
	 * AJAX: Import log data from JSON.
	 *
	 * @return void
	 */
	public function ajax_import() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON data, decoded and validated field-by-field in bulk_insert().
		$raw_data = isset( $_POST['import_data'] ) ? wp_unslash( $_POST['import_data'] ) : '';

		$data = json_decode( $raw_data, true );

		if ( ! is_array( $data ) || empty( $data ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid JSON data.', 'securefusion' ) ] );
			return;
		}

		$db       = new BruteForceDB();
		$inserted = $db->bulk_insert( $data );

		wp_send_json_success(
			[
				/* translators: %d: Number of imported rows. */
				'message' => sprintf( esc_html__( '%d records imported successfully.', 'securefusion' ), $inserted ),
			]
		);
	}


	/**
	 * AJAX: Get IPs for a specific range prefix.
	 *
	 * @return void
	 */
	public function ajax_range_ips() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Validated below.
		$range_prefix = isset( $_POST['range_prefix'] ) ? sanitize_text_field( wp_unslash( $_POST['range_prefix'] ) ) : '';

		if ( empty( $range_prefix ) || ! preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}$/', $range_prefix ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid range prefix.', 'securefusion' ) ] );
			return;
		}

		$db  = new BruteForceDB();
		$ips = $db->get_ips_by_range_prefix( $range_prefix );

		$ip_list = [];
		foreach ( $ips as $row ) {
			$ip_list[] = $row->ip;
		}

		wp_send_json_success(
			[
				'ips'    => $ip_list,
				'range'  => $range_prefix . '.0/24',
				/* translators: %d: Number of IPs in the range. */
				'title'  => sprintf( esc_html__( '%d IPs in range %s', 'securefusion' ), count( $ip_list ), $range_prefix . '.0/24' ),
			]
		);
	}


	/**
	 * Normalize the order parameter.
	 *
	 * sanitize_key() lowercases the value, so we must normalize to uppercase
	 * before any comparison.
	 *
	 * @param string $order Raw order value (may be lowercase from sanitize_key).
	 * @return string 'ASC' or 'DESC'.
	 */
	private function normalize_order( $order ) {
		return strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
	}


	/**
	 * Render the login log page HTML.
	 *
	 * @return void
	 */
	public function render() {
		$db = new BruteForceDB();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only pagination parameter.
		$current_page = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only sorting parameter.
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( $_GET['orderby'] ) : 'last_attempt';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only sorting parameter.
		$order = isset( $_GET['order'] ) ? $this->normalize_order( sanitize_key( $_GET['order'] ) ) : 'DESC';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only filter parameter.
		$range_filter = isset( $_GET['range'] ) ? sanitize_text_field( wp_unslash( $_GET['range'] ) ) : '';

		$offset      = ( $current_page - 1 ) * self::PER_PAGE;
		$total_rows  = $range_filter ? $db->get_total_rows_by_range( $range_filter ) : $db->get_total_rows();
		$total_pages = (int) ceil( $total_rows / self::PER_PAGE );

		if ( $range_filter ) {
			$rows = $db->get_rows_by_range( $range_filter, self::PER_PAGE, $offset, $orderby, $order );
		} else {
			$rows = $db->get_all_rows( self::PER_PAGE, $offset, $orderby, $order );
		}

		// IP ranges for the range section.
		$ip_ranges = $db->get_ip_ranges();

		$plugin_url = plugins_url( '/', SECUREFUSION_BASENAME );
		$page_url   = admin_url( 'admin.php?page=securefusion-login-log' );

		// Preserve range filter in sort/page URLs.
		if ( $range_filter ) {
			$page_url = add_query_arg( 'range', $range_filter, $page_url );
		}

		$this->enqueue_assets();
		?>
		<div class="wrap securefusion-login-log">
			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="sf-sr-only"><?php esc_html_e( 'Failed Login Attempts', 'securefusion' ); ?></h1>

			<header class="sf-log-header">
				<img src="<?php echo esc_url( $plugin_url ); ?>assets/icon.svg" alt="SecureFusion" class="sf-log-logo">
				<div class="sf-log-header-text">
					<h2 class="sf-log-title"><?php esc_html_e( 'Failed Login Attempts', 'securefusion' ); ?></h2>
					<p class="sf-log-desc"><?php esc_html_e( 'Monitor and manage brute force login attempt records.', 'securefusion' ); ?></p>
				</div>
			</header>

			<div id="sf-log-notice" class="sf-log-notice" style="display:none;"></div>

			<div class="sf-log-stats">
				<div class="sf-stat-card">
					<span class="sf-stat-icon dashicons dashicons-warning"></span>
					<div class="sf-stat-data">
						<span class="sf-stat-value"><?php echo (int) $db->get_total_attempts(); ?></span>
						<span class="sf-stat-label"><?php esc_html_e( 'Total Failed Attempts', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="sf-stat-card">
					<span class="sf-stat-icon dashicons dashicons-admin-site-alt3"></span>
					<div class="sf-stat-data">
						<span class="sf-stat-value"><?php echo (int) $db->get_unique_ips_count(); ?></span>
						<span class="sf-stat-label"><?php esc_html_e( 'Unique IP Addresses', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="sf-stat-card">
					<span class="sf-stat-icon dashicons dashicons-database"></span>
					<div class="sf-stat-data">
						<span class="sf-stat-value"><?php echo (int) $total_rows; ?></span>
						<span class="sf-stat-label"><?php esc_html_e( 'Total Records', 'securefusion' ); ?></span>
					</div>
				</div>
			</div>

			<?php if ( ! empty( $ip_ranges ) ) : ?>
				<div class="sf-range-section">
					<div class="sf-range-header">
						<h3>
							<span class="dashicons dashicons-networking"></span>
							<?php esc_html_e( 'IP Ranges', 'securefusion' ); ?>
						</h3>
						<?php if ( $range_filter ) : ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=securefusion-login-log' ) ); ?>" class="button button-small sf-clear-filter">
								<span class="dashicons dashicons-no-alt"></span>
								<?php esc_html_e( 'Clear Filter', 'securefusion' ); ?>
							</a>
						<?php endif; ?>
					</div>
					<div class="sf-range-badges">
						<?php foreach ( $ip_ranges as $range ) : ?>
							<?php
							$range_url = add_query_arg(
								[
									'range' => $range->range_prefix,
									'paged' => 1,
								],
								admin_url( 'admin.php?page=securefusion-login-log' )
							);
							$is_active = ( $range_filter === $range->range_prefix );
							?>
							<div class="sf-range-badge <?php echo $is_active ? 'sf-range-active' : ''; ?>">
								<a href="<?php echo esc_url( $range_url ); ?>" class="sf-range-link" title="<?php esc_attr_e( 'Filter by this range', 'securefusion' ); ?>">
									<span class="sf-range-name"><?php echo esc_html( $range->range_prefix ); ?>.0/24</span>
									<span class="sf-range-count"><?php echo (int) $range->ip_count; ?> IPs</span>
									<span class="sf-range-attempts"><?php echo (int) $range->total_attempts; ?> <?php esc_html_e( 'attempts', 'securefusion' ); ?></span>
								</a>
								<button type="button"
									class="sf-range-detail-btn"
									data-range="<?php echo esc_attr( $range->range_prefix ); ?>"
									title="<?php esc_attr_e( 'Show IP list', 'securefusion' ); ?>">
									<span class="dashicons dashicons-visibility"></span>
								</button>
							</div>
						<?php endforeach; ?>
					</div>
				</div>

				<div id="sf-range-modal" class="sf-range-modal" style="display:none;">
					<div class="sf-range-modal-content">
						<div class="sf-range-modal-header">
							<h3 id="sf-range-modal-title"></h3>
							<button type="button" id="sf-range-modal-close" class="sf-range-modal-close">&times;</button>
						</div>
						<div class="sf-range-modal-body">
							<textarea id="sf-range-modal-textarea" readonly rows="10"></textarea>
						</div>
						<div class="sf-range-modal-footer">
							<button type="button" id="sf-range-copy-btn" class="button button-primary">
								<span class="dashicons dashicons-clipboard"></span>
								<?php esc_html_e( 'Copy to Clipboard', 'securefusion' ); ?>
							</button>
							<span id="sf-range-copy-status" class="sf-copy-status"></span>
						</div>
					</div>
				</div>
			<?php endif; ?>

			<div class="sf-log-toolbar">
				<div class="sf-toolbar-left">
					<button type="button" id="sf-log-export" class="button button-secondary">
						<span class="dashicons dashicons-download"></span>
						<?php esc_html_e( 'Export JSON', 'securefusion' ); ?>
					</button>
					<label for="sf-log-import-file" class="button button-secondary sf-import-label">
						<span class="dashicons dashicons-upload"></span>
						<?php esc_html_e( 'Import JSON', 'securefusion' ); ?>
					</label>
					<input type="file" id="sf-log-import-file" accept=".json" class="sf-hidden-file">
				</div>
				<div class="sf-toolbar-right">
					<button type="button" id="sf-log-reset" class="button sf-btn-danger">
						<span class="dashicons dashicons-trash"></span>
						<?php esc_html_e( 'Reset All Data', 'securefusion' ); ?>
					</button>
				</div>
			</div>

			<div class="sf-log-table-wrap">
				<?php if ( $range_filter ) : ?>
					<div class="sf-active-filter">
						<span class="dashicons dashicons-filter"></span>
						<?php
						printf(
							/* translators: %s: IP range prefix. */
							esc_html__( 'Filtered by range: %s', 'securefusion' ),
							'<strong>' . esc_html( $range_filter ) . '.0/24</strong>'
						);
						?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=securefusion-login-log' ) ); ?>" class="sf-filter-clear-link">
							<?php esc_html_e( 'Show all', 'securefusion' ); ?>
						</a>
					</div>
				<?php endif; ?>

				<?php if ( $total_rows > 0 ) : ?>
					<table class="wp-list-table widefat fixed striped sf-log-table">
						<thead>
							<tr>
								<?php
								$columns = [
									'ip'           => esc_html__( 'IP Address', 'securefusion' ),
									'attempts'     => esc_html__( 'Attempts', 'securefusion' ),
									'last_attempt' => esc_html__( 'Last Attempt', 'securefusion' ),
								];

								foreach ( $columns as $col_key => $col_label ) :
									$is_sorted  = ( $orderby === $col_key );
									$next_order = $is_sorted && $order === 'ASC' ? 'DESC' : 'ASC';
									$sort_url   = add_query_arg(
										[
											'orderby' => $col_key,
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
							</tr>
						</thead>
						<tbody id="sf-log-tbody">
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="column-ip">
										<code><?php echo esc_html( $row->ip ); ?></code>
									</td>
									<td class="column-attempts">
										<span class="sf-attempt-badge <?php echo (int) $row->attempts >= 10 ? 'sf-danger' : ( (int) $row->attempts >= 5 ? 'sf-warning' : 'sf-normal' ); ?>">
											<?php echo (int) $row->attempts; ?>
										</span>
									</td>
									<td class="column-last_attempt">
										<?php
										$timestamp = (int) $row->last_attempt;
										if ( $timestamp > 0 ) {
											echo esc_html(
												wp_date(
													get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
													$timestamp
												)
											);
											echo '<br><small class="sf-time-ago">';
											echo esc_html( human_time_diff( $timestamp, time() ) . ' ' . __( 'ago', 'securefusion' ) );
											echo '</small>';
										} else {
											echo '—';
										}
										?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>

					<?php if ( $total_pages > 1 ) : ?>
						<div class="sf-log-pagination">
							<span class="sf-pagination-info">
								<?php
								printf(
									/* translators: 1: Current page, 2: Total pages, 3: Total items. */
									esc_html__( 'Page %1$s of %2$s (%3$s items)', 'securefusion' ),
									number_format_i18n( $current_page ),
									number_format_i18n( $total_pages ),
									number_format_i18n( $total_rows )
								);
								?>
							</span>
							<span class="sf-pagination-links">
								<?php
								// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links() returns safe HTML.
								echo paginate_links(
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
								);
								?>
							</span>
						</div>
					<?php endif; ?>

				<?php else : ?>
					<div class="sf-log-empty">
						<span class="dashicons dashicons-shield-alt"></span>
						<p>
							<?php if ( $range_filter ) : ?>
								<?php esc_html_e( 'No records found for this IP range.', 'securefusion' ); ?>
							<?php else : ?>
								<?php esc_html_e( 'No failed login attempts recorded yet. Your site is clean!', 'securefusion' ); ?>
							<?php endif; ?>
						</p>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}
