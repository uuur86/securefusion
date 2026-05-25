<?php
/**
 * SecurityLog Class
 *
 * Handles the security log page with listing, type-based filtering,
 * reset (delete by type), JSON export, import, IP block toggle,
 * and IP range analysis.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

/**
 * SecurityLog functionality class.
 */
class SecurityLog {

	use WPCommon;

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
	 * Get available log type options for the selector.
	 *
	 * @return array Associative array of type_value => label.
	 */
	private function get_log_type_options() {
		return [
			''                                  => esc_html__( 'All Types', 'securefusion' ),
			BruteForceDB::TYPE_FAILED_LOGIN     => esc_html__( 'Failed Login', 'securefusion' ),
			BruteForceDB::TYPE_SUCCESSFUL_LOGIN => esc_html__( 'Successful Login', 'securefusion' ),
			BruteForceDB::TYPE_BAD_REQUEST      => esc_html__( 'Bad Request', 'securefusion' ),
			BruteForceDB::TYPE_BAD_COOKIE       => esc_html__( 'Bad Cookie', 'securefusion' ),
			BruteForceDB::TYPE_BAD_BOT          => esc_html__( 'Bad Bot', 'securefusion' ),
			BruteForceDB::TYPE_BAD_QUERY        => esc_html__( 'Bad Query', 'securefusion' ),
			BruteForceDB::TYPE_BLOCKED          => esc_html__( 'Blocked', 'securefusion' ),
		];
	}


	/**
	 * Get display label for a log type.
	 *
	 * @param string $type Canonical log type.
	 * @return string Human-readable label.
	 */
	private function get_log_type_label( $type ) {
		$options = $this->get_log_type_options();
		$type    = BruteForceDB::normalize_log_type( $type );
		return isset( $options[ $type ] ) ? $options[ $type ] : ucfirst( str_replace( '_', ' ', $type ) );
	}


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
		add_action( 'wp_ajax_securefusion_toggle_ip_block', [ $this, 'ajax_toggle_ip_block' ] );
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
			'securefusionLog',
			[
				'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
				'nonce'          => wp_create_nonce( self::NONCE_ACTION ),
				'confirmReset'   => esc_html__( 'WARNING: This action is irreversible! Selected log data will be permanently deleted. Are you absolutely sure?', 'securefusion' ),
				'confirmImport'  => esc_html__( 'Importing data will add records to the existing table. Continue?', 'securefusion' ),
				'resetSuccess'   => esc_html__( 'Data has been deleted successfully.', 'securefusion' ),
				'exportEmpty'    => esc_html__( 'No data to export.', 'securefusion' ),
				'importSuccess'  => esc_html__( 'Import completed successfully.', 'securefusion' ),
				'importError'    => esc_html__( 'Import failed. Please check the file format.', 'securefusion' ),
				'invalidFile'    => esc_html__( 'Please select a valid JSON file.', 'securefusion' ),
				'processing'     => esc_html__( 'Processing...', 'securefusion' ),
				'copied'         => esc_html__( 'Copied to clipboard!', 'securefusion' ),
				'copyFailed'     => esc_html__( 'Copy failed. Please select and copy manually.', 'securefusion' ),
				'blockSuccess'   => esc_html__( 'IP has been blocked.', 'securefusion' ),
				'unblockSuccess' => esc_html__( 'IP has been unblocked.', 'securefusion' ),
				'blockFailed'    => esc_html__( 'IP block/unblock operation failed.', 'securefusion' ),
				'confirmBlock'   => esc_html__( 'Are you sure you want to block this IP?', 'securefusion' ),
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
	 * AJAX: Reset (delete) log data by type or all.
	 *
	 * @return void
	 */
	public function ajax_reset() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Already verified above.
		$log_type = isset( $_POST['log_type'] ) ? sanitize_text_field( wp_unslash( $_POST['log_type'] ) ) : '';

		$db      = new BruteForceDB();
		$success = $db->delete_by_type( $log_type );

		if ( $success ) {
			wp_send_json_success( [ 'message' => esc_html__( 'Data has been deleted.', 'securefusion' ) ] );
		} else {
			wp_send_json_error( [ 'message' => esc_html__( 'Failed to delete data.', 'securefusion' ) ] );
		}
	}


	/**
	 * AJAX: Export log data as JSON (filtered by type).
	 *
	 * @return void
	 */
	public function ajax_export() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Already verified above.
		$log_type = isset( $_POST['log_type'] ) ? sanitize_text_field( wp_unslash( $_POST['log_type'] ) ) : '';

		$db   = new BruteForceDB();
		$rows = $db->get_all_rows_for_export( $log_type );

		$export = [];
		foreach ( $rows as $row ) {
			$export[] = [
				'ip'             => $row->ip,
				'attempts'       => (int) $row->attempts,
				'last_attempt'   => (int) $row->last_attempt,
				'log_type'       => $row->log_type ?? 'failed_login',
				'user_agent'     => $row->user_agent ?? '',
				'payload'        => $row->payload ?? '',
				'is_blocked'     => (int) ( $row->is_blocked ?? 0 ),
				'is_whitelisted' => (int) ( $row->is_whitelisted ?? 0 ),
			];
		}

		$type_suffix = $log_type ? '-' . $log_type : '';

		wp_send_json_success(
			[
				'data'     => $export,
				'filename' => 'securefusion-log' . $type_suffix . '-' . gmdate( 'Y-m-d' ) . '.json',
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

		// phpcs:ignore -- Already sanitized and validated with validate_ajax_request function.
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

		// phpcs:ignore -- Already sanitized and validated with validate_ajax_request function.
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
				'ips'   => $ip_list,
				'range' => $range_prefix . '.0/24',
				/* translators: %d: Number of IPs in the range. */
				'title' => sprintf( esc_html__( '%1$d IPs in range %2$s', 'securefusion' ), count( $ip_list ), $range_prefix . '.0/24' ),
			]
		);
	}


	/**
	 * AJAX: Toggle IP block/unblock status.
	 *
	 * @return void
	 */
	public function ajax_toggle_ip_block() {
		if ( ! $this->validate_ajax_request() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Already verified above.
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Already verified above.
		$action = isset( $_POST['block_action'] ) ? sanitize_text_field( wp_unslash( $_POST['block_action'] ) ) : '';

		$is_valid_ip   = filter_var( $ip, FILTER_VALIDATE_IP );
		$is_valid_cidr = false;
		if ( ! $is_valid_ip && preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $ip ) ) {
			list( $subnet, $mask ) = explode( '/', $ip );
			if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && $mask >= 0 && $mask <= 32 ) {
				$is_valid_cidr = true;
			}
		}

		if ( ! $is_valid_ip && ! $is_valid_cidr ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid IP address or range.', 'securefusion' ) ] );
			return;
		}

		$db = new BruteForceDB();

		if ( $action === 'block' ) {
			if ( $db->is_ip_whitelisted( $ip ) ) {
				wp_send_json_error( [ 'message' => esc_html__( 'This IP is whitelisted and cannot be blocked.', 'securefusion' ) ] );
				return;
			}

			$success = $db->block_ip( $ip );

			if ( $success ) {
				wp_send_json_success(
					[
						'message'    => esc_html__( 'IP has been blocked.', 'securefusion' ),
						'new_status' => 'blocked',
					]
				);
			}
		} elseif ( $action === 'unblock' ) {
			$success = $db->unblock_ip( $ip );

			if ( $success ) {
				wp_send_json_success(
					[
						'message'    => esc_html__( 'IP has been unblocked.', 'securefusion' ),
						'new_status' => 'active',
					]
				);
			}
		}

		wp_send_json_error( [ 'message' => esc_html__( 'Operation failed.', 'securefusion' ) ] );
	}


	/**
	 * Normalize the order parameter.
	 *
	 * The sanitize_key() function lowercases the value, so we must normalize to uppercase
	 * before any comparison.
	 *
	 * @param string $order Raw order value (may be lowercase from sanitize_key).
	 * @return string 'ASC' or 'DESC'.
	 */
	private function normalize_order( $order ) {
		return strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
	}


	/**
	 * Render the security log page HTML.
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
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only filter parameter.
		$type_filter = isset( $_GET['log_type'] ) ? sanitize_text_field( wp_unslash( $_GET['log_type'] ) ) : '';

		$offset      = ( $current_page - 1 ) * self::PER_PAGE;
		$total_rows  = $range_filter
			? $db->get_total_rows_by_range( $range_filter, $type_filter )
			: $db->get_total_rows( $type_filter );
		$total_pages = (int) ceil( $total_rows / self::PER_PAGE );

		if ( $range_filter ) {
			$rows = $db->get_rows_by_range( $range_filter, self::PER_PAGE, $offset, $orderby, $order, $type_filter );
		} else {
			$rows = $db->get_all_rows( self::PER_PAGE, $offset, $orderby, $order, $type_filter );
		}

		$page_url = admin_url( 'admin.php?page=securefusion-security-log' );

		// Preserve filters in sort/page URLs.
		if ( $range_filter ) {
			$page_url = add_query_arg( 'range', $range_filter, $page_url );
		}
		if ( $type_filter ) {
			$page_url = add_query_arg( 'log_type', $type_filter, $page_url );
		}

		$this->enqueue_assets();
		?>
		<div class="wrap fynd-sf-login-log">
			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'Security Log', 'securefusion' ); ?></h1>

			<?php
			$this->render_header(
				esc_html__( 'Security Log', 'securefusion' ),
				esc_html__( 'Monitor and manage security events, blocked IPs, and attack records.', 'securefusion' )
			);
			?>

			<div id="fynd-sf-log-notice" class="fynd-sf-log-notice" style="display:none;"></div>

			<div class="fynd-sf-log-stats">
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-shield"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts(); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Total Attacks', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-lock"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'failed_login' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Failed Logins', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-warning"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_request' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Requests', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-excerpt-view"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_cookie' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Cookies', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-networking"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_bot' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Bots', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-search"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_query' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Queries', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-admin-site-alt3"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_unique_ips_count(); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Unique IPs', 'securefusion' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-database"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $total_rows; ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Total Records', 'securefusion' ); ?></span>
					</div>
				</div>
			</div>


			<div class="fynd-sf-log-toolbar">
				<div class="fynd-sf-toolbar-left">
					<select id="fynd-sf-filter-log-type" class="fynd-sf-type-select">
						<?php foreach ( $this->get_log_type_options() as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $type_filter, $value ); ?>>
								<?php echo esc_html( $label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
					<button type="button" id="fynd-sf-log-export" class="fynd-sf-btn fynd-sf-btn-secondary">
						<span class="dashicons dashicons-download"></span>
						<?php esc_html_e( 'Export JSON', 'securefusion' ); ?>
					</button>
					<label for="fynd-sf-log-import-file" class="fynd-sf-btn fynd-sf-btn-secondary fynd-sf-import-label">
						<span class="dashicons dashicons-upload"></span>
						<?php esc_html_e( 'Import JSON', 'securefusion' ); ?>
					</label>
					<input type="file" id="fynd-sf-log-import-file" accept=".json" class="fynd-sf-hidden-file">
				</div>
				<div class="fynd-sf-toolbar-right">
					<button type="button" id="fynd-sf-log-reset" class="fynd-sf-btn fynd-sf-btn-danger">
						<span class="dashicons dashicons-trash"></span>
						<?php esc_html_e( 'Delete Data', 'securefusion' ); ?>
					</button>
				</div>
			</div>

			<div class="fynd-sf-log-table-wrap">
				<?php if ( $range_filter ) : ?>
					<div class="fynd-sf-active-filter">
						<span class="dashicons dashicons-filter"></span>
						<?php
						printf(
							/* translators: %s: IP range prefix. */
							esc_html__( 'Filtered by range: %s', 'securefusion' ),
							'<strong>' . esc_html( $range_filter ) . '.0/24</strong>'
						);
						?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=securefusion-security-log' . ( $type_filter ? '&log_type=' . $type_filter : '' ) ) ); ?>" class="fynd-sf-filter-clear-link">
							<?php esc_html_e( 'Show all', 'securefusion' ); ?>
						</a>
					</div>
				<?php endif; ?>

				<?php if ( $total_rows > 0 ) : ?>
					<table class="wp-list-table widefat fixed striped fynd-sf-log-table">
						<thead>
							<tr>
								<?php
								$columns = [
									'ip'           => esc_html__( 'IP Address', 'securefusion' ),
									'log_type'     => esc_html__( 'Attack Type', 'securefusion' ),
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
								<th scope="col" class="manage-column column-status"><?php esc_html_e( 'Status', 'securefusion' ); ?></th>
								<th scope="col" class="manage-column column-actions"><?php esc_html_e( 'Actions', 'securefusion' ); ?></th>
							</tr>
						</thead>
						<tbody id="fynd-sf-log-tbody">
							<?php foreach ( $rows as $row ) : ?>
								<?php
								$is_blocked     = ! empty( $row->is_blocked );
								$is_whitelisted = ! empty( $row->is_whitelisted );
								$row_log_type   = isset( $row->log_type ) ? $row->log_type : 'failed_login';
								$row_ua         = isset( $row->user_agent ) ? $row->user_agent : '';
								$row_payload    = isset( $row->payload ) ? $row->payload : '';
								?>
								<tr data-ip="<?php echo esc_attr( $row->ip ); ?>">
									<td class="column-ip">
										<code><?php echo esc_html( $row->ip ); ?></code>
										<?php if ( $row_ua ) : ?>
											<div class="fynd-sf-meta-line" title="<?php echo esc_attr( $row_ua ); ?>">
												<span class="dashicons dashicons-laptop"></span>
												<span class="fynd-sf-meta-text"><?php echo esc_html( mb_substr( $row_ua, 0, 60 ) ); ?><?php echo strlen( $row_ua ) > 60 ? '…' : ''; ?></span>
											</div>
										<?php endif; ?>
										<?php if ( $row_payload ) : ?>
											<div class="fynd-sf-meta-line" title="<?php echo esc_attr( $row_payload ); ?>">
												<span class="dashicons dashicons-editor-code"></span>
												<span class="fynd-sf-meta-text"><?php echo esc_html( mb_substr( $row_payload, 0, 60 ) ); ?><?php echo strlen( $row_payload ) > 60 ? '…' : ''; ?></span>
												<button type="button" class="fynd-sf-view-payload-btn" data-payload="<?php echo esc_attr( $row_payload ); ?>" title="<?php esc_attr_e( 'View Payload Details', 'securefusion' ); ?>">
													<span class="dashicons dashicons-visibility"></span>
												</button>
											</div>
										<?php endif; ?>
									</td>
									<td class="column-log_type">
										<span class="fynd-sf-type-badge fynd-sf-type-<?php echo esc_attr( $row_log_type ); ?>">
											<?php echo esc_html( $this->get_log_type_label( $row_log_type ) ); ?>
										</span>
									</td>
									<td class="column-attempts">
										<span class="fynd-sf-attempt-badge <?php echo (int) $row->attempts >= 10 ? 'fynd-sf-danger' : ( (int) $row->attempts >= 5 ? 'fynd-sf-warning' : 'fynd-sf-normal' ); ?>">
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
											echo '<br><small class="fynd-sf-time-ago">';
											echo esc_html( human_time_diff( $timestamp, time() ) . ' ' . __( 'ago', 'securefusion' ) );
											echo '</small>';
										} else {
											echo '—';
										}
										?>
									</td>
									<td class="column-status">
										<?php if ( $is_whitelisted ) : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-whitelisted"><?php esc_html_e( 'Whitelisted', 'securefusion' ); ?></span>
										<?php elseif ( $is_blocked ) : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-blocked"><?php esc_html_e( 'Blocked', 'securefusion' ); ?></span>
										<?php else : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-active"><?php esc_html_e( 'Active', 'securefusion' ); ?></span>
										<?php endif; ?>
									</td>
									<td class="column-actions">
										<?php if ( $is_whitelisted ) : ?>
											<span class="fynd-sf-action-protected" title="<?php esc_attr_e( 'Admin IP — Cannot be blocked', 'securefusion' ); ?>">
												<span class="dashicons dashicons-shield-alt"></span>
											</span>
										<?php elseif ( $is_blocked ) : ?>
											<button type="button" class="fynd-sf-btn fynd-sf-btn-sm fynd-sf-btn-unblock" data-ip="<?php echo esc_attr( $row->ip ); ?>" data-action="unblock">
												<span class="dashicons dashicons-unlock"></span>
												<?php esc_html_e( 'Unblock', 'securefusion' ); ?>
											</button>
										<?php else : ?>
											<button type="button" class="fynd-sf-btn fynd-sf-btn-sm fynd-sf-btn-block" data-ip="<?php echo esc_attr( $row->ip ); ?>" data-action="block">
												<span class="dashicons dashicons-lock"></span>
												<?php esc_html_e( 'Block', 'securefusion' ); ?>
											</button>
										<?php endif; ?>
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
									esc_html__( 'Page %1$s of %2$s (%3$s items)', 'securefusion' ),
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
						<p>
							<?php if ( $range_filter || $type_filter ) : ?>
								<?php esc_html_e( 'No records found for the current filter.', 'securefusion' ); ?>
							<?php else : ?>
								<?php esc_html_e( 'No security events recorded yet. Your site is clean!', 'securefusion' ); ?>
							<?php endif; ?>
						</p>
					</div>
				<?php endif; ?>
			</div>

			<!-- Payload Details Modal -->
			<div id="fynd-sf-payload-modal" class="fynd-sf-modal" style="display: none;">
				<div class="fynd-sf-modal-content">
					<div class="fynd-sf-modal-header">
						<h3 class="fynd-sf-modal-title"><?php esc_html_e( 'Payload Details', 'securefusion' ); ?></h3>
						<button type="button" class="fynd-sf-modal-close">&times;</button>
					</div>
					<div class="fynd-sf-modal-body">
						<textarea id="fynd-sf-payload-text" readonly class="fynd-sf-modal-textarea"></textarea>
					</div>
					<div class="fynd-sf-modal-footer">
						<button type="button" class="fynd-sf-btn fynd-sf-btn-primary fynd-sf-modal-copy-btn">
							<span class="dashicons dashicons-clipboard"></span>
							<span class="fynd-sf-modal-copy-btn-text"><?php esc_html_e( 'Copy Payload', 'securefusion' ); ?></span>
						</button>
						<button type="button" class="fynd-sf-modal-close-btn fynd-sf-btn fynd-sf-btn-secondary">
							<?php esc_html_e( 'Close', 'securefusion' ); ?>
						</button>
					</div>
				</div>
			</div>
		</div>
		<?php
	}
}
