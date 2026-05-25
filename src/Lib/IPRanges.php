<?php
/**
 * IPRanges Class
 *
 * Handles the IP Ranges page with listing, pagination, and exporting as a txt list.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

/**
 * IPRanges functionality class.
 */
class IPRanges {

	use WPCommon;

	/**
	 * Nonce action for AJAX operations.
	 *
	 * @var string
	 */
	const NONCE_ACTION = 'securefusion_ip_ranges';

	/**
	 * Rows per page.
	 *
	 * @var int
	 */
	const PER_PAGE = 20;

	/**
	 * Enqueue page-specific assets.
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		// Reusing some of the security-log styles.
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
				'nonce'          => wp_create_nonce( \SecureFusion\Lib\SecurityLog::NONCE_ACTION ),
				'confirmReset'   => esc_html__( 'WARNING: This action is irreversible! All failed login attempt data will be permanently deleted. Are you absolutely sure?', 'secuplug' ),
				'confirmImport'  => esc_html__( 'Importing data will add records to the existing table. Continue?', 'secuplug' ),
				'resetSuccess'   => esc_html__( 'All data has been deleted successfully.', 'secuplug' ),
				'exportEmpty'    => esc_html__( 'No data to export.', 'secuplug' ),
				'importSuccess'  => esc_html__( 'Import completed successfully.', 'secuplug' ),
				'importError'    => esc_html__( 'Import failed. Please check the file format.', 'secuplug' ),
				'invalidFile'    => esc_html__( 'Please select a valid JSON file.', 'secuplug' ),
				'processing'     => esc_html__( 'Processing...', 'secuplug' ),
				'copied'         => esc_html__( 'Copied to clipboard!', 'secuplug' ),
				'copyFailed'     => esc_html__( 'Copy failed. Please select and copy manually.', 'secuplug' ),
				'blockSuccess'   => esc_html__( 'IP range has been blocked.', 'secuplug' ),
				'unblockSuccess' => esc_html__( 'IP range has been unblocked.', 'secuplug' ),
				'blockFailed'    => esc_html__( 'IP range block/unblock operation failed.', 'secuplug' ),
				'confirmBlock'   => esc_html__( 'Are you sure you want to block this IP range?', 'secuplug' ),
			]
		);
	}


	/**
	 * Render the IP ranges page HTML.
	 *
	 * @return void
	 */
	public function render() {
		$db = new BruteForceDB();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$current_page = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( $_GET['orderby'] ) : 'ip_count';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$order = isset( $_GET['order'] ) ? ( strtoupper( sanitize_key( $_GET['order'] ) ) === 'ASC' ? 'ASC' : 'DESC' ) : 'DESC';

		$offset      = ( $current_page - 1 ) * self::PER_PAGE;
		$total_rows  = $db->get_total_ip_ranges();
		$total_pages = (int) ceil( $total_rows / self::PER_PAGE );

		$rows = $db->get_paginated_ip_ranges( self::PER_PAGE, $offset, $orderby, $order );

		$page_url = admin_url( 'admin.php?page=securefusion-ip-ranges' );

		$this->enqueue_assets();
		?>
		<div class="wrap fynd-sf-login-log fynd-sf-ip-ranges">
			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'IP Ranges', 'secuplug' ); ?></h1>

			<?php
			$txt_btn = '<button type="button" id="fynd-sf-open-txt-list-btn" class="fynd-sf-btn fynd-sf-btn-primary">' .
				'<span class="dashicons dashicons-list-view"></span> ' .
				esc_html__( 'IP Range TXT List', 'secuplug' ) .
				'</button>';

			$this->render_header(
				esc_html__( 'IP Ranges Management', 'secuplug' ),
				esc_html__( 'View and manage IP subnets that have generated failed login attempts.', 'secuplug' ),
				[ $txt_btn ]
			);
			?>

			<div class="fynd-sf-log-table-wrap" style="margin-top: 20px;">
				<?php if ( $total_rows > 0 ) : ?>
					<table class="wp-list-table widefat fixed striped fynd-sf-log-table">
						<thead>
							<tr>
								<?php
								$columns = [
									'range_prefix'   => esc_html__( 'IP Range', 'secuplug' ),
									'ip_count'       => esc_html__( 'Unique IPs', 'secuplug' ),
									'total_attempts' => esc_html__( 'Total Attempts', 'secuplug' ),
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
								<th scope="col" class="manage-column column-actions"><?php esc_html_e( 'Actions', 'secuplug' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $rows as $row ) : ?>
								<?php
								$cidr             = $this->calculate_cidr( $row->range_prefix, $row->min_last_octet, $row->max_last_octet );
								$is_range_blocked = $db->is_range_blocked( $cidr );
								$range_url        = add_query_arg(
									[
										'range' => $row->range_prefix,
										'paged' => 1,
									],
									admin_url( 'admin.php?page=securefusion-security-log' )
								);
								?>
								<tr>
									<td class="column-range_prefix column-ip">
										<strong><code><?php echo esc_html( $cidr ); ?></code></strong>
									</td>
									<td class="column-ip_count column-attempts">
										<span class="fynd-sf-attempt-badge fynd-sf-normal">
											<?php echo (int) $row->ip_count; ?>
										</span>
									</td>
									<td class="column-total_attempts column-last_attempt">
										<span class="fynd-sf-attempt-badge <?php echo (int) $row->total_attempts >= 50 ? 'fynd-sf-danger' : ( (int) $row->total_attempts >= 20 ? 'fynd-sf-warning' : 'fynd-sf-normal' ); ?>">
											<?php echo (int) $row->total_attempts; ?>
										</span>
									</td>
									<td class="column-actions">
										<div class="fynd-sf-actions-wrap">
											<a href="<?php echo esc_url( $range_url ); ?>" class="fynd-sf-btn fynd-sf-btn-secondary">
												<span class="dashicons dashicons-filter"></span>
												<?php esc_html_e( 'Logs', 'secuplug' ); ?>
											</a>
											<button type="button" class="fynd-sf-btn fynd-sf-btn-secondary fynd-sf-range-detail-btn" data-range="<?php echo esc_attr( $row->range_prefix ); ?>">
												<span class="dashicons dashicons-visibility"></span>
												<?php esc_html_e( 'List', 'secuplug' ); ?>
											</button>
											<?php if ( $is_range_blocked ) : ?>
												<button type="button" class="fynd-sf-btn fynd-sf-btn-unblock" data-ip="<?php echo esc_attr( $cidr ); ?>" data-action="unblock">
													<span class="dashicons dashicons-unlock"></span>
													<?php esc_html_e( 'Unblock', 'secuplug' ); ?>
												</button>
											<?php else : ?>
												<button type="button" class="fynd-sf-btn fynd-sf-btn-block" data-ip="<?php echo esc_attr( $cidr ); ?>" data-action="block">
													<span class="dashicons dashicons-lock"></span>
													<?php esc_html_e( 'Block', 'secuplug' ); ?>
												</button>
											<?php endif; ?>
										</div>
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
						<p><?php esc_html_e( 'No IP ranges found. Your site is clean!', 'secuplug' ); ?></p>
					</div>
				<?php endif; ?>
			</div>

			<!-- IP Range Detail Modal -->
			<div id="fynd-sf-range-modal" class="fynd-sf-modal" style="display:none;">
				<div class="fynd-sf-modal-content">
					<div class="fynd-sf-modal-header">
						<h3 id="fynd-sf-range-modal-title" class="fynd-sf-modal-title"><?php esc_html_e( 'IPs in Range', 'secuplug' ); ?></h3>
						<button type="button" class="fynd-sf-modal-close">&times;</button>
					</div>
					<div class="fynd-sf-modal-body">
						<textarea id="fynd-sf-range-modal-textarea" readonly class="fynd-sf-modal-textarea"></textarea>
					</div>
					<div class="fynd-sf-modal-footer">
						<button type="button" class="fynd-sf-btn fynd-sf-btn-primary fynd-sf-modal-copy-btn">
							<span class="dashicons dashicons-clipboard"></span>
							<span class="fynd-sf-modal-copy-btn-text"><?php esc_html_e( 'Copy IP List', 'secuplug' ); ?></span>
						</button>
						<button type="button" class="fynd-sf-modal-close-btn fynd-sf-btn fynd-sf-btn-secondary">
							<?php esc_html_e( 'Close', 'secuplug' ); ?>
						</button>
					</div>
				</div>
			</div>

			<!-- IP Range TXT List Modal -->
			<?php
			$all_ranges = $db->get_ip_ranges();
			$txt_list   = '';
			if ( is_array( $all_ranges ) ) {
				foreach ( $all_ranges as $range ) {
					$cidr      = $this->calculate_cidr( $range->range_prefix, $range->min_last_octet, $range->max_last_octet );
					$txt_list .= $cidr . "\n";
				}
			}
			?>
			<div id="fynd-sf-txt-list-modal" class="fynd-sf-modal" style="display:none;">
				<div class="fynd-sf-modal-content">
					<div class="fynd-sf-modal-header">
						<h3 class="fynd-sf-modal-title"><?php esc_html_e( 'IP Range TXT List', 'secuplug' ); ?></h3>
						<button type="button" class="fynd-sf-modal-close">&times;</button>
					</div>
					<div class="fynd-sf-modal-body">
						<textarea readonly class="fynd-sf-modal-textarea"><?php echo esc_textarea( $txt_list ); ?></textarea>
					</div>
					<div class="fynd-sf-modal-footer">
						<button type="button" class="fynd-sf-btn fynd-sf-btn-primary fynd-sf-modal-copy-btn">
							<span class="dashicons dashicons-clipboard"></span>
							<span class="fynd-sf-modal-copy-btn-text"><?php esc_html_e( 'Copy List', 'secuplug' ); ?></span>
						</button>
						<button type="button" class="fynd-sf-modal-close-btn fynd-sf-btn fynd-sf-btn-secondary">
							<?php esc_html_e( 'Close', 'secuplug' ); ?>
						</button>
					</div>
				</div>
			</div>
		</div>
		<?php
	}
}
