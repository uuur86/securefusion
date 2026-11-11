<?php
/**
 * SecurityLogView responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * SecurityLogView methods.
 *
 * @mixin SecurityLog
 * @method void enqueue_assets() Load the log page assets.
 * @method void render_header( string $title, string $description, array $custom_actions = [] ) Page header.
 * @method string normalize_order( string $order ) Normalize a sort direction.
 * @method array get_log_type_options() Log type labels keyed by type.
 * @method string get_log_type_label( string $type ) Label for one log type.
 */
trait SecurityLogView {

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

		$offset     = ( $current_page - 1 ) * SecurityLog::PER_PAGE;
		$total_rows = $range_filter
			? $db->get_total_rows_by_range( $range_filter, $type_filter )
			: $db->get_total_rows( $type_filter );

		$total_pages = (int) ceil( $total_rows / SecurityLog::PER_PAGE );

		if ( $range_filter ) {

			$rows = $db->get_rows_by_range( $range_filter, SecurityLog::PER_PAGE, $offset, $orderby, $order, $type_filter );

		} else {

			$rows = $db->get_all_rows( SecurityLog::PER_PAGE, $offset, $orderby, $order, $type_filter );

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
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'Security Log', 'secuplug' ); ?></h1>

			<?php
			$this->render_header(
				esc_html__( 'Security Log', 'secuplug' ),
				esc_html__( 'Monitor and manage security events, blocked IPs, and attack records.', 'secuplug' )
			);
			?>

			<div id="fynd-sf-log-notice" class="fynd-sf-log-notice" style="display:none;"></div>

			<div class="fynd-sf-log-stats">
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-shield"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts(); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Total Attacks', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-lock"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'failed_login' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Failed Logins', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-warning"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_request' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Requests', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-excerpt-view"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_cookie' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Cookies', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-networking"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_bot' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Bots', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-search"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_total_attempts_by_type( 'bad_query' ); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Bad Queries', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-admin-site-alt3"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $db->get_unique_ips_count(); ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Unique IPs', 'secuplug' ); ?></span>
					</div>
				</div>
				<div class="fynd-sf-stat-card">
					<span class="fynd-sf-stat-icon dashicons dashicons-database"></span>
					<div class="fynd-sf-stat-data">
						<span class="fynd-sf-stat-value"><?php echo (int) $total_rows; ?></span>
						<span class="fynd-sf-stat-label"><?php esc_html_e( 'Total Records', 'secuplug' ); ?></span>
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
						<?php esc_html_e( 'Export JSON', 'secuplug' ); ?>
					</button>
					<label for="fynd-sf-log-import-file" class="fynd-sf-btn fynd-sf-btn-secondary fynd-sf-import-label">
						<span class="dashicons dashicons-upload"></span>
						<?php esc_html_e( 'Import JSON', 'secuplug' ); ?>
					</label>
					<input type="file" id="fynd-sf-log-import-file" accept=".json" class="fynd-sf-hidden-file">
				</div>
				<div class="fynd-sf-toolbar-right">
					<button type="button" id="fynd-sf-log-reset" class="fynd-sf-btn fynd-sf-btn-danger">
						<span class="dashicons dashicons-trash"></span>
						<?php esc_html_e( 'Delete Data', 'secuplug' ); ?>
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
							esc_html__( 'Filtered by range: %s', 'secuplug' ),
							'<strong>' . esc_html( $range_filter ) . '.0/24</strong>'
						);
						?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=securefusion-security-log' . ( $type_filter ? '&log_type=' . $type_filter : '' ) ) ); ?>" class="fynd-sf-filter-clear-link">
							<?php esc_html_e( 'Show all', 'secuplug' ); ?>
						</a>
					</div>
				<?php endif; ?>

				<?php if ( $total_rows > 0 ) : ?>
					<table class="wp-list-table widefat fixed striped fynd-sf-log-table">
						<thead>
							<tr>
								<?php
								$columns = [
									'ip'           => esc_html__( 'IP Address', 'secuplug' ),
									'log_type'     => esc_html__( 'Attack Type', 'secuplug' ),
									'attempts'     => esc_html__( 'Attempts', 'secuplug' ),
									'last_attempt' => esc_html__( 'Last Attempt', 'secuplug' ),
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
								<th scope="col" class="manage-column column-status"><?php esc_html_e( 'Status', 'secuplug' ); ?></th>
								<th scope="col" class="manage-column column-actions"><?php esc_html_e( 'Actions', 'secuplug' ); ?></th>
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
												<button type="button" class="fynd-sf-view-payload-btn" data-payload="<?php echo esc_attr( $row_payload ); ?>" title="<?php esc_attr_e( 'View Payload Details', 'secuplug' ); ?>">
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

											echo esc_html( human_time_diff( $timestamp, time() ) . ' ' . __( 'ago', 'secuplug' ) );

											echo '</small>';

										} else {

											echo '—';

										}
										?>
									</td>
									<td class="column-status">
										<?php if ( $is_whitelisted ) : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-whitelisted"><?php esc_html_e( 'Whitelisted', 'secuplug' ); ?></span>
										<?php elseif ( $is_blocked ) : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-blocked"><?php esc_html_e( 'Blocked', 'secuplug' ); ?></span>
										<?php else : ?>
											<span class="fynd-sf-status-badge fynd-sf-status-active"><?php esc_html_e( 'Active', 'secuplug' ); ?></span>
										<?php endif; ?>
									</td>
									<td class="column-actions">
										<?php if ( $is_whitelisted ) : ?>
											<span class="fynd-sf-action-protected" title="<?php esc_attr_e( 'Admin IP — Cannot be blocked', 'secuplug' ); ?>">
												<span class="dashicons dashicons-shield-alt"></span>
											</span>
										<?php elseif ( $is_blocked ) : ?>
											<button type="button" class="fynd-sf-btn fynd-sf-btn-sm fynd-sf-btn-unblock" data-ip="<?php echo esc_attr( $row->ip ); ?>" data-action="unblock">
												<span class="dashicons dashicons-unlock"></span>
												<?php esc_html_e( 'Unblock', 'secuplug' ); ?>
											</button>
										<?php else : ?>
											<button type="button" class="fynd-sf-btn fynd-sf-btn-sm fynd-sf-btn-block" data-ip="<?php echo esc_attr( $row->ip ); ?>" data-action="block">
												<span class="dashicons dashicons-lock"></span>
												<?php esc_html_e( 'Block', 'secuplug' ); ?>
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
						<p>
							<?php if ( $range_filter || $type_filter ) : ?>
								<?php esc_html_e( 'No records found for the current filter.', 'secuplug' ); ?>
							<?php else : ?>
								<?php esc_html_e( 'No security events recorded yet. Your site is clean!', 'secuplug' ); ?>
							<?php endif; ?>
						</p>
					</div>
				<?php endif; ?>
			</div>

			<!-- Payload Details Modal -->
			<div id="fynd-sf-payload-modal" class="fynd-sf-modal" style="display: none;">
				<div class="fynd-sf-modal-content">
					<div class="fynd-sf-modal-header">
						<h3 class="fynd-sf-modal-title"><?php esc_html_e( 'Payload Details', 'secuplug' ); ?></h3>
						<button type="button" class="fynd-sf-modal-close">&times;</button>
					</div>
					<div class="fynd-sf-modal-body">
						<textarea id="fynd-sf-payload-text" readonly class="fynd-sf-modal-textarea"></textarea>
					</div>
					<div class="fynd-sf-modal-footer">
						<button type="button" class="fynd-sf-btn fynd-sf-btn-primary fynd-sf-modal-copy-btn">
							<span class="dashicons dashicons-clipboard"></span>
							<span class="fynd-sf-modal-copy-btn-text"><?php esc_html_e( 'Copy Payload', 'secuplug' ); ?></span>
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
