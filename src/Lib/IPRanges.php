<?php
/**
 * IPRanges Class
 *
 * Handles the IP Ranges page with listing, pagination, and exporting as a txt list.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

/**
 * IPRanges Class
 *
 * @package securefusion
 */
class IPRanges {

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
		// Reusing some of the login-log styles and adding specific ones if needed.
		wp_enqueue_style(
			'securefusion-login-log-css',
			plugins_url( 'assets/css/login-log.css', SECUREFUSION_BASENAME ),
			[],
			SECUREFUSION_VERSION
		);
	}

	/**
	 * Calculate the smallest CIDR block for a /24 prefix given the min and max last octet.
	 *
	 * @param string $range_prefix   The first 3 octets (e.g. '192.168.1').
	 * @param int    $min_last_octet The minimum last octet.
	 * @param int    $max_last_octet The maximum last octet.
	 * @return string The CIDR notation (e.g. '192.168.1.0/28').
	 */
	private function calculate_cidr( $range_prefix, $min_last_octet, $max_last_octet ) {
		$min = (int) $min_last_octet;
		$max = (int) $max_last_octet;

		$diff = $min ^ $max;
		$mask = 32;

		while ( $diff > 0 ) {
			$diff >>= 1;
			$mask--;
		}

		$shift_amount = 32 - $mask;
		$network_last_octet = $min & ( ~ ( ( 1 << $shift_amount ) - 1 ) & 0xFF );

		return $range_prefix . '.' . $network_last_octet . '/' . $mask;
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

		$plugin_url = plugins_url( '/', SECUREFUSION_BASENAME );
		$page_url   = admin_url( 'admin.php?page=securefusion-ip-ranges' );

		$this->enqueue_assets();
		?>
		<div class="wrap securefusion-login-log securefusion-ip-ranges">
			<h1 class="sf-sr-only"><?php esc_html_e( 'IP Ranges', 'securefusion' ); ?></h1>

			<header class="sf-log-header">
				<img src="<?php echo esc_url( $plugin_url ); ?>assets/icon.svg" alt="SecureFusion" class="sf-log-logo">
				<div class="sf-log-header-text">
					<h2 class="sf-log-title"><?php esc_html_e( 'IP Ranges Management', 'securefusion' ); ?></h2>
					<p class="sf-log-desc"><?php esc_html_e( 'View and manage IP subnets that have generated failed login attempts.', 'securefusion' ); ?></p>
				</div>
			</header>

			<div class="sf-log-toolbar" style="margin-top: 20px;">
				<div class="sf-toolbar-left">
					<button type="button" id="sf-copy-txt-list" class="button button-primary">
						<span class="dashicons dashicons-clipboard"></span>
						<?php esc_html_e( 'Copy TXT List', 'securefusion' ); ?>
					</button>
					<span id="sf-copy-status" style="margin-left:10px; font-weight:bold; color:green; display:none;">
						<?php esc_html_e( 'Copied!', 'securefusion' ); ?>
					</span>
				</div>
			</div>

			<div class="sf-log-table-wrap" style="margin-top: 20px;">
				<?php if ( $total_rows > 0 ) : ?>
					<table class="wp-list-table widefat fixed striped sf-log-table">
						<thead>
							<tr>
								<?php
								$columns = [
									'range_prefix'   => esc_html__( 'IP Range', 'securefusion' ),
									'ip_count'       => esc_html__( 'Unique IPs', 'securefusion' ),
									'total_attempts' => esc_html__( 'Total Attempts', 'securefusion' ),
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
								<th scope="col" class="manage-column"><?php esc_html_e( 'Actions', 'securefusion' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $rows as $row ) : ?>
								<?php
								$range_url = add_query_arg(
									[
										'range' => $row->range_prefix,
										'paged' => 1,
									],
									admin_url( 'admin.php?page=securefusion-login-log' )
								);
								?>
								<tr>
									<td class="column-ip">
										<?php $cidr = $this->calculate_cidr( $row->range_prefix, $row->min_last_octet, $row->max_last_octet ); ?>
										<strong><code><?php echo esc_html( $cidr ); ?></code></strong>
									</td>
									<td class="column-attempts">
										<span class="sf-attempt-badge sf-normal">
											<?php echo (int) $row->ip_count; ?>
										</span>
									</td>
									<td class="column-last_attempt">
										<span class="sf-attempt-badge <?php echo (int) $row->total_attempts >= 50 ? 'sf-danger' : ( (int) $row->total_attempts >= 20 ? 'sf-warning' : 'sf-normal' ); ?>">
											<?php echo (int) $row->total_attempts; ?>
										</span>
									</td>
									<td>
										<a href="<?php echo esc_url( $range_url ); ?>" class="button button-small">
											<span class="dashicons dashicons-filter" style="margin-top:4px;"></span>
											<?php esc_html_e( 'Filter Logs', 'securefusion' ); ?>
										</a>
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
						<p><?php esc_html_e( 'No IP ranges found. Your site is clean!', 'securefusion' ); ?></p>
					</div>
				<?php endif; ?>
			</div>
		</div>

		<?php
		// All ranges for the copy button
		$all_ranges = $db->get_ip_ranges();
		$txt_list   = '';
		foreach ( $all_ranges as $range ) {
			$cidr = $this->calculate_cidr( $range->range_prefix, $range->min_last_octet, $range->max_last_octet );
			$txt_list .= $cidr . "\n";
		}
		?>
		<textarea id="sf-hidden-txt-list" style="display:none;" aria-hidden="true"><?php echo esc_textarea( $txt_list ); ?></textarea>
		<script>
			document.addEventListener('DOMContentLoaded', function() {
				var copyBtn = document.getElementById('sf-copy-txt-list');
				if (copyBtn) {
					copyBtn.addEventListener('click', function(e) {
						e.preventDefault();
						var txt = document.getElementById('sf-hidden-txt-list').value;
						navigator.clipboard.writeText(txt).then(function() {
							var status = document.getElementById('sf-copy-status');
							status.style.display = 'inline';
							setTimeout(function() {
								status.style.display = 'none';
							}, 2000);
						});
					});
				}
			});
		</script>
		<?php
	}
}
