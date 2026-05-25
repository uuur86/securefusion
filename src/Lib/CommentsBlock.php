<?php
/**
 * CommentsBlock Class
 *
 * Handles IP blocking from the WordPress Comments list table (edit-comments.php).
 * Allows individual IP blocking and bulk blocking of all spam comment IPs or ranges.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * CommentsBlock functionality class.
 */
class CommentsBlock {

	use WPCommon;

	/**
	 * Nonce action name.
	 */
	const NONCE_ACTION = 'securefusion_comments_block';

	/**
	 * Initialize the comments block class.
	 */
	public function init() {
		if ( ! is_admin() ) {
			return;
		}

		add_filter( 'comment_row_actions', [ $this, 'comment_row_actions' ], 10, 2 );
		add_action( 'restrict_manage_comments', [ $this, 'restrict_manage_comments' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );

		// AJAX handlers.
		add_action( 'wp_ajax_securefusion_toggle_comment_ip_block', [ $this, 'ajax_toggle_ip_block' ] );
		add_action( 'wp_ajax_securefusion_block_all_spam_ips', [ $this, 'ajax_block_all_spam_ips' ] );

		// Cache invalidation hooks.
		add_action( 'transition_comment_status', [ $this, 'clear_spam_cache' ] );
		add_action( 'comment_post', [ $this, 'clear_spam_cache' ] );
		add_action( 'edit_comment', [ $this, 'clear_spam_cache' ] );
		add_action( 'deleted_comment', [ $this, 'clear_spam_cache' ] );
	}

	/**
	 * Add custom "Block IP" / "Unblock IP" actions under comment rows.
	 *
	 * @param array       $actions Existing comment row actions.
	 * @param \WP_Comment $comment Comment object.
	 *
	 * @return array Modified comment row actions with block/unblock options.
	 */
	public function comment_row_actions( $actions, $comment ) {
		$ip = $comment->comment_author_IP;

		if ( empty( $ip ) ) {
			return $actions;
		}

		$db = new BruteForceDB();

		if ( $db->is_ip_whitelisted( $ip ) ) {
			$actions['sf_ip_status'] = '<span style="color: #01b9ba; font-weight: bold;" title="' . esc_attr__( 'Admin/Whitelisted IP address.', 'secuplug' ) . '">' . esc_html__( 'Whitelisted IP', 'secuplug' ) . '</span>';
		} elseif ( $db->is_ip_blocked( $ip ) ) {
			$actions['sf_ip_block'] = sprintf(
				'<a href="#" class="sf-comment-toggle-ip-btn" data-ip="%1$s" data-action="unblock" style="color: #2271b1; font-weight: 500;">%2$s</a>',
				esc_attr( $ip ),
				esc_html__( 'Unblock IP', 'secuplug' )
			);
		} else {
			$actions['sf_ip_block'] = sprintf(
				'<a href="#" class="sf-comment-toggle-ip-btn" data-ip="%1$s" data-action="block" style="color: #d63638; font-weight: 500;">%2$s</a>',
				esc_attr( $ip ),
				esc_html__( 'Block IP', 'secuplug' )
			);
		}

		return $actions;
	}

	/**
	 * Inject the responsive bulk block panel in the filters bar on the comments list table.
	 */
	public function restrict_manage_comments() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-state-changing query parameter check.
		if ( ! isset( $_GET['comment_status'] ) || $_GET['comment_status'] !== 'spam' ) {
			return;
		}

		// Check if we have spam comments to block.
		$spam_count = wp_cache_get( 'sf_spam_comments_with_ip_count', 'securefusion' );

		if ( false === $spam_count ) {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$spam_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'spam' AND comment_author_IP != ''" );

			wp_cache_set( 'sf_spam_comments_with_ip_count', $spam_count, 'securefusion', 300 );
		}

		if ( $spam_count === 0 ) {
			return;
		}

		// Responsive layout matching WordPress toolbar classes.
		?>
		<div class="alignleft actions sf-comments-block-container">
			<label class="sf-block-ranges-label">
				<input type="checkbox" id="sf-block-ranges-chk" name="sf_block_ranges" value="1">
				<?php esc_html_e( 'Block ranges', 'secuplug' ); ?>
			</label>
			<button type="button" id="sf-block-spam-btn" class="button button-secondary sf-block-spam-button">
				<span class="dashicons dashicons-shield-alt"></span>
				<?php esc_html_e( 'Block Spam', 'secuplug' ); ?>
			</button>
		</div>
		<?php
	}

	/**
	 * Enqueue stylesheet and script on comments edit page.
	 *
	 * @param string $hook Current admin page hook suffix.
	 */
	public function enqueue_assets( $hook ) {
		if ( $hook !== 'edit-comments.php' ) {
			return;
		}

		wp_enqueue_style(
			'securefusion-comments-block-css',
			plugins_url( 'assets/css/comments-block.css', SECUREFUSION_BASENAME ),
			[],
			SECUREFUSION_VERSION
		);

		wp_enqueue_script(
			'securefusion-comments-block-js',
			plugins_url( 'assets/js/comments-block.js', SECUREFUSION_BASENAME ),
			[ 'jquery' ],
			SECUREFUSION_VERSION,
			true
		);

		wp_localize_script(
			'securefusion-comments-block-js',
			'sfCommentsBlock',
			[
				'ajaxUrl'         => admin_url( 'admin-ajax.php' ),
				'nonce'           => wp_create_nonce( self::NONCE_ACTION ),
				'confirmBlock'    => esc_html__( 'Are you sure you want to block this IP?', 'secuplug' ),
				'confirmUnblock'  => esc_html__( 'Are you sure you want to unblock this IP?', 'secuplug' ),
				'confirmBulk'     => esc_html__( 'Are you sure you want to block all IP addresses/ranges for all comments currently in Spam?', 'secuplug' ),
				'blockText'       => esc_html__( 'Block IP', 'secuplug' ),
				'unblockText'     => esc_html__( 'Unblock IP', 'secuplug' ),
				'whitelistedText' => esc_html__( 'Whitelisted IP', 'secuplug' ),
				'successText'     => esc_html__( 'Operation completed successfully.', 'secuplug' ),
				'errorText'       => esc_html__( 'Operation failed.', 'secuplug' ),
				'processing'      => esc_html__( 'Processing...', 'secuplug' ),
			]
		);
	}

	/**
	 * AJAX handler to toggle block/unblock on a single comment IP.
	 */
	public function ajax_toggle_ip_block() {
		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['nonce'] ) ), self::NONCE_ACTION ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Security check failed.', 'secuplug' ) ] );

			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Permission denied.', 'secuplug' ) ] );

			return;
		}

		$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$action = isset( $_POST['block_action'] ) ? sanitize_text_field( wp_unslash( $_POST['block_action'] ) ) : '';

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Invalid IP address.', 'secuplug' ) ] );

			return;
		}

		$db = new BruteForceDB();

		if ( $action === 'block' ) {

			if ( $db->is_ip_whitelisted( $ip ) ) {
				wp_send_json_error( [ 'message' => esc_html__( 'This IP is whitelisted and cannot be blocked.', 'secuplug' ) ] );
				return;
			}

			$success = $db->block_ip( $ip );

			if ( $success ) {
				wp_send_json_success( [ 'message' => esc_html__( 'IP blocked.', 'secuplug' ) ] );
			}
		} elseif ( $action === 'unblock' ) {
			$success = $db->unblock_ip( $ip );

			if ( $success ) {
				wp_send_json_success( [ 'message' => esc_html__( 'IP unblocked.', 'secuplug' ) ] );
			}
		}

		wp_send_json_error( [ 'message' => esc_html__( 'Operation failed.', 'secuplug' ) ] );
	}

	/**
	 * AJAX handler to bulk block all spam comment IPs or ranges.
	 */
	public function ajax_block_all_spam_ips() {
		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['nonce'] ) ), self::NONCE_ACTION ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Security check failed.', 'secuplug' ) ] );

			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'Permission denied.', 'secuplug' ) ] );

			return;
		}

		$block_ranges = isset( $_POST['block_ranges'] ) && $_POST['block_ranges'] === '1';

		$spam_ips = wp_cache_get( 'sf_spam_ips_list', 'securefusion' );

		if ( false === $spam_ips ) {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$spam_ips = $wpdb->get_col( "SELECT DISTINCT comment_author_IP FROM {$wpdb->comments} WHERE comment_approved = 'spam' AND comment_author_IP != ''" );

			wp_cache_set( 'sf_spam_ips_list', $spam_ips, 'securefusion', 300 );
		}

		if ( empty( $spam_ips ) ) {
			wp_send_json_error( [ 'message' => esc_html__( 'No spam comment IPs found.', 'secuplug' ) ] );

			return;
		}

		$targets_to_block = [];

		if ( $block_ranges ) {
			$ipv4_groups = [];
			$ipv6_groups = [];

			foreach ( $spam_ips as $ip ) {
				$ip = trim( $ip );
				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					$parts = explode( '.', $ip );
					if ( count( $parts ) === 4 ) {
						$prefix                   = $parts[0] . '.' . $parts[1] . '.' . $parts[2];
						$last_octet               = (int) $parts[3];
						$ipv4_groups[ $prefix ][] = $last_octet;
					}
				} elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
					$parts = explode( ':', $ip );
					if ( count( $parts ) >= 4 ) {
						$prefix                   = implode( ':', array_slice( $parts, 0, 4 ) );
						$ipv6_groups[ $prefix ][] = $ip;
					} else {
						$targets_to_block[] = $ip;
					}
				}
			}

			// Process IPv4 subnets using inherited calculate_cidr helper.
			foreach ( $ipv4_groups as $prefix => $last_octets ) {
				$min                = min( $last_octets );
				$max                = max( $last_octets );
				$targets_to_block[] = $this->calculate_cidr( $prefix, $min, $max );
			}

			// Process IPv6 subnets.
			foreach ( $ipv6_groups as $prefix => $ips ) {
				$ips = array_unique( $ips );
				if ( count( $ips ) === 1 ) {
					$targets_to_block[] = $ips[0];
				} else {
					$targets_to_block[] = $prefix . '::/64';
				}
			}
		} else {
			// Plain exact IP blocking.
			foreach ( $spam_ips as $ip ) {
				$ip = trim( $ip );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$targets_to_block[] = $ip;
				}
			}
		}

		$targets_to_block = array_unique( $targets_to_block );
		$db               = new BruteForceDB();
		$blocked_count    = 0;

		foreach ( $targets_to_block as $target ) {
			// Skip if already whitelisted.
			if ( $db->is_ip_whitelisted( $target ) ) {
				continue;
			}

			// Block the IP or calculated range.
			if ( $db->block_ip( $target ) ) {
				++$blocked_count;
			}
		}

		wp_send_json_success(
			[
				/* translators: %d: Number of blocked IPs/ranges. */
				'message' => sprintf( esc_html__( 'Successfully blocked %d IP addresses/ranges.', 'secuplug' ), $blocked_count ),
			]
		);
	}



	/**
	 * Clear spam comments cache.
	 *
	 * @return void
	 */
	public function clear_spam_cache() {
		wp_cache_delete( 'sf_spam_comments_with_ip_count', 'securefusion' );
		wp_cache_delete( 'sf_spam_ips_list', 'securefusion' );
	}
}
