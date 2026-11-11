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

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * SecurityLog functionality class.
 */
class SecurityLog {

	use SecurityLogView;

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
			''                                   => esc_html__( 'All Types', 'secuplug' ),
			BruteForceDB::TYPE_FAILED_LOGIN      => esc_html__( 'Failed Login', 'secuplug' ),
			BruteForceDB::TYPE_SUCCESSFUL_LOGIN  => esc_html__( 'Successful Login', 'secuplug' ),
			BruteForceDB::TYPE_BAD_REQUEST       => esc_html__( 'Bad Request', 'secuplug' ),
			BruteForceDB::TYPE_BAD_COOKIE        => esc_html__( 'Bad Cookie', 'secuplug' ),
			BruteForceDB::TYPE_BAD_BOT           => esc_html__( 'Bad Bot', 'secuplug' ),
			BruteForceDB::TYPE_BAD_QUERY         => esc_html__( 'Bad Query', 'secuplug' ),
			BruteForceDB::TYPE_BLOCKED           => esc_html__( 'Blocked', 'secuplug' ),
			BruteForceDB::TYPE_OVERSIZED_REQUEST => esc_html__( 'Oversized Request', 'secuplug' ),
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
				'confirmReset'   => esc_html__( 'WARNING: This action is irreversible! Selected log data will be permanently deleted. Are you absolutely sure?', 'secuplug' ),
				'confirmImport'  => esc_html__( 'Importing data will add records to the existing table. Continue?', 'secuplug' ),
				'resetSuccess'   => esc_html__( 'Data has been deleted successfully.', 'secuplug' ),
				'exportEmpty'    => esc_html__( 'No data to export.', 'secuplug' ),
				'importSuccess'  => esc_html__( 'Import completed successfully.', 'secuplug' ),
				'importError'    => esc_html__( 'Import failed. Please check the file format.', 'secuplug' ),
				'invalidFile'    => esc_html__( 'Please select a valid JSON file.', 'secuplug' ),
				'processing'     => esc_html__( 'Processing...', 'secuplug' ),
				'loading'        => __( 'Loading...', 'secuplug' ),
				'error'          => __( 'Error', 'secuplug' ),
				'loadFailed'     => __( 'Failed to load IP list.', 'secuplug' ),
				'copied'         => esc_html__( 'Copied to clipboard!', 'secuplug' ),
				'copyFailed'     => esc_html__( 'Copy failed. Please select and copy manually.', 'secuplug' ),
				'blockSuccess'   => esc_html__( 'IP has been blocked.', 'secuplug' ),
				'unblockSuccess' => esc_html__( 'IP has been unblocked.', 'secuplug' ),
				'blockFailed'    => esc_html__( 'IP block/unblock operation failed.', 'secuplug' ),
				'confirmBlock'   => esc_html__( 'Are you sure you want to block this IP?', 'secuplug' ),
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

			wp_send_json_error( [ 'message' => esc_html__( 'Security check failed.', 'secuplug' ) ] );

			return false;

		}

		if ( ! current_user_can( 'manage_options' ) ) {

			wp_send_json_error( [ 'message' => esc_html__( 'Permission denied.', 'secuplug' ) ] );

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

			wp_send_json_success( [ 'message' => esc_html__( 'Data has been deleted.', 'secuplug' ) ] );

		} else {

			wp_send_json_error( [ 'message' => esc_html__( 'Failed to delete data.', 'secuplug' ) ] );

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

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce/capability checked above; preserve JSON syntax, then validate decoded rows in bulk_insert.
		$raw_data = isset( $_POST['import_data'] ) && is_string( $_POST['import_data'] ) ? wp_unslash( $_POST['import_data'] ) : '';

		if ( strlen( $raw_data ) > 2 * MB_IN_BYTES ) {

			wp_send_json_error( [ 'message' => esc_html__( 'Import data is too large.', 'secuplug' ) ] );

			return;

		}

		$data = json_decode( $raw_data, true );

		if ( ! is_array( $data ) || empty( $data ) ) {

			wp_send_json_error( [ 'message' => esc_html__( 'Invalid JSON data.', 'secuplug' ) ] );

			return;

		}

		$db       = new BruteForceDB();
		$inserted = $db->bulk_insert( $data );

		wp_send_json_success(
			[
				/* translators: %d: Number of imported rows. */
				'message' => sprintf( esc_html__( '%d records imported successfully.', 'secuplug' ), $inserted ),
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

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- validate_ajax_request checked nonce and capability above.
		$range_prefix = isset( $_POST['range_prefix'] ) ? sanitize_text_field( wp_unslash( $_POST['range_prefix'] ) ) : '';

		if ( empty( $range_prefix ) || ! preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}$/', $range_prefix ) ) {

			wp_send_json_error( [ 'message' => esc_html__( 'Invalid range prefix.', 'secuplug' ) ] );

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
				'title' => sprintf( esc_html__( '%1$d IPs in range %2$s', 'secuplug' ), count( $ip_list ), $range_prefix . '.0/24' ),
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

			wp_send_json_error( [ 'message' => esc_html__( 'Invalid IP address or range.', 'secuplug' ) ] );

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

				wp_send_json_success(
					[
						'message'    => esc_html__( 'IP has been blocked.', 'secuplug' ),
						'new_status' => 'blocked',
					]
				);

			}

		} elseif ( $action === 'unblock' ) {

			$success = $db->unblock_ip( $ip );

			if ( $success ) {

				wp_send_json_success(
					[
						'message'    => esc_html__( 'IP has been unblocked.', 'secuplug' ),
						'new_status' => 'active',
					]
				);

			}

		}

		wp_send_json_error( [ 'message' => esc_html__( 'Operation failed.', 'secuplug' ) ] );

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

}
