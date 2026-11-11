<?php
/**
 * AdminDashboardWidgets responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * AdminDashboardWidgets methods.
 *
 * @mixin Admin
 */
trait AdminDashboardWidgets {

	/**
	 * Prepare the security log statistics for Chart.js rendering.
	 *
	 * @return array Multi-dimensional array of chart data.
	 */
	protected function get_dashboard_chart_data() {

		$db = new BruteForceDB();

		// 1. Daily Stats (Last 30 days)
		$daily_raw    = $db->get_daily_attempts_stats( 30 );
		$daily_labels = array();

		for ( $i = 29; $i >= 0; $i-- ) {

			$timestamp      = time() - ( $i * DAY_IN_SECONDS );
			$daily_labels[] = function_exists( 'wp_date' ) ? wp_date( 'Y-m-d', $timestamp ) : gmdate( 'Y-m-d', $timestamp );

		}

		// Initialize datasets for each type.
		$types = array(
			BruteForceDB::TYPE_FAILED_LOGIN,
			BruteForceDB::TYPE_BAD_REQUEST,
			BruteForceDB::TYPE_BAD_COOKIE,
			BruteForceDB::TYPE_BAD_BOT,
			BruteForceDB::TYPE_BAD_QUERY,
			BruteForceDB::TYPE_BLOCKED,
		);

		$daily_data = array();

		foreach ( $types as $type ) {

			$daily_data[ $type ] = array_fill( 0, 30, 0 );

		}

		if ( is_array( $daily_raw ) ) {

			foreach ( $daily_raw as $row ) {

				$label_index = array_search( $row->date_str, $daily_labels, true );

				if ( false !== $label_index && isset( $daily_data[ $row->log_type ] ) ) {

					$daily_data[ $row->log_type ][ $label_index ] = (int) $row->count;

				}

			}

		}

		// 2. Monthly Stats (Last 12 months)
		$monthly_raw    = $db->get_monthly_attempts_stats( 12 );
		$monthly_labels = array();

		for ( $i = 11; $i >= 0; $i-- ) {

			$timestamp        = strtotime( gmdate( 'Y-m-01' ) . " -{$i} months" );
			$monthly_labels[] = function_exists( 'wp_date' ) ? wp_date( 'Y-m', $timestamp ) : gmdate( 'Y-m', $timestamp );

		}

		$monthly_data = array();

		foreach ( $types as $type ) {

			$monthly_data[ $type ] = array_fill( 0, 12, 0 );

		}

		if ( is_array( $monthly_raw ) ) {

			foreach ( $monthly_raw as $row ) {

				$label_index = array_search( $row->month_str, $monthly_labels, true );

				if ( false !== $label_index && isset( $monthly_data[ $row->log_type ] ) ) {

					$monthly_data[ $row->log_type ][ $label_index ] = (int) $row->count;

				}

			}

		}

		// Human readable labels for types.
		$type_labels = array(
			BruteForceDB::TYPE_FAILED_LOGIN => __( 'Failed Login', 'secuplug' ),
			BruteForceDB::TYPE_BAD_REQUEST  => __( 'Bad Request', 'secuplug' ),
			BruteForceDB::TYPE_BAD_COOKIE   => __( 'Bad Cookie', 'secuplug' ),
			BruteForceDB::TYPE_BAD_BOT      => __( 'Bad Bot', 'secuplug' ),
			BruteForceDB::TYPE_BAD_QUERY    => __( 'Bad Query', 'secuplug' ),
			BruteForceDB::TYPE_BLOCKED      => __( 'Blocked Request', 'secuplug' ),
		);

		return array(
			'daily'       => array(
				'labels'   => $daily_labels,
				'datasets' => $daily_data,
			),
			'monthly'     => array(
				'labels'   => $monthly_labels,
				'datasets' => $monthly_data,
			),
			'type_labels' => $type_labels,
		);

	}



	/**
	 * Add status box.
	 *
	 * @param string $title   Title.
	 * @param mixed  $status  Status.
	 * @param string $desc    Description.
	 * @param array  $button  Button array.
	 * @param string $details Optional expanded guidance HTML.
	 *
	 * @return void
	 */
	public function add_status_box( $title, $status = false, $desc = '', $button = [], $details = '' ) {

		$card_class = 'dashboard-item';

		if ( $status !== false ) {

			$card_class .= $status ? ' fynd-sf-status-enabled' : ' fynd-sf-status-disabled';

		} else {

			$card_class .= ' fynd-sf-status-neutral';

		}
		?>
		<div class="<?php echo esc_attr( $card_class ); ?>">
			<h2>
				<?php echo esc_html( $title ); ?>
			</h2>
			<?php
			if ( ! empty( $desc ) ) :
				?>
				<p class="description">
					<?php echo esc_html( $desc ); ?>
				</p>
				<?php
			endif;

			if ( $status !== false ) :
				?>
				<div class="status-wrapper" style="margin-top: 10px;">
					<span class="status <?php echo esc_attr( $status ? 'enabled' : 'disabled' ); ?>">
						<?php $status ? esc_html_e( 'enabled', 'secuplug' ) : esc_html_e( 'disabled', 'secuplug' ); ?>
					</span>
				</div>
				<?php
			endif;

			if ( ! empty( $details ) ) :
				?>
				<details class="fsf-card-details">
					<summary><?php esc_html_e( 'Review guidance', 'secuplug' ); ?></summary>
					<div class="fsf-card-details__body"><?php echo wp_kses_post( $details ); ?></div>
				</details>
				<?php
			endif;

			if ( ! empty( $button ) ) :
				?>
				<p style="margin-top: 15px; margin-bottom: 0;">
					<a href="<?php echo esc_attr( $button[1] ); ?>" class="fynd-sf-btn fynd-sf-btn-secondary">
						<?php echo esc_html( $button[0] ); ?>
					</a>
				</p>
				<?php
			endif;
			?>
		</div>
		<?php
	}

}
