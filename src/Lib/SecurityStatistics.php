<?php
/**
 * SecurityStatistics responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * SecurityStatistics methods.
 *
 * @mixin BruteForceDB
 * @property \wpdb  $wpdb       WordPress database, set in BruteForceDB::__construct().
 * @property string $table_name Log table name, set in BruteForceDB::__construct().
 */
trait SecurityStatistics {

	/**
	 * Get the total sum of all failed login attempts.
	 *
	 * Uses object caching with a dedicated key.
	 *
	 * @return int The total number of failed attempts.
	 */
	public function get_total_attempts() {

		$wpdb = $this->wpdb;

		$cached = \wp_cache_get( 'securefusion_bf_total_attempts', BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return (int) $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$total = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT SUM(attempts) FROM %i WHERE log_type NOT IN (%s, %s)',
				$this->table_name,
				BruteForceDB::TYPE_SUCCESSFUL_LOGIN,
				BruteForceDB::TYPE_OVERSIZED_REQUEST
			)
		);

		$total = (int) $total;

		\wp_cache_set( 'securefusion_bf_total_attempts', $total, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $total;

	}


	/**
	 * Count addresses with a logged event since a moment, for the activity notification.
	 *
	 * @param int $since Unix time.
	 * @return int
	 */
	public function count_addresses_since( $since ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; asked at most once a day per administrator.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(DISTINCT ip) FROM %i WHERE last_attempt >= %d AND log_type <> %s',
				$this->table_name,
				absint( $since ),
				BruteForceDB::TYPE_SUCCESSFUL_LOGIN
			)
		);

		return (int) $count;

	}


	/**
	 * Summarize recent requests over the size limit, for the settings warning.
	 *
	 * @param int $days Days to look back.
	 * @return array{requests:int,addresses:int}
	 */
	public function get_oversized_request_summary( $days ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; the caller caches this result.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT COUNT(*) AS requests, COUNT(DISTINCT ip) AS addresses FROM %i WHERE log_type = %s AND last_attempt >= %d',
				$this->table_name,
				BruteForceDB::TYPE_OVERSIZED_REQUEST,
				time() - ( absint( $days ) * DAY_IN_SECONDS )
			)
		);

		return [
			'requests'  => $row ? (int) $row->requests : 0,
			'addresses' => $row ? (int) $row->addresses : 0,
		];

	}


	/**
	 * Get the total sum of attempts for a specific log type.
	 *
	 * Uses object caching.
	 *
	 * @param string $type Raw log type value.
	 * @return int Total number of attempts for this type.
	 */
	public function get_total_attempts_by_type( $type ) {

		$wpdb = $this->wpdb;

		$type      = BruteForceDB::normalize_log_type( $type );
		$cache_key = 'securefusion_bf_total_attempts_' . $type;
		$cached    = \wp_cache_get( $cache_key, BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return (int) $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$total = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT SUM(attempts) FROM %i WHERE log_type = %s',
				$this->table_name,
				$type
			)
		);

		$total = (int) $total;

		\wp_cache_set( $cache_key, $total, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $total;

	}


	/**
	 * Get the count of unique IP addresses that have failed login attempts.
	 *
	 * Uses object caching with a dedicated key.
	 *
	 * @return int The count of unique IP addresses.
	 */
	public function get_unique_ips_count() {

		$wpdb = $this->wpdb;

		$cached = \wp_cache_get( 'securefusion_bf_unique_ips', BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return (int) $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(DISTINCT ip) FROM %i WHERE log_type != %s',
				$this->table_name,
				BruteForceDB::TYPE_SUCCESSFUL_LOGIN
			)
		);

		$count = (int) $count;

		\wp_cache_set( 'securefusion_bf_unique_ips', $count, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $count;

	}


	/**
	 * Get daily security log counts grouped by log type for the last 30 days.
	 *
	 * @param int $days Number of days to look back. Default 30.
	 * @return array Array of objects with log_type, date_str, and count.
	 */
	public function get_daily_attempts_stats( $days = 30 ) {

		$wpdb = $this->wpdb;

		$time_limit = time() - ( $days * DAY_IN_SECONDS );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$results = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT log_type, YEAR(FROM_UNIXTIME(last_attempt)) as yr, MONTH(FROM_UNIXTIME(last_attempt)) as mo, DAY(FROM_UNIXTIME(last_attempt)) as dy, COUNT(*) as count
				 FROM %i
				 WHERE last_attempt >= %d
				 GROUP BY log_type, YEAR(FROM_UNIXTIME(last_attempt)), MONTH(FROM_UNIXTIME(last_attempt)), DAY(FROM_UNIXTIME(last_attempt))
				 ORDER BY yr ASC, mo ASC, dy ASC',
				$this->table_name,
				$time_limit
			)
		);

		// Format to YYYY-MM-DD.
		if ( is_array( $results ) ) {

			foreach ( $results as $row ) {

				$row->date_str = sprintf( '%04d-%02d-%02d', $row->yr, $row->mo, $row->dy );

			}

		}

		return $results;

	}


	/**
	 * Get monthly security log counts grouped by log type for the last 12 months.
	 *
	 * @param int $months Number of months to look back. Default 12.
	 * @return array Array of objects with log_type, month_str, and count.
	 */
	public function get_monthly_attempts_stats( $months = 12 ) {

		$wpdb = $this->wpdb;

		$time_limit = time() - ( $months * 30 * DAY_IN_SECONDS );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$results = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT log_type, YEAR(FROM_UNIXTIME(last_attempt)) as yr, MONTH(FROM_UNIXTIME(last_attempt)) as mo, COUNT(*) as count
				 FROM %i
				 WHERE last_attempt >= %d
				 GROUP BY log_type, YEAR(FROM_UNIXTIME(last_attempt)), MONTH(FROM_UNIXTIME(last_attempt))
				 ORDER BY yr ASC, mo ASC',
				$this->table_name,
				$time_limit
			)
		);

		// Format to YYYY-MM.
		if ( is_array( $results ) ) {

			foreach ( $results as $row ) {

				$row->month_str = sprintf( '%04d-%02d', $row->yr, $row->mo );

			}

		}

		return $results;

	}

}
