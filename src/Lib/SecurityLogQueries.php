<?php
/**
 * SecurityLogQueries responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * SecurityLogQueries methods.
 *
 * @mixin BruteForceDB
 * @property \wpdb  $wpdb           WordPress database, set in BruteForceDB::__construct().
 * @property string $table_name     Log table name, set in BruteForceDB::__construct().
 * @property string $ip_rules_table IP rules table name, set in BruteForceDB::__construct().
 */
trait SecurityLogQueries {

	/**
	 * Get paginated rows from the brute force table.
	 *
	 * @param int    $per_page Number of rows per page.
	 * @param int    $offset   Offset for pagination.
	 * @param string $orderby  Column to order by (whitelisted).
	 * @param string $order    ASC or DESC.
	 * @param string $type_filter Optional log type filter (e.g. 'failed_login', 'bad_request').
	 *
	 * @return array Array of row objects.
	 */
	public function get_all_rows( $per_page = 20, $offset = 0, $orderby = 'last_attempt', $order = 'DESC', $type_filter = '' ) {

		$wpdb = $this->wpdb;

		$allowed_columns = [ 'id', 'ip', 'attempts', 'last_attempt', 'log_type' ];
		$orderby         = \in_array( $orderby, $allowed_columns, true ) ? $orderby : 'last_attempt';
		$order           = strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
		$per_page        = absint( $per_page );
		$offset          = absint( $offset );

		if ( $type_filter === 'blocked' ) {

			$orderby_sql = $orderby;

			if ( $orderby === 'ip' ) {

				$orderby_sql = 'INET_ATON(r.ip)';

			} elseif ( $orderby === 'id' ) {

				$orderby_sql = 'MIN(r.id)';

			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			return $wpdb->get_results(
				$wpdb->prepare(
					// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Only allowlisted SQL ordering expressions and normalized ASC/DESC; values remain bound below.
					"SELECT
						MIN(r.id) AS id,
						r.ip AS ip,
						COALESCE(SUM(l.attempts), 0) AS attempts,
						COALESCE(MAX(l.last_attempt), MAX(r.created_at)) AS last_attempt,
						'blocked' AS log_type,
						MAX(l.user_agent) AS user_agent,
						MAX(l.payload) AS payload,
						1 AS is_blocked,
						0 AS is_whitelisted
					FROM %i r
					LEFT JOIN %i l ON r.ip = l.ip
					WHERE r.rule_type = 'blocked' AND ( r.expiration <= 0 OR r.expiration >= %d )
					GROUP BY r.ip
					ORDER BY {$orderby_sql} {$order}
					LIMIT %d OFFSET %d",
					// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$this->ip_rules_table,
					$this->table_name,
					time(),
					$per_page,
					$offset
				)
			);

		}

		$orderby_sql = 'l.' . $orderby;

		if ( $orderby === 'ip' ) {

			$orderby_sql = 'INET_ATON(l.ip)';

		}

		$type_filter = empty( $type_filter ) ? '' : BruteForceDB::normalize_log_type( $type_filter );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Only allowlisted SQL ordering expressions and normalized ASC/DESC; values remain bound below.
				"SELECT
					l.id,
					l.ip,
					l.attempts,
					l.last_attempt,
					l.log_type,
					l.user_agent,
					l.payload,
					IF(r.rule_type = 'blocked' AND ( r.expiration <= 0 OR r.expiration >= %d ), 1, 0) AS is_blocked,
					IF(r.rule_type = 'whitelisted', 1, 0) AS is_whitelisted
				FROM %i l
				LEFT JOIN %i r ON l.ip = r.ip
				WHERE (%s = '' OR l.log_type = %s)
				ORDER BY {$orderby_sql} {$order}
				LIMIT %d OFFSET %d",
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				time(),
				$this->table_name,
				$this->ip_rules_table,
				$type_filter,
				$type_filter,
				$per_page,
				$offset
			)
		);

	}


	/**
	 * Get total number of rows in the brute force table.
	 *
	 * @param string $type_filter Optional log type filter (e.g. 'failed_login', 'bad_request', 'blocked').
	 *
	 * @return int Total row count.
	 */
	public function get_total_rows( $type_filter = '' ) {

		$wpdb = $this->wpdb;

		if ( $type_filter === 'blocked' ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$count = $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM %i WHERE rule_type = %s AND ( expiration <= 0 OR expiration >= %d )',
					$this->ip_rules_table,
					'blocked',
					time()
				)
			);

			return (int) $count;

		}

		if ( ! empty( $type_filter ) ) {

			$type_filter = BruteForceDB::normalize_log_type( $type_filter );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$count = $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM %i WHERE log_type = %s',
					$this->table_name,
					$type_filter
				)
			);

		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$count = $wpdb->get_var(
				$wpdb->prepare( 'SELECT COUNT(*) FROM %i', $this->table_name )
			);

		}

		return (int) $count;

	}


	/**
	 * Get all rows for export (no pagination).
	 *
	 * @param string $type_filter Optional log type filter (e.g. 'failed_login', 'bad_request', 'blocked').
	 *
	 * @return array Array of row objects.
	 */
	public function get_all_rows_for_export( $type_filter = '' ) {

		$wpdb = $this->wpdb;

		if ( $type_filter === 'blocked' ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT
					r.ip AS ip,
					COALESCE(SUM(l.attempts), 0) AS attempts,
					COALESCE(MAX(l.last_attempt), MAX(r.created_at)) AS last_attempt,
					'blocked' AS log_type,
					MAX(l.user_agent) AS user_agent,
					MAX(l.payload) AS payload,
					1 AS is_blocked,
					0 AS is_whitelisted
				FROM %i r
				LEFT JOIN %i l ON r.ip = l.ip
				WHERE r.rule_type = 'blocked' AND ( r.expiration <= 0 OR r.expiration >= %d )
				GROUP BY r.ip
				ORDER BY last_attempt DESC",
					$this->ip_rules_table,
					$this->table_name,
					time()
				)
			);

		}

		$type_filter = empty( $type_filter ) ? '' : BruteForceDB::normalize_log_type( $type_filter );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT
				l.ip,
				l.attempts,
				l.last_attempt,
				l.log_type,
				l.user_agent,
				l.payload,
				IF(r.rule_type = 'blocked' AND ( r.expiration <= 0 OR r.expiration >= %d ), 1, 0) AS is_blocked,
				IF(r.rule_type = 'whitelisted', 1, 0) AS is_whitelisted
			FROM %i l
			LEFT JOIN %i r ON l.ip = r.ip
			WHERE (%s = '' OR l.log_type = %s)
			ORDER BY l.last_attempt DESC",
				time(),
				$this->table_name,
				$this->ip_rules_table,
				$type_filter,
				$type_filter
			)
		);

	}

}
