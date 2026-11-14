<?php
/**
 * IPRangeQueries responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * IPRangeQueries methods.
 *
 * @mixin BruteForceDB
 * @property \wpdb  $wpdb           WordPress database, set in BruteForceDB::__construct().
 * @property string $table_name     Log table name, set in BruteForceDB::__construct().
 * @property string $ip_rules_table IP rules table name, set in BruteForceDB::__construct().
 */
trait IPRangeQueries {

	/**
	 * Get IP ranges grouped by /24 subnet (first 3 octets).
	 *
	 * Returns each unique range prefix with the count of unique IPs
	 * and total attempts in that range.
	 *
	 * @return array Array of objects with range_prefix, ip_count, total_attempts.
	 */
	public function get_ip_ranges() {

		$wpdb = $this->wpdb;

		$cached = \wp_cache_get( 'securefusion_bf_ip_ranges', BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT SUBSTRING_INDEX(ip, '.', 3) AS range_prefix,
				COUNT(DISTINCT ip) AS ip_count,
				SUM(attempts) AS total_attempts,
				MIN(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS min_last_octet,
				MAX(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS max_last_octet
			FROM %i
			WHERE ip LIKE %s
			GROUP BY range_prefix
			ORDER BY INET_ATON(CONCAT(SUBSTRING_INDEX(ip, '.', 3), '.0')) ASC",
				$this->table_name,
				'%.%.%.%'
			)
		);

		// Cache for 5 minutes.
		\wp_cache_set( 'securefusion_bf_ip_ranges', $rows, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $rows;

	}


	/**
	 * Get paginated IP ranges grouped by /24 subnet.
	 *
	 * @param int    $per_page Number of items per page.
	 * @param int    $offset   Pagination offset.
	 * @param string $orderby  Column to order by (whitelisted).
	 * @param string $order    ASC or DESC.
	 *
	 * @return array Array of objects.
	 */
	public function get_paginated_ip_ranges( $per_page = 20, $offset = 0, $orderby = 'ip_count', $order = 'DESC' ) {

		$wpdb = $this->wpdb;

		$allowed_columns = [ 'range_prefix', 'ip_count', 'total_attempts' ];
		$orderby         = in_array( $orderby, $allowed_columns, true ) ? $orderby : 'ip_count';
		$order           = strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
		$per_page        = absint( $per_page );
		$offset          = absint( $offset );

		if ( $orderby === 'range_prefix' ) {

			$orderby_sql = "INET_ATON(CONCAT(SUBSTRING_INDEX(ip, '.', 3), '.0'))";

		} else {

			$orderby_sql = $orderby;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Only allowlisted SQL ordering expressions and normalized ASC/DESC; values remain bound below.
				"SELECT SUBSTRING_INDEX(ip, '.', 3) AS range_prefix,
					COUNT(DISTINCT ip) AS ip_count,
					SUM(attempts) AS total_attempts,
					MIN(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS min_last_octet,
					MAX(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS max_last_octet
				FROM %i
				WHERE ip LIKE %s
				GROUP BY range_prefix
				ORDER BY {$orderby_sql} {$order}
				LIMIT %d OFFSET %d",
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$this->table_name,
				'%.%.%.%',
				$per_page,
				$offset
			)
		);

	}


	/**
	 * Get total count of unique IP ranges.
	 *
	 * @return int Total number of unique /24 ranges.
	 */
	public function get_total_ip_ranges() {

		$wpdb = $this->wpdb;

		$cached = \wp_cache_get( 'securefusion_bf_total_ip_ranges', BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return (int) $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT SUBSTRING_INDEX(ip, '.', 3))
			FROM %i
			WHERE ip LIKE %s",
				$this->table_name,
				'%.%.%.%'
			)
		);

		$count = (int) $count;

		\wp_cache_set( 'securefusion_bf_total_ip_ranges', $count, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $count;

	}


	/**
	 * Get all IPs within a specific /24 range prefix.
	 *
	 * @param string $range_prefix First 3 octets (e.g. '192.168.1').
	 * @return array Array of row objects with ip property.
	 */
	public function get_ips_by_range_prefix( $range_prefix ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DISTINCT ip FROM %i WHERE ip LIKE %s ORDER BY CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED) ASC",
				$this->table_name,
				$wpdb->esc_like( $range_prefix ) . '.%'
			)
		);

	}


	/**
	 * Get paginated rows filtered by IP range prefix.
	 *
	 * @param string $range_prefix First 3 octets (e.g. '192.168.1').
	 * @param int    $per_page     Number of rows per page.
	 * @param int    $offset       Offset for pagination.
	 * @param string $orderby      Column to order by (whitelisted).
	 * @param string $order        ASC or DESC.
	 * @param string $type_filter Optional log type filter (e.g. 'failed_login', 'bad_request', 'blocked').
	 *
	 * @return array Array of row objects.
	 */
	public function get_rows_by_range( $range_prefix, $per_page = 20, $offset = 0, $orderby = 'last_attempt', $order = 'DESC', $type_filter = '' ) {

		$wpdb = $this->wpdb;

		$allowed_columns = [ 'id', 'ip', 'attempts', 'last_attempt', 'log_type' ];
		$orderby         = in_array( $orderby, $allowed_columns, true ) ? $orderby : 'last_attempt';
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

			$range_esc = $wpdb->esc_like( $range_prefix ) . '.%';

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
					WHERE r.rule_type = 'blocked' AND ( r.expiration <= 0 OR r.expiration >= %d ) AND r.ip LIKE %s
					GROUP BY r.ip
					ORDER BY {$orderby_sql} {$order}
					LIMIT %d OFFSET %d",
					// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$this->ip_rules_table,
					$this->table_name,
					time(),
					$range_esc,
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

		$range_esc = $wpdb->esc_like( $range_prefix ) . '.%';

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
			WHERE l.ip LIKE %s AND (%s = '' OR l.log_type = %s)
			ORDER BY {$orderby_sql} {$order}
			LIMIT %d OFFSET %d",
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				time(),
				$this->table_name,
				$this->ip_rules_table,
				$range_esc,
				$type_filter,
				$type_filter,
				$per_page,
				$offset
			)
		);

	}


	/**
	 * Get total row count filtered by IP range prefix.
	 *
	 * @param string $range_prefix First 3 octets (e.g. '192.168.1').
	 * @param string $type_filter Optional log type filter (e.g. 'failed_login', 'bad_request', 'blocked').
	 *
	 * @return int Total row count for the range.
	 */
	public function get_total_rows_by_range( $range_prefix, $type_filter = '' ) {

		$wpdb = $this->wpdb;

		if ( $type_filter === 'blocked' ) {

			$range_prefix = $wpdb->esc_like( $range_prefix );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$count = $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM %i WHERE rule_type = %s AND ( expiration <= 0 OR expiration >= %d ) AND ip LIKE %s',
					$this->ip_rules_table,
					'blocked',
					time(),
					$range_prefix . '%'
				)
			);

			return (int) $count;

		}

		$range_prefix = $wpdb->esc_like( $range_prefix );
		$table_name   = $this->table_name;

		if ( ! empty( $type_filter ) ) {

			$type_filter = BruteForceDB::normalize_log_type( $type_filter );
			$query       = $wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ip LIKE %s AND log_type = %s',
				$table_name,
				$range_prefix . '%',
				$type_filter
			);

		} else {

			$query = $wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ip LIKE %s',
				$table_name,
				$range_prefix . '%'
			);

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Both branches assign this query exclusively from wpdb::prepare with bound values and identifiers.
		return (int) $wpdb->get_var( $query );

	}

}
