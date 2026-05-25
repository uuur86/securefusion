<?php
/**
 * BruteForceDB Class
 *
 * Provides secure CRUD operations for the securefusion_brute_force_table.
 * Manages object caching for all read/write operations.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

/**
 * BruteForceDB functionality class.
 */
class BruteForceDB {

	/**
	 * Cache group identifier for all brute force related cache entries.
	 *
	 * @var string
	 */
	const CACHE_GROUP = 'securefusion_bf';

	/**
	 * Cache expiration time in seconds (5 minutes).
	 *
	 * @var int
	 */
	const CACHE_TTL = 300;

	/**
	 * Maximum user agent length stored in DB (truncation limit).
	 *
	 * @var int
	 */
	const MAX_USER_AGENT_LENGTH = 255;

	/**
	 * Maximum payload length stored in DB (truncation limit).
	 *
	 * @var int
	 */
	const MAX_PAYLOAD_LENGTH = 1000;

	/**
	 * Canonical log type constants.
	 *
	 * @var string
	 */
	const TYPE_FAILED_LOGIN     = 'failed_login';
	const TYPE_BAD_REQUEST      = 'bad_request';
	const TYPE_BAD_COOKIE       = 'bad_cookie';
	const TYPE_BAD_BOT          = 'bad_bot';
	const TYPE_BAD_QUERY        = 'bad_query';
	const TYPE_BLOCKED          = 'blocked';
	const TYPE_SUCCESSFUL_LOGIN = 'successful_login';

	/**
	 * The validated, prefixed table name.
	 *
	 * @var string
	 */
	private $table_name;

	/**
	 * The validated, prefixed IP rules table name.
	 *
	 * @var string
	 */
	private $ip_rules_table;

	/**
	 * WordPress database instance.
	 *
	 * @var \wpdb
	 */
	private $wpdb;


	/**
	 * Constructor.
	 *
	 * Initializes the wpdb reference and constructs the validated table names.
	 */
	public function __construct() {
		global $wpdb;

		$this->wpdb           = $wpdb;
		$this->table_name     = \esc_sql( $wpdb->prefix ) . 'securefusion_brute_force_table';
		$this->ip_rules_table = \esc_sql( $wpdb->prefix ) . 'securefusion_ip_rules';
	}


	/**
	 * Normalize a log type string to its canonical form.
	 *
	 * Follows Rule 3: Normalize any non-standard or alternative key names
	 * to their canonical form before any further logic.
	 *
	 * @param string $type Raw log type value.
	 * @return string Canonical log type.
	 */
	public static function normalize_log_type( $type ) {
		$type = strtolower( trim( $type ) );

		$aliases = [
			// successful_login aliases.
			'successful_login' => self::TYPE_SUCCESSFUL_LOGIN,
			'success_login'    => self::TYPE_SUCCESSFUL_LOGIN,

			// failed_login aliases.
			'failed_login'  => self::TYPE_FAILED_LOGIN,
			'failed_logins' => self::TYPE_FAILED_LOGIN,
			'login'         => self::TYPE_FAILED_LOGIN,
			'logins'        => self::TYPE_FAILED_LOGIN,
			'login_failure' => self::TYPE_FAILED_LOGIN,

			// bad_request aliases.
			'bad_request'   => self::TYPE_BAD_REQUEST,
			'bad_requests'  => self::TYPE_BAD_REQUEST,
			'request'       => self::TYPE_BAD_REQUEST,
			'requests'      => self::TYPE_BAD_REQUEST,

			// bad_cookie aliases.
			'bad_cookie'    => self::TYPE_BAD_COOKIE,
			'bad_cookies'   => self::TYPE_BAD_COOKIE,
			'cookie'        => self::TYPE_BAD_COOKIE,
			'cookies'       => self::TYPE_BAD_COOKIE,

			// bad_bot aliases.
			'bad_bot'       => self::TYPE_BAD_BOT,
			'bad_bots'      => self::TYPE_BAD_BOT,
			'bot'           => self::TYPE_BAD_BOT,
			'bots'          => self::TYPE_BAD_BOT,

			// bad_query aliases.
			'bad_query'     => self::TYPE_BAD_QUERY,
			'bad_queries'   => self::TYPE_BAD_QUERY,
			'query'         => self::TYPE_BAD_QUERY,
			'queries'       => self::TYPE_BAD_QUERY,

			// blocked aliases.
			'blocked'       => self::TYPE_BLOCKED,
			'block'         => self::TYPE_BLOCKED,
		];

		return isset( $aliases[ $type ] ) ? $aliases[ $type ] : self::TYPE_FAILED_LOGIN;
	}


	/**
	 * Get the validated table name.
	 *
	 * @return string The prefixed table name.
	 */
	public function get_table_name() {
		return $this->table_name;
	}


	/**
	 * Get a row by IP address.
	 *
	 * Uses object caching to minimize direct database queries.
	 * Falls back to a prepared database query on cache miss.
	 *
	 * @param string $ip The IP address to look up.
	 * @return object|null The row object with 'ip', 'attempts', 'last_attempt' properties, or null if not found.
	 */
	public function get_row_by_ip( $ip ) {
		$cache_key = 'securefusion_bf_ip_' . md5( $ip );
		$cached    = \wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached ) {
			return $cached;
		}

		// phpcs:disable
		$data = $this->wpdb->get_row(
			$this->wpdb->prepare(
				"SELECT COUNT(*) as attempts, MAX(last_attempt) as last_attempt FROM {$this->table_name} WHERE ip = %s AND log_type = %s",
				$ip,
				self::TYPE_FAILED_LOGIN
			)
		);
		// phpcs:enable

		if ( ! $data || ! $data->last_attempt ) {
			$row = null;
		} else {
			$row = (object) [
				'ip'           => $ip,
				'attempts'     => (int) $data->attempts,
				'last_attempt' => (int) $data->last_attempt,
			];
		}

		wp_cache_set( $cache_key, $row, self::CACHE_GROUP, self::CACHE_TTL );

		return $row;
	}


	/**
	 * Get failed login attempts in a specific time window.
	 *
	 * @param string $ip             Client IP.
	 * @param int    $window_seconds Time window in seconds.
	 * @return int Number of failed login attempts.
	 */
	public function get_failed_login_attempts_in_window( $ip, $window_seconds ) {
		$cutoff = time() - absint( $window_seconds );
		// phpcs:disable
		$attempts = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->table_name} WHERE ip = %s AND log_type = %s AND last_attempt >= %d",
				$ip,
				self::TYPE_FAILED_LOGIN,
				$cutoff
			)
		);
		// phpcs:enable

		return (int) $attempts;
	}


	/**
	 * Increment the attempt count for an existing IP and update the last_attempt timestamp.
	 *
	 * Now just inserts a new attempt to keep them as separate records.
	 *
	 * @param string $ip       The IP address to update.
	 * @param int    $attempts The current attempt count (ignored).
	 * @return int|false The number of rows inserted, or false on error.
	 */
	public function increment_attempts( $ip, $attempts ) {
		return $this->insert_attempt( $ip );
	}


	/**
	 * Insert a new IP row with initial attempt count of 1.
	 *
	 * Invalidates the relevant object cache entries after the write.
	 *
	 * @param string $ip The IP address to insert.
	 * @return int|false The number of rows inserted, or false on error.
	 */
	public function insert_attempt( $ip ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $this->wpdb->insert(
			$this->table_name,
			array(
				'ip'           => $ip,
				'attempts'     => 1,
				'last_attempt' => time(),
				'log_type'     => self::TYPE_FAILED_LOGIN,
			),
			array( '%s', '%d', '%d', '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );

		return $result;
	}


	/**
	 * Get the total sum of all failed login attempts.
	 *
	 * Uses object caching with a dedicated key.
	 *
	 * @return int The total number of failed attempts.
	 */
	public function get_total_attempts() {
		$cached = \wp_cache_get( 'securefusion_bf_total_attempts', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:disable
		$total = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT SUM(attempts) FROM {$this->table_name} WHERE log_type != %s",
				self::TYPE_SUCCESSFUL_LOGIN
			)
		);
		// phpcs:enable

		$total = (int) $total;
		\wp_cache_set( 'securefusion_bf_total_attempts', $total, self::CACHE_GROUP, self::CACHE_TTL );

		return $total;
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
		$type      = self::normalize_log_type( $type );
		$cache_key = 'securefusion_bf_total_attempts_' . $type;
		$cached    = \wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:disable
		$total = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT SUM(attempts) FROM {$this->table_name} WHERE log_type = %s",
				$type
			)
		);
		// phpcs:enable

		$total = (int) $total;
		\wp_cache_set( $cache_key, $total, self::CACHE_GROUP, self::CACHE_TTL );

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
		$cached = \wp_cache_get( 'securefusion_bf_unique_ips', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:disable
		$count = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT COUNT(DISTINCT ip) FROM {$this->table_name} WHERE log_type != %s",
				self::TYPE_SUCCESSFUL_LOGIN
			)
		);
		// phpcs:enable

		$count = (int) $count;
		\wp_cache_set( 'securefusion_bf_unique_ips', $count, self::CACHE_GROUP, self::CACHE_TTL );

		return $count;
	}


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

			// phpcs:disable
			return $this->wpdb->get_results(
				$this->wpdb->prepare(
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
					FROM {$this->ip_rules_table} r
					LEFT JOIN {$this->table_name} l ON r.ip = l.ip
					WHERE r.rule_type = 'blocked'
					GROUP BY r.ip
					ORDER BY {$orderby_sql} {$order}
					LIMIT %d OFFSET %d",
					$per_page,
					$offset
				)
			);
			// phpcs:enable
		}

		$orderby_sql = 'l.' . $orderby;
		if ( $orderby === 'ip' ) {
			$orderby_sql = 'INET_ATON(l.ip)';
		}

		$where = '';
		if ( ! empty( $type_filter ) ) {
			$type_filter = self::normalize_log_type( $type_filter );
			$where       = $this->wpdb->prepare( ' WHERE l.log_type = %s', $type_filter );
		}

		// phpcs:disable
		return $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SELECT 
					l.id, 
					l.ip, 
					l.attempts, 
					l.last_attempt, 
					l.log_type, 
					l.user_agent, 
					l.payload, 
					IF(r.rule_type = 'blocked', 1, 0) AS is_blocked, 
					IF(r.rule_type = 'whitelisted', 1, 0) AS is_whitelisted 
				FROM {$this->table_name} l
				LEFT JOIN {$this->ip_rules_table} r ON l.ip = r.ip
				{$where}
				ORDER BY {$orderby_sql} {$order}
				LIMIT %d OFFSET %d",
				$per_page,
				$offset
			)
		);
		// phpcs:enable
	}


	/**
	 * Get total number of rows in the brute force table.
	 *
	 * @param string $type_filter Optional log type filter (e.g. 'failed_login', 'bad_request', 'blocked').
	 *
	 * @return int Total row count.
	 */
	public function get_total_rows( $type_filter = '' ) {
		if ( $type_filter === 'blocked' ) {
			// phpcs:disable
			$count = $this->wpdb->get_var(
				$this->wpdb->prepare(
					"SELECT COUNT(*) FROM {$this->ip_rules_table} WHERE rule_type = %s",
					'blocked'
				)
			);
			// phpcs:enable

			return (int) $count;
		}

		$where = '';
		if ( ! empty( $type_filter ) ) {
			$type_filter = self::normalize_log_type( $type_filter );
			$where       = $this->wpdb->prepare( ' WHERE log_type = %s', $type_filter );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$count = $this->wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant.
			"SELECT COUNT(*) FROM {$this->table_name}{$where}"
		);

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
		if ( $type_filter === 'blocked' ) {
			// phpcs:disable
			return $this->wpdb->get_results(
				"SELECT 
					r.ip AS ip,
					COALESCE(SUM(l.attempts), 0) AS attempts,
					COALESCE(MAX(l.last_attempt), MAX(r.created_at)) AS last_attempt,
					'blocked' AS log_type,
					MAX(l.user_agent) AS user_agent,
					MAX(l.payload) AS payload,
					1 AS is_blocked,
					0 AS is_whitelisted
				FROM {$this->ip_rules_table} r
				LEFT JOIN {$this->table_name} l ON r.ip = l.ip
				WHERE r.rule_type = 'blocked'
				GROUP BY r.ip
				ORDER BY last_attempt DESC"
			);
			// phpcs:enable
		}

		$where = '';
		if ( ! empty( $type_filter ) ) {
			$type_filter = self::normalize_log_type( $type_filter );
			$where       = $this->wpdb->prepare( ' WHERE l.log_type = %s', $type_filter );
		}

		// phpcs:disable
		return $this->wpdb->get_results(
			"SELECT 
				l.ip, 
				l.attempts, 
				l.last_attempt, 
				l.log_type, 
				l.user_agent, 
				l.payload, 
				IF(r.rule_type = 'blocked', 1, 0) AS is_blocked, 
				IF(r.rule_type = 'whitelisted', 1, 0) AS is_whitelisted 
			FROM {$this->table_name} l
			LEFT JOIN {$this->ip_rules_table} r ON l.ip = r.ip
			{$where}
			ORDER BY l.last_attempt DESC"
		);
		// phpcs:enable
	}


	/**
	 * Get IP ranges grouped by /24 subnet (first 3 octets).
	 *
	 * Returns each unique range prefix with the count of unique IPs
	 * and total attempts in that range.
	 *
	 * @return array Array of objects with range_prefix, ip_count, total_attempts.
	 */
	public function get_ip_ranges() {
		$cached = \wp_cache_get( 'securefusion_bf_ip_ranges', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return $cached;
		}

		// phpcs:disable
		$rows = $this->wpdb->get_results(
			"SELECT SUBSTRING_INDEX(ip, '.', 3) AS range_prefix,
				COUNT(DISTINCT ip) AS ip_count,
				SUM(attempts) AS total_attempts,
				MIN(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS min_last_octet,
				MAX(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS max_last_octet
			FROM {$this->table_name}
			WHERE ip LIKE '%.%.%.%'
			GROUP BY range_prefix
			ORDER BY INET_ATON(CONCAT(SUBSTRING_INDEX(ip, '.', 3), '.0')) ASC"
		);
		// phpcs:enable

		// Cache for 5 minutes.
		\wp_cache_set( 'securefusion_bf_ip_ranges', $rows, self::CACHE_GROUP, self::CACHE_TTL );

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

		// phpcs:disable
		return $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SELECT SUBSTRING_INDEX(ip, '.', 3) AS range_prefix,
					COUNT(DISTINCT ip) AS ip_count,
					SUM(attempts) AS total_attempts,
					MIN(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS min_last_octet,
					MAX(CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED)) AS max_last_octet
				FROM {$this->table_name}
				WHERE ip LIKE '%.%.%.%'
				GROUP BY range_prefix
				ORDER BY {$orderby_sql} {$order}
				LIMIT %d OFFSET %d",
				$per_page,
				$offset
			)
		);
		// phpcs:enable
	}


	/**
	 * Get total count of unique IP ranges.
	 *
	 * @return int Total number of unique /24 ranges.
	 */
	public function get_total_ip_ranges() {
		$cached = \wp_cache_get( 'securefusion_bf_total_ip_ranges', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:disable
		$count = $this->wpdb->get_var(
			"SELECT COUNT(DISTINCT SUBSTRING_INDEX(ip, '.', 3))
			FROM {$this->table_name}
			WHERE ip LIKE '%.%.%.%'"
		);
		// phpcs:enable

		$count = (int) $count;
		\wp_cache_set( 'securefusion_bf_total_ip_ranges', $count, self::CACHE_GROUP, self::CACHE_TTL );

		return $count;
	}


	/**
	 * Get all IPs within a specific /24 range prefix.
	 *
	 * @param string $range_prefix First 3 octets (e.g. '192.168.1').
	 * @return array Array of row objects with ip property.
	 */
	public function get_ips_by_range_prefix( $range_prefix ) {
		// phpcs:disable
		$query = $this->wpdb->prepare(
			"SELECT DISTINCT ip FROM {$this->table_name} WHERE ip LIKE %s ORDER BY CAST(SUBSTRING_INDEX(ip, '.', -1) AS UNSIGNED) ASC",
			$this->wpdb->esc_like( $range_prefix ) . '.%'
		);

		return $this->wpdb->get_results( $query );
		// phpcs:enable
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
			$range_esc = $this->wpdb->esc_like( $range_prefix ) . '.%';

			// phpcs:disable
			return $this->wpdb->get_results(
				$this->wpdb->prepare(
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
					FROM {$this->ip_rules_table} r
					LEFT JOIN {$this->table_name} l ON r.ip = l.ip
					WHERE r.rule_type = 'blocked' AND r.ip LIKE %s
					GROUP BY r.ip
					ORDER BY {$orderby_sql} {$order}
					LIMIT %d OFFSET %d",
					$range_esc,
					$per_page,
					$offset
				)
			);
			// phpcs:enable
		}

		$orderby_sql = 'l.' . $orderby;
		if ( $orderby === 'ip' ) {
			$orderby_sql = 'INET_ATON(l.ip)';
		}

		$type_where = '';
		if ( ! empty( $type_filter ) ) {
			$type_filter = self::normalize_log_type( $type_filter );
			$type_where  = $this->wpdb->prepare( ' AND l.log_type = %s', $type_filter );
		}

		$range_esc = $this->wpdb->esc_like( $range_prefix ) . '.%';

		// phpcs:disable
		$query = $this->wpdb->prepare(
			"SELECT 
				l.id, 
				l.ip, 
				l.attempts, 
				l.last_attempt, 
				l.log_type, 
				l.user_agent, 
				l.payload, 
				IF(r.rule_type = 'blocked', 1, 0) AS is_blocked, 
				IF(r.rule_type = 'whitelisted', 1, 0) AS is_whitelisted 
			FROM {$this->table_name} l
			LEFT JOIN {$this->ip_rules_table} r ON l.ip = r.ip
			WHERE l.ip LIKE %s{$type_where}
			ORDER BY {$orderby_sql} {$order}
			LIMIT %d OFFSET %d",
			$range_esc,
			$per_page,
			$offset
		);

		return $this->wpdb->get_results( $query );
		// phpcs:enable
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
		if ( $type_filter === 'blocked' ) {
			$range_prefix = $this->wpdb->esc_like( $range_prefix );
			// phpcs:disable
			$count = $this->wpdb->get_var(
				$this->wpdb->prepare(
					"SELECT COUNT(*) FROM {$this->ip_rules_table} WHERE rule_type = %s AND ip LIKE %s",
					'blocked',
					$range_prefix . '%'
				)
			);
			// phpcs:enable

			return (int) $count;
		}

		$range_prefix = $this->wpdb->esc_like( $range_prefix );
		$table_name   = $this->table_name;

		if ( ! empty( $type_filter ) ) {
			$type_filter = self::normalize_log_type( $type_filter );
			$query       = $this->wpdb->prepare(
				'SELECT COUNT(*) FROM ' . \esc_sql( $table_name ) . ' WHERE ip LIKE %s AND log_type = %s',
				$range_prefix . '%',
				$type_filter
			);
		} else {
			$query = $this->wpdb->prepare(
				'SELECT COUNT(*) FROM ' . \esc_sql( $table_name ) . ' WHERE ip LIKE %s',
				$range_prefix . '%'
			);
		}

		// phpcs:ignore
		return (int) $this->wpdb->get_var( $query );
	}


	/**
	 * Clean up old IP addresses based on inactivity and attempt count.
	 *
	 * @param int $days         Number of days of inactivity required for deletion.
	 * @param int $max_attempts Maximum number of attempts allowed for an IP to be deleted.
	 * @return int|false Number of deleted rows, or false on failure.
	 */
	public function cleanup_old_ips( $days, $max_attempts ) {
		$cutoff_time = time() - ( absint( $days ) * DAY_IN_SECONDS );
		$table_name  = $this->table_name;

		// phpcs:disable
		$result      = $this->wpdb->query(
			$this->wpdb->prepare(
				"DELETE FROM {$table_name} WHERE attempts < %d AND last_attempt < %d",
				absint( $max_attempts ),
				absint( $cutoff_time )
			)
		);
		// phpcs:enable

		if ( $result !== false && $result > 0 ) {
			$this->invalidate_all_cache();
		}

		return $result;
	}


	/**
	 * Truncate (delete all rows from) the brute force table.
	 *
	 * @return bool Whether the operation succeeded.
	 */
	public function truncate_table() {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant.
		$result = $this->wpdb->query( "TRUNCATE TABLE {$this->table_name}" );

		$this->invalidate_all_cache();

		return $result !== false;
	}


	/**
	 * Bulk insert rows (used for import).
	 *
	 * Validates and sanitizes each row before insertion.
	 *
	 * @param array $rows Array of associative arrays with 'ip', 'attempts', 'last_attempt' keys.
	 * @return int Number of rows successfully inserted.
	 */
	public function bulk_insert( $rows ) {
		$inserted = 0;

		foreach ( $rows as $row ) {
			if ( ! isset( $row['ip'], $row['attempts'], $row['last_attempt'] ) ) {
				continue;
			}

			$ip = filter_var( $row['ip'], FILTER_VALIDATE_IP );

			if ( ! $ip ) {
				continue;
			}

			$log_type   = isset( $row['log_type'] ) ? self::normalize_log_type( $row['log_type'] ) : self::TYPE_FAILED_LOGIN;
			$user_agent = isset( $row['user_agent'] ) ? mb_substr( sanitize_text_field( $row['user_agent'] ), 0, self::MAX_USER_AGENT_LENGTH ) : '';
			$payload    = isset( $row['payload'] ) ? mb_substr( sanitize_textarea_field( $row['payload'] ), 0, self::MAX_PAYLOAD_LENGTH ) : '';

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->insert(
				$this->table_name,
				array(
					'ip'           => $ip,
					'attempts'     => absint( $row['attempts'] ),
					'last_attempt' => absint( $row['last_attempt'] ),
					'log_type'     => $log_type,
					'user_agent'   => $user_agent,
					'payload'      => $payload,
				),
				array( '%s', '%d', '%d', '%s', '%s', '%s' )
			);

			if ( $result ) {
				++$inserted;
			}

			// Handle rules insertion if imported rows contain block/whitelist flags.
			if ( isset( $row['is_blocked'] ) && absint( $row['is_blocked'] ) === 1 ) {
				$this->block_ip( $ip );
			} elseif ( isset( $row['is_whitelisted'] ) && absint( $row['is_whitelisted'] ) === 1 ) {
				$this->whitelist_ip( $ip );
			}
		}

		if ( $inserted > 0 ) {
			$this->invalidate_all_cache();
		}

		return $inserted;
	}


	/**
	 * Invalidate all cache entries related to a specific IP address.
	 *
	 * Also invalidates aggregate statistics since they may have changed.
	 *
	 * @param string $ip The IP address whose cache should be invalidated.
	 * @return void
	 */
	private function invalidate_cache_for_ip( $ip ) {
		$cache_key = 'securefusion_bf_ip_' . md5( $ip );

		\wp_cache_delete( $cache_key, self::CACHE_GROUP );
		$this->invalidate_all_cache();
	}


	/**
	 * Invalidate all aggregate cache entries.
	 *
	 * @return void
	 */
	private function invalidate_all_cache() {
		\wp_cache_delete( 'securefusion_bf_total_attempts', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_attempts_failed_login', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_attempts_bad_request', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_attempts_bad_cookie', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_attempts_bad_bot', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_attempts_bad_query', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_attempts_blocked', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_unique_ips', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_rows', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_ip_ranges', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_blocked_rules', self::CACHE_GROUP );
	}


	/**
	 * Migrate the old plugin table to the new table name.
	 *
	 * Checks if the old 'secuplug_brute_force_table' exists and renames it.
	 * Uses $wpdb->prepare() for the existence check.
	 *
	 * @return void
	 */
	public function maybe_migrate_old_table() {
		$old_table = $this->wpdb->prefix . 'secuplug_brute_force_table';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$exists = $this->wpdb->get_var(
			/* phpcs:ignore */
			$this->wpdb->prepare( 'SHOW TABLES LIKE %s', $this->wpdb->esc_like( $old_table ) )
		);

		if ( $exists === $old_table ) {
			/*
			 * RENAME TABLE does not support parameterized table names in MySQL.
			 * Both values are constructed from $wpdb->prefix (WordPress internal property)
			 * concatenated with hardcoded string literals — no user input is involved.
			 * Backtick-quoting the identifiers protects against reserved word conflicts.
			 */
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$this->wpdb->query( "RENAME TABLE `{$old_table}` TO `{$this->table_name}`" );
		}
	}


	/**
	 * Create the brute force table if it doesn't exist.
	 *
	 * Uses WordPress dbDelta() for safe schema management.
	 *
	 * @return void
	 */
	public function create_table() {
		$charset_collate = $this->wpdb->get_charset_collate();
		$table_name      = $this->table_name;
		$rules_table     = $this->ip_rules_table;

		$sql_logs = "CREATE TABLE {$table_name} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip varchar(50) NOT NULL,
            attempts int DEFAULT '0' NOT NULL,
            expiration int DEFAULT '0' NOT NULL,
            last_attempt int DEFAULT '0' NOT NULL,
            log_type varchar(50) DEFAULT 'failed_login' NOT NULL,
            user_agent text NULL,
            payload text NULL,
            PRIMARY KEY  (id),
            KEY  ip_log_type (ip(20), log_type(15))
        ) {$charset_collate};";

		$sql_rules = "CREATE TABLE {$rules_table} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip varchar(50) NOT NULL,
            rule_type varchar(50) NOT NULL,
            created_at int DEFAULT '0' NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY  ip (ip)
        ) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		\dbDelta( $sql_logs );
		\dbDelta( $sql_rules );
	}


	/**
	 * Safe check and addition of the composite index if missing.
	 *
	 * @return void
	 */
	public function maybe_add_database_indexes() {
		// Check if index exists on {$this->table_name}.
		// phpcs:disable
		$index_exists = $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SHOW INDEX FROM {$this->table_name} WHERE Key_name = %s",
				'ip_log_type'
			)
		);

		if ( empty( $index_exists ) ) {
			
			$this->wpdb->query(
				$this->wpdb->prepare(
					'ALTER TABLE ' . esc_sql( $this->table_name ) . ' ADD KEY ip_log_type (ip(20), log_type(15))'
				)
			);
		}
		// phpcs:enable
	}


	/**
	 * Migrate existing rows to set a default log type if they are empty or null.
	 *
	 * @return void
	 */
	public function migrate_existing_rows_to_failed_login() {
		// phpcs:disable
		$this->wpdb->query(
			$this->wpdb->prepare(
				"UPDATE {$this->table_name} SET log_type = %s WHERE log_type = '' OR log_type IS NULL",
				self::TYPE_FAILED_LOGIN
			)
		);
		// phpcs:enable
	}


	/**
	 * Log a security event with full details.
	 *
	 * Truncates user_agent and payload to configured limits to prevent log poisoning.
	 *
	 * @param string $ip         Client IP address.
	 * @param string $log_type   Raw log type (will be normalized).
	 * @param string $user_agent HTTP User-Agent string.
	 * @param string $payload    Request payload or triggering data.
	 * @return int|false The number of rows inserted, or false on error.
	 */
	public function log_attempt_with_details( $ip, $log_type, $user_agent = '', $payload = '' ) {
		$log_type   = self::normalize_log_type( $log_type );
		$user_agent = mb_substr( sanitize_text_field( $user_agent ), 0, self::MAX_USER_AGENT_LENGTH );
		$payload    = mb_substr( $payload, 0, self::MAX_PAYLOAD_LENGTH );

		// Always insert a new row to preserve payload/username/browser details.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $this->wpdb->insert(
			$this->table_name,
			array(
				'ip'           => $ip,
				'attempts'     => 1,
				'last_attempt' => time(),
				'log_type'     => $log_type,
				'user_agent'   => $user_agent,
				'payload'      => $payload,
			),
			array( '%s', '%d', '%d', '%s', '%s', '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );

		return $result;
	}


	/**
	 * Block an IP address permanently.
	 *
	 * Whitelisted IPs cannot be blocked.
	 *
	 * @param string $ip The IP address to block.
	 * @return bool True if blocked, false if whitelisted or error.
	 */
	public function block_ip( $ip ) {
		if ( $this->is_ip_whitelisted( $ip ) ) {
			return false;
		}

		// phpcs:disable
		$existing_id = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT id FROM {$this->ip_rules_table} WHERE ip = %s LIMIT 1",
				$ip
			)
		);
		// phpcs:enable

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->update(
				$this->ip_rules_table,
				array(
					'rule_type'  => 'blocked',
					'created_at' => time(),
				),
				array( 'id' => $existing_id ),
				array( '%s', '%d' ),
				array( '%d' )
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->insert(
				$this->ip_rules_table,
				array(
					'ip'         => $ip,
					'rule_type'  => 'blocked',
					'created_at' => time(),
				),
				array( '%s', '%s', '%d' )
			);
		}

		$this->invalidate_cache_for_ip( $ip );
		\wp_cache_delete( 'securefusion_bf_whitelisted_' . md5( $ip ), self::CACHE_GROUP );

		return $result !== false;
	}


	/**
	 * Unblock an IP address.
	 *
	 * @param string $ip The IP address to unblock.
	 * @return bool Whether the operation succeeded.
	 */
	public function unblock_ip( $ip ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $this->wpdb->delete(
			$this->ip_rules_table,
			array(
				'ip'        => $ip,
				'rule_type' => 'blocked',
			),
			array( '%s', '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );
		\wp_cache_delete( 'securefusion_bf_blocked_' . md5( $ip ), self::CACHE_GROUP );

		return $result !== false;
	}


	/**
	 * Delete any IP rule (blocked or whitelisted).
	 *
	 * @param string $ip The IP or CIDR range.
	 * @return bool Whether the operation succeeded.
	 */
	public function delete_ip_rule( $ip ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $this->wpdb->delete(
			$this->ip_rules_table,
			array( 'ip' => $ip ),
			array( '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );
		\wp_cache_delete( 'securefusion_bf_blocked_' . md5( $ip ), self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_whitelisted_' . md5( $ip ), self::CACHE_GROUP );

		return $result !== false;
	}


	/**
	 * Get all blocked IP and range rules.
	 *
	 * Uses caching to avoid repeated DB queries on every request.
	 *
	 * @return array Array of IP/Range strings.
	 */
	public function get_blocked_rules() {
		$cache_key = 'securefusion_bf_blocked_rules';
		$cached    = \wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached ) {
			return $cached;
		}

		// phpcs:disable
		$rules = $this->wpdb->get_col(
			$this->wpdb->prepare(
				"SELECT ip FROM {$this->ip_rules_table} WHERE rule_type = %s",
				'blocked'
			)
		);
		 // phpcs:enable

		if ( ! is_array( $rules ) ) {
			$rules = [];
		}

		\wp_cache_set( $cache_key, $rules, self::CACHE_GROUP, self::CACHE_TTL );

		return $rules;
	}


	/**
	 * Check if an IP address is within a CIDR range or matches exactly.
	 *
	 * @param string $ip    Client IP address.
	 * @param string $range IP address or CIDR range (e.g. 192.168.1.0/24).
	 * @return bool True if IP is in range.
	 */
	public function ip_in_range( $ip, $range ) {
		if ( strpos( $range, '/' ) === false ) {
			return $ip === $range;
		}

		list( $subnet, $bits ) = explode( '/', $range );
		$ip_dec                = ip2long( $ip );
		$subnet_dec            = ip2long( $subnet );

		if ( false === $ip_dec || false === $subnet_dec ) {
			return false;
		}

		$bits = (int) $bits;
		if ( $bits < 0 || $bits > 32 ) {
			return false;
		}

		$mask = ~ ( ( 1 << ( 32 - $bits ) ) - 1 );

		return ( $ip_dec & $mask ) === ( $subnet_dec & $mask );
	}


	/**
	 * Check if a specific CIDR range is directly blocked in rules.
	 *
	 * @param string $cidr CIDR range (e.g. 192.168.1.0/24).
	 * @return bool True if directly blocked.
	 */
	public function is_range_blocked( $cidr ) {
		$blocked_rules = $this->get_blocked_rules();
		return in_array( $cidr, $blocked_rules, true );
	}


	/**
	 * Check if an IP address is currently blocked (either directly or via range).
	 *
	 * @param string $ip The IP address to check.
	 * @return bool True if blocked.
	 */
	public function is_ip_blocked( $ip ) {
		$blocked_rules = $this->get_blocked_rules();
		$exact_rules   = [];
		$cidr_rules    = [];

		foreach ( $blocked_rules as $rule ) {
			if ( strpos( $rule, '/' ) === false ) {
				$exact_rules[ $rule ] = true;
			} else {
				$cidr_rules[] = $rule;
			}
		}

		if ( isset( $exact_rules[ $ip ] ) ) {
			return true;
		}

		foreach ( $cidr_rules as $rule ) {
			if ( $this->ip_in_range( $ip, $rule ) ) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Whitelist an IP address (admin IP).
	 *
	 * Whitelisted IPs are immune to blocking.
	 *
	 * @param string $ip The IP address to whitelist.
	 * @return bool Whether the operation succeeded.
	 */
	public function whitelist_ip( $ip ) {
		// phpcs:disable
		$existing_id = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT id FROM {$this->ip_rules_table} WHERE ip = %s LIMIT 1",
				$ip
			)
		);
		 // phpcs:enable

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->update(
				$this->ip_rules_table,
				array(
					'rule_type'  => 'whitelisted',
					'created_at' => time(),
				),
				array( 'id' => $existing_id ),
				array( '%s', '%d' ),
				array( '%d' )
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->insert(
				$this->ip_rules_table,
				array(
					'ip'         => $ip,
					'rule_type'  => 'whitelisted',
					'created_at' => time(),
				),
				array( '%s', '%s', '%d' )
			);
		}

		$this->invalidate_cache_for_ip( $ip );
		\wp_cache_delete( 'securefusion_bf_blocked_' . md5( $ip ), self::CACHE_GROUP );

		return $result !== false;
	}


	/**
	 * Check if an IP address is whitelisted.
	 *
	 * @param string $ip The IP address to check.
	 * @return bool True if whitelisted.
	 */
	public function is_ip_whitelisted( $ip ) {
		$cache_key = 'securefusion_bf_whitelisted_' . md5( $ip );
		$cached    = \wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (bool) $cached;
		}

		// phpcs:disable
		$rule_type = $this->wpdb->get_var(
			$this->wpdb->prepare(
				"SELECT rule_type FROM {$this->ip_rules_table} WHERE ip = %s LIMIT 1",
				$ip
			)
		);
		 // phpcs:enable

		$result = ( $rule_type === 'whitelisted' );
		\wp_cache_set( $cache_key, $result ? 1 : 0, self::CACHE_GROUP, self::CACHE_TTL );

		return $result;
	}


	/**
	 * Delete rows by log type, or truncate all if type is empty.
	 *
	 * @param string $type_filter Log type to delete. Empty string for all.
	 * @return bool Whether the operation succeeded.
	 */
	public function delete_by_type( $type_filter = '' ) {
		if ( empty( $type_filter ) ) {
			return $this->truncate_table();
		}

		if ( $type_filter === 'blocked' ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->delete(
				$this->ip_rules_table,
				array( 'rule_type' => 'blocked' ),
				array( '%s' )
			);
		} else {
			$type_filter = self::normalize_log_type( $type_filter );
			// phpcs:disable
			$result = $this->wpdb->query(
				$this->wpdb->prepare(
					"DELETE FROM {$this->table_name} WHERE log_type = %s",
					$type_filter
				)
			);
			 // phpcs:enable
		}

		$this->invalidate_all_cache();

		return $result !== false;
	}


	/**
	 * Get paginated IP rules.
	 *
	 * @param int    $per_page Number of rules per page.
	 * @param int    $offset   Offset for pagination.
	 * @param string $orderby  Column to order by (whitelisted).
	 * @param string $order    ASC or DESC.
	 * @return array Array of rule objects.
	 */
	public function get_all_rules( $per_page = 20, $offset = 0, $orderby = 'created_at', $order = 'DESC' ) {
		$allowed_columns = [ 'id', 'ip', 'rule_type', 'created_at' ];
		$orderby         = in_array( $orderby, $allowed_columns, true ) ? $orderby : 'created_at';
		$order           = strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
		$per_page        = absint( $per_page );
		$offset          = absint( $offset );

		// phpcs:disable
		return $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SELECT id, ip, rule_type, created_at FROM {$this->ip_rules_table} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
				$per_page,
				$offset
			)
		);
		 // phpcs:enable
	}


	/**
	 * Get total count of rules in the table.
	 *
	 * @return int Total rule count.
	 */
	public function get_total_rules_count() {
		// phpcs:ignore
		return (int) $this->wpdb->get_var( "SELECT COUNT(*) FROM {$this->ip_rules_table}" );
	}


	/**
	 * Get daily security log counts grouped by log type for the last 30 days.
	 *
	 * @param int $days Number of days to look back. Default 30.
	 * @return array Array of objects with log_type, date_str, and count.
	 */
	public function get_daily_attempts_stats( $days = 30 ) {
		$time_limit = time() - ( $days * DAY_IN_SECONDS );
		// phpcs:disable
		$results = $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SELECT log_type, YEAR(FROM_UNIXTIME(last_attempt)) as yr, MONTH(FROM_UNIXTIME(last_attempt)) as mo, DAY(FROM_UNIXTIME(last_attempt)) as dy, COUNT(*) as count 
				 FROM `{$this->table_name}` 
				 WHERE last_attempt >= %d 
				 GROUP BY log_type, YEAR(FROM_UNIXTIME(last_attempt)), MONTH(FROM_UNIXTIME(last_attempt)), DAY(FROM_UNIXTIME(last_attempt))
				 ORDER BY yr ASC, mo ASC, dy ASC",
				$time_limit
			)
		);
		// phpcs:enable

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
		$time_limit = time() - ( $months * 30 * DAY_IN_SECONDS );
		// phpcs:disable
		$results = $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SELECT log_type, YEAR(FROM_UNIXTIME(last_attempt)) as yr, MONTH(FROM_UNIXTIME(last_attempt)) as mo, COUNT(*) as count 
				 FROM `{$this->table_name}` 
				 WHERE last_attempt >= %d 
				 GROUP BY log_type, YEAR(FROM_UNIXTIME(last_attempt)), MONTH(FROM_UNIXTIME(last_attempt))
				 ORDER BY yr ASC, mo ASC",
				$time_limit
			)
		);
		 // phpcs:enable

		// Format to YYYY-MM.
		if ( is_array( $results ) ) {
			foreach ( $results as $row ) {
				$row->month_str = sprintf( '%04d-%02d', $row->yr, $row->mo );
			}
		}

		return $results;
	}
}
