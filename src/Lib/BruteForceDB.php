<?php
/**
 * BruteForceDB Class
 *
 * Centralized, secure database access layer for the brute force protection table.
 * All SQL operations use $wpdb->prepare() for parameterized values.
 * Table name is validated once at construction and reused safely.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

/**
 * BruteForceDB Class
 *
 * Provides secure CRUD operations for the securefusion_brute_force_table.
 * Manages object caching for all read/write operations.
 *
 * @package securefusion
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
	 * The validated, prefixed table name.
	 *
	 * @var string
	 */
	private $table_name;

	/**
	 * WordPress database instance.
	 *
	 * @var \wpdb
	 */
	private $wpdb;


	/**
	 * Constructor.
	 *
	 * Initializes the wpdb reference and constructs the validated table name.
	 */
	public function __construct() {
		global $wpdb;

		$this->wpdb       = $wpdb;
		$this->table_name = $wpdb->prefix . 'securefusion_brute_force_table';
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
		$cache_key = 'bf_ip_' . md5( $ip );
		$cached    = wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached ) {
			return $cached;
		}

		// Table name is safe: constructed from $wpdb->prefix (internal WP value) + a hardcoded string literal.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Table name is safe: constructed from $wpdb->prefix (internal WP value) + a hardcoded string literal.
		$row = $this->wpdb->get_row(
			/* phpcs:ignore */
			$this->wpdb->prepare( "SELECT ip, attempts, last_attempt FROM {$this->table_name} WHERE ip = %s", $ip )
		);

		// Cache even null results to prevent repeated DB hits for unknown IPs.
		wp_cache_set( $cache_key, $row, self::CACHE_GROUP, self::CACHE_TTL );

		return $row;
	}


	/**
	 * Increment the attempt count for an existing IP and update the last_attempt timestamp.
	 *
	 * Invalidates the relevant object cache entries after the write.
	 *
	 * @param string $ip       The IP address to update.
	 * @param int    $attempts The current attempt count (will be incremented by 1).
	 * @return int|false The number of rows updated, or false on error.
	 */
	public function increment_attempts( $ip, $attempts ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $this->wpdb->update(
			$this->table_name,
			array(
				'attempts'     => $attempts + 1,
				'last_attempt' => time(),
			),
			array( 'ip' => $ip ),
			array( '%d', '%d' ),
			array( '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );

		return $result;
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
			),
			array( '%s', '%d', '%d' )
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
		$cached = wp_cache_get( 'bf_total_attempts', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$total = $this->wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant, not user input.
			"SELECT SUM(attempts) FROM {$this->table_name}"
		);

		$total = (int) $total;
		wp_cache_set( 'bf_total_attempts', $total, self::CACHE_GROUP, self::CACHE_TTL );

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
		$cached = wp_cache_get( 'bf_unique_ips', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$count = $this->wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant, not user input.
			"SELECT COUNT(DISTINCT ip) FROM {$this->table_name}"
		);

		$count = (int) $count;
		wp_cache_set( 'bf_unique_ips', $count, self::CACHE_GROUP, self::CACHE_TTL );

		return $count;
	}


	/**
	 * Get paginated rows from the brute force table.
	 *
	 * @param int    $per_page Number of rows per page.
	 * @param int    $offset   Offset for pagination.
	 * @param string $orderby  Column to order by (whitelisted).
	 * @param string $order    ASC or DESC.
	 * @return array Array of row objects.
	 */
	public function get_all_rows( $per_page = 20, $offset = 0, $orderby = 'last_attempt', $order = 'DESC' ) {
		$allowed_columns = [ 'id', 'ip', 'attempts', 'last_attempt' ];
		$orderby         = in_array( $orderby, $allowed_columns, true ) ? $orderby : 'last_attempt';
		$order           = strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
		$per_page        = absint( $per_page );
		$offset          = absint( $offset );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $this->wpdb->get_results(
			/* phpcs:ignore */
			$this->wpdb->prepare(
				"SELECT id, ip, attempts, last_attempt FROM {$this->table_name} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
				$per_page,
				$offset
			)
		);
	}


	/**
	 * Get total number of rows in the brute force table.
	 *
	 * @return int Total row count.
	 */
	public function get_total_rows() {
		$cached = wp_cache_get( 'bf_total_rows', self::CACHE_GROUP );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$count = $this->wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant.
			"SELECT COUNT(*) FROM {$this->table_name}"
		);

		$count = (int) $count;
		wp_cache_set( 'bf_total_rows', $count, self::CACHE_GROUP, self::CACHE_TTL );

		return $count;
	}


	/**
	 * Get all rows for export (no pagination).
	 *
	 * @return array Array of row objects.
	 */
	public function get_all_rows_for_export() {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $this->wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant.
			"SELECT ip, attempts, last_attempt FROM {$this->table_name} ORDER BY last_attempt DESC"
		);
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $this->wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from validated $wpdb->prefix constant.
			"SELECT SUBSTRING_INDEX(ip, '.', 3) AS range_prefix,
				COUNT(DISTINCT ip) AS ip_count,
				SUM(attempts) AS total_attempts
			FROM {$this->table_name}
			WHERE ip LIKE '%.%.%.%'
			GROUP BY range_prefix
			ORDER BY ip_count DESC"
		);
	}


	/**
	 * Get all IPs within a specific /24 range prefix.
	 *
	 * @param string $range_prefix First 3 octets (e.g. '192.168.1').
	 * @return array Array of row objects with ip property.
	 */
	public function get_ips_by_range_prefix( $range_prefix ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $this->wpdb->get_results(
			/* phpcs:ignore */
			$this->wpdb->prepare(
				"SELECT DISTINCT ip FROM {$this->table_name} WHERE ip LIKE %s ORDER BY ip ASC",
				$this->wpdb->esc_like( $range_prefix ) . '.%'
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
	 * @return array Array of row objects.
	 */
	public function get_rows_by_range( $range_prefix, $per_page = 20, $offset = 0, $orderby = 'last_attempt', $order = 'DESC' ) {
		$allowed_columns = [ 'id', 'ip', 'attempts', 'last_attempt' ];
		$orderby         = in_array( $orderby, $allowed_columns, true ) ? $orderby : 'last_attempt';
		$order           = strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
		$per_page        = absint( $per_page );
		$offset          = absint( $offset );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $this->wpdb->get_results(
			/* phpcs:ignore */
			$this->wpdb->prepare(
				"SELECT id, ip, attempts, last_attempt FROM {$this->table_name} WHERE ip LIKE %s ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
				$this->wpdb->esc_like( $range_prefix ) . '.%',
				$per_page,
				$offset
			)
		);
	}


	/**
	 * Get total row count filtered by IP range prefix.
	 *
	 * @param string $range_prefix First 3 octets (e.g. '192.168.1').
	 * @return int Total row count for the range.
	 */
	public function get_total_rows_by_range( $range_prefix ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $this->wpdb->get_var(
			/* phpcs:ignore */
			$this->wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->table_name} WHERE ip LIKE %s",
				$this->wpdb->esc_like( $range_prefix ) . '.%'
			)
		);
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

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $this->wpdb->insert(
				$this->table_name,
				array(
					'ip'           => $ip,
					'attempts'     => absint( $row['attempts'] ),
					'last_attempt' => absint( $row['last_attempt'] ),
				),
				array( '%s', '%d', '%d' )
			);

			if ( $result ) {
				++$inserted;
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
		$cache_key = 'bf_ip_' . md5( $ip );

		wp_cache_delete( $cache_key, self::CACHE_GROUP );
		$this->invalidate_all_cache();
	}


	/**
	 * Invalidate all aggregate cache entries.
	 *
	 * @return void
	 */
	private function invalidate_all_cache() {
		wp_cache_delete( 'bf_total_attempts', self::CACHE_GROUP );
		wp_cache_delete( 'bf_unique_ips', self::CACHE_GROUP );
		wp_cache_delete( 'bf_total_rows', self::CACHE_GROUP );
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

		$sql = "CREATE TABLE {$table_name} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip varchar(50) NOT NULL,
            attempts int DEFAULT '0' NOT NULL,
            expiration int DEFAULT '0' NOT NULL,
            last_attempt int DEFAULT '0' NOT NULL,
            PRIMARY KEY  (id)
        ) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}
}
