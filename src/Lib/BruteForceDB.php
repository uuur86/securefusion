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

		// Aggregate stats are now stale.
		wp_cache_delete( 'bf_total_attempts', self::CACHE_GROUP );
		wp_cache_delete( 'bf_unique_ips', self::CACHE_GROUP );
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
