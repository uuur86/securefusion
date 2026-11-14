<?php
/**
 * SecuritySchema responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * SecuritySchema methods.
 *
 * @mixin BruteForceDB
 * @property \wpdb  $wpdb           WordPress database, set in BruteForceDB::__construct().
 * @property string $table_name     Log table name, set in BruteForceDB::__construct().
 * @property string $ip_rules_table IP rules table name, set in BruteForceDB::__construct().
 */
trait SecuritySchema {

	/**
	 * Migrate the old plugin table to the new table name.
	 *
	 * Checks if the old 'secuplug_brute_force_table' exists and renames it.
	 * Uses $wpdb->prepare() for the existence check.
	 *
	 * @return void
	 */
	public function maybe_migrate_old_table() {

		$wpdb = $this->wpdb;

		$old_table = \esc_sql( $wpdb->prefix . 'secuplug_brute_force_table' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$exists = $wpdb->get_var(
			$wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $old_table ) )
		);

		if ( $exists === $old_table ) {

			/*
			 * WordPress %i placeholders quote table identifiers before execution.
			 * Both values are constructed from $wpdb->prefix (WordPress internal property)
			 * concatenated with hardcoded string literals, so no user input is involved.
			 * Backtick-quoting the identifiers protects against reserved word conflicts.
			 */
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$wpdb->query( $wpdb->prepare( 'RENAME TABLE %i TO %i', $old_table, $this->table_name ) );

		}

	}


	/**
	 * Verify required columns and index definitions after schema changes.
	 *
	 * @return bool Whether the required schema exists.
	 */
	public function schema_is_ready() {

		$wpdb = $this->wpdb;

		$schemas = [
			$this->table_name     => [
				[ 'id', 'ip', 'attempts', 'expiration', 'last_attempt', 'log_type', 'user_agent', 'payload' ],
				[
					'PRIMARY'     => [ 'id' ],
					'ip_log_type' => [ 'ip', 'log_type' ],
				],
			],
			$this->ip_rules_table => [
				[ 'id', 'ip', 'rule_type', 'created_at', 'expiration', 'is_range' ],
				[
					'PRIMARY'         => [ 'id' ],
					'ip'              => [ 'ip' ],
					'range_rules'     => [ 'is_range', 'rule_type', 'id' ],
					'rule_expiration' => [ 'rule_type', 'expiration' ],
				],
			],
		];

		foreach ( $schemas as $table => $required ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$columns = $wpdb->get_col( $wpdb->prepare( 'SHOW COLUMNS FROM %i', $table ) );

			if ( $wpdb->last_error || array_diff( $required[0], (array) $columns ) ) {

				return false;

			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$rows = $wpdb->get_results( $wpdb->prepare( 'SHOW INDEX FROM %i', $table ), ARRAY_A );

			if ( $wpdb->last_error ) {

				return false;

			}

			$indexes = [];

			foreach ( (array) $rows as $row ) {

				if ( in_array( $row['Key_name'], [ 'PRIMARY', 'ip' ], true ) && (int) $row['Non_unique'] !== 0 ) {

					return false;

				}

				$indexes[ $row['Key_name'] ][ (int) $row['Seq_in_index'] ] = $row['Column_name'];

			}

			foreach ( $required[1] as $name => $fields ) {

				$actual = $indexes[ $name ] ?? [];

				ksort( $actual );

				if ( array_values( $actual ) !== $fields ) {

					return false;

				}

			}

		}

		return true;

	}


	/**
	 * Create the brute force table if it doesn't exist.
	 *
	 * Uses WordPress dbDelta() for safe schema management.
	 *
	 * @return void
	 */
	public function create_table() {

		$wpdb = $this->wpdb;

		$charset_collate = $wpdb->get_charset_collate();
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
            expiration int DEFAULT '0' NOT NULL,
            is_range tinyint(1) DEFAULT '0' NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY  ip (ip),
            KEY  range_rules (is_range,rule_type,id),
            KEY  rule_expiration (rule_type,expiration)
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

		$wpdb = $this->wpdb;

		// Check if index exists on {$this->table_name}.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$index_exists = $wpdb->get_results(
			$wpdb->prepare(
				'SHOW INDEX FROM %i WHERE Key_name = %s',
				$this->table_name,
				'ip_log_type'
			)
		);

		if ( empty( $index_exists ) ) {

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Versioned plugin schema migration requires this DDL operation.
					'ALTER TABLE %i ADD KEY ip_log_type (ip(20), log_type(15))',
					$this->table_name
				)
			);

		}

		// Check if expiration column exists in ip_rules_table.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$col_exists = $wpdb->get_results(
			$wpdb->prepare(
				'SHOW COLUMNS FROM %i LIKE %s',
				$this->ip_rules_table,
				'expiration'
			)
		);

		if ( empty( $col_exists ) ) {

			$this->create_table();

		}

	}


	/**
	 * Clear payloads that older versions stored with cookies or password fields.
	 *
	 * Uses keyset pagination, so each call touches at most one batch of rows. IP address,
	 * date and log type stay in place.
	 *
	 * @param int $after_id   Last row already processed.
	 * @param int $batch_size Rows to process.
	 * @return int Last row processed, or 0 when no rows remain.
	 */
	public function redact_legacy_payloads( $after_id, $batch_size = 500 ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; this migration needs fresh data.
		$last_id = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT MAX(id) FROM (SELECT id FROM %i WHERE id > %d ORDER BY id ASC LIMIT %d) AS batch',
				$this->table_name,
				$after_id,
				$batch_size
			)
		);

		if ( $last_id <= 0 ) {

			return 0;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; this migration needs fresh data.
		$wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET payload = %s WHERE id > %d AND id <= %d AND ( log_type = %s OR payload LIKE %s OR payload LIKE %s )',
				$this->table_name,
				'[removed]',
				$after_id,
				$last_id,
				BruteForceDB::TYPE_BAD_COOKIE,
				'%' . $wpdb->esc_like( 'pwd=' ) . '%',
				'%' . $wpdb->esc_like( 'password=' ) . '%'
			)
		);

		return $last_id;

	}


	/**
	 * Flag range rules stored before the `is_range` column existed.
	 *
	 * Runs once per schema revision from Main::install_database(), in the same request that
	 * added the column, so the range lookup never misses older ranges. One statement over the
	 * rules table, as migrate_existing_rows_to_failed_login() does over the log table; it only
	 * changes rows that are still unflagged, so a repeated run touches nothing.
	 *
	 * @return void
	 */
	public function flag_range_rules() {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; this migration needs fresh data.
		$wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET is_range = 1 WHERE is_range = 0 AND ip LIKE %s',
				$this->ip_rules_table,
				'%' . $wpdb->esc_like( '/' ) . '%'
			)
		);

	}


	/**
	 * Migrate existing rows to set a default log type if they are empty or null.
	 *
	 * @return void
	 */
	public function migrate_existing_rows_to_failed_login() {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET log_type = %s WHERE log_type = '' OR log_type IS NULL",
				$this->table_name,
				BruteForceDB::TYPE_FAILED_LOGIN
			)
		);

	}

}
