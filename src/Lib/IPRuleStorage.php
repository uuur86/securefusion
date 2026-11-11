<?php
/**
 * IPRuleStorage responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}


/**
 * IPRuleStorage methods.
 *
 * @mixin BruteForceDB
 * @property \wpdb  $wpdb           WordPress database, set in BruteForceDB::__construct().
 * @property string $table_name     Log table name, set in BruteForceDB::__construct().
 * @property string $ip_rules_table IP rules table name, set in BruteForceDB::__construct().
 * @method void invalidate_cache_for_ip( string $ip ) Clear cached data for one address.
 * @method void invalidate_all_cache() Clear cached aggregate data.
 * @method bool truncate_table() Delete every log row.
 */
trait IPRuleStorage {

	/**
	 * Block an IP address.
	 *
	 * Whitelisted IPs cannot be blocked.
	 *
	 * @param string $ip               The IP address to block.
	 * @param int    $duration_seconds Optional lockout duration in seconds.
	 * @return bool True if blocked, false if whitelisted or error.
	 */
	public function block_ip( $ip, $duration_seconds = 0 ) {

		$wpdb = $this->wpdb;

		if ( $this->is_ip_whitelisted( $ip ) ) {

			return false;

		}

		$expiration = 0;

		if ( $duration_seconds > 0 ) {

			$expiration = time() + (int) $duration_seconds;

		}

		$now = time();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$result = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, rule_type, created_at, expiration)
				 VALUES (%s, %s, %d, %d)
				 ON DUPLICATE KEY UPDATE rule_type = %s, created_at = %d, expiration = %d',
				$this->ip_rules_table,
				$ip,
				'blocked',
				$now,
				$expiration,
				'blocked',
				$now,
				$expiration
			)
		);

		$this->invalidate_cache_for_ip( $ip );

		\wp_cache_delete( 'securefusion_bf_whitelisted_' . md5( $ip ), BruteForceDB::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_blocked_rules', BruteForceDB::CACHE_GROUP );

		return $result !== false;

	}


	/**
	 * Unblock an IP address.
	 *
	 * @param string $ip The IP address to unblock.
	 * @return bool Whether the operation succeeded.
	 */
	public function unblock_ip( $ip ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$result = $wpdb->delete(
			$this->ip_rules_table,
			array(
				'ip'        => $ip,
				'rule_type' => 'blocked',
			),
			array( '%s', '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );

		\wp_cache_delete( 'securefusion_bf_blocked_' . md5( $ip ), BruteForceDB::CACHE_GROUP );

		return $result !== false;

	}


	/**
	 * Delete any IP rule (blocked or whitelisted).
	 *
	 * @param string $ip The IP or CIDR range.
	 * @return bool Whether the operation succeeded.
	 */
	public function delete_ip_rule( $ip ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$result = $wpdb->delete(
			$this->ip_rules_table,
			array( 'ip' => $ip ),
			array( '%s' )
		);

		$this->invalidate_cache_for_ip( $ip );

		\wp_cache_delete( 'securefusion_bf_blocked_' . md5( $ip ), BruteForceDB::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_whitelisted_' . md5( $ip ), BruteForceDB::CACHE_GROUP );

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

		$wpdb = $this->wpdb;

		$cache_key = 'securefusion_bf_blocked_rules';
		$cached    = \wp_cache_get( $cache_key, BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT ip, expiration FROM %i WHERE rule_type = %s',
				$this->ip_rules_table,
				'blocked'
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {

			$rows = [];

		}

		$now         = time();
		$rules       = [];
		$expired_ips = [];

		foreach ( $rows as $row ) {

			$expiration = isset( $row['expiration'] ) ? (int) $row['expiration'] : 0;

			if ( $expiration > 0 && $now > $expiration ) {

				$expired_ips[] = $row['ip'];

			} else {

				$rules[] = $row['ip'];

			}

		}

		if ( ! empty( $expired_ips ) ) {

			foreach ( $expired_ips as $expired_ip ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
				$wpdb->delete(
					$this->ip_rules_table,
					array(
						'ip'        => $expired_ip,
						'rule_type' => 'blocked',
					),
					array( '%s', '%s' )
				);

			}
			$this->invalidate_all_cache();

		}

		\wp_cache_set( $cache_key, $rules, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

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

		$ip_dec     = ip2long( $ip );
		$subnet_dec = ip2long( $subnet );

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

		$wpdb = $this->wpdb;

		if ( $this->is_ip_whitelisted( $ip ) ) {

			return true;

		}

		$now = time();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$result = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, rule_type, created_at, expiration)
				 VALUES (%s, %s, %d, 0)
				 ON DUPLICATE KEY UPDATE rule_type = %s, created_at = %d, expiration = 0',
				$this->ip_rules_table,
				$ip,
				'whitelisted',
				$now,
				'whitelisted',
				$now
			)
		);

		$this->invalidate_cache_for_ip( $ip );

		\wp_cache_delete( 'securefusion_bf_blocked_' . md5( $ip ), BruteForceDB::CACHE_GROUP );

		return $result !== false;

	}


	/**
	 * Get all whitelisted IP and range rules.
	 *
	 * Uses caching to avoid repeated DB queries on every request.
	 *
	 * @return array Array of IP/Range strings.
	 */
	public function get_whitelisted_rules() {

		$wpdb = $this->wpdb;

		$cache_key = 'securefusion_bf_whitelisted_rules';
		$cached    = \wp_cache_get( $cache_key, BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return $cached;

		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT ip FROM %i WHERE rule_type = %s',
				$this->ip_rules_table,
				'whitelisted'
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {

			$rows = [];

		}

		$rules = [];

		foreach ( $rows as $row ) {

			$rules[] = $row['ip'];

		}

		\wp_cache_set( $cache_key, $rules, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $rules;

	}


	/**
	 * Check if an IP address is whitelisted.
	 *
	 * @param string $ip The IP address to check.
	 * @return bool True if whitelisted.
	 */
	public function is_ip_whitelisted( $ip ) {

		$cache_key = 'securefusion_bf_whitelisted_' . md5( $ip );
		$cached    = \wp_cache_get( $cache_key, BruteForceDB::CACHE_GROUP );

		if ( false !== $cached ) {

			return (bool) $cached;

		}

		$whitelisted_rules = $this->get_whitelisted_rules();
		$exact_rules       = [];
		$cidr_rules        = [];

		foreach ( $whitelisted_rules as $rule ) {

			if ( strpos( $rule, '/' ) === false ) {

				$exact_rules[ $rule ] = true;

			} else {

				$cidr_rules[] = $rule;

			}

		}

		$result = false;

		if ( isset( $exact_rules[ $ip ] ) ) {

			$result = true;

		} else {

			foreach ( $cidr_rules as $rule ) {

				if ( $this->ip_in_range( $ip, $rule ) ) {

					$result = true;

					break;

				}

			}

		}

		\wp_cache_set( $cache_key, $result ? 1 : 0, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $result;

	}


	/**
	 * Delete rows by log type, or truncate all if type is empty.
	 *
	 * @param string $type_filter Log type to delete. Empty string for all.
	 * @return bool Whether the operation succeeded.
	 */
	public function delete_by_type( $type_filter = '' ) {

		$wpdb = $this->wpdb;

		if ( empty( $type_filter ) ) {

			return $this->truncate_table();

		}

		if ( $type_filter === 'blocked' ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$result = $wpdb->delete(
				$this->ip_rules_table,
				array( 'rule_type' => 'blocked' ),
				array( '%s' )
			);

		} else {

			$type_filter = BruteForceDB::normalize_log_type( $type_filter );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
			$result = $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE log_type = %s',
					$this->table_name,
					$type_filter
				)
			);

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

		$wpdb = $this->wpdb;

		$allowed_columns = [ 'id', 'ip', 'rule_type', 'created_at', 'expiration' ];
		$orderby         = in_array( $orderby, $allowed_columns, true ) ? $orderby : 'created_at';
		$order           = strtoupper( $order ) === 'ASC' ? 'ASC' : 'DESC';
		$per_page        = absint( $per_page );
		$offset          = absint( $offset );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Only allowlisted SQL ordering expressions and normalized ASC/DESC; values remain bound below.
				"SELECT id, ip, rule_type, created_at, expiration FROM %i ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$this->ip_rules_table,
				$per_page,
				$offset
			)
		);

	}


	/**
	 * Get total count of rules in the table.
	 *
	 * @return int Total rule count.
	 */
	public function get_total_rules_count() {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $this->ip_rules_table ) );

	}

}
