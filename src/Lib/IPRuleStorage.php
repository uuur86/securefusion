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
 * Request-path lookups ("is this address blocked or allowed?") read one address through the
 * unique key on `ip` plus a bounded list of range rules (`is_range = 1`, at most
 * BruteForceDB::MAX_RANGE_RULES rows). Expired blocks simply do not match; they are deleted by
 * the cleanup cron, never on a visitor request.
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
	 * @return bool True if blocked, false if whitelisted, over the range limit or error.
	 */
	public function block_ip( $ip, $duration_seconds = 0 ) {

		$wpdb = $this->wpdb;

		if ( $this->is_ip_whitelisted( $ip ) || $this->range_rule_limit_reached( $ip ) ) {

			return false;

		}

		$expiration = 0;

		if ( $duration_seconds > 0 ) {

			$expiration = time() + (int) $duration_seconds;

		}

		$now      = time();
		$is_range = self::is_range_rule( $ip ) ? 1 : 0;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; rule writes start a new cache generation.
		$result = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, rule_type, created_at, expiration, is_range)
				 VALUES (%s, %s, %d, %d, %d)
				 ON DUPLICATE KEY UPDATE rule_type = %s, created_at = %d, expiration = %d, is_range = %d',
				$this->ip_rules_table,
				$ip,
				'blocked',
				$now,
				$expiration,
				$is_range,
				'blocked',
				$now,
				$expiration,
				$is_range
			)
		);

		$this->flush_rule_cache();
		$this->invalidate_cache_for_ip( $ip );

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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; rule writes start a new cache generation.
		$result = $wpdb->delete(
			$this->ip_rules_table,
			array(
				'ip'        => $ip,
				'rule_type' => 'blocked',
			),
			array( '%s', '%s' )
		);

		$this->flush_rule_cache();
		$this->invalidate_cache_for_ip( $ip );

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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; rule writes start a new cache generation.
		$result = $wpdb->delete(
			$this->ip_rules_table,
			array( 'ip' => $ip ),
			array( '%s' )
		);

		$this->flush_rule_cache();
		$this->invalidate_cache_for_ip( $ip );

		return $result !== false;

	}


	/**
	 * Get all active blocked IP and range rules.
	 *
	 * Admin and compatibility use only: it reads every blocked row, so the request path must
	 * use is_ip_blocked() instead. Expired rows are left for the cleanup cron.
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API; cached below.
		$rules = $wpdb->get_col(
			$wpdb->prepare(
				'SELECT ip FROM %i WHERE rule_type = %s AND ( expiration <= 0 OR expiration >= %d )',
				$this->ip_rules_table,
				'blocked',
				time()
			)
		);

		$rules = is_array( $rules ) ? $rules : [];

		\wp_cache_set( $cache_key, $rules, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return $rules;

	}


	/**
	 * Check if an IP address is within a CIDR range or matches exactly.
	 *
	 * @param string $ip    Client IP address.
	 * @param string $range IP address or CIDR range (e.g. 192.168.1.0/24 or 2001:db8::/64).
	 * @return bool True if IP is in range.
	 */
	public function ip_in_range( $ip, $range ) {

		if ( ! self::is_range_rule( (string) $range ) ) {

			return $ip === $range;

		}

		return self::cidr_contains( (string) $range, (string) $ip );

	}


	/**
	 * Whether a CIDR range holds an address, for IPv4 and IPv6.
	 *
	 * The prefix length must be a plain decimal number within the family (0-32 for IPv4,
	 * 0-128 for IPv6); anything else never matches. An IPv4 address never matches an IPv6
	 * range and the other way round, with one exception: an IPv4-mapped IPv6 address
	 * (::ffff:192.0.2.1) is the IPv4 address it carries, and a mapped range of /96 or longer
	 * (::ffff:192.0.2.0/120) is the IPv4 range it carries. A mapped range shorter than /96
	 * reaches beyond the mapped space and therefore matches no address.
	 *
	 * @param string $cidr CIDR range.
	 * @param string $ip   Address.
	 * @return bool
	 */
	public static function cidr_contains( $cidr, $ip ) {

		$cidr = (string) $cidr;
		$ip   = (string) $ip;

		if ( strlen( $cidr ) > 64 || strlen( $ip ) > 64 || 1 !== substr_count( $cidr, '/' ) ) {

			return false;

		}

		list( $subnet, $bits ) = explode( '/', $cidr );

		if ( 1 !== preg_match( '/^(?:0|[1-9][0-9]{0,2})$/', $bits ) ) {

			return false;

		}

		$network = self::packed_address( $subnet );
		$address = self::packed_address( $ip );
		$bits    = (int) $bits;

		if ( null === $network || null === $address || $bits > 8 * strlen( $network ) ) {

			return false;

		}

		$mapped_network = self::unmapped_ipv4( $network );

		if ( null !== $mapped_network && $bits >= 96 ) {

			$network = $mapped_network;
			$bits   -= 96;

		}

		$mapped_address = self::unmapped_ipv4( $address );

		if ( null !== $mapped_address ) {

			$address = $mapped_address;

		}

		if ( strlen( $network ) !== strlen( $address ) ) {

			return false;

		}

		$bytes = intdiv( $bits, 8 );
		$rest  = $bits % 8;

		if ( $bytes > 0 && 0 !== strncmp( $network, $address, $bytes ) ) {

			return false;

		}

		if ( 0 === $rest ) {

			return true;

		}

		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;

		return ( ord( $network[ $bytes ] ) & $mask ) === ( ord( $address[ $bytes ] ) & $mask );

	}


	/**
	 * Binary form of a valid IP address.
	 *
	 * @param string $ip Address text.
	 * @return string|null 4 or 16 bytes, or null for anything that is not an address.
	 */
	private static function packed_address( $ip ) {

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {

			return null;

		}

		$packed = inet_pton( $ip );

		return false === $packed ? null : $packed;

	}


	/**
	 * IPv4 address carried by an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
	 *
	 * @param string $packed Binary address.
	 * @return string|null Four bytes, or null when the address is not IPv4-mapped.
	 */
	private static function unmapped_ipv4( $packed ) {

		if ( 16 !== strlen( $packed ) || 0 !== strncmp( $packed, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {

			return null;

		}

		return substr( $packed, 12 );

	}


	/**
	 * Whether a stored rule is a range (CIDR) rather than one address.
	 *
	 * @param string $rule Rule value.
	 * @return bool
	 */
	public static function is_range_rule( $rule ) {

		return false !== strpos( (string) $rule, '/' );

	}


	/**
	 * Spellings under which one address can be stored as an exact rule.
	 *
	 * The address as given, its canonical IPv6 form, and the IPv4 address an IPv4-mapped IPv6
	 * address carries. Anything that is not an address (a CIDR string) is looked up as given.
	 *
	 * @param string $ip Address or rule value.
	 * @return string[] One to three values.
	 */
	public static function exact_rule_candidates( $ip ) {

		$candidates = [ (string) $ip ];

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {

			$packed = inet_pton( $ip );

			if ( false !== $packed ) {

				$candidates[] = (string) inet_ntop( $packed );

				$mapped = self::unmapped_ipv4( $packed );

				if ( null !== $mapped ) {

					$candidates[] = (string) inet_ntop( $mapped );

				}

			}

		}

		return array_values( array_unique( $candidates ) );

	}


	/**
	 * Decide block and allow for one address from the rule rows that can apply to it.
	 *
	 * Precedence is the one SecureFusion has always had: blocked and whitelisted are answered
	 * independently, and each caller decides which wins (the login lockout, the payload limit
	 * and new blocks skip whitelisted addresses; the request block in Middleware::init() does
	 * not ask the allowlist). A whitelisted rule matches regardless of its expiration; a
	 * blocked rule matches while its expiration is 0 (permanent) or not yet passed.
	 *
	 * @param string $ip         Address being checked.
	 * @param array  $exact_rows Rows stored under one of the address' own spellings.
	 * @param array  $range_rows Range rows; only the first BruteForceDB::MAX_RANGE_RULES are read.
	 * @param int    $now        Current time.
	 * @return array{blocked: bool, whitelisted: bool}
	 */
	public static function decide_ip_rules( $ip, array $exact_rows, array $range_rows, $now ) {

		$decision = [
			'blocked'     => false,
			'whitelisted' => false,
		];

		$matched = $exact_rows;

		foreach ( array_slice( $range_rows, 0, BruteForceDB::MAX_RANGE_RULES ) as $row ) {

			if ( isset( $row['ip'] ) && self::cidr_contains( $row['ip'], $ip ) ) {

				$matched[] = $row;

			}

		}

		foreach ( $matched as $row ) {

			$type       = isset( $row['rule_type'] ) ? $row['rule_type'] : '';
			$expiration = isset( $row['expiration'] ) ? (int) $row['expiration'] : 0;

			if ( 'whitelisted' === $type ) {

				$decision['whitelisted'] = true;

			} elseif ( 'blocked' === $type && ( $expiration <= 0 || $now <= $expiration ) ) {

				$decision['blocked'] = true;

			}

		}

		return $decision;

	}


	/**
	 * Block and allow decision for one address, from at most one query per request.
	 *
	 * @param string $ip Address (or a rule value such as a CIDR string, matched exactly).
	 * @return array{blocked: bool, whitelisted: bool}
	 */
	private function match_ip_rules( $ip ) {

		$ip   = (string) $ip;
		$rows = ( '' === $ip || strlen( $ip ) > 64 ) ? null : $this->ip_rule_rows( $ip );

		if ( null === $rows ) {

			return [
				'blocked'     => false,
				'whitelisted' => false,
			];

		}

		return self::decide_ip_rules( $ip, $rows['exact'], $rows['ranges'], time() );

	}


	/**
	 * Rule rows that can apply to one address: its exact rows and the bounded range list.
	 *
	 * The first lookup of a request reads both in one statement; the range list is then shared
	 * by every other address checked in the same request. Both parts use an index: the unique
	 * key on `ip` and `range_rules (is_range, rule_type, id)`.
	 *
	 * @param string $ip Address or rule value.
	 * @return array{exact: array, ranges: array}|null Null when the database could not answer.
	 */
	private function ip_rule_rows( $ip ) {

		$wpdb = $this->wpdb;

		$generation = $this->rule_cache_generation();
		$exact_key  = 'securefusion_bf_rule_' . $generation . '_' . md5( $ip );
		$range_key  = 'securefusion_bf_ranges_' . $generation;
		$exact      = \wp_cache_get( $exact_key, BruteForceDB::CACHE_GROUP );
		$ranges     = \wp_cache_get( $range_key, BruteForceDB::CACHE_GROUP );

		if ( is_array( $exact ) && is_array( $ranges ) ) {

			return [
				'exact'  => $exact,
				'ranges' => $ranges,
			];

		}

		$candidates  = array_pad( self::exact_rule_candidates( $ip ), 3, $ip );
		$now         = time();
		$need_exact  = ! is_array( $exact );
		$need_ranges = ! is_array( $ranges );

		if ( $need_exact && $need_ranges ) {

			$both = $this->fetch_exact_and_range_rules( $candidates, $now );

			// Databases that cannot run the combined statement get the two parts separately.
			if ( null !== $both ) {

				list( $exact, $ranges ) = $both;

				$need_exact  = false;
				$need_ranges = false;

			}

		}

		if ( $need_exact ) {

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; cached above per rule generation.
			$exact = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT ip, rule_type, expiration FROM %i WHERE ip IN (%s, %s, %s)',
					$this->ip_rules_table,
					$candidates[0],
					$candidates[1],
					$candidates[2]
				),
				ARRAY_A
			);

			if ( ! is_array( $exact ) || $wpdb->last_error ) {

				return null;

			}

		}

		if ( $need_ranges ) {

			$ranges = $this->fetch_range_rules( $now );

			// Without the range list (an unfinished schema update) exact rules still apply.
			// The failure is not cached, so the next lookup asks again.
			if ( null === $ranges ) {

				return [
					'exact'  => $exact,
					'ranges' => [],
				];

			}

		}

		\wp_cache_set( $exact_key, $exact, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );
		\wp_cache_set( $range_key, $ranges, BruteForceDB::CACHE_GROUP, BruteForceDB::CACHE_TTL );

		return [
			'exact'  => $exact,
			'ranges' => $ranges,
		];

	}


	/**
	 * Exact rows for an address and the active range rules, in one statement.
	 *
	 * @param string[] $candidates Three exact spellings (repeated when fewer exist).
	 * @param int      $now        Current time.
	 * @return array|null [ exact rows, range rows ], or null when the statement failed.
	 */
	private function fetch_exact_and_range_rules( array $candidates, $now ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; the caller caches per rule generation.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"(SELECT 'exact' AS part, ip, rule_type, expiration FROM %i WHERE ip IN (%s, %s, %s))
				UNION ALL
				(SELECT 'range' AS part, ip, rule_type, expiration FROM %i
				 WHERE is_range = 1 AND ( rule_type = %s OR expiration <= 0 OR expiration >= %d )
				 ORDER BY rule_type DESC, id DESC LIMIT %d)",
				$this->ip_rules_table,
				$candidates[0],
				$candidates[1],
				$candidates[2],
				$this->ip_rules_table,
				'whitelisted',
				$now,
				BruteForceDB::MAX_RANGE_RULES
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) || $wpdb->last_error ) {

			return null;

		}

		$exact  = [];
		$ranges = [];

		foreach ( $rows as $row ) {

			$part = isset( $row['part'] ) ? $row['part'] : '';

			unset( $row['part'] );

			if ( 'range' === $part ) {

				$ranges[] = $row;

			} else {

				$exact[] = $row;

			}

		}

		return [ $exact, $ranges ];

	}


	/**
	 * Active range rules, whitelisted ranges first, then the newest blocked ranges.
	 *
	 * Bounded by BruteForceDB::MAX_RANGE_RULES. Rules past the bound are not read; new range
	 * rules are refused at that point (range_rule_limit_reached()) and the IP Rules screen
	 * warns when older data holds more.
	 *
	 * @param int $now Current time.
	 * @return array|null Rows, or null when the database could not answer.
	 */
	private function fetch_range_rules( $now ) {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; the caller caches per rule generation.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT ip, rule_type, expiration FROM %i
				 WHERE is_range = 1 AND ( rule_type = %s OR expiration <= 0 OR expiration >= %d )
				 ORDER BY rule_type DESC, id DESC LIMIT %d',
				$this->ip_rules_table,
				'whitelisted',
				$now,
				BruteForceDB::MAX_RANGE_RULES
			),
			ARRAY_A
		);

		return ( ! is_array( $rows ) || $wpdb->last_error ) ? null : $rows;

	}


	/**
	 * Cache generation for rule lookups; every rule write starts a new one.
	 *
	 * @return string
	 */
	private function rule_cache_generation() {

		$generation = \wp_cache_get( 'securefusion_bf_rules_generation', BruteForceDB::CACHE_GROUP );

		if ( ! is_string( $generation ) || '' === $generation ) {

			$generation = uniqid( '', true );

			\wp_cache_set( 'securefusion_bf_rules_generation', $generation, BruteForceDB::CACHE_GROUP );

		}

		return $generation;

	}


	/**
	 * Make every cached rule lookup stale, on this and (with a persistent cache) other requests.
	 *
	 * @return void
	 */
	private function flush_rule_cache() {

		\wp_cache_set( 'securefusion_bf_rules_generation', uniqid( '', true ), BruteForceDB::CACHE_GROUP );

	}


	/**
	 * Number of range rules stored, active or not.
	 *
	 * @return int
	 */
	public function count_range_rules() {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; admin screens need a fresh count.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE is_range = 1', $this->ip_rules_table ) );

	}


	/**
	 * Whether a new range rule would exceed the number of range rules read per request.
	 *
	 * Updating a range that already exists is always allowed.
	 *
	 * @param string $ip Rule value.
	 * @return bool
	 */
	public function range_rule_limit_reached( $ip ) {

		if ( ! self::is_range_rule( $ip ) ) {

			return false;

		}

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; the limit needs a fresh count.
		$others = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE is_range = 1 AND ip <> %s',
				$this->ip_rules_table,
				$ip
			)
		);

		return $others >= BruteForceDB::MAX_RANGE_RULES;

	}


	/**
	 * Delete expired blocks in batches.
	 *
	 * Keyset batches through `rule_expiration (rule_type, expiration)`. Bounded by
	 * $max_batches * $batch_size rows and by the deadline; what is left is deleted on the
	 * next run. Expired rows never match a lookup, so leaving some for later is harmless.
	 *
	 * @param float $deadline    microtime( true ) value after which no new batch starts.
	 * @param int   $batch_size  Rows per batch.
	 * @param int   $max_batches Batches per call.
	 * @return int Rows deleted.
	 */
	public function cleanup_expired_ip_rules( $deadline, $batch_size = 500, $max_batches = 20 ) {

		$wpdb = $this->wpdb;

		$now         = time();
		$batch_size  = max( 1, absint( $batch_size ) );
		$max_batches = max( 1, absint( $max_batches ) );
		$deleted     = 0;

		for ( $batch = 0; $batch < $max_batches; $batch++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; cleanup needs fresh data.
			$ids = $wpdb->get_col(
				$wpdb->prepare(
					'SELECT id FROM %i WHERE rule_type = %s AND expiration > 0 AND expiration < %d ORDER BY expiration ASC, id ASC LIMIT %d',
					$this->ip_rules_table,
					'blocked',
					$now,
					$batch_size
				)
			);

			if ( empty( $ids ) || $wpdb->last_error ) {

				break;

			}

			$ids          = array_map( 'absint', $ids );
			$placeholders = implode( ', ', array_fill( 0, count( $ids ), '%d' ) );

			// A block renewed after the SELECT keeps its row: the expiration is checked again.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API.
			$result = $wpdb->query(
				$wpdb->prepare( // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- The values are passed as one array.
					// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- One %d placeholder per id; every value is bound.
					"DELETE FROM %i WHERE id IN ({$placeholders}) AND rule_type = %s AND expiration > 0 AND expiration < %d",
					// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
					array_merge( [ $this->ip_rules_table ], $ids, [ 'blocked', $now ] )
				)
			);

			if ( false === $result ) {

				break;

			}

			$deleted += (int) $result;

			if ( count( $ids ) < $batch_size || microtime( true ) >= $deadline ) {

				break;

			}

		}

		if ( $deleted > 0 ) {

			$this->flush_rule_cache();
			$this->invalidate_all_cache();

		}

		return $deleted;

	}


	/**
	 * Check if a specific CIDR range is directly blocked in rules.
	 *
	 * @param string $cidr CIDR range (e.g. 192.168.1.0/24).
	 * @return bool True if directly blocked.
	 */
	public function is_range_blocked( $cidr ) {

		// A CIDR string is looked up as an exact rule value; it is not an address, so no range
		// rule can contain it.
		return $this->match_ip_rules( $cidr )['blocked'];

	}


	/**
	 * Check if an IP address is currently blocked (either directly or via range).
	 *
	 * @param string $ip The IP address to check.
	 * @return bool True if blocked.
	 */
	public function is_ip_blocked( $ip ) {

		return $this->match_ip_rules( $ip )['blocked'];

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

		if ( $this->range_rule_limit_reached( $ip ) ) {

			return false;

		}

		$now      = time();
		$is_range = self::is_range_rule( $ip ) ? 1 : 0;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API; rule writes start a new cache generation.
		$result = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, rule_type, created_at, expiration, is_range)
				 VALUES (%s, %s, %d, 0, %d)
				 ON DUPLICATE KEY UPDATE rule_type = %s, created_at = %d, expiration = 0, is_range = %d',
				$this->ip_rules_table,
				$ip,
				'whitelisted',
				$now,
				$is_range,
				'whitelisted',
				$now,
				$is_range
			)
		);

		$this->flush_rule_cache();
		$this->invalidate_cache_for_ip( $ip );

		return $result !== false;

	}


	/**
	 * Get all whitelisted IP and range rules.
	 *
	 * Admin and compatibility use only: the request path uses is_ip_whitelisted().
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API; cached below.
		$rules = $wpdb->get_col(
			$wpdb->prepare(
				'SELECT ip FROM %i WHERE rule_type = %s',
				$this->ip_rules_table,
				'whitelisted'
			)
		);

		$rules = is_array( $rules ) ? $rules : [];

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

		return $this->match_ip_rules( $ip )['whitelisted'];

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

			$this->flush_rule_cache();

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
	 * Get paginated IP rules that are in force (expired blocks are left out).
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
				"SELECT id, ip, rule_type, created_at, expiration FROM %i
				 WHERE rule_type <> %s OR expiration <= 0 OR expiration >= %d
				 ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$this->ip_rules_table,
				'blocked',
				time(),
				$per_page,
				$offset
			)
		);

	}


	/**
	 * Get the number of rules in force (expired blocks are left out).
	 *
	 * @return int Total rule count.
	 */
	public function get_total_rules_count() {

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE rule_type <> %s OR expiration <= 0 OR expiration >= %d',
				$this->ip_rules_table,
				'blocked',
				time()
			)
		);

	}

}
