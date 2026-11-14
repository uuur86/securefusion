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

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

/**
 * BruteForceDB functionality class.
 */
class BruteForceDB {

	use SecurityStatistics;

	use SecurityLogQueries;

	use IPRangeQueries;

	use SecuritySchema;

	use IPRuleStorage;


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
	 * Most range (CIDR) rules read on one request.
	 *
	 * Whitelisted ranges are read first, then the newest blocked ranges. New range rules are
	 * refused once this many exist, and the IP Rules screen warns if older data holds more.
	 *
	 * @var int
	 */
	const MAX_RANGE_RULES = 200;

	/**
	 * Schema revision recorded in `securefusion_db_verified` after a verified install.
	 *
	 * Raising it runs the install and migration once more on every site, through
	 * Main::maybe_update_plugin(). Revision 2: `is_range` column, `range_rules` and
	 * `rule_expiration` indexes on the IP rules table.
	 *
	 * @var string
	 */
	const SCHEMA_REVISION = '2';

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

	const TYPE_OVERSIZED_REQUEST = 'oversized_request';

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
			'successful_login'   => self::TYPE_SUCCESSFUL_LOGIN,
			'success_login'      => self::TYPE_SUCCESSFUL_LOGIN,

			// failed_login aliases.
			'failed_login'       => self::TYPE_FAILED_LOGIN,
			'failed_logins'      => self::TYPE_FAILED_LOGIN,
			'login'              => self::TYPE_FAILED_LOGIN,
			'logins'             => self::TYPE_FAILED_LOGIN,
			'login_failure'      => self::TYPE_FAILED_LOGIN,

			// bad_request aliases.
			'bad_request'        => self::TYPE_BAD_REQUEST,
			'bad_requests'       => self::TYPE_BAD_REQUEST,
			'request'            => self::TYPE_BAD_REQUEST,
			'requests'           => self::TYPE_BAD_REQUEST,

			// bad_cookie aliases.
			'bad_cookie'         => self::TYPE_BAD_COOKIE,
			'bad_cookies'        => self::TYPE_BAD_COOKIE,
			'cookie'             => self::TYPE_BAD_COOKIE,
			'cookies'            => self::TYPE_BAD_COOKIE,

			// bad_bot aliases.
			'bad_bot'            => self::TYPE_BAD_BOT,
			'bad_bots'           => self::TYPE_BAD_BOT,
			'bot'                => self::TYPE_BAD_BOT,
			'bots'               => self::TYPE_BAD_BOT,

			// bad_query aliases.
			'bad_query'          => self::TYPE_BAD_QUERY,
			'bad_queries'        => self::TYPE_BAD_QUERY,
			'query'              => self::TYPE_BAD_QUERY,
			'queries'            => self::TYPE_BAD_QUERY,

			// blocked aliases.
			'blocked'            => self::TYPE_BLOCKED,
			'block'              => self::TYPE_BLOCKED,

			// oversized_request aliases.
			'oversized_request'  => self::TYPE_OVERSIZED_REQUEST,
			'oversized_requests' => self::TYPE_OVERSIZED_REQUEST,
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
	 * Get failed login attempts in a specific time window.
	 *
	 * @param string $ip             Client IP.
	 * @param int    $window_seconds Time window in seconds.
	 * @return int Number of failed login attempts.
	 */
	public function get_failed_login_attempts_in_window( $ip, $window_seconds ) {

		return $this->count_attempts_in_window( $ip, self::TYPE_FAILED_LOGIN, $window_seconds );

	}


	/**
	 * Count an address's log rows of one type in a recent time window.
	 *
	 * @param string $ip             Client IP.
	 * @param string $log_type       Canonical log type.
	 * @param int    $window_seconds Time window in seconds.
	 * @return int Number of matching rows.
	 */
	public function count_attempts_in_window( $ip, $log_type, $window_seconds ) {

		$wpdb = $this->wpdb;

		$cutoff = time() - absint( $window_seconds );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$attempts = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ip = %s AND log_type = %s AND last_attempt >= %d',
				$this->table_name,
				$ip,
				$log_type,
				$cutoff
			)
		);

		return (int) $attempts;

	}


	/**
	 * Clean up old IP addresses based on inactivity and attempt count.
	 *
	 * @param int $days         Number of days of inactivity required for deletion.
	 * @param int $max_attempts Maximum number of attempts allowed for an IP to be deleted.
	 * @return int|false Number of deleted rows, or false on failure.
	 */
	public function cleanup_old_ips( $days, $max_attempts ) {

		$wpdb = $this->wpdb;

		$cutoff_time = time() - ( absint( $days ) * DAY_IN_SECONDS );
		$table_name  = $this->table_name;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security tables have no WordPress CRUD API. Fresh security decisions, live reports or schema checks must not use stale cached results.
		$result = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE attempts < %d AND last_attempt < %d',
				$table_name,
				absint( $max_attempts ),
				absint( $cutoff_time )
			)
		);

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

		$wpdb = $this->wpdb;

		$result = $wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', $this->table_name ) );

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

		$wpdb = $this->wpdb;

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

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
			$result = $wpdb->insert(
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
		\wp_cache_delete( 'securefusion_bf_total_attempts_oversized_request', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_unique_ips', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_rows', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_total_ip_ranges', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_blocked_rules', self::CACHE_GROUP );
		\wp_cache_delete( 'securefusion_bf_whitelisted_rules', self::CACHE_GROUP );

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

		$wpdb = $this->wpdb;

		$log_type   = self::normalize_log_type( $log_type );
		$user_agent = mb_substr( sanitize_text_field( $user_agent ), 0, self::MAX_USER_AGENT_LENGTH );
		$payload    = mb_substr( $payload, 0, self::MAX_PAYLOAD_LENGTH );

		// Always insert a new row to preserve payload/username/browser details.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom security tables have no WordPress CRUD API.
		$result = $wpdb->insert(
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

}
