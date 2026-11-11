<?php
/**
 * Atomic short-lived locks for inline inventory and scan writes.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Prevent concurrent capture from undoing an administrator's approval changes.
 */
class CSPInlineLock {

	/**
	 * Run a mutation under a site-local lease.
	 *
	 * @param string   $scope Internal lock scope.
	 * @param callable $callback Mutation to run.
	 * @return mixed False if another request owns the lease.
	 */
	public static function run( $scope, $callback ) {

		global $wpdb;

		$name = 'securefusion_inline_lock_' . $scope;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Lease ownership must bypass stale option caches.
		$old = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM $wpdb->options WHERE option_name = %s", $name ) );

		if ( is_string( $old ) && '' !== $old && (int) $old < time() - 120 ) {

			self::release( $name, $old );

		}

		$owner = time() . ':' . bin2hex( random_bytes( 16 ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- INSERT IGNORE uses the unique option_name index; add_option can overwrite a concurrent insert.
		$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO $wpdb->options (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $owner ) );

		if ( 1 !== $inserted ) {

			return false;

		}

		try {

			return $callback();

		} finally {

			self::release( $name, $owner );

		}

	}

	/**
	 * Release only the exact lease acquired by this request, including stale cleanup.
	 *
	 * @param string $name Option name.
	 * @param string $owner Lease value.
	 * @return void
	 */
	private static function release( $name, $owner ) {

		global $wpdb;

		$where = [
			'option_name'  => $name,
			'option_value' => $owner,
		];

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic compare-and-delete prevents an expired owner deleting a newer lease; invalidate the option cache below.
		$wpdb->delete( $wpdb->options, $where, [ '%s', '%s' ] );

		wp_cache_delete( $name, 'options' );

	}

}
