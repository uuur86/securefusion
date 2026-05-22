<?php
/**
 * SecureFusion Uninstall
 *
 * Fired when the plugin is uninstalled (deleted from wp-admin > Plugins).
 *
 * WordPress trigger chain (verified against WP 6.9.4 core source):
 *   delete_plugins()
 *     → is_uninstallable_plugin()  — checks uninstall_plugins option OR uninstall.php existence
 *     → uninstall_plugin()         — defines WP_UNINSTALL_PLUGIN, then include_once this file
 *
 * No register_uninstall_hook() is needed because WordPress automatically
 * detects and executes this file when it exists in the plugin root directory.
 * The uninstall.php approach takes priority over register_uninstall_hook().
 *
 * @package securefusion
 */

use WaspCreators\Wasp;

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/vendor/autoload.php';

/**
 * Removes all per-site plugin data.
 *
 * In multisite, this function is called once per blog via switch_to_blog().
 * Only per-site resources are cleaned here: options, transients, cron hooks,
 * custom tables (which use $wpdb->prefix, blog-specific), and object cache.
 *
 * @return void
 */
function securefusion_uninstall_site_data() {
	global $wpdb;

	// ──────────────────────────────────────────────
	// 1. Per-site Options (current + legacy prefix).
	// ──────────────────────────────────────────────
	$wasp = new Wasp(
		'securefusion-settings',
		'securefusion',
		'securefusion'
	);

	$wasp->remove_settings();

	// ──────────────────────────────────────────────
	// 2. Per-site Transients.
	// ──────────────────────────────────────────────
	delete_transient( 'securefusion_ssl_cert_data' );

	// Wildcard cleanup: catches any transients that may be added in future versions.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_securefusion_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_securefusion_' ) . '%'
		)
	);

	// ──────────────────────────────────────────────
	// 3. Per-site Cron hooks.
	// wp_clear_scheduled_hook() operates on the current blog's cron option.
	// In multisite, each blog has its own cron schedule, so this MUST run
	// inside the per-blog loop via switch_to_blog() — NOT outside it.
	// ──────────────────────────────────────────────
	wp_clear_scheduled_hook( 'securefusion_cleanup_ips_cron' );

	// ──────────────────────────────────────────────
	// 4. Drop custom database tables.
	// $wpdb->prefix is blog-specific in multisite, so each blog's
	// tables are targeted correctly via switch_to_blog().
	// ──────────────────────────────────────────────
	$tables_to_drop = [
		$wpdb->prefix . 'securefusion_brute_force_table',
		$wpdb->prefix . 'securefusion_ip_rules',
		$wpdb->prefix . 'secuplug_brute_force_table',
	];

	foreach ( $tables_to_drop as $table ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( 'DROP TABLE IF EXISTS ' . esc_sql( $table ) );
	}

	// ──────────────────────────────────────────────
	// 5. Object cache cleanup.
	// ──────────────────────────────────────────────
	$cache_group = 'securefusion_bf';

	$cache_keys = [
		'securefusion_bf_total_attempts',
		'securefusion_bf_unique_ips',
		'securefusion_bf_total_rows',
		'securefusion_bf_total_ip_ranges',
		'securefusion_bf_ip_ranges',
	];

	foreach ( $cache_keys as $key ) {
		wp_cache_delete( $key, $cache_group );
	}

	// Flush entire cache group if the persistent cache backend supports it (WP 6.1+).
	if ( function_exists( 'wp_cache_flush_group' ) ) {
		wp_cache_flush_group( $cache_group );
	}
}


/**
 * Removes network-wide plugin data.
 *
 * These resources are stored once for the entire network, not per-blog.
 * Site options live in wp_sitemeta, site transients also live there.
 * This function should be called ONCE, not inside the per-blog loop.
 *
 * @return void
 */
function securefusion_uninstall_network_data() {
	global $wpdb;

	// ──────────────────────────────────────────────
	// 1. Network-wide site options.
	// ──────────────────────────────────────────────
	$wasp = new Wasp(
		'securefusion-settings',
		'securefusion',
		'securefusion'
	);

	$wasp->remove_settings();

	// ──────────────────────────────────────────────
	// 2. Network-wide site transients.
	// ──────────────────────────────────────────────
	delete_site_transient( 'securefusion_ssl_cert_data' );

	// Wildcard cleanup for wp_sitemeta.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
			$wpdb->esc_like( '_site_transient_securefusion_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_securefusion_' ) . '%'
		)
	);

	// ──────────────────────────────────────────────
	// 3. PAnD (Persist Admin Notices Dismissal).
	// PAnD stores dismissed notices as site_options with the key
	// format: 'pand-' . md5( $notice_id ).
	// The notice 'do-securefusion-settings-forever' splits into
	// identifier 'do-securefusion-settings' + period 'forever'.
	// ──────────────────────────────────────────────
	$pand_notice_ids = [
		'do-securefusion-settings',
	];

	foreach ( $pand_notice_ids as $notice_id ) {
		$pand_cache_key = 'pand-' . md5( $notice_id );
		delete_option( $pand_cache_key );
		delete_site_option( $pand_cache_key );
	}
}


// ──────────────────────────────────────────────────────
// Execution: Run cleanup for all sites in multisite,
// or just the single site.
// ──────────────────────────────────────────────────────
if ( is_multisite() ) {
	global $wpdb;

	// 1. Clean up each blog's per-site data.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$securefusion_blog_ids = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );

	foreach ( $securefusion_blog_ids as $securefusion_blog_id ) {
		switch_to_blog( $securefusion_blog_id );
		securefusion_uninstall_site_data();
		restore_current_blog();
	}

	// 2. Clean up network-wide data (once, outside the loop).
	securefusion_uninstall_network_data();

} else {
	// Single site: all data is per-site.
	securefusion_uninstall_site_data();

	// PAnD cleanup still needed for single site.
	$securefusion_pand_notice_ids = [
		'do-securefusion-settings',
	];

	foreach ( $securefusion_pand_notice_ids as $securefusion_pand_notice_id ) {
		$securefusion_pand_cache_key = 'pand-' . md5( $securefusion_pand_notice_id );
		delete_option( $securefusion_pand_cache_key );
	}
}
