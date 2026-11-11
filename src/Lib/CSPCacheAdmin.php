<?php
/**
 * Page-cache status and cache driver controls on the policy screen.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Says in plain words how verified pages and page caches currently get along, and offers the fix.
 */
class CSPCacheAdmin {

	/**
	 * Register the AJAX handler and the events that make an earlier self-test stale.
	 *
	 * @return void
	 */
	public static function register() {

		add_action( 'wp_ajax_securefusion_csp_cache', [ __CLASS__, 'ajax' ] );

		// A cache plugin switched on or off changes who answers page requests.
		add_action( 'activated_plugin', [ CSPCacheSetup::class, 'invalidate' ] );
		add_action( 'deactivated_plugin', [ CSPCacheSetup::class, 'invalidate' ] );
		add_action( 'securefusion_cleanup_ips_cron', [ CSPCacheSetup::class, 'recheck' ] );

		add_action( 'update_option_' . Settings::SITE_OPTION, [ CSPCacheSetup::class, 'settings_changed' ], 10, 2 );
		add_action( 'update_site_option_' . Settings::NETWORK_OPTION, [ CSPCacheSetup::class, 'network_settings_changed' ], 10, 3 );

	}

	/**
	 * Install, remove or re-test the driver.
	 *
	 * @return void
	 */
	public static function ajax() {

		check_ajax_referer( 'securefusion_csp_cache', 'nonce' );

		if ( ! CSPCacheSetup::can_manage() ) {

			wp_send_json_error( [ 'message' => __( 'Permission denied.', 'secuplug' ) ], 403 );

			return;

		}

		$operation = isset( $_POST['operation'] ) && is_string( $_POST['operation'] ) ? sanitize_key( wp_unslash( $_POST['operation'] ) ) : '';
		$manual    = false;

		if ( 'install' === $operation ) {

			$manual = ! CSPCacheSetup::install();

		} elseif ( 'remove' === $operation ) {

			$manual = ! CSPCacheSetup::remove();

		} elseif ( 'check' === $operation ) {

			CSPCacheSetup::verify();

		} else {

			wp_send_json_error( [ 'message' => __( 'Unknown operation or stale record. Refresh the list.', 'secuplug' ) ], 400 );

			return;

		}

		ob_start();

		self::render( $manual ? $operation : '' );

		wp_send_json_success( [ 'html' => ob_get_clean() ] );

	}

	/**
	 * Describe what happens to verified pages in a page cache right now.
	 *
	 * @param array $settings Resolved settings.
	 * @param bool  $ready    Whether the driver passed its self-test.
	 * @return string
	 */
	public static function summary( $settings, $ready ) {

		if ( 'strict' !== CSPPolicy::level( $settings ) ) {

			return __( 'Inline code is not verified right now, so page caches are not affected.', 'secuplug' );

		}

		if ( 'hash' === CSPInline::method_for( $settings ) ) {

			return 'hash' === ( $settings['csp_inline_method'] ?? 'auto' )
				? __( 'Hash method: pages stay in every cache. Each piece of inline code adds about 55 bytes to the policy.', 'secuplug' )
				: __( 'A page cache was found, so hashes are used and pages stay cached. Each piece of inline code adds about 55 bytes to the policy. Install the cache driver to use one short nonce instead.', 'secuplug' );

		}

		if ( $ready ) {

			return __( 'Cached pages receive a fresh nonce on every visit through the cache driver.', 'secuplug' );

		}

		if ( 'enforce' !== CSPPolicy::mode( $settings ) ) {

			return __( 'While you test, pages stay cached. Once you enforce, pages are marked as not cacheable so that no cache can hand one nonce to every visitor.', 'secuplug' );

		}

		return __( 'Pages are marked as not cacheable, so no cache can hand one nonce to every visitor. If a cache or CDN keeps your pages, install the cache driver or choose Hash.', 'secuplug' );

	}

	/**
	 * Explain the driver's state.
	 *
	 * @param bool  $installed Whether wp-config.php holds the block.
	 * @param array $status    Last self-test.
	 * @return string
	 */
	private static function driver_state( $installed, $status ) {

		if ( ! $installed ) {

			return __( 'Cache driver: not installed.', 'secuplug' );

		}

		$reason = $status['reason'] ?? '';

		if ( 'ok' === $reason ) {

			/* translators: %s: how long ago, for example "5 minutes". */
			return sprintf( __( 'Cache driver: working. Checked %s ago.', 'secuplug' ), human_time_diff( (int) ( $status['checked'] ?? time() ) ) );

		}

		if ( 'bypassed' === $reason ) {

			return __( 'Cache driver: installed but not used. A cache answers visitors before PHP runs, so the driver cannot refresh the nonce. To keep pages cached, choose the Hash method above, or exclude HTML pages from that cache and check again.', 'secuplug' );

		}

		if ( 'unreachable' === $reason ) {

			return __( 'Cache driver: installed but not used. The site could not request its own home page, so the driver could not be tested.', 'secuplug' );

		}

		return __( 'Cache driver: installed, not confirmed yet. Servers can keep the previous wp-config.php for a few minutes. Check again shortly.', 'secuplug' );

	}

	/**
	 * Render the panel.
	 *
	 * @param string $failed Operation that could not change wp-config.php: install, remove or empty.
	 * @return void
	 */
	public static function render( $failed = '' ) {

		$settings  = Settings::all();
		$installed = CSPCacheSetup::installed();
		$status    = CSPCache::status();

		// First view after a change in the caching setup: test once, then remember the answer.
		if ( $installed && ! $status && defined( 'SECUREFUSION_CSP_DRIVER_KEY' ) && CSPCacheSetup::can_manage() ) {

			$status = CSPCacheSetup::verify();

		}

		$caches = CSPCacheSetup::detect();
		$manage = CSPCacheSetup::can_manage();
		$needed = 'strict' === CSPPolicy::level( $settings );

		?>
		<div class="fsf-csp-overview fsf-csp-cache<?php echo $needed || $installed ? '' : ' fsf-csp-cache--idle'; ?>" data-nonce="<?php echo esc_attr( wp_create_nonce( 'securefusion_csp_cache' ) ); ?>">
			<h3><?php esc_html_e( 'Page cache', 'secuplug' ); ?></h3>
			<p>
				<?php
				if ( $caches ) {

					/* translators: %s: comma-separated cache names. */
					echo esc_html( sprintf( __( 'Detected: %s.', 'secuplug' ), implode( ', ', $caches ) ) );

				} else {

					esc_html_e( 'No page cache detected.', 'secuplug' );

				}
				?>
				<?php echo esc_html( self::summary( $settings, ! empty( $status['ok'] ) && $installed ) ); ?>
			</p>
			<p><?php echo esc_html( self::driver_state( $installed, $status ) ); ?></p>
			<?php if ( 'install' === $failed ) : ?>
				<p class="fsf-field-warning"><?php esc_html_e( 'wp-config.php could not be changed from here. To install the driver by hand, add these lines directly below the first line (<?php) of wp-config.php, then check again:', 'secuplug' ); ?></p>
				<pre class="fsf-csp-policy fsf-csp-policy--block"><?php echo esc_html( CSPCacheSetup::manual_block() ); ?></pre>
			<?php elseif ( 'remove' === $failed ) : ?>
				<p class="fsf-field-warning">
					<?php
					/* translators: 1: first marker line, 2: last marker line. */
					echo esc_html( sprintf( __( 'wp-config.php could not be changed from here. Delete the lines from "%1$s" to "%2$s" by hand.', 'secuplug' ), CSPCacheSetup::BLOCK_START, CSPCacheSetup::BLOCK_END ) );
					?>
				</p>
			<?php endif; ?>
			<?php if ( $manage ) : ?>
				<div class="fsf-inline-actions">
					<?php if ( ! $installed ) : ?>
						<button type="button" class="fsf-btn fsf-btn--fix" data-cache-action="install"<?php disabled( ! $needed ); ?>><?php esc_html_e( 'Install cache driver', 'secuplug' ); ?></button>
					<?php else : ?>
						<button type="button" class="fsf-btn" data-cache-action="check"><?php esc_html_e( 'Check again', 'secuplug' ); ?></button>
						<button type="button" class="fsf-btn fsf-btn--quiet" data-cache-action="remove"><?php esc_html_e( 'Remove cache driver', 'secuplug' ); ?></button>
					<?php endif; ?>
				</div>
				<?php if ( ! $installed && ! $needed ) : ?>
					<p class="description"><?php esc_html_e( 'Not needed right now: the driver only refreshes the nonce of verified inline code. It becomes available when protection is on and "Allow all inline code" is off.', 'secuplug' ); ?></p>
				<?php elseif ( ! $installed ) : ?>
					<p class="description"><?php esc_html_e( 'Adds five marked lines to wp-config.php so a fresh nonce is set before your page cache answers. Nothing else is changed, and removing the driver deletes the lines again. It is tested right away and only used if the test passes.', 'secuplug' ); ?></p>
				<?php endif; ?>
			<?php endif; ?>
			<p class="fsf-csp-cache__status" role="status" aria-live="polite" tabindex="-1"></p>
		</div>
		<?php

	}

}
