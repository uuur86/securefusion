<?php
/**
 * Review of what a site loads, grouped by the theme or plugin behind it.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Exceptions only: installed code is trusted automatically and never needs approval.
 */
class CSPInlineAdmin {

	/**
	 * Register the authenticated AJAX handler.
	 *
	 * @return void
	 */
	public static function register() {

		add_action( 'wp_ajax_securefusion_inline', [ __CLASS__, 'ajax' ] );

		CSPCacheAdmin::register();

	}

	/**
	 * Validate and read one scalar request field after authentication.
	 *
	 * @param string $key Field name.
	 * @return string
	 */
	private static function input( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Called only by ajax after authentication; exact literal comparison grants no permission.
		if ( 'path' === $key && isset( $_POST[ $key ] ) && '*' === $_POST[ $key ] ) {

			return '*';

		}

		if ( 'path' === $key ) {

			// Preserve encoded path segments so scope matches the browser request exactly.
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Called only after ajax authentication; valid_path also checks the sanitized scope.
			return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? sanitize_url( wp_unslash( $_POST[ $key ] ) ) : '';

		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Called only by ajax after check_ajax_referer and capability verification.
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';

	}

	/**
	 * Parse a path list with one exact path per line.
	 *
	 * @param string $raw Submitted text.
	 * @return string[] Valid paths, or an empty list if any line is invalid or there are too many.
	 */
	public static function parse_paths( $raw ) {

		$paths = [];

		foreach ( preg_split( '/\R/', substr( (string) $raw, 0, 8192 ), -1, PREG_SPLIT_NO_EMPTY ) as $line ) {

			$line = trim( $line );

			if ( '' === $line ) {

				continue;

			}

			// Preserve encoded path segments so scope matches the browser request exactly.
			$path = '*' === $line ? '*' : sanitize_url( $line );

			if ( ! self::valid_path( $path ) ) {

				return [];

			}

			$paths[] = $path;

		}

		if ( in_array( '*', $paths, true ) ) {

			return [ '*' ];

		}

		$paths = array_values( array_unique( $paths ) );

		return count( $paths ) <= CSPInlineRules::PATH_LIMIT ? $paths : [];

	}

	/**
	 * Apply one change to a single record.
	 *
	 * @param string   $id Record key.
	 * @param callable $change Receives the record and returns the new one.
	 * @return bool Whether the inventory was updated.
	 */
	private static function change_row( $id, $change ) {

		return CSPInlineRules::update(
			static function ( $current ) use ( $id, $change ) {

				if ( isset( $current[ $id ] ) ) {

					$current[ $id ] = $change( $current[ $id ] );

				}

				return $current;

			}
		);

	}

	/**
	 * Apply one authenticated inventory operation.
	 *
	 * @return void
	 */
	public static function ajax() {

		check_ajax_referer( 'securefusion_inline', 'nonce' );

		if ( ! current_user_can( Settings::site_capability() ) ) {

			wp_send_json_error( [ 'message' => __( 'Permission denied.', 'secuplug' ) ], 403 );

			return;

		}

		$operation = self::input( 'operation' );
		$rows      = CSPInlineRules::all();
		$id        = self::input( 'id' );
		$saved     = true;

		if ( in_array( $operation, [ 'scan', 'rescan' ], true ) ) {

			CSPInlineScan::step( 'rescan' === $operation );

		} elseif ( 'approve_all' === $operation || 'revoke_all' === $operation ) {

			$source = self::input( 'source' );
			$saved  = CSPInlineRules::bulk( '' !== $source ? $source : '*', 'approve_all' === $operation );

		} elseif ( 'block_source' === $operation || 'trust_source' === $operation ) {

			$source = self::input( 'source' );

			if ( ! in_array( $source, array_merge( CSPInlineSources::installed(), [ CSPInlineSources::EXTERNAL ] ), true ) ) {

				wp_send_json_error( [ 'message' => __( 'Unknown operation or stale record. Refresh the list.', 'secuplug' ) ], 400 );

				return;

			}

			CSPInlineRules::set_blocked( $source, 'block_source' === $operation );

		} elseif ( 'approve' === $operation && isset( $rows[ $id ] ) ) {

			$approved = '1' === self::input( 'approved' );
			$saved    = self::change_row(
				$id,
				static function ( $row ) use ( $approved ) {

					$row = CSPInlineRules::with_approval( $row, $approved );

					if ( $approved ) {

						unset( $row['revoked'] );

					} else {

						$row['revoked'] = true;

					}

					return $row;

				}
			);

		} elseif ( 'delete' === $operation && isset( $rows[ $id ] ) ) {

			$saved = CSPInlineRules::update(
				static function ( $current ) use ( $id ) {

					unset( $current[ $id ] );

					return $current;

				}
			);

		} elseif ( 'save' === $operation && isset( $rows[ $id ] ) ) {

			// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Called only after ajax authentication; parse_paths sanitizes and validates each line.
			$paths = self::parse_paths( isset( $_POST['path'] ) && is_string( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : '' );

			if ( ! $paths ) {

				wp_send_json_error( [ 'message' => __( 'Enter up to 10 exact paths, one per line, or * for every page.', 'secuplug' ) ], 400 );

				return;

			}

			$saved = self::change_row(
				$id,
				static function ( $row ) use ( $paths ) {

					return array_merge(
						$row,
						[
							'path'   => $paths[0],
							'paths'  => $paths,
							'scoped' => true,
						]
					);

				}
			);

		} elseif ( 'add' === $operation ) {

			$type   = self::input( 'type' );
			$digest = self::input( 'digest' );
			$path   = self::input( 'path' );

			if ( count( $rows ) >= CSPInlineRules::LIMIT || ! in_array( $type, [ 'script', 'style' ], true ) || ! preg_match( '#^[A-Za-z0-9+/]{43}=$#D', $digest ) || ! self::valid_path( $path ) ) {

				wp_send_json_error( [ 'message' => __( 'Enter a SHA-256 base64 digest and an exact path, or *.', 'secuplug' ) ], 400 );

				return;

			}

			$saved = CSPInlineRules::observe(
				[
					[
						'type'   => $type,
						'digest' => $digest,
						'path'   => $path,
						'origin' => '',
						'label'  => substr( self::input( 'label' ), 0, 120 ),
						'source' => CSPInlineSources::UNKNOWN,
					],
				]
			);

		} elseif ( 'refresh' !== $operation ) {

			wp_send_json_error( [ 'message' => __( 'Unknown operation or stale record. Refresh the list.', 'secuplug' ) ], 400 );

			return;

		}

		if ( ! $saved ) {

			wp_send_json_error( [ 'message' => __( 'The list is busy. Retry your change.', 'secuplug' ) ], 409 );

			return;

		}

		ob_start();

		self::rows();

		$html = ob_get_clean();

		wp_send_json_success(
			[
				'html'  => $html,
				'count' => count( self::reviewable() ),
				'scan'  => self::scan_status(),
			]
		);

	}

	/**
	 * Permit an exact path only; no query strings, wildcards or expressions.
	 *
	 * @param string $path Scope.
	 * @return bool
	 */
	public static function valid_path( $path ) {

		return '*' === $path || ( strlen( $path ) <= 512 && 1 === preg_match( '#^/(?!/)[^\s?\#]*$#D', $path ) );

	}

	/**
	 * Records only the site owner can judge. Installed code never appears here.
	 *
	 * @return array
	 */
	private static function reviewable() {

		$blocked = CSPInlineRules::blocked();

		return array_filter(
			CSPInlineRules::all(),
			static function ( $row ) use ( $blocked ) {

				$source = $row['source'] ?? CSPInlineSources::UNKNOWN;

				// Code of a trusted source is allowed where it is printed. Once the owner excludes
				// the source, each piece waits for its own decision.
				return empty( $row['origin'] ) && ( ! CSPInlineSources::trustable( $source ) || isset( $blocked[ $source ] ) );

			}
		);

	}

	/**
	 * Explain why a page was last sent with fewer rules than the settings ask for.
	 *
	 * @return string Empty when every page received its full policy.
	 */
	public static function reduced_notice() {

		$note = get_transient( CSPInline::NOTE );

		if ( ! $note ) {

			return '';

		}

		$reason = is_array( $note ) ? (string) ( $note['reason'] ?? '' ) : 'inline';
		$detail = is_array( $note ) ? (string) ( $note['detail'] ?? '' ) : '';

		if ( 'output' === $reason ) {

			/* translators: %s: file and line that sent output early. */
			return sprintf( __( 'On at least one page the full policy could not be sent, because the response had already started (%s). That page only received the always-on rules. A theme or plugin that flushes output early causes this.', 'secuplug' ), $detail );

		}

		if ( 'data' === $reason ) {

			return __( 'On at least one page an optimizer moved inline scripts into data: addresses (Autoptimize does this when it defers inline JavaScript). A hash cannot verify those, so that page was sent with all inline code allowed. Install the cache driver or choose the Nonce method, or turn that optimizer option off.', 'secuplug' );

		}

		if ( 'limits' === $reason ) {

			return __( 'On at least one page the policy grew too large for common web servers. That page was sent without some of the optional limits (images, fonts, media and similar), keeping the script rules. Shorten the allow lists to get them back.', 'secuplug' );

		}

		if ( 'all' === $reason ) {

			return __( 'On at least one page the policy grew too large for common web servers even without inline verification. That page only received the always-on rules. Shorten the allow lists.', 'secuplug' );

		}

		return __( 'On at least one page the policy grew too large for common web servers. That page was sent without inline verification, keeping only the host limits. Install the cache driver or choose the Nonce method, or shorten the allow lists.', 'secuplug' );

	}

	/**
	 * Show exactly what the saved settings send, so nothing has to be inferred.
	 *
	 * @return void
	 */
	private static function overview() {

		$settings  = Settings::all();
		$level     = CSPPolicy::level( $settings );
		$generated = CSPIntegrations::sources( $settings );
		$pending   = 0;

		foreach ( self::reviewable() as $row ) {

			if ( empty( $row['approved'] ) ) {

				++$pending;

			}

			if ( ! empty( $row['approved'] ) && isset( CSPInlineRules::HOST_TYPES[ $row['type'] ] ) ) {

				$generated[ CSPInlineRules::HOST_TYPES[ $row['type'] ] ][] = $row['digest'];

			}

		}

		if ( 'strict' === $level ) {

			$inline = 'hash' === CSPInline::method_for( $settings ) ? "'sha256-COMPUTED-PER-PAGE'" : "'nonce-RANDOM'";

			$generated['script'][] = $inline;
			$generated['style'][]  = $inline;

		}

		$sent   = CSPInlineScan::sent_policy();
		$tested = 'enforce' !== CSPPolicy::mode( $settings ) && 'off' !== $level;
		$policy = CSPPolicy::build(
			$settings,
			$generated,
			[
				'level'  => $level,
				'https'  => is_ssl(),
				'report' => $tested,
			]
		);

		?>
		<div class="fsf-csp-overview">
			<h3><?php esc_html_e( 'Sent to visitors now', 'secuplug' ); ?></h3>
			<?php if ( '' === $policy ) : ?>
				<p><?php esc_html_e( 'No Content Security Policy is sent.', 'secuplug' ); ?></p>
			<?php else : ?>
				<p>
					<?php
					if ( $tested ) {

						esc_html_e( 'Framing and base URL rules are enforced. The rest of the rules below is only being tested:', 'secuplug' );

					} else {

						esc_html_e( 'These rules are enforced:', 'secuplug' );

					}
					?>
				</p>
				<code class="fsf-csp-policy"><?php echo esc_html( $policy ); ?></code>
			<?php endif; ?>
			<?php if ( false !== strpos( $policy, 'script-src' ) && null !== $sent && false === strpos( $sent, 'script-src' ) ) : ?>
				<p class="fsf-field-warning"><?php esc_html_e( 'The last scan received fewer rules than this from your home page. Either something on the server replaces the header, or the page was sent before its policy was complete. The page answered with:', 'secuplug' ); ?></p>
				<code class="fsf-csp-policy"><?php echo esc_html( '' !== $sent ? $sent : __( 'No Content Security Policy.', 'secuplug' ) ); ?></code>
			<?php endif; ?>
			<?php if ( 'strict' === $level && $pending > 0 && ! $tested ) : ?>
				<p class="fsf-field-warning">
					<?php
					/* translators: %d: number of items waiting for review. */
					echo esc_html( sprintf( _n( '%d item in page content is not approved, so browsers are blocking it.', '%d items in page content are not approved, so browsers are blocking them.', $pending, 'secuplug' ), $pending ) );
					?>
				</p>
			<?php endif; ?>
			<?php if ( 'strict' === $level && '1' !== (string) ( $settings['csp_block_event_handlers'] ?? '0' ) ) : ?>
				<p class="description"><?php esc_html_e( 'Still open: code in attributes such as onclick and onerror runs, because many themes need it. Once your pages work, turn on "Block inline event handlers" and visit them again; a notification tells you if one needs it.', 'secuplug' ); ?></p>
			<?php endif; ?>
			<?php if ( '' !== self::reduced_notice() ) : ?>
				<p class="fsf-field-warning"><?php echo esc_html( self::reduced_notice() . ' ' . __( 'This note clears when you save the settings.', 'secuplug' ) ); ?></p>
			<?php endif; ?>
		</div>
		<?php

	}

	/**
	 * Render the review panel outside the form builder's HTML sanitizer.
	 *
	 * @param bool $network Whether this is the network settings screen.
	 * @return void
	 */
	public static function render( $network ) {

		if ( ! current_user_can( Settings::site_capability() ) ) {

			return;

		}

		self::overview();

		$settings = Settings::all();
		$level    = CSPPolicy::level( $settings );

		// Always shown: the answer changes when a cache plugin is added or removed later, and an
		// installed driver must stay removable.
		CSPCacheAdmin::render();

		// Exceptions feed host lists and inline approval, which Off does not have.
		if ( 'off' === $level ) {

			return;

		}

		if ( $network ) {

			echo '<p class="description">' . esc_html__( 'Each site reviews its own exceptions in its own SecureFusion settings.', 'secuplug' ) . '</p>';

			return;

		}

		$scan = self::scan_status();

		?>
		<section class="fsf-inline-manager" data-nonce="<?php echo esc_attr( wp_create_nonce( 'securefusion_inline' ) ); ?>" data-scan-status="<?php echo esc_attr( $scan['status'] ); ?>">
			<h3><?php esc_html_e( 'Exceptions', 'secuplug' ); ?></h3>
			<p><?php esc_html_e( 'Nothing is needed here on most sites. Code and hosts from WordPress, your theme and active plugins are allowed automatically as each page is produced. An optional scan finds what only you can judge: code pasted into page content and hosts that scripts load on their own.', 'secuplug' ); ?></p>
			<p class="fsf-inline-scan-status" role="status" aria-live="polite"><?php echo esc_html( $scan['message'] ); ?></p>
			<p class="fsf-inline-scan-current"></p>
			<details class="fsf-inline-issues" hidden><summary><?php esc_html_e( 'Pages that could not be scanned', 'secuplug' ); ?></summary><ul class="fsf-inline-scan-errors"></ul></details>
			<div class="fsf-inline-actions">
				<button type="button" class="fsf-btn" data-inline-action="rescan"><?php esc_html_e( 'Scan site', 'secuplug' ); ?></button>
				<button type="button" class="fsf-btn fsf-btn--fix" data-inline-action="approve_all" data-confirm="<?php esc_attr_e( 'Approve everything listed? Anything malicious already on your pages would be approved too.', 'secuplug' ); ?>"><?php esc_html_e( 'Approve all', 'secuplug' ); ?></button>
				<button type="button" class="fsf-btn fsf-btn--quiet" data-inline-action="revoke_all"><?php esc_html_e( 'Revoke all', 'secuplug' ); ?></button>
			</div>
			<p class="fsf-inline-status" role="status" aria-live="polite" tabindex="-1"></p>
			<div class="fsf-inline-filters">
				<label><?php esc_html_e( 'Find', 'secuplug' ); ?><input type="search" class="fsf-inline-search"></label>
				<label class="fsf-inline-pending"><input type="checkbox" class="fsf-inline-only-pending"><?php esc_html_e( 'Only waiting for approval', 'secuplug' ); ?></label>
			</div>
			<div class="fsf-inline-rows"><?php self::rows(); ?></div>
			<details class="fsf-inline-manual">
				<summary><?php esc_html_e( 'Add a hash by hand', 'secuplug' ); ?></summary>
				<label><?php esc_html_e( 'Name', 'secuplug' ); ?><input type="text" data-inline-field="label" maxlength="120"></label>
				<label><?php esc_html_e( 'Type', 'secuplug' ); ?><select data-inline-field="type"><option value="script"><?php esc_html_e( 'Script', 'secuplug' ); ?></option><option value="style"><?php esc_html_e( 'Style', 'secuplug' ); ?></option></select></label>
				<label><?php esc_html_e( 'SHA-256 digest (base64 only)', 'secuplug' ); ?><input type="text" data-inline-field="digest" maxlength="44"></label>
				<label><?php esc_html_e( 'Exact page path, or * for every page', 'secuplug' ); ?><input type="text" data-inline-field="path" value="*" maxlength="512"></label>
				<button type="button" class="fsf-btn" data-inline-action="add"><?php esc_html_e( 'Add', 'secuplug' ); ?></button>
			</details>
		</section>
		<?php
	}

	/**
	 * Describe progress without exposing probe credentials or queued URLs.
	 *
	 * @return array
	 */
	private static function scan_status() {

		$state  = CSPInlineScan::state();
		$status = $state['status'] ?? 'idle';
		$labels = [
			'idle'     => __( 'Not scanned yet', 'secuplug' ),
			'running'  => __( 'Scanning', 'secuplug' ),
			'complete' => __( 'Scan complete', 'secuplug' ),
			'partial'  => __( 'Scan incomplete: some pages failed', 'secuplug' ),
			'error'    => __( 'Scan failed', 'secuplug' ),
		];

		$message = sprintf(
			/* translators: 1: scan state, 2: pages processed, 3: discovered URLs, 4: items found, 5: failed pages. */
			__( '%1$s: %2$d of %3$d pages, %4$d items found, %5$d pages failed.', 'secuplug' ),
			$labels[ $status ] ?? $labels['error'],
			$state['processed'] ?? 0,
			$state['discovered'] ?? 0,
			count( self::reviewable() ),
			$state['failed'] ?? 0
		);

		if ( ! empty( $state['cached'] ) ) {

			$message .= ' ' . sprintf(
				/* translators: %d: number of pages. */
				_n( '%d page was answered by a page cache, so only its external hosts could be checked. Clear the cache and scan again to check its inline code.', '%d pages were answered by a page cache, so only their external hosts could be checked. Clear the cache and scan again to check their inline code.', (int) $state['cached'], 'secuplug' ),
				(int) $state['cached']
			);

		}

		return [
			'status'  => $status,
			'message' => $message,
			'current' => $state['current'] ?? '',
			'errors'  => $state['errors'] ?? [],
		];

	}

	/**
	 * Group records by the source that produced them.
	 *
	 * @param array $rows Inventory.
	 * @return array<string,array> Source key => records, WordPress and theme first.
	 */
	public static function grouped( $rows ) {

		$groups = [];

		foreach ( $rows as $id => $row ) {

			$groups[ $row['source'] ?? CSPInlineSources::UNKNOWN ][ $id ] = $row;

		}

		$rank = [
			'core'     => 0,
			'theme'    => 1,
			'plugin'   => 2,
			'external' => 3,
			'unknown'  => 4,
		];

		uksort(
			$groups,
			static function ( $a, $b ) use ( $rank ) {

				return [ $rank[ CSPInlineSources::kind( $a ) ], $a ] <=> [ $rank[ CSPInlineSources::kind( $b ) ], $b ];

			}
		);

		return $groups;

	}

	/**
	 * Name a record's type for people.
	 *
	 * @param string $type Record type.
	 * @return string
	 */
	private static function type_label( $type ) {

		$labels = [
			'script'      => __( 'Inline script', 'secuplug' ),
			'style'       => __( 'Inline style', 'secuplug' ),
			'host_script' => __( 'Script host', 'secuplug' ),
			'host_style'  => __( 'Style host', 'secuplug' ),
			'host_frame'  => __( 'Embed host', 'secuplug' ),
		];

		return $labels[ $type ] ?? $type;

	}

	/**
	 * List what is trusted automatically, for the rare site that needs to exclude one source.
	 *
	 * @return void
	 */
	private static function trusted_sources() {

		$blocked = CSPInlineRules::blocked();
		$sources = array_merge( CSPInlineSources::installed(), [ CSPInlineSources::EXTERNAL ] );

		?>
		<details class="fsf-inline-trusted" data-inline-source="__trusted">
			<summary>
				<?php
				/* translators: %d: number of sources trusted automatically. */
				echo esc_html( sprintf( __( 'Trusted automatically (%d)', 'secuplug' ), count( $sources ) - count( array_intersect_key( $blocked, array_flip( $sources ) ) ) ) );
				?>
			</summary>
			<p class="description"><?php esc_html_e( 'Exclude a source only if you know it must not run inline code or load external hosts.', 'secuplug' ); ?></p>
			<?php foreach ( $sources as $source ) : ?>
				<?php $is_blocked = isset( $blocked[ $source ] ); ?>
				<div class="fsf-inline-trusted__row">
					<span class="fsf-inline-group__name"><?php echo esc_html( CSPInlineSources::label( $source ) ); ?></span>
					<span class="fsf-inline-state fsf-inline-state--<?php echo $is_blocked ? 'off' : 'on'; ?>"><?php echo esc_html( $is_blocked ? __( 'Excluded', 'secuplug' ) : __( 'Trusted', 'secuplug' ) ); ?></span>
					<div class="fsf-inline-actions">
						<input type="hidden" data-inline-field="source" value="<?php echo esc_attr( $source ); ?>">
						<button type="button" class="fsf-btn fsf-btn--quiet" data-inline-action="<?php echo $is_blocked ? 'trust_source' : 'block_source'; ?>"><?php echo esc_html( $is_blocked ? __( 'Trust again', 'secuplug' ) : __( 'Exclude', 'secuplug' ) ); ?></button>
					</div>
				</div>
			<?php endforeach; ?>
		</details>
		<?php

	}

	/**
	 * Render records grouped by source.
	 *
	 * @return void
	 */
	private static function rows() {

		self::trusted_sources();

		$rows = self::reviewable();

		if ( ! $rows ) {

			echo '<p>' . esc_html__( 'Nothing needs your review.', 'secuplug' ) . '</p>';

			return;

		}

		$kinds = [
			'core'     => __( 'WordPress', 'secuplug' ),
			'theme'    => __( 'Theme', 'secuplug' ),
			'plugin'   => __( 'Plugin', 'secuplug' ),
			'external' => __( 'External', 'secuplug' ),
			'unknown'  => __( 'Unknown', 'secuplug' ),
		];

		foreach ( self::grouped( $rows ) as $source => $records ) {

			$kind    = CSPInlineSources::kind( $source );
			$pending = count(
				array_filter(
					$records,
					static function ( $row ) {

						return empty( $row['approved'] ); }
				)
			); // phpcs:ignore Generic.Formatting.DisallowMultipleStatements.SameLine -- One-line predicate.
			$name    = CSPInlineSources::label( $source );

			?>
			<details class="fsf-inline-group" data-inline-source="<?php echo esc_attr( $source ); ?>" data-kind="<?php echo esc_attr( $kind ); ?>">
				<summary>
					<span class="fsf-inline-group__name"><?php echo esc_html( $name ); ?></span>
					<span class="fsf-inline-tag"><?php echo esc_html( $kinds[ $kind ] ); ?></span>
					<span class="fsf-inline-group__count">
						<?php
						if ( $pending > 0 ) {

							/* translators: 1: items waiting, 2: total items. */
							echo esc_html( sprintf( __( '%1$d of %2$d waiting', 'secuplug' ), $pending, count( $records ) ) );

						} else {

							/* translators: %d: total items. */
							echo esc_html( sprintf( __( 'All %d approved', 'secuplug' ), count( $records ) ) );

						}
						?>
					</span>
				</summary>
				<div class="fsf-inline-actions">
					<input type="hidden" data-inline-field="source" value="<?php echo esc_attr( $source ); ?>">
					<button type="button" class="fsf-btn fsf-btn--fix" data-inline-action="approve_all">
						<?php
						/* translators: %s: theme or plugin name. */
						echo esc_html( sprintf( __( 'Approve all from %s', 'secuplug' ), $name ) );
						?>
					</button>
					<button type="button" class="fsf-btn fsf-btn--quiet" data-inline-action="revoke_all"><?php esc_html_e( 'Revoke', 'secuplug' ); ?></button>
				</div>
				<?php
				foreach ( $records as $id => $row ) {

					self::record( $id, $row );

				}
				?>
			</details>
			<?php

		}

	}

	/**
	 * Render one record.
	 *
	 * @param string $id Record key.
	 * @param array  $row Record.
	 * @return void
	 */
	private static function record( $id, $row ) {

		$approved = ! empty( $row['approved'] );
		$inline   = isset( $row['type'] ) && in_array( $row['type'], [ 'script', 'style' ], true );

		?>
		<details class="fsf-inline-record" data-inline-id="<?php echo esc_attr( $id ); ?>" data-pending="<?php echo $approved ? '0' : '1'; ?>">
			<summary>
				<span class="fsf-inline-record__name"><?php echo esc_html( $row['label'] ?? '' ); ?></span>
				<span class="fsf-inline-tag"><?php echo esc_html( self::type_label( $row['type'] ?? '' ) ); ?></span>
				<span class="fsf-inline-state fsf-inline-state--<?php echo $approved ? 'on' : 'off'; ?>"><?php echo esc_html( $approved ? __( 'Approved', 'secuplug' ) : __( 'Waiting', 'secuplug' ) ); ?></span>
			</summary>
			<?php if ( ! empty( $row['excerpt'] ) ) : ?>
				<pre class="fsf-inline-excerpt"><?php echo esc_html( $row['excerpt'] ); ?></pre>
			<?php endif; ?>
			<?php if ( $inline ) : ?>
				<p><code><?php echo esc_html( 'sha256-' . ( $row['digest'] ?? '' ) ); ?></code></p>
				<p class="description">
					<?php esc_html_e( 'Printed directly into the page, so only this exact text is allowed. If it changes, approve it again.', 'secuplug' ); ?>
				</p>
				<label><?php esc_html_e( 'Pages, one path per line, or * for every page', 'secuplug' ); ?><textarea data-inline-field="path" rows="2"><?php echo esc_textarea( implode( "\n", CSPInlineRules::paths( $row ) ) ); ?></textarea></label>
			<?php endif; ?>
			<div class="fsf-inline-actions">
				<input type="hidden" data-inline-field="approved" value="<?php echo $approved ? '0' : '1'; ?>">
				<button type="button" class="fsf-btn <?php echo $approved ? '' : 'fsf-btn--fix'; ?>" data-inline-action="approve"><?php echo esc_html( $approved ? __( 'Revoke', 'secuplug' ) : __( 'Approve', 'secuplug' ) ); ?></button>
				<?php if ( $inline ) : ?>
					<button type="button" class="fsf-btn fsf-btn--quiet" data-inline-action="save"><?php esc_html_e( 'Save pages', 'secuplug' ); ?></button>
				<?php endif; ?>
				<button type="button" class="fsf-btn fsf-btn--quiet" data-inline-action="delete"><?php esc_html_e( 'Remove', 'secuplug' ); ?></button>
			</div>
		</details>
		<?php

	}

}
