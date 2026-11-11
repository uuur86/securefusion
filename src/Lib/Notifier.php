<?php
/**
 * Security notifications for administrators, shown at the bottom right of any page.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Tells an administrator what the plugin just did or needs, where they are, with the fix one click away.
 *
 * Costs nothing for visitors: the script is only printed for users who may change the settings.
 * Blocked content is reported by the browser itself, so no request is made until a button is pressed.
 * Server notices are asked for at most once per interval and browser.
 */
class Notifier {

	const ACTION = 'securefusion_notices';

	/**
	 * Per-user state: dismissed notices and the time of the last activity summary.
	 */
	const USER_OPTION = 'securefusion_notices';

	/**
	 * Kinds of notification, each with its own switch.
	 */
	const CATEGORIES = [ 'csp', 'status', 'activity' ];

	/**
	 * Seconds between two requests for server notices from one browser.
	 */
	const INTERVAL = 600;

	/**
	 * Most dismissals remembered per user; the oldest leave first.
	 */
	const MAX_DISMISSED = 40;

	/**
	 * Register the script and its request handler.
	 *
	 * @return void
	 */
	public static function register() {

		add_action( 'wp_enqueue_scripts', [ __CLASS__, 'enqueue' ], 0 );
		add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue' ], 0 );
		add_action( 'wp_ajax_' . self::ACTION, [ __CLASS__, 'ajax' ] );

	}

	/**
	 * Whether a kind of notification is switched on.
	 *
	 * @param array  $settings Resolved settings.
	 * @param string $category One of CATEGORIES.
	 * @return bool
	 */
	public static function wants( $settings, $category ) {

		return '0' !== (string) ( $settings['notify_enable'] ?? '1' ) && '0' !== (string) ( $settings[ 'notify_' . $category ] ?? '1' );

	}

	/**
	 * Resource types the policy limits, which are the only ones a blocked host can be allowed for.
	 *
	 * Browser add-ons rewrite policies and add directives of their own; reports for those are not ours.
	 *
	 * @param array $settings Resolved settings.
	 * @return string[]
	 */
	public static function limited_types( $settings ) {

		$level = CSPPolicy::level( $settings );

		if ( 'off' === $level ) {

			return [];

		}

		$types = [ 'script' ];

		foreach ( array_keys( CSPPolicy::LIMITS ) as $type ) {

			if ( CSPPolicy::limits( $settings, $type ) || 'worker' === $type || ( 'style' === $type && 'strict' === $level ) ) {

				$types[] = $type;

			}

		}

		return $types;

	}

	/**
	 * Print the notification script for users who may change the settings.
	 *
	 * @return void
	 */
	public static function enqueue() {

		if ( ! is_user_logged_in() || is_network_admin() || ! current_user_can( Settings::site_capability() ) ) {

			return;

		}

		// Inside the Customizer preview the page is a working surface, not a visit.
		if ( function_exists( 'is_customize_preview' ) && is_customize_preview() ) {

			return;

		}

		$settings   = Settings::all();
		$categories = [];

		foreach ( self::CATEGORIES as $category ) {

			if ( self::wants( $settings, $category ) ) {

				$categories[] = $category;

			}

		}

		if ( ! $categories ) {

			return;

		}

		$style  = 'assets/css/notifier.css';
		$script = 'assets/js/notifier.js';

		wp_enqueue_style( 'securefusion-notifier', plugins_url( $style, SECUREFUSION_BASENAME ), [], (string) filemtime( SECUREFUSION_PATH . $style ) );

		// In the head and without dependencies, so it listens before the rest of the page loads.
		wp_enqueue_script( 'securefusion-notifier', plugins_url( $script, SECUREFUSION_BASENAME ), [], (string) filemtime( SECUREFUSION_PATH . $script ), false );

		wp_localize_script(
			'securefusion-notifier',
			'securefusionNotifier',
			[
				'url'        => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( self::ACTION ),
				'categories' => $categories,
				'limited'    => is_admin() ? [] : self::limited_types( $settings ),
				'strict'     => 'strict' === CSPPolicy::level( $settings ),
				'review'     => self::settings_url( 'security_policies' ),
				'interval'   => self::INTERVAL,
				'text'       => [
					'region'      => __( 'SecureFusion notifications', 'secuplug' ),
					'blocked'     => __( 'Blocked by your security policy', 'secuplug' ),
					'wouldBlock'  => __( 'Would be blocked (test mode)', 'secuplug' ),
					'hint'        => __( 'Allow it only if you know this host and your site needs it.', 'secuplug' ),
					'inline'      => __( 'Code written directly into this page is not approved. Review it under Exceptions.', 'secuplug' ),
					'inlineType'  => __( 'Inline code', 'secuplug' ),
					'eval'        => __( 'A script on this page builds code while it runs. Allow it only if something on the page stopped working.', 'secuplug' ),
					'evalType'    => __( 'Code built at runtime (eval)', 'secuplug' ),
					'handler'     => __( 'This page uses attributes such as onclick or onload. Allow them only if something on the page stopped working.', 'secuplug' ),
					'handlerType' => __( 'Inline event handler', 'secuplug' ),
					'allow'       => __( 'Allow', 'secuplug' ),
					'ignore'      => __( 'Do not ask again', 'secuplug' ),
					'review'      => __( 'Review', 'secuplug' ),
					'reload'      => __( 'Reload page', 'secuplug' ),
					'dismiss'     => __( 'Dismiss', 'secuplug' ),
					'mute'        => __( 'Turn off notifications like this', 'secuplug' ),
					'working'     => __( 'Working…', 'secuplug' ),
					'error'       => __( 'The request failed. Nothing was changed.', 'secuplug' ),
					'types'       => [
						'script'      => __( 'Script', 'secuplug' ),
						'style'       => __( 'Stylesheet', 'secuplug' ),
						'img'         => __( 'Image', 'secuplug' ),
						'font'        => __( 'Font', 'secuplug' ),
						'frame'       => __( 'Embed', 'secuplug' ),
						'connect'     => __( 'Connection', 'secuplug' ),
						'media'       => __( 'Audio or video', 'secuplug' ),
						'worker'      => __( 'Background worker', 'secuplug' ),
						'form_action' => __( 'Form target', 'secuplug' ),
					],
				],
			]
		);

	}

	/**
	 * Address of a settings tab.
	 *
	 * @param string $tab Tab id.
	 * @return string
	 */
	private static function settings_url( $tab ) {

		return admin_url( 'admin.php?page=securefusion-settings#' . $tab );

	}

	/**
	 * Read one request value.
	 *
	 * @param string $key Field name.
	 * @return string
	 */
	private static function input( $key ) {

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- ajax() verifies the nonce before any value is read.
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';

	}

	/**
	 * Answer the notification script.
	 *
	 * @return void
	 */
	public static function ajax() {

		check_ajax_referer( self::ACTION, 'nonce' );

		if ( ! current_user_can( Settings::site_capability() ) ) {

			wp_send_json_error( [ 'message' => __( 'Permission denied.', 'secuplug' ) ], 403 );

			return;

		}

		$operation = sanitize_key( self::input( 'operation' ) );

		if ( 'list' === $operation ) {

			wp_send_json_success( [ 'notices' => self::pending() ] );

			return;

		}

		if ( 'dismiss' === $operation ) {

			self::dismiss( sanitize_key( self::input( 'id' ) ) );

			wp_send_json_success( [] );

			return;

		}

		if ( 'mute' === $operation ) {

			$category = sanitize_key( self::input( 'category' ) );

			if ( in_array( $category, self::CATEGORIES, true ) ) {

				Settings::update_site( [ 'notify_' . $category => '0' ] );

				wp_send_json_success( [ 'message' => __( 'Turned off. You can turn it back on under SecureFusion > Settings > Notifications.', 'secuplug' ) ] );

				return;

			}

		}

		if ( 'enforce' === $operation ) {

			Settings::update_site( [ 'csp_mode' => 'enforce' ] );

			wp_send_json_success( [ 'message' => __( 'The policy is now enforced. Notifications will tell you when something is blocked.', 'secuplug' ) ] );

			return;

		}

		$switches = [
			'allow_eval'     => [ 'csp_allow_eval', '1', __( 'Code built at runtime is now allowed on every page.', 'secuplug' ) ],
			'allow_handlers' => [ 'csp_block_event_handlers', '0', __( 'Inline event handlers are now allowed.', 'secuplug' ) ],
		];

		if ( isset( $switches[ $operation ] ) ) {

			Settings::update_site( [ $switches[ $operation ][0] => $switches[ $operation ][1] ] );

			wp_send_json_success(
				[
					'message' => $switches[ $operation ][2],
					'reload'  => true,
				]
			);

			return;

		}

		if ( 'allow' === $operation ) {

			$message = self::allow( sanitize_key( self::input( 'type' ) ), sanitize_url( self::input( 'url' ), [ 'http', 'https', 'ws', 'wss' ] ) );

			if ( '' !== $message ) {

				wp_send_json_success(
					[
						'message' => $message,
						'reload'  => true,
					]
				);

				return;

			}

		}

		wp_send_json_error( [ 'message' => __( 'This request could not be used. Reload the page and try again.', 'secuplug' ) ], 400 );

	}

	/**
	 * Allow the host of a blocked address, or the whole service it belongs to.
	 *
	 * @param string $type Resource type: script or a key of CSPPolicy::LIMITS.
	 * @param string $url  Blocked address without query.
	 * @return string Confirmation, or empty when the request is not usable.
	 */
	public static function allow( $type, $url ) {

		$parts = wp_parse_url( $url );
		$types = array_merge( [ 'script' ], array_keys( CSPPolicy::LIMITS ) );

		if ( ! in_array( $type, $types, true ) || ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {

			return '';

		}

		$origin = strtolower( $parts['scheme'] . '://' . $parts['host'] ) . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );

		if ( ! CSP::validate_host_source( $origin ) ) {

			return '';

		}

		$settings = Settings::all();
		$provider = CSPIntegrations::provider_for( $url, $type );

		if ( '' !== $provider ) {

			Settings::update_site( [ 'csp_service_' . $provider => '1' ] );

			/* translators: %s: service name, for example "Google Analytics". */
			return sprintf( __( '%s is now allowed under Services.', 'secuplug' ), CSPIntegrations::catalog()[ $provider ]['label'] ?? $provider );

		}

		$key   = 'csp_allowed_' . $type . '_sources';
		$hosts = CSP::host_list( $settings[ $key ] ?? '' );

		if ( ! in_array( $origin, $hosts, true ) ) {

			$hosts[] = $origin;

			Settings::update_site( [ $key => implode( PHP_EOL, $hosts ) ] );

		}

		/* translators: %s: host, for example "https://cdn.example.com". */
		return sprintf( __( '%s is now allowed.', 'secuplug' ), $origin );

	}

	/**
	 * Read the current user's notification state.
	 *
	 * @return array{dismissed: array<string,int>, seen: int}
	 */
	private static function state() {

		$state = get_user_option( self::USER_OPTION );
		$state = is_array( $state ) ? $state : [];

		return [
			'dismissed' => isset( $state['dismissed'] ) && is_array( $state['dismissed'] ) ? array_map( 'intval', $state['dismissed'] ) : [],
			'seen'      => (int) ( $state['seen'] ?? 0 ),
		];

	}

	/**
	 * Remember that the current user closed a notice.
	 *
	 * @param string $id Notice id.
	 * @return void
	 */
	private static function dismiss( $id ) {

		if ( '' === $id ) {

			return;

		}

		$state                     = self::state();
		$state['dismissed'][ $id ] = time();

		asort( $state['dismissed'] );

		$state['dismissed'] = array_slice( $state['dismissed'], -self::MAX_DISMISSED, null, true );

		update_user_option( get_current_user_id(), self::USER_OPTION, $state );

	}

	/**
	 * Collect what the current user should be told now.
	 *
	 * Each notice: id, category, title, text, repeat (seconds before a dismissed notice may return,
	 * 0 for never) and actions (label plus either an operation or a url).
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private static function pending() {

		$settings = Settings::all();
		$state    = self::state();
		$notices  = [];

		if ( self::wants( $settings, 'status' ) ) {

			$notices = self::status_notices( $settings );

		}

		/**
		 * Filters the notices offered to an administrator.
		 *
		 * @param array $notices  Notices, see Notifier::pending().
		 * @param array $settings Resolved settings.
		 */
		$notices = (array) apply_filters( 'securefusion_notices', $notices, $settings );
		$now     = time();
		$result  = [];

		foreach ( $notices as $notice ) {

			$id       = sanitize_key( $notice['id'] ?? '' );
			$category = $notice['category'] ?? 'status';
			$closed   = $state['dismissed'][ $id ] ?? 0;
			$repeat   = (int) ( $notice['repeat'] ?? 0 );

			if ( '' === $id || ! self::wants( $settings, $category ) || ( $closed && ( 0 === $repeat || $now - $closed < $repeat ) ) ) {

				continue;

			}

			$result[] = [
				'id'       => $id,
				'category' => $category,
				'title'    => (string) ( $notice['title'] ?? '' ),
				'text'     => (string) ( $notice['text'] ?? '' ),
				'actions'  => array_values( (array) ( $notice['actions'] ?? [] ) ),
			];

		}

		$summary = self::wants( $settings, 'activity' ) ? self::activity_notice( $state ) : null;

		if ( $summary ) {

			$result[] = $summary;

		}

		return $result;

	}

	/**
	 * Things about the protection itself that need a decision.
	 *
	 * @param array $settings Resolved settings.
	 * @return array<int,array<string,mixed>>
	 */
	private static function status_notices( $settings ) {

		$notices = [];
		$review  = [
			'label' => __( 'Open settings', 'secuplug' ),
			'url'   => self::settings_url( 'security_policies' ),
		];

		if ( 'off' !== CSPPolicy::level( $settings ) && 'enforce' !== CSPPolicy::mode( $settings ) ) {

			$notices[] = [
				'id'       => 'csp_test',
				'category' => 'status',
				'repeat'   => WEEK_IN_SECONDS,
				'title'    => __( 'Your security policy is only being tested', 'secuplug' ),
				'text'     => __( 'Nothing is blocked yet, so visitors are not protected by it. Browse your pages: a notification appears for anything that would be blocked. When everything works, enforce the policy.', 'secuplug' ),
				'actions'  => [
					[
						'label'     => __( 'Enforce now', 'secuplug' ),
						'operation' => 'enforce',
						'primary'   => true,
					],
					$review,
				],
			];

		}

		if ( '' !== CSPInlineAdmin::reduced_notice() ) {

			$notices[] = [
				'id'       => 'csp_overflow',
				'category' => 'status',
				'repeat'   => DAY_IN_SECONDS,
				'title'    => __( 'A page was sent with fewer security rules', 'secuplug' ),
				'text'     => CSPInlineAdmin::reduced_notice(),
				'actions'  => [ $review ],
			];

		}

		$driver = CSPCache::status();

		if ( $driver && empty( $driver['ok'] ) && CSPCacheSetup::installed() ) {

			$notices[] = [
				'id'       => 'cache_driver',
				'category' => 'status',
				'repeat'   => DAY_IN_SECONDS,
				'title'    => __( 'The cache driver is not in use', 'secuplug' ),
				'text'     => __( 'It did not pass its test, so it is not used. The Page cache box in the settings says why.', 'secuplug' ),
				'actions'  => [ $review ],
			];

		}

		if ( get_option( 'securefusion_db_error' ) ) {

			$notices[] = [
				'id'       => 'database',
				'category' => 'status',
				'repeat'   => DAY_IN_SECONDS,
				'title'    => __( 'Database setup is incomplete', 'secuplug' ),
				'text'     => __( 'Logging and address blocking may not work. Check the database permissions; setup is retried automatically.', 'secuplug' ),
				'actions'  => [],
			];

		}

		return $notices;

	}

	/**
	 * Summarize what was stopped since the last summary, at most once a day.
	 *
	 * @param array $state Current user's state.
	 * @return array<string,mixed>|null
	 */
	private static function activity_notice( $state ) {

		$now = time();

		if ( $now - $state['seen'] < DAY_IN_SECONDS ) {

			return null;

		}

		$since = max( $state['seen'], $now - WEEK_IN_SECONDS );
		$count = ( new BruteForceDB() )->count_addresses_since( $since );

		$state['seen'] = $now;

		update_user_option( get_current_user_id(), self::USER_OPTION, $state );

		if ( $count < 1 ) {

			return null;

		}

		return [
			'id'       => 'activity',
			'category' => 'activity',
			'title'    => __( 'Security summary', 'secuplug' ),
			'text'     => sprintf(
				/* translators: 1: number of addresses, 2: time span, for example "3 days". */
				_n( '%1$s address was stopped or logged in the last %2$s.', '%1$s addresses were stopped or logged in the last %2$s.', $count, 'secuplug' ),
				number_format_i18n( $count ),
				human_time_diff( $since, $now )
			),
			'actions'  => [
				[
					'label' => __( 'Open security log', 'secuplug' ),
					'url'   => admin_url( 'admin.php?page=securefusion-security-log' ),
				],
			],
		];

	}

}
