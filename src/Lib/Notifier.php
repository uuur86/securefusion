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
 * Costs nothing for visitors: the script, its styles and its settings are only printed for users who
 * pass allowed(), and the request handler answers nobody else. Blocked content is reported by the
 * browser itself and gathered into one box per kind and page; no request is made and nothing changes
 * until a button is pressed. Server notices are asked for at most once per interval and browser.
 *
 * Other modules can add notices with the `securefusion_notices` filter and answer their own action
 * operations with the `securefusion_notice_operation` filter.
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
	 * Most hosts allowed with one click.
	 */
	const MAX_HOSTS = 20;

	/**
	 * Most inline code blocks approved with one click.
	 */
	const MAX_CODES = 10;

	/**
	 * Longest blocked address accepted from the browser.
	 */
	const MAX_URL = 2048;

	/**
	 * Most server notices sent to the browser at once, and most actions per notice.
	 */
	const MAX_NOTICES = 10;
	const MAX_ACTIONS = 3;

	/**
	 * Time the policy last gained an exception from a notification.
	 */
	const CHANGED_OPTION = 'securefusion_csp_changed';

	/**
	 * Time the policy was first seen in test mode.
	 */
	const TEST_OPTION = 'securefusion_csp_test_since';

	/**
	 * Register the script and its request handler.
	 *
	 * @return void
	 */
	public static function register() {

		add_action( 'wp_enqueue_scripts', [ __CLASS__, 'enqueue' ], 0 );
		add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue' ], 0 );

		// Logged-in only: there is no wp_ajax_nopriv_ handler, so visitors cannot reach any operation.
		add_action( 'wp_ajax_' . self::ACTION, [ __CLASS__, 'ajax' ] );

	}

	/**
	 * Whether the current user may see notifications and act on them.
	 *
	 * @return bool
	 */
	public static function allowed() {

		return is_user_logged_in() && current_user_can( Settings::site_capability() );

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

		if ( is_network_admin() || ! self::allowed() ) {

			return;

		}

		// Inside the Customizer preview the page is a working surface, not a visit.
		if ( function_exists( 'is_customize_preview' ) && is_customize_preview() ) {

			return;

		}

		$settings   = Settings::all();
		$categories = [];

		foreach ( self::CATEGORIES as $category ) {

			// A summary is never urgent: it waits for the dashboard instead of interrupting a visit to the site.
			if ( self::wants( $settings, $category ) && ( 'activity' !== $category || is_admin() ) ) {

				$categories[] = $category;

			}

		}

		if ( ! $categories ) {

			return;

		}

		// This page now carries a request token for this user: no shared cache may hand it to anyone else.
		if ( ! is_admin() ) {

			CSPCache::exclude();

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
				'maxHosts'   => self::MAX_HOSTS,
				'maxCodes'   => self::MAX_CODES,
				'text'       => [
					'region'       => __( 'SecureFusion notifications', 'secuplug' ),
					'blocked'      => __( 'Blocked by your security policy', 'secuplug' ),
					'wouldBlock'   => __( 'Would be blocked (test mode)', 'secuplug' ),
					'hint'         => __( 'Allow only hosts you know and your site needs.', 'secuplug' ),
					'inline'       => __( 'Code written directly into this page is not approved yet. Check how it starts and allow it only if you recognize it.', 'secuplug' ),
					'inlineReview' => __( 'Code written directly into this page is not approved yet. The review lists it with where it came from.', 'secuplug' ),
					'inlineType'   => __( 'Inline code', 'secuplug' ),
					'allowCode'    => __( 'Allow this code', 'secuplug' ),
					/* translators: %s: number of further items. */
					'more'         => __( 'and %s more', 'secuplug' ),
					'eval'         => __( 'A script on this page builds code while it runs. Allow it only if something on the page stopped working.', 'secuplug' ),
					'evalType'     => __( 'Code built at runtime (eval)', 'secuplug' ),
					'handler'      => __( 'This page uses attributes such as onclick or onload. Allow them only if something on the page stopped working.', 'secuplug' ),
					'handlerType'  => __( 'Inline event handler', 'secuplug' ),
					'allow'        => __( 'Allow', 'secuplug' ),
					'ignore'       => __( 'Do not ask again', 'secuplug' ),
					'review'       => __( 'Review', 'secuplug' ),
					'reload'       => __( 'Reload page', 'secuplug' ),
					'dismiss'      => __( 'Dismiss', 'secuplug' ),
					'mute'         => __( 'Turn off notifications like this', 'secuplug' ),
					'working'      => __( 'Working…', 'secuplug' ),
					'error'        => __( 'The request failed. Nothing was changed.', 'secuplug' ),
					'types'        => [
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
	 * Read the raw "items" field, a JSON list sent by the script.
	 *
	 * @return string
	 */
	private static function raw_items() {

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- ajax() verifies the nonce; decode_items() bounds and validates every field.
		return isset( $_POST['items'] ) && is_string( $_POST['items'] ) ? wp_unslash( $_POST['items'] ) : '';

	}

	/**
	 * Decode a JSON list of flat objects whose fields are all strings.
	 *
	 * The whole list is refused when it is too long, too large, nested or holds any other value.
	 *
	 * @param string   $raw    JSON text.
	 * @param string[] $fields Required field names.
	 * @param int      $limit  Most items.
	 * @param int      $length Most bytes of JSON text.
	 * @return array<int,array<string,string>> Items, or none.
	 */
	public static function decode_items( $raw, $fields, $limit, $length ) {

		if ( ! is_string( $raw ) || '' === $raw || strlen( $raw ) > $length ) {

			return [];

		}

		$items = json_decode( $raw, true, 3 );

		if ( ! is_array( $items ) || count( $items ) > $limit ) {

			return [];

		}

		$result = [];

		foreach ( $items as $item ) {

			$row = [];

			foreach ( $fields as $field ) {

				if ( ! is_array( $item ) || ! is_string( $item[ $field ] ?? null ) ) {

					return [];

				}

				$row[ $field ] = $item[ $field ];

			}

			$result[] = $row;

		}

		return $result;

	}

	/**
	 * Answer the notification script.
	 *
	 * @return void
	 */
	public static function ajax() {

		check_ajax_referer( self::ACTION, 'nonce' );

		if ( ! self::allowed() ) {

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

		if ( 'recheck_cache' === $operation && CSPCacheSetup::can_manage() ) {

			$status = CSPCacheSetup::verify();

			wp_send_json_success( [ 'message' => ! empty( $status['ok'] ) ? __( 'The cache driver passed its test and is in use again.', 'secuplug' ) : __( 'The cache driver still fails its test. The Page cache box in the settings says why.', 'secuplug' ) ] );

			return;

		}

		$message = '';

		if ( 'allow_hosts' === $operation ) {

			$message = self::allow_hosts( self::decode_items( self::raw_items(), [ 'type', 'url' ], self::MAX_HOSTS, self::MAX_HOSTS * ( self::MAX_URL + 64 ) ) );

		}

		if ( 'allow_inline' === $operation ) {

			$message = self::allow_inline( self::decode_items( self::raw_items(), [ 'type', 'code' ], self::MAX_CODES, self::MAX_CODES * ( CSPInlineRules::MAX_CODE + 64 ) ) );

		}

		$switches = [
			'allow_eval'     => [ 'csp_allow_eval', '1', __( 'Code built at runtime is now allowed on every page.', 'secuplug' ) ],
			'allow_handlers' => [ 'csp_block_event_handlers', '0', __( 'Inline event handlers are now allowed.', 'secuplug' ) ],
		];

		if ( isset( $switches[ $operation ] ) ) {

			Settings::update_site( [ $switches[ $operation ][0] => $switches[ $operation ][1] ] );

			self::changed();

			$message = $switches[ $operation ][2];

		}

		if ( '' !== $message ) {

			wp_send_json_success(
				[
					'message' => $message,
					'reload'  => true,
				]
			);

			return;

		}

		$builtin = [ 'list', 'dismiss', 'mute', 'enforce', 'recheck_cache', 'allow_hosts', 'allow_inline', 'allow_eval', 'allow_handlers' ];

		if ( '' !== $operation && ! in_array( $operation, $builtin, true ) ) {

			/**
			 * Answers an action operation of a notice added with the `securefusion_notices` filter.
			 *
			 * Runs only after the nonce and the capability (Notifier::allowed()) were checked, and only
			 * for operations SecureFusion does not handle itself. Check the operation name, do the work,
			 * and read further request fields yourself. Return
			 * [ 'message' => string, 'reload' => bool ] to answer; anything else means the operation
			 * is unknown. The message is shown as plain text.
			 *
			 * @param array|null $answer    Null.
			 * @param string     $operation Operation name, already passed through sanitize_key().
			 */
			$answer = apply_filters( 'securefusion_notice_operation', null, $operation );

			if ( is_array( $answer ) && is_string( $answer['message'] ?? null ) ) {

				wp_send_json_success(
					[
						'message' => wp_strip_all_tags( $answer['message'] ),
						'reload'  => ! empty( $answer['reload'] ),
					]
				);

				return;

			}

		}

		wp_send_json_error( [ 'message' => __( 'This request could not be used. Reload the page and try again.', 'secuplug' ) ], 400 );

	}

	/**
	 * Origin of a blocked address, when it can be a policy host source.
	 *
	 * @param string $url Blocked address.
	 * @return string Origin, or empty.
	 */
	private static function origin( $url ) {

		if ( '' === $url || strlen( $url ) > self::MAX_URL ) {

			return '';

		}

		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) || ! in_array( strtolower( $parts['scheme'] ), [ 'http', 'https', 'ws', 'wss' ], true ) ) {

			return '';

		}

		$origin = strtolower( $parts['scheme'] . '://' . $parts['host'] ) . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );

		return CSP::validate_host_source( $origin ) ? $origin : '';

	}

	/**
	 * Allow the hosts of blocked addresses, or the services they belong to, with one settings write.
	 *
	 * Only types the policy already limits are accepted: the lists in CSPPolicy::LISTED start to limit
	 * their type with their first host, so allowing one there would block everything else of that type.
	 * One unusable item refuses the whole request.
	 *
	 * @param array<int,array{type:string,url:string}> $items At most MAX_HOSTS blocked addresses.
	 * @return string Confirmation, or empty when the request is not usable.
	 */
	public static function allow_hosts( $items ) {

		if ( ! is_array( $items ) || ! $items || count( $items ) > self::MAX_HOSTS ) {

			return '';

		}

		$settings = Settings::all();
		$limited  = self::limited_types( $settings );
		$catalog  = CSPIntegrations::catalog();
		$changes  = [];
		$services = [];
		$hosts    = [];

		foreach ( $items as $item ) {

			$type   = is_array( $item ) && is_string( $item['type'] ?? null ) ? $item['type'] : '';
			$url    = is_array( $item ) && is_string( $item['url'] ?? null ) ? $item['url'] : '';
			$origin = in_array( $type, $limited, true ) ? self::origin( $url ) : '';

			if ( '' === $origin ) {

				return '';

			}

			$provider = CSPIntegrations::provider_for( $url, $type );

			if ( '' !== $provider ) {

				$changes[ 'csp_service_' . $provider ] = '1';
				$services[ $provider ]                 = (string) ( $catalog[ $provider ]['label'] ?? $provider );

				continue;

			}

			$key  = 'csp_allowed_' . $type . '_sources';
			$list = isset( $changes[ $key ] ) ? CSP::host_list( $changes[ $key ] ) : CSP::host_list( $settings[ $key ] ?? '' );

			if ( ! in_array( $origin, $list, true ) ) {

				$list[]          = $origin;
				$changes[ $key ] = implode( PHP_EOL, $list );

			}

			$hosts[ $origin ] = $origin;

		}

		if ( $changes ) {

			Settings::update_site( $changes );

			self::changed();

		}

		$parts = [];

		if ( $services ) {

			/* translators: %s: comma-separated service names, for example "Google Analytics, Stripe". */
			$parts[] = sprintf( _n( '%s is now allowed under Services.', '%s are now allowed under Services.', count( $services ), 'secuplug' ), implode( ', ', $services ) );

		}

		if ( $hosts ) {

			/* translators: %s: comma-separated hosts, for example "https://cdn.example.com". */
			$parts[] = sprintf( _n( '%s is now allowed.', '%s are now allowed.', count( $hosts ), 'secuplug' ), implode( ', ', $hosts ) );

		}

		return implode( ' ', $parts );

	}

	/**
	 * Approve inline code the owner chose in a notification. Only while inline code is verified.
	 *
	 * @param array<int,array{type:string,code:string}> $items At most MAX_CODES code blocks.
	 * @return string Confirmation, or empty when nothing was approved.
	 */
	public static function allow_inline( $items ) {

		if ( ! is_array( $items ) || ! $items || count( $items ) > self::MAX_CODES || 'strict' !== CSPPolicy::level( Settings::all() ) ) {

			return '';

		}

		$count = 0;

		foreach ( $items as $item ) {

			if ( is_array( $item ) && is_string( $item['type'] ?? null ) && is_string( $item['code'] ?? null ) && CSPInlineRules::approve_code( $item['type'], $item['code'] ) ) {

				++$count;

			}

		}

		if ( $count < 1 ) {

			return '';

		}

		self::changed();

		/* translators: %s: number of approved code blocks. */
		return sprintf( _n( '%s code block is now approved on every page. You can take it back under Exceptions.', '%s code blocks are now approved on every page. You can take them back under Exceptions.', $count, 'secuplug' ), number_format_i18n( $count ) );

	}

	/**
	 * Remember that the policy just gained an exception, which restarts the quiet week.
	 *
	 * @return void
	 */
	public static function changed() {

		update_option( self::CHANGED_OPTION, time(), false );

	}

	/**
	 * Days the policy has run in test mode without needing a new exception, or -1 when it is not testing.
	 *
	 * @param array $settings Resolved settings.
	 * @return int
	 */
	private static function quiet_days( $settings ) {

		if ( 'off' === CSPPolicy::level( $settings ) || 'enforce' === CSPPolicy::mode( $settings ) ) {

			if ( false !== get_option( self::TEST_OPTION ) ) {

				delete_option( self::TEST_OPTION );

			}

			return -1;

		}

		$since = (int) get_option( self::TEST_OPTION, 0 );

		if ( $since < 1 ) {

			$since = time();

			update_option( self::TEST_OPTION, $since, false );

		}

		$since = max( $since, (int) get_option( self::CHANGED_OPTION, 0 ) );

		return (int) floor( max( 0, time() - $since ) / DAY_IN_SECONDS );

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
	 * Keep the actions of a notice the script can safely offer.
	 *
	 * @param mixed $actions Actions from a notice.
	 * @return array<int,array<string,mixed>> At most MAX_ACTIONS, each with a label and a url or an operation.
	 */
	private static function actions( $actions ) {

		$result = [];

		foreach ( is_array( $actions ) ? array_slice( $actions, 0, self::MAX_ACTIONS ) : [] as $action ) {

			if ( ! is_array( $action ) || ! is_string( $action['label'] ?? null ) || '' === $action['label'] ) {

				continue;

			}

			$url       = is_string( $action['url'] ?? null ) ? esc_url_raw( $action['url'], [ 'http', 'https' ] ) : '';
			$operation = is_string( $action['operation'] ?? null ) ? sanitize_key( $action['operation'] ) : '';
			$clean     = [
				'label'   => $action['label'],
				'primary' => ! empty( $action['primary'] ),
			];

			if ( '' !== $url ) {

				$clean['url'] = $url;

			} elseif ( '' !== $operation ) {

				$clean['operation'] = $operation;

			} else {

				continue;

			}

			$result[] = $clean;

		}

		return $result;

	}

	/**
	 * Collect what the current user should be told now.
	 *
	 * Called from ajax() after the nonce and capability checks.
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
		 * Each notice is an array with:
		 * - id       (string) Unique key, used to remember a dismissal.
		 * - category (string) One of Notifier::CATEGORIES; follows that category's switch. Default status.
		 * - title    (string) Short title, shown as plain text.
		 * - text     (string) One or two sentences, shown as plain text.
		 * - repeat   (int)    Seconds before a dismissed notice may return, 0 for never.
		 * - actions  (array)  Up to three buttons: label (string), primary (bool), and either url
		 *                     (http or https) or operation (a key answered through the
		 *                     `securefusion_notice_operation` filter).
		 *
		 * At most ten notices are sent at once. Only users who pass Notifier::allowed() ever see them.
		 *
		 * @param array $notices  Notices.
		 * @param array $settings Resolved settings.
		 */
		$notices = (array) apply_filters( 'securefusion_notices', $notices, $settings );
		$now     = time();
		$result  = [];

		foreach ( $notices as $notice ) {

			if ( count( $result ) >= self::MAX_NOTICES ) {

				break;

			}

			if ( ! is_array( $notice ) ) {

				continue;

			}

			$id       = sanitize_key( is_string( $notice['id'] ?? null ) ? $notice['id'] : '' );
			$category = in_array( $notice['category'] ?? '', self::CATEGORIES, true ) ? $notice['category'] : 'status';
			$closed   = $state['dismissed'][ $id ] ?? 0;
			$repeat   = (int) ( $notice['repeat'] ?? 0 );

			if ( '' === $id || ! self::wants( $settings, $category ) || ( $closed && ( 0 === $repeat || $now - $closed < $repeat ) ) ) {

				continue;

			}

			$result[] = [
				'id'       => $id,
				'category' => $category,
				'title'    => is_string( $notice['title'] ?? null ) ? $notice['title'] : '',
				'text'     => is_string( $notice['text'] ?? null ) ? $notice['text'] : '',
				'actions'  => self::actions( $notice['actions'] ?? [] ),
			];

		}

		// Only a page that shows the summary (the dashboard) may use it up; see enqueue().
		$summary = self::wants( $settings, 'activity' ) && '1' === self::input( 'activity' ) ? self::activity_notice( $state ) : null;

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

		$quiet = self::quiet_days( $settings );

		// Asked only once testing has shown something: a week without a new exception.
		if ( $quiet >= 7 ) {

			$notices[] = [
				'id'       => 'csp_ready',
				'category' => 'status',
				'repeat'   => 2 * WEEK_IN_SECONDS,
				'title'    => __( 'Your security policy is ready to protect visitors', 'secuplug' ),
				'text'     => sprintf(
					/* translators: %s: number of days. */
					_n( 'It has been tested for %s day without needing a new exception, but it still blocks nothing. Turn it on now; anything blocked later shows up here with a fix.', 'It has been tested for %s days without needing a new exception, but it still blocks nothing. Turn it on now; anything blocked later shows up here with a fix.', $quiet, 'secuplug' ),
					number_format_i18n( $quiet )
				),
				'actions'  => [
					[
						'label'     => __( 'Turn on protection', 'secuplug' ),
						'operation' => 'enforce',
						'primary'   => true,
					],
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
				'text'     => __( 'It did not pass its test, so it is not used. Test it again after changing your cache settings.', 'secuplug' ),
				'actions'  => [
					[
						'label'     => __( 'Test again', 'secuplug' ),
						'operation' => 'recheck_cache',
						'primary'   => true,
					],
					$review,
				],
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
	 * Summarize what was stopped since the last summary, at most once a week.
	 *
	 * @param array $state Current user's state.
	 * @return array<string,mixed>|null
	 */
	private static function activity_notice( $state ) {

		$now = time();

		if ( $now - $state['seen'] < WEEK_IN_SECONDS ) {

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
