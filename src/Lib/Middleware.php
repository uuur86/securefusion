<?php
/**
 * Middleware Class
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * Middleware functionality class.
 */
class Middleware {

	use WPCommon;
	use RequestFirewall;

	use RestAccess;

	use LoginTracking;




	/**
	 * Brute force database service instance.
	 *
	 * @var BruteForceDB
	 */
	private $brute_force_db;


	/**
	 * Policy inputs for this response, kept so a later hook can correct them: settings, generated, context.
	 *
	 * @var array|null
	 */
	private $csp = null;


	/**
	 * Whether this response carries our X-Frame-Options header.
	 *
	 * @var bool
	 */
	private $frame_header_sent = false;


	/**
	 * Period in which oversized requests from one address are counted, in seconds.
	 */
	const OVERSIZED_WINDOW = 600;


	/**
	 * Longest block an oversized request can cause: 7 days, in minutes.
	 */
	const OVERSIZED_MAX_BLOCK_MINUTES = 10080;


	/**
	 * REST services under wp/v1 and wp/v2 that anonymous visitors may not use.
	 *
	 * @var string[]
	 */
	const REST_PROTECTED_SERVICES = [
		'users',
		'posts',
		'pages',
		'comments',
		'taxonomies',
		'categories',
		'tags',
		'types',
		'statuses',
		'settings',
		'themes',
		'plugins',
		'blocks',
		'block-types',
		'block-directories',
		'block-patterns',
		'block-pattern-categories',
		'search',
		'media',
	];


	/**
	 * Longest REST route we try to match; longer routes are matched on their prefix only.
	 */
	const REST_ROUTE_MAX_LENGTH = 512;


	/**
	 * Allowed HSTS durations in seconds, shortest first: 1 day, 30 days, 1 year, 2 years.
	 */
	const HSTS_MAX_AGES = [ 86400, 2592000, 31536000, 63072000 ];


	/**
	 * Create the storage service here so hooks can never run without it.
	 */
	public function __construct() {

		$this->brute_force_db = new BruteForceDB();

	}


	/**
	 * Initialize middleware.
	 *
	 * @return void
	 */
	public function init() {

		if ( defined( 'WP_CLI' ) && \WP_CLI ) {

			return;

		}

		global $wp;

		if ( ! function_exists( 'wp_get_current_user' ) ) {

			include ABSPATH . '/wp-includes/pluggable.php';

		}

		// Get client IP early for blocking checks.
		$ip = $this->get_client_ip();

		// Block check: deny blocked IPs before any processing.
		if ( $ip && $this->brute_force_db->is_ip_blocked( $ip ) ) {

			status_header( 403 );

			exit( 'Access Denied' );

		}

		if ( \current_user_can( 'manage_options' ) ) {

			// Automatically whitelist admin IPs if public.
			if ( $ip && $this->is_public_ip( $ip ) ) {

				$this->brute_force_db->whitelist_ip( $ip );

			}

			return;

		}

		// Payload size limit check (excluding multipart/form-data uploads).
		$this->check_payload_size_limit( $ip );

		if ( $this->get_settings( 'filter_bad_requests' ) ) {

			$this->filter_bad_requests();

		}

		if ( $this->get_settings( 'disable_rest_api' ) ) {

			// Match on the route WordPress resolved, not on REQUEST_URI: this covers
			// sub-directory sites (/site1/wp-json/...), ?rest_route= and index.php/wp-json/.
			add_filter( 'rest_authentication_errors', [ $this, 'arm_rest_route_check' ], 1 );
			add_filter( 'rest_pre_dispatch', [ $this, 'restrict_rest_route' ], 5, 3 );

		}

	}


	/**
	 * Apply security headers.
	 *
	 * @return void
	 */
	public function headers() {

		// Do not apply security headers in the admin area to avoid conflicts with plugins.
		if ( is_admin() ) {

			return;

		}

		$hide_versions = $this->get_settings( 'hide_versions' );
		$bad_bots      = $this->get_settings( 'bad_bots' );
		$http_headers  = $this->get_settings( 'http_headers' );

		$enable_coop = $this->get_settings( 'enable_coop' );

		if ( $bad_bots ) {

			$bad_bots   = get_option( 'bad_bots_list', '^libwww-perl.*' );
			$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

			if ( preg_match( "/{$bad_bots}/i", $user_agent ) ) {

				// Log the bad bot event with details.
				$ip = $this->get_client_ip();

				if ( $ip ) {

					$this->brute_force_db->log_attempt_with_details( $ip, BruteForceDB::TYPE_BAD_BOT, $user_agent, $this->request_path_for_log() );

				}

				status_header( 403 );

				exit( 'Access Denied' );

			}

		}

		// Output already started (another plugin, WP-CLI, cron, tests): header() would only add
		// "headers already sent" warnings to the log.
		if ( headers_sent() ) {

			return;

		}

		if ( $hide_versions ) {

			header( 'Server: ' );
			header_remove( 'X-Powered-By' );

		}

		if ( $http_headers ) {

			// Cross-Origin Opener Policy (COOP).
			if ( $enable_coop ) {

				header( 'Cross-Origin-Opener-Policy: same-origin' );

			}

			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'X-Content-Type-Options: nosniff' );

			$this->frame_header_sent = true;

			header( 'Referrer-Policy: strict-origin-when-cross-origin' );

		}

		$this->send_hsts();
		$this->send_csp();

		// Framing stays blocked until WordPress itself confirms the embed card. The request URL is
		// not proof: any page accepts "?embed=1" and still renders in full.
		add_action( 'wp', [ $this, 'allow_embed_framing' ], 0 );

	}


	/**
	 * Let other sites frame the WordPress embed card, and nothing else.
	 *
	 * @return void
	 */
	public function allow_embed_framing() {

		if ( ! is_embed() || headers_sent() ) {

			return;

		}

		if ( $this->frame_header_sent ) {

			header_remove( 'X-Frame-Options' );

		}

		if ( null === $this->csp ) {

			return;

		}

		// The card prints its own inline code outside the traced hooks, so it only gets the always-on rules.
		$this->csp['context']['embed']    = true;
		$this->csp['context']['baseline'] = true;

		header_remove( 'Content-Security-Policy-Report-Only' );

		$this->emit_csp( $this->csp['settings'], [], $this->csp['context'] );

	}


	/**
	 * Send Strict-Transport-Security when the owner opted in and this request is on HTTPS.
	 *
	 * @return void
	 */
	private function send_hsts() {

		if ( ! $this->get_settings( 'enable_hsts' ) || ! is_ssl() ) {

			return;

		}

		$max_age = (int) $this->get_settings( 'hsts_max_age' );

		if ( ! in_array( $max_age, self::HSTS_MAX_AGES, true ) ) {

			$max_age = self::HSTS_MAX_AGES[0];

		}

		$value      = 'max-age=' . $max_age;
		$subdomains = (bool) $this->get_settings( 'enable_hsts_subdomains' );

		if ( $subdomains ) {

			$value .= '; includeSubDomains';

		}

		// Browser preload lists reject anything shorter or without subdomains.
		if ( $subdomains && $max_age >= YEAR_IN_SECONDS && $this->get_settings( 'enable_hsts_preload' ) ) {

			$value .= '; preload';

		}

		header( 'Strict-Transport-Security: ' . $value );

	}


	/**
	 * Whether this request renders a login screen, which prints code no scan ever sees.
	 *
	 * @param string $uri Request URI.
	 * @return bool
	 */
	private function is_login_request( $uri ) {

		// WordPress compares the login URL with SCRIPT_NAME, and an empty name matches every URL.
		// Servers that leave it empty would turn every page into a login screen here.
		if ( ! empty( $_SERVER['SCRIPT_NAME'] ) && is_login() ) {

			return true;

		}

		$slug = trim( (string) $this->get_settings( 'custom_login_url' ), '/' );
		$path = trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' );

		return '' !== $slug && ( $path === $slug || '/' . $slug === substr( $path, -strlen( $slug ) - 1 ) );

	}


	/**
	 * Whether a page builder or the Customizer is drawing this page for an editor.
	 *
	 * Builders print large amounts of their own inline code. Only asked for users who can edit, so
	 * a visitor cannot drop the policy by adding one of these parameters.
	 *
	 * @return bool
	 */
	private function is_builder_request() {

		if ( function_exists( 'is_customize_preview' ) && is_customize_preview() ) {

			return true;

		}

		$markers = [ 'customize_changeset_uuid', 'elementor-preview', 'et_fb', 'fl_builder', 'ct_builder', 'bricks', 'vc_editable', 'brizy-edit', 'tve', 'breakdance', 'oxygen_iframe' ];

		/**
		 * Filters the query parameters that mark a page builder request.
		 *
		 * @param string[] $markers Query parameter names.
		 */
		$markers = (array) apply_filters( 'securefusion_csp_builder_parameters', $markers );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only the presence of a parameter name is read.
		return (bool) array_intersect_key( $_GET, array_flip( array_filter( $markers, 'is_string' ) ) );

	}


	/**
	 * Send the Content-Security-Policy for this audience.
	 *
	 * @return void
	 */
	private function send_csp() {

		$settings = Settings::all();
		$role     = 'visitor';

		if ( is_user_logged_in() ) {

			$role = current_user_can( 'manage_options' ) ? 'admin' : 'member';

		}

		$level = CSPPolicy::level( $settings );
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';

		$exempt  = CSPPolicy::exempt( $settings, $role );
		$context = [
			'level'    => $level,
			'https'    => is_ssl(),
			'embed'    => false,
			'baseline' => $this->is_login_request( $uri ) || ( 'visitor' !== $role && current_user_can( 'edit_posts' ) && $this->is_builder_request() ),
			'observe'  => false,
		];

		if ( $exempt && ! $context['baseline'] ) {

			// An exempt administrator still gets the rules as a test, so notifications can show what
			// visitors would lose. Nothing is blocked for them.
			$context['observe']  = 'admin' === $role && Notifier::wants( $settings, 'csp' );
			$context['baseline'] = ! $context['observe'];

		}

		// The always-on rules name no hosts, so the provider catalog is only read when a host list is sent.
		$deferred  = ! $context['baseline'] && CSPPolicy::limits_code( $settings, $level );
		$generated = $deferred ? CSPIntegrations::sources( $settings ) : [];

		if ( $deferred ) {

			foreach ( CSPInline::boot( $settings, $level, $context['observe'] ) as $type => $sources ) {

				$generated[ $type ] = array_merge( $generated[ $type ] ?? [], $sources );

			}

		}

		$this->csp = [
			'settings'  => $settings,
			'generated' => $generated,
			'context'   => $context,
		];

		if ( ! $deferred ) {

			$this->emit_csp( $settings, $generated, $context );

			return;

		}

		// The always-on rules are valid before the page exists; the full policy replaces them once the page is known.
		$this->emit_csp( $settings, [], array_merge( $context, [ 'baseline' => true ] ) );

		CSPInline::on_finish(
			function ( $learned, $verified = true ) {

				$context = array_merge( $this->csp['context'], [ 'unverified' => ! $verified ] );

				return $this->emit_csp( $this->csp['settings'], array_merge_recursive( $this->csp['generated'], $learned ), $context );

			}
		);

	}


	/**
	 * Send policy headers for one set of sources.
	 *
	 * @param array $settings Resolved settings.
	 * @param array $generated Sources by type.
	 * @param array $context Policy context.
	 * @return array<string,string> Headers sent.
	 */
	private function emit_csp( $settings, $generated, $context ) {

		/**
		 * Filters the largest policy sent, in bytes.
		 *
		 * Nginx answers 502 when all response headers together exceed its buffer, 4 KB by default.
		 * Raise this only on a server whose buffers are known to be larger.
		 *
		 * @param int $limit Bytes.
		 */
		$context['limit'] = min( 16384, (int) apply_filters( 'securefusion_csp_max_header', CSPPolicy::MAX_HEADER ) );

		$result = CSPPolicy::headers( $settings, $generated, $context );

		foreach ( $result['headers'] as $name => $value ) {

			header( $name . ': ' . $value );

		}

		CSPInline::note( $result['reduced'] );

		return $result['headers'];

	}

}
