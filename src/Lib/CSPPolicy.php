<?php
/**
 * Single source of truth for the Content-Security-Policy a response receives.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Build policy values independently of HTTP output.
 *
 * Allow lists can only add hosts, so no two settings can disagree about inline code.
 *
 * Internally a response has one of three levels: 'off', 'strict' (inline code is verified, the
 * default whenever protection is on) and 'basic' (only script hosts are limited, chosen with
 * "Allow all inline code"). The settings form stores 'off' or 'basic' in csp_level.
 */
class CSPPolicy {

	const LEVELS = [ 'off', 'basic', 'strict' ];

	/**
	 * Largest policy we send. Nginx's default fastcgi buffer is 4 KB for all response headers,
	 * and a larger response answers 502 for the whole page.
	 */
	const MAX_HEADER = 2800;

	/**
	 * Resource types with an allow list of their own, and the directive each list belongs to.
	 */
	const LIMITS = [
		'style'       => 'style-src',
		'font'        => 'font-src',
		'img'         => 'img-src',
		'frame'       => 'frame-src',
		'worker'      => 'worker-src',
		'connect'     => 'connect-src',
		'media'       => 'media-src',
		'form_action' => 'form-action',
	];

	/**
	 * Types limited only once their list holds a host, in the order they are given up when a
	 * policy is too large: least protective first. An empty list means no limit. The style and
	 * worker rules exist on their own, so those lists only add hosts.
	 */
	const LISTED = [ 'media', 'img', 'font', 'connect', 'frame', 'form_action' ];

	/**
	 * Resolve the configured protection level.
	 *
	 * @param array $settings Resolved settings.
	 * @return string
	 */
	public static function level( $settings ) {

		if ( 'off' === ( $settings['csp_level'] ?? 'basic' ) ) {

			return 'off';

		}

		// Inline code is verified unless the owner chose to allow all of it.
		return '1' === (string) ( $settings['csp_allow_inline'] ?? '0' ) ? 'basic' : 'strict';

	}

	/**
	 * Whether a resource type is limited: its list names at least one host.
	 *
	 * @param array  $settings Resolved settings.
	 * @param string $type     One of LISTED.
	 * @return bool
	 */
	public static function limits( $settings, $type ) {

		return in_array( $type, self::LISTED, true ) && (bool) CSP::host_list( $settings[ 'csp_allowed_' . $type . '_sources' ] ?? '' );

	}

	/**
	 * Read the On/Off switch each list had in older versions.
	 *
	 * A list is now a limit as soon as it holds a host. A list whose switch was off never limited
	 * anything, so it is emptied; otherwise the hosts that shipped as defaults would start
	 * blocking images and fonts on update. Removing the switch makes this run once per stored layer.
	 *
	 * @param array $values Stored values from one settings layer.
	 * @return array
	 */
	private static function without_switches( $values ) {

		foreach ( self::LISTED as $type ) {

			$switch = 'enable_csp_' . $type;

			if ( ! array_key_exists( $switch, $values ) ) {

				continue;

			}

			if ( '1' !== (string) $values[ $switch ] ) {

				$values[ 'csp_allowed_' . $type . '_sources' ] = '';

			}

			unset( $values[ $switch ] );

		}

		unset( $values['enable_csp_worker'] );

		return $values;

	}

	/**
	 * Whether anything beyond the safe baseline is enforced or only tested.
	 *
	 * @param array $settings Resolved settings.
	 * @return string 'enforce' or 'report'.
	 */
	public static function mode( $settings ) {

		return 'enforce' === ( $settings['csp_mode'] ?? 'report' ) ? 'enforce' : 'report';

	}

	/**
	 * Translate settings saved by older versions into the protection level.
	 *
	 * @param array|mixed $values Stored values from one settings layer.
	 * @return array|mixed
	 */
	public static function upgrade_values( $values ) {

		// Also used as an option filter, where a missing option arrives as false.
		if ( ! is_array( $values ) ) {

			return $values;

		}

		$values = self::without_switches( $values );

		if ( isset( $values['csp_level'] ) ) {

			// The settings form only offers Off and On; development builds stored other names.
			if ( 'off' !== $values['csp_level'] ) {

				$values['csp_level'] = 'basic';

			}

			return $values;

		}

		$level = self::legacy_level( $values );

		if ( '' === $level ) {

			return $values;

		}

		$values['csp_level'] = 'off' === $level ? 'off' : 'basic';

		// Scripts were not limited on this site before, so the policy starts as a test.
		if ( 'basic' === $level ) {

			$values['csp_mode'] = 'report';

			return $values;

		}

		if ( isset( $values['csp_mode'] ) ) {

			$values['csp_mode'] = self::mode( $values );

		} else {

			$tested             = ! empty( $values['csp_easy_mode'] ) || ! empty( $values['enable_csp_report_only'] );
			$values['csp_mode'] = $tested ? 'report' : 'enforce';

		}

		// This site already ran its own rules. Keep what its pages may rely on.
		if ( 'enhanced' === $level ) {

			$values['csp_allow_inline'] = '1';

		}

		if ( ! isset( $values['csp_allow_eval'] ) ) {

			$values['csp_allow_eval'] = '1';

		}

		return $values;

	}

	/**
	 * Map a pre-level configuration to the closest level.
	 *
	 * @param array $values Stored values from one settings layer.
	 * @return string Level, or empty when this layer holds no CSP decision.
	 */
	private static function legacy_level( $values ) {

		$disabled = isset( $values['http_headers'] ) && '0' === (string) $values['http_headers'];
		$keys     = [ 'csp_profile', 'csp_mode', 'csp_easy_mode', 'enable_csp_report_only', 'csp_inline_enabled', 'enable_csp_script', 'enable_csp_style' ];

		if ( ! array_intersect_key( $values, array_flip( $keys ) ) ) {

			return $disabled ? 'off' : '';

		}

		if ( $disabled ) {

			return 'off';

		}

		if ( 'auto' === ( $values['csp_profile'] ?? '' ) ) {

			return 'basic';

		}

		$inline = (string) ( $values['csp_inline_enabled'] ?? '0' );

		if ( '1' === $inline ) {

			return 'strict';

		}

		$custom = 'unsafe' === $inline
			|| ! empty( $values['csp_easy_mode'] )
			|| 'report_all' === ( $values['csp_mode'] ?? '' )
			|| '1' === (string) ( $values['enable_csp_script'] ?? '0' )
			|| '1' === (string) ( $values['enable_csp_style'] ?? '0' );

		return $custom ? 'enhanced' : 'basic';

	}

	/**
	 * Whether an audience only gets the always-on rules. Page builders print code visitors never get.
	 *
	 * @param array  $settings Resolved settings.
	 * @param string $role visitor, member or admin.
	 * @return bool
	 */
	public static function exempt( $settings, $role ) {

		if ( 'visitor' === $role ) {

			return false;

		}

		return '1' !== (string) ( $settings[ 'admin' === $role ? 'csp_scope_admins' : 'csp_scope_members' ] ?? '1' );

	}

	/**
	 * Whether the policy depends on what the page loads, so it can only be finished once the page exists.
	 *
	 * @param array  $settings Resolved settings.
	 * @param string $level Protection level.
	 * @return bool
	 */
	public static function limits_code( $settings, $level ) {

		return 'off' !== self::level( [ 'csp_level' => $level ] + (array) $settings );

	}

	/**
	 * Build one directive's source list.
	 *
	 * @param array  $settings  Resolved settings.
	 * @param array  $generated Sources by type: services, approved hosts, inline permissions.
	 * @param string $type      Source type.
	 * @param string $keywords  Keywords the level grants.
	 * @return string
	 */
	private static function sources( $settings, $generated, $type, $keywords = '' ) {

		$hosts = array_merge( CSP::host_list( $settings[ 'csp_allowed_' . $type . '_sources' ] ?? '' ), $generated[ $type ] ?? [] );

		// A data: URL carries its own code, so allowing it for scripts would allow any injected script.
		if ( 'script' === $type ) {

			$hosts = array_diff( $hosts, [ 'data:' ] );

			// Once all inline code is allowed that is no longer a loss, and optimizers that defer
			// inline scripts (Autoptimize) turn each of them into a data: address.
			if ( false !== strpos( $keywords, "'unsafe-inline'" ) ) {

				$keywords .= ' data:';

			}

		}

		return CSP::normalize_csp_sources( "'self'" . $keywords . ' ' . implode( ' ', $hosts ) );

	}

	/**
	 * Build a policy.
	 *
	 * The baseline (object, base URL and framing rules) names no hosts and is safe on every page.
	 * 'basic' adds script host limits, 'strict' also verifies inline code. Other resource types
	 * are limited only when their list names a host.
	 *
	 * @param array $settings  Resolved settings.
	 * @param array $generated Sources by type.
	 * @param array $context   Keys: level, https, report, embed, baseline, skip (optional limits to leave out).
	 * @return string Empty when no policy applies.
	 */
	public static function build( $settings, $generated = [], $context = [] ) {

		$level = $context['level'] ?? self::level( $settings );

		if ( 'off' === $level ) {

			return '';

		}

		$baseline = ! empty( $context['baseline'] );
		$report   = ! empty( $context['report'] );
		$strict   = ! $baseline && 'strict' === $level;
		$limited  = ! $baseline;
		$skip     = (array) ( $context['skip'] ?? [] );
		$policy   = [];

		if ( $limited ) {

			// Pages that load a script known to need it get 'unsafe-eval' through $generated instead.
			$eval     = '1' === (string) ( $settings['csp_allow_eval'] ?? '0' ) ? " 'unsafe-eval'" : '';
			$policy[] = 'script-src ' . self::sources( $settings, $generated, 'script', ( $strict ? '' : " 'unsafe-inline'" ) . $eval );

			$policy[] = 'worker-src ' . self::sources( $settings, $generated, 'worker', ' blob:' );

		}

		if ( $strict ) {

			$policy[] = 'style-src ' . self::sources( $settings, $generated, 'style' );

			// A nonce or hash cannot cover attributes; without these, style="" and onclick="" stop working.
			$policy[] = "style-src-attr 'unsafe-inline'";

			if ( '1' !== (string) ( $settings['csp_block_event_handlers'] ?? '0' ) ) {

				$policy[] = "script-src-attr 'unsafe-inline'";

			}

		}

		if ( ! $baseline ) {

			foreach ( self::LISTED as $type ) {

				if ( self::limits( $settings, $type ) && ! in_array( $type, $skip, true ) ) {

					$policy[] = self::LIMITS[ $type ] . ' ' . self::sources( $settings, $generated, $type );

				}

			}

		}

		// 'self' keeps the PDF preview of the core File block working.
		$policy[] = "object-src 'self'";
		$policy[] = "base-uri 'self'";

		if ( empty( $context['embed'] ) ) {

			$policy[] = "frame-ancestors 'self'";

		}

		if ( ! empty( $context['https'] ) && ! $report && '0' !== (string) ( $settings['csp_upgrade_insecure_requests'] ?? '1' ) ) {

			$policy[] = 'upgrade-insecure-requests';

		}

		$url = $settings['csp_report_uri'] ?? '';

		if ( ! $baseline && is_string( $url ) && preg_match( '#^https?://[^\s;,]+$#D', $url ) && filter_var( $url, FILTER_VALIDATE_URL ) ) {

			$policy[] = 'report-uri ' . $url;

		}

		return implode( '; ', $policy ) . ';';

	}

	/**
	 * Build the largest policy that fits the header budget.
	 *
	 * Optional limits are left out one at a time, least protective first, so a long allow list
	 * costs an image or font rule before it costs anything about scripts.
	 *
	 * @param array $settings  Resolved settings.
	 * @param array $generated Sources by type.
	 * @param array $context   Policy context.
	 * @param int   $limit     Largest policy in bytes.
	 * @return array{0: string, 1: bool} Policy (empty when nothing fits) and whether limits were left out.
	 */
	private static function fit( $settings, $generated, $context, $limit ) {

		$skip = [];

		// Bounded by the six listed limits.
		foreach ( array_merge( [ '' ], self::LISTED ) as $type ) {

			if ( '' !== $type ) {

				if ( ! self::limits( $settings, $type ) ) {

					continue;

				}

				$skip[] = $type;

			}

			$policy = self::build( $settings, $generated, array_merge( $context, [ 'skip' => $skip ] ) );

			if ( strlen( $policy ) <= $limit ) {

				return [ $policy, (bool) $skip ];

			}

		}

		return [ '', true ];

	}

	/**
	 * Decide the response headers.
	 *
	 * The safe baseline is always enforced, so testing a stricter policy never lowers protection.
	 * A policy too large for common server buffers would answer 502 for the whole page, so it is
	 * reduced in steps: optional limits first, then inline verification (which keeps the script
	 * host limits), and only then everything but the baseline.
	 *
	 * @param array $settings  Resolved settings.
	 * @param array $generated Sources by type.
	 * @param array $context   Keys: level, https, embed, observe (test only, whatever the mode),
	 *                         limit (largest policy in bytes), unverified (inline code could not be identified).
	 * @return array{headers: array<string,string>, overflow: bool, reduced: string} "reduced" names what
	 *         was given up: empty, limits, inline or all.
	 */
	public static function headers( $settings, $generated, $context ) {

		$enforced = 'Content-Security-Policy';
		$tested   = 'Content-Security-Policy-Report-Only';
		$baseline = self::build( $settings, [], array_merge( $context, [ 'baseline' => true ] ) );
		$result   = [
			'headers'  => [],
			'overflow' => false,
			'reduced'  => '',
		];

		if ( '' === $baseline ) {

			return $result;

		}

		$result['headers'] = [ $enforced => $baseline ];

		if ( ! empty( $context['baseline'] ) ) {

			return $result;

		}

		$limit  = max( 512, (int) ( $context['limit'] ?? self::MAX_HEADER ) );
		$report = ! empty( $context['observe'] ) || 'enforce' !== self::mode( $settings );
		$loose  = [ 'level' => 'basic' ];

		$context['report'] = $report;

		if ( ! empty( $context['unverified'] ) ) {

			// Without knowing the page's inline code, a list of hashes would block all of it.
			$generated = self::without_inline_tokens( $generated );
			$context   = array_merge( $context, $loose );

		}

		list( $candidate, $skipped ) = self::fit( $settings, $generated, $context, $limit );

		if ( $skipped ) {

			$result['reduced'] = 'limits';

		}

		if ( '' === $candidate && 'strict' === ( $context['level'] ?? self::level( $settings ) ) ) {

			list( $candidate ) = self::fit( $settings, self::without_inline_tokens( $generated ), array_merge( $context, $loose ), $limit );

			$result['reduced'] = 'inline';

		}

		$result['overflow'] = '' !== $result['reduced'];

		if ( '' === $candidate || $candidate === $baseline ) {

			$result['reduced'] = '' === $candidate ? 'all' : $result['reduced'];

			return $result;

		}

		$result['headers'] = $report ? [
			$enforced => $baseline,
			$tested   => $candidate,
		] : [ $enforced => $candidate ];

		return $result;

	}

	/**
	 * Remove nonces and hashes, which only make sense while inline code is verified.
	 *
	 * @param array $generated Sources by type.
	 * @return array
	 */
	private static function without_inline_tokens( $generated ) {

		foreach ( $generated as $type => $sources ) {

			$generated[ $type ] = array_values(
				array_filter(
					(array) $sources,
					static function ( $source ) {

						return 0 !== strpos( (string) $source, "'nonce-" ) && 0 !== strpos( (string) $source, "'sha" );

					}
				)
			);

		}

		return $generated;

	}

}
