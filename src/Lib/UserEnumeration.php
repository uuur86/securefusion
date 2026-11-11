<?php
/**
 * UserEnumeration Class
 *
 * Keeps login names away from anonymous visitors without hurting SEO: numeric author
 * lookups, the REST users endpoint, administrator entries in the users sitemap, oEmbed
 * author data and comment CSS classes. Pretty author archives keep working.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

use SecureFusion\Lib\Traits\WPCommon;

/**
 * User enumeration protection.
 */
class UserEnumeration {

	use WPCommon;

	/**
	 * Longest REST route we look at; the users route is matched on its prefix only.
	 */
	const REST_ROUTE_MAX_LENGTH = 512;



	/**
	 * Registers the hooks when the "hide_usernames" setting is on.
	 *
	 * @return void
	 */
	public function init() {

		if ( ! $this->get_settings( 'hide_usernames' ) ) {

			return;

		}

		add_filter( 'request', [ $this, 'block_author_query' ] );
		add_filter( 'wp_sitemaps_users_query_args', [ $this, 'exclude_admins_from_sitemap' ] );
		add_filter( 'oembed_response_data', [ $this, 'filter_oembed_author' ], 10, 2 );
		add_filter( 'comment_class', [ $this, 'filter_comment_class' ], 10, 4 );
		add_filter( 'rest_pre_dispatch', [ $this, 'restrict_users_route' ], 5, 3 );

	}



	/**
	 * Answers "?author=N" with a 404 instead of redirecting to /author/<nicename>/.
	 *
	 * Only with pretty permalinks: on plain permalinks "?author=N" is the only URL of an
	 * author archive, so it is left alone there. Users who can list users are not affected.
	 *
	 * @param array $query_vars Parsed query variables.
	 * @return array Query variables.
	 */
	public function block_author_query( $query_vars ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Presence check only, nothing is processed.
		if ( is_admin() || ! isset( $_GET['author'] ) ) {

			return $query_vars;

		}

		if ( '' === (string) get_option( 'permalink_structure' ) ) {

			return $query_vars;

		}

		if ( current_user_can( 'list_users' ) ) {

			return $query_vars;

		}

		unset( $query_vars['author'] );

		// WP::send_headers() turns this into a 404 status with no-cache headers.
		$query_vars['error'] = '404';

		return $query_vars;

	}



	/**
	 * Leaves administrators out of the users sitemap.
	 *
	 * Their author archives stay reachable; only the sitemap entry is removed. When no
	 * other author has published posts, WordPress lists no users sitemap at all.
	 *
	 * @param array $args WP_User_Query arguments of the users sitemap.
	 * @return array Query arguments.
	 */
	public function exclude_admins_from_sitemap( $args ) {

		$excluded = isset( $args['role__not_in'] ) ? (array) $args['role__not_in'] : [];

		$excluded[] = 'administrator';

		$args['role__not_in'] = array_values( array_unique( $excluded ) );

		return $args;

	}



	/**
	 * Removes oEmbed author data that would reveal the login name.
	 *
	 * @param array    $data oEmbed response data.
	 * @param \WP_Post $post Embedded post.
	 * @return array Response data.
	 */
	public function filter_oembed_author( $data, $post ) {

		if ( ! is_array( $data ) || ! $post instanceof \WP_Post ) {

			return $data;

		}

		$user = get_userdata( (int) $post->post_author );

		if ( ! $user instanceof \WP_User ) {

			return $data;

		}

		if ( isset( $data['author_name'] ) && self::name_reveals_login( $data['author_name'], $user ) ) {

			unset( $data['author_name'] );

		}

		if ( isset( $data['author_url'] ) && self::nicename_reveals_login( $user ) ) {

			unset( $data['author_url'] );

		}

		return $data;

	}



	/**
	 * Removes the "comment-author-<nicename>" class when the nicename reveals the login.
	 *
	 * @param string[]         $classes    Comment classes.
	 * @param string|string[]  $css_class  Extra classes passed to comment_class().
	 * @param int|string       $comment_id Comment ID.
	 * @param \WP_Comment|null $comment    Comment.
	 * @return string[] Comment classes.
	 */
	public function filter_comment_class( $classes, $css_class = '', $comment_id = 0, $comment = null ) {

		if ( ! is_array( $classes ) || ! $comment instanceof \WP_Comment || empty( $comment->user_id ) ) {

			return $classes;

		}

		$user = get_userdata( (int) $comment->user_id );

		if ( ! $user instanceof \WP_User || ! self::nicename_reveals_login( $user ) ) {

			return $classes;

		}

		$leaking = 'comment-author-' . sanitize_html_class( $user->user_nicename, (string) $user->ID );

		return array_values(
			array_filter(
				$classes,
				static function ( $css ) use ( $leaking ) {

					return $css !== $leaking;

				}
			)
		);

	}



	/**
	 * Blocks the REST users endpoint for anonymous visitors.
	 *
	 * Also covers users embedded with "_embed" and batch sub-requests, because both are
	 * dispatched through 'rest_pre_dispatch' while WordPress serves a REST request.
	 * Server-side rest_do_request() calls on normal page loads are not affected.
	 *
	 * @param mixed            $result  Response to replace the requested version with.
	 * @param \WP_REST_Server  $server  Server instance.
	 * @param \WP_REST_Request $request Request used to generate the response.
	 * @return mixed Unchanged result, or a WP_Error when the request is blocked.
	 */
	public function restrict_users_route( $result, $server, $request ) {

		if ( ! $this->is_serving_rest_request() ) {

			return $result;

		}

		if ( is_wp_error( $result ) || ! $request instanceof \WP_REST_Request ) {

			return $result;

		}

		// CORS preflight requests never carry credentials.
		if ( 'OPTIONS' === $request->get_method() ) {

			return $result;

		}

		if ( is_user_logged_in() || ! self::is_users_route( $request->get_route() ) ) {

			return $result;

		}

		// Same filter as Middleware::is_rest_api_access_allowed() (documented there).
		if ( apply_filters( 'securefusion_rest_allow_request', false, $request, $this->get_client_ip() ) ) {

			return $result;

		}

		return new \WP_Error(
			'rest_user_cannot_view',
			esc_html__( 'Sorry, you are not allowed to list users.', 'secuplug' ),
			array( 'status' => rest_authorization_required_code() )
		);

	}



	/**
	 * Whether WordPress is serving a REST request (wp-json or ?rest_route=).
	 *
	 * @return bool
	 */
	protected function is_serving_rest_request() {

		return defined( 'REST_REQUEST' ) && REST_REQUEST;

	}



	/**
	 * Whether a REST route belongs to the core users endpoint (wp/v2/users).
	 *
	 * @param string $route Route as returned by WP_REST_Request::get_route().
	 * @return bool
	 */
	public static function is_users_route( $route ) {

		if ( ! is_string( $route ) || '' === $route ) {

			return false;

		}

		$route = substr( $route, 0, self::REST_ROUTE_MAX_LENGTH );
		$route = '/' . trim( (string) preg_replace( '#/{2,}#', '/', $route ), '/' );

		$matched = preg_match( '#^/wp/v2/users(?:/|$)#i', $route );

		// A regex failure must not open the endpoint silently.
		return false === $matched ? true : 1 === $matched;

	}



	/**
	 * Whether the user's nicename (used in author URLs and CSS classes) reveals the login.
	 *
	 * WordPress derives the nicename from the login, so unless someone changed it, it is
	 * the login itself or a slug of it ("john.doe" becomes "john-doe").
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function nicename_reveals_login( \WP_User $user ) {

		$login    = (string) $user->user_login;
		$nicename = (string) $user->user_nicename;

		if ( '' === $login || '' === $nicename ) {

			return false;

		}

		return strtolower( $login ) === strtolower( $nicename ) || sanitize_title( $login ) === $nicename;

	}



	/**
	 * Whether a public name (display name, oEmbed author name) reveals the login.
	 *
	 * @param string   $name Public name.
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function name_reveals_login( $name, \WP_User $user ) {

		$name  = trim( (string) $name );
		$login = (string) $user->user_login;

		if ( '' === $name || '' === $login ) {

			return false;

		}

		return strtolower( $name ) === strtolower( $login ) || sanitize_title( $name ) === sanitize_title( $login );

	}

}
