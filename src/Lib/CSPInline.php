<?php
/**
 * Inline authorization at the points where WordPress, themes and plugins print code.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Trust is decided where code is printed, because only there is its producer known. The decision
 * travels with the element as a per-response token, never as a hash of its text: optimizers
 * (Autoptimize, HTML minifiers, WordPress's own template buffer) rewrite inline code after it is
 * printed, so a hash taken at print time does not match what the browser receives. Hashes are
 * taken once, from the finished page. Never persist a token.
 */
class CSPInline {

	/**
	 * Snapshot of approved and pending records.
	 *
	 * @var array
	 */
	private static $rows = [];

	/**
	 * Current request path without query parameters.
	 *
	 * @var string
	 */
	private static $path = '/';

	/**
	 * Attribute naming the producer of code that was not trusted, on scan responses only.
	 */
	const LABEL = 'data-securefusion-source';

	/**
	 * Transient holding why a page was last sent with fewer rules: reason and detail.
	 */
	const NOTE = 'securefusion_csp_overflow';

	/**
	 * Largest page held back to finish its policy, in bytes. Larger pages leave in chunks.
	 */
	const HOLD_LIMIT = 4194304;

	/**
	 * Fresh token for this response only. Printed as the nonce attribute of trusted inline code;
	 * with the hash method it is replaced by hashes before the page leaves.
	 *
	 * @var string
	 */
	private static $nonce = '';

	/**
	 * Inline code already decided on this response: "type:digest" => [ allowed, source ].
	 *
	 * @var array<string,array{0: bool, 1: string}>
	 */
	private static $decided = [];

	/**
	 * Whether the administrator opted into discovery.
	 *
	 * @var bool
	 */
	private static $capture = false;

	/**
	 * Whether request hooks have been installed.
	 *
	 * @var bool
	 */
	private static $started = false;

	/**
	 * Protection level for this response.
	 *
	 * @var string
	 */
	private static $level = 'off';

	/**
	 * Sources the owner excluded from automatic trust.
	 *
	 * @var array<string,bool>
	 */
	private static $blocked = [];

	/**
	 * Inline code the owner revoked: "type:digest" => true.
	 *
	 * @var array<string,bool>
	 */
	private static $denied = [];

	/**
	 * Exact inline code the owner approved for this path: "type:digest" => true.
	 *
	 * @var array<string,bool>
	 */
	private static $approved = [];

	/**
	 * Output buffer level of the held page, or 0 while nothing is held.
	 *
	 * @var int
	 */
	private static $depth = 0;

	/**
	 * Whether the held page has been finished.
	 *
	 * @var bool
	 */
	private static $settled = false;

	/**
	 * Whether trusted code on this page cannot be covered by a hash: an optimizer moved it into
	 * a data: address.
	 *
	 * @var bool
	 */
	private static $opaque = false;

	/**
	 * How allowed inline code is identified on this response: nonce or hash.
	 *
	 * @var string
	 */
	private static $method = 'nonce';

	/**
	 * Hosts learned while the page was produced and hashes taken from the finished page, by type.
	 *
	 * @var array<string,string[]>
	 */
	private static $runtime = [
		'script' => [],
		'style'  => [],
	];

	/**
	 * Sends the final policy once the page is finished: receives the learned sources by type and
	 * whether inline code could be identified, and returns the headers it sent.
	 *
	 * @var callable|null
	 */
	private static $finish = null;

	/**
	 * Request text used to refuse code that merely echoes the request.
	 *
	 * @var string|null
	 */
	private static $input = null;

	/**
	 * Wrappers installed on hook callbacks, so none is wrapped twice: hook => priority => id => wrapper.
	 *
	 * @var array<string,array<int,array<string,\Closure>>>
	 */
	private static $traced = [];

	/**
	 * Whether the nonce on this page is a placeholder the cache driver replaces on every response.
	 *
	 * @var bool
	 */
	private static $relay = false;

	/**
	 * Prepare policy sources before headers are sent.
	 *
	 * @param array  $settings Resolved settings.
	 * @param string $level Protection level for this response.
	 * @param bool   $observe Whether this response only tests the policy, whatever the mode.
	 * @return array Additional sources by type.
	 */
	public static function boot( $settings, $level = 'off', $observe = false ) {

		if ( self::$started ) {

			return self::sources();

		}

		self::$started = true;
		self::$level   = $level;
		self::$path    = self::request_path();

		if ( 'off' !== $level ) {

			// One query for both lists on sites without a persistent object cache.
			wp_prime_option_caches( [ CSPInlineRules::OPTION, CSPInlineRules::BLOCK_OPTION ] );

			self::$rows    = CSPInlineRules::all();
			self::$blocked = CSPInlineRules::blocked();

			foreach ( self::$rows as $row ) {

				$key = ( $row['type'] ?? '' ) . ':' . ( $row['digest'] ?? '' );

				if ( ! empty( $row['revoked'] ) ) {

					self::$denied[ $key ] = true;

				} elseif ( 'strict' === $level && CSPInlineRules::allows( $row, self::$path ) && preg_match( '#^[A-Za-z0-9+/]{43}=$#D', $row['digest'] ?? '' ) ) {

					self::$approved[ $key ] = true;

				}

			}

		}

		self::$capture = '' !== CSPInlineScan::request_key();

		self::$relay = CSPCache::driver_ready();

		if ( self::enabled() ) {

			self::$method = self::method_for( $settings );

		}

		if ( self::enabled() || self::$capture ) {

			self::$nonce = bin2hex( random_bytes( 16 ) );

		}

		// A nonce that a cache hands to every visitor protects nobody. While only testing nothing is
		// blocked, so pages may stay cached until the policy is enforced.
		$unshared = self::enabled() && 'nonce' === self::$method && ! self::$relay && ! $observe && 'enforce' === CSPPolicy::mode( $settings );

		if ( self::$capture || $unshared ) {

			CSPCache::exclude();

		}

		if ( self::$capture || self::enabled() ) {

			add_filter( 'wp_inline_script_attributes', [ __CLASS__, 'script_attributes' ], 100, 2 );
			add_action( 'template_redirect', [ __CLASS__, 'trace_hooks' ], PHP_INT_MAX );
			CSPNonce::install_styles();

		}

		add_filter( 'script_loader_tag', [ __CLASS__, 'track_script' ], 100, 3 );
		add_filter( 'style_loader_tag', [ __CLASS__, 'track_style' ], 100, 3 );

		if ( self::$capture ) {

			self::hold();

		}

		return self::sources();

	}

	/**
	 * Current request path without query parameters.
	 *
	 * @return string
	 */
	private static function request_path() {

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		$path = wp_parse_url( $uri, PHP_URL_PATH );

		return is_string( $path ) && '' !== $path ? $path : '/';

	}

	/**
	 * Enable a verified loopback probe even when no policy needs the inventory.
	 *
	 * @return void
	 */
	public static function discover() {

		if ( ! self::$started && '' !== CSPInlineScan::request_key() ) {

			self::boot( Settings::all(), 'off' );

		}

	}

	/**
	 * Check whether inline code is limited on this response.
	 *
	 * @return bool
	 */
	private static function enabled() {

		return 'strict' === self::$level;

	}

	/**
	 * Pick how inline code is identified.
	 *
	 * A nonce is one short token whatever the page holds, but it must be new on every visit. Behind
	 * a page cache only the cache driver can do that. Until it runs, Automatic lists the hashes of
	 * the page's own code instead, which stay valid for as long as the page is cached.
	 *
	 * @param array $settings Resolved settings.
	 * @return string nonce or hash.
	 */
	public static function method_for( $settings ) {

		$method = $settings['csp_inline_method'] ?? 'auto';

		if ( 'hash' === $method || 'nonce' === $method ) {

			return $method;

		}

		return ! CSPCache::shared() || CSPCache::driver_ready() ? 'nonce' : 'hash';

	}

	/**
	 * Whether this page printed a script that builds code while it runs.
	 *
	 * WordPress templates (wp.template) compile to functions in the browser. Pages without them
	 * keep eval blocked.
	 *
	 * @return bool
	 */
	private static function needs_eval() {

		foreach ( (array) apply_filters( 'securefusion_csp_eval_handles', [ 'wp-util' ] ) as $handle ) {

			if ( is_string( $handle ) && wp_script_is( $handle, 'done' ) ) {

				return true;

			}

		}

		return false;

	}

	/**
	 * Finish the policy once the page exists, so it can include what producing the page revealed.
	 *
	 * @param callable $callback Receives the learned sources by type and whether inline code could
	 *                           be identified; returns the headers it sent.
	 * @return void
	 */
	public static function on_finish( $callback ) {

		self::$finish = $callback;

		self::hold();

	}

	/**
	 * Hold the page back until it is complete.
	 *
	 * The buffer is opened before any optimizer opens its own, so it receives the page as the
	 * browser will: after Autoptimize, HTML minifiers and WordPress's template buffer have rewritten
	 * it. Past HOLD_LIMIT the page leaves in chunks, so a large download cannot exhaust memory.
	 *
	 * @return void
	 */
	private static function hold() {

		if ( self::$depth > 0 || ! ob_start( [ __CLASS__, 'release' ], self::HOLD_LIMIT ) ) {

			return;

		}

		self::$depth   = ob_get_level();
		self::$settled = false;

		add_action( 'shutdown', [ __CLASS__, 'finish' ], 0 );

	}

	/**
	 * Finish the held page before WordPress flushes the buffers on shutdown.
	 *
	 * Doing the work here, outside an output handler, keeps third-party code that runs on our
	 * filters free to use output buffers itself.
	 *
	 * @return void
	 */
	public static function finish() {

		if ( self::$settled || ! self::holding() ) {

			return;

		}

		// Optimizers buffer above us. WordPress closes their buffers on this hook one step later;
		// closing them now hands over the page they produce. Bounded by the open buffers.
		for ( $level = ob_get_level(); $level > self::$depth; $level-- ) {

			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A buffer may refuse to close; release() then finishes the page.
			if ( ! @ob_end_flush() ) {

				return;

			}

		}

		// Closing them can push the page past HOLD_LIMIT, which already sent it through release().
		if ( self::$settled || ob_get_level() !== self::$depth || ! self::holding() ) {

			return;

		}

		self::$settled = true;

		$html = (string) ob_get_clean();

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The page itself, with policy tokens settled.
		echo self::complete( $html, true );

	}

	/**
	 * Whether the buffer at our level is still ours. Code that sends a file discards every buffer
	 * first, and another buffer may have taken the level since.
	 *
	 * @return bool
	 */
	private static function holding() {

		$status = self::$depth > 0 ? ob_get_status( true ) : [];

		return __CLASS__ . '::release' === ( $status[ self::$depth - 1 ]['name'] ?? '' );

	}

	/**
	 * Output handler: finish a page whose buffer was closed or overflowed before shutdown.
	 *
	 * Themes and plugins that flush every buffer early would otherwise leave the page with the
	 * always-on rules only.
	 *
	 * @param string $html  Buffered output.
	 * @param int    $phase Output handler flags.
	 * @return string
	 */
	public static function release( $html, $phase = PHP_OUTPUT_HANDLER_FINAL ) {

		// A cleaned buffer is discarded, and may be filled again.
		if ( self::$settled || ( $phase & PHP_OUTPUT_HANDLER_CLEAN ) ) {

			return $html;

		}

		self::$settled = true;

		try {

			return self::complete( $html, (bool) ( $phase & PHP_OUTPUT_HANDLER_FINAL ) );

		} catch ( \Throwable $e ) {

			return $html;

		}

	}

	/**
	 * Settle the tokens of a finished page and send its policy.
	 *
	 * Without a rendered template the body is not ours: a file, an API answer, or a page a cache
	 * replayed. Those keep the always-on rules already sent.
	 *
	 * @param string $html  Page, or its first part when it is too large to hold.
	 * @param bool   $whole Whether this is the complete page.
	 * @return string
	 */
	private static function complete( $html, $whole ) {

		$callback = self::$finish;

		self::$finish = null;

		if ( $whole && self::$capture ) {

			self::capture_html( $html );

		}

		if ( null === $callback || ! did_action( 'template_redirect' ) ) {

			return $html;

		}

		if ( headers_sent( $file, $line ) ) {

			// Something flushed the response before the page was complete; name it for the owner.
			self::note( 'output', self::relative_file( (string) $file ) . ':' . (int) $line );

			return $html;

		}

		// Hashes can only be taken from the whole page. A nonce was already printed with each element.
		$verified = $whole || 'hash' !== self::$method || ! self::enabled();

		if ( $whole ) {

			$html = self::settle( $html );

		}

		if ( self::$opaque ) {

			// Blocking the site's own scripts would break the page, so it is sent as if all
			// inline code were allowed, and the owner is told why.
			$verified = false;

			self::note( 'data' );

		}

		if ( self::needs_eval() ) {

			self::$runtime['script'][] = "'unsafe-eval'";

		}

		$headers = $callback( array_map( 'array_unique', self::$runtime ), $verified );

		if ( $whole && self::$relay && is_array( $headers ) && CSPCache::is_html_response() ) {

			$html .= CSPCache::marker( 'nonce' === self::$method ? self::$nonce : '', $headers );

		}

		return $html;

	}

	/**
	 * Replace print-time decisions with what the finished page needs.
	 *
	 * Runs only when there is something to settle: the hash method (each trusted element becomes
	 * a hash of its final text), code the owner approved by its exact text, or code they revoked.
	 * One pass over a page of at most HOLD_LIMIT bytes.
	 *
	 * @param string $html Complete page.
	 * @return string
	 */
	public static function settle( $html ) {

		$hash = 'hash' === self::$method;

		if ( ! self::enabled() || '' === self::$nonce || ( ! $hash && ! self::$approved && ! self::$denied ) ) {

			return $html;

		}

		if ( false === stripos( $html, '<script' ) && false === stripos( $html, '<style' ) ) {

			return $html;

		}

		$tags = new \WP_HTML_Tag_Processor( $html );

		while ( $tags->next_tag() ) {

			$type = self::code_type( $tags );

			if ( '' === $type ) {

				// Autoptimize defers inline scripts by moving their code into a data: address.
				// The token came along, but no hash can stand in for it.
				if ( $hash && 'SCRIPT' === $tags->get_tag() && self::$nonce === $tags->get_attribute( 'nonce' ) ) {

					self::$opaque = self::$opaque || 0 === stripos( (string) $tags->get_attribute( 'src' ), 'data:' );

					$tags->remove_attribute( 'nonce' );

				}

				continue;

			}

			$marked = self::$nonce === $tags->get_attribute( 'nonce' );
			$code   = $tags->get_modifiable_text();
			$key    = $type . ':' . CSPInlineRules::digest( $code );

			if ( $marked && ( '' === trim( $code ) || isset( self::$denied[ $key ] ) ) ) {

				// Empty elements need no permission; revoked text loses the one its producer earned.
				$tags->remove_attribute( 'nonce' );

				continue;

			}

			if ( ! $marked && ! isset( self::$approved[ $key ] ) ) {

				continue;

			}

			if ( $hash ) {

				self::$runtime[ $type ][] = "'sha256-" . substr( $key, strlen( $type ) + 1 ) . "'";

				$tags->remove_attribute( 'nonce' );

			} elseif ( ! $marked ) {

				$tags->set_attribute( 'nonce', self::$nonce );

			}

		}

		return $tags->get_updated_html();

	}

	/**
	 * Remember why a page went out with fewer rules, for the settings screen. One write a day.
	 *
	 * @param string $reason limits, inline, all, data or output.
	 * @param string $detail Where output started, for "output".
	 * @return void
	 */
	public static function note( $reason, $detail = '' ) {

		if ( '' === $reason || get_transient( self::NOTE ) ) {

			return;

		}

		set_transient(
			self::NOTE,
			[
				'reason' => $reason,
				'detail' => substr( $detail, 0, 200 ),
			],
			DAY_IN_SECONDS
		);

	}

	/**
	 * Shorten a file path to what identifies the theme or plugin.
	 *
	 * @param string $file Absolute path.
	 * @return string
	 */
	private static function relative_file( $file ) {

		$file = wp_normalize_path( $file );
		$root = wp_normalize_path( ABSPATH );

		return 0 === strpos( $file, $root ) ? substr( $file, strlen( $root ) ) : basename( $file );

	}

	/**
	 * Collect approved hosts and this response's nonce.
	 *
	 * Approved inline code is not listed here: settle() allows it where a page really holds it,
	 * so every page's policy carries only what that page needs.
	 *
	 * @return array
	 */
	private static function sources() {

		$result = [
			'script' => [],
			'style'  => [],
		];

		foreach ( self::$rows as $row ) {

			$type = $row['type'] ?? '';

			if ( isset( CSPInlineRules::HOST_TYPES[ $type ] ) && ! empty( $row['approved'] ) ) {

				$result[ CSPInlineRules::HOST_TYPES[ $type ] ][] = $row['digest'];

			}

		}

		if ( self::enabled() && 'nonce' === self::$method && '' !== self::$nonce ) {

			$result['script'][] = "'nonce-" . self::$nonce . "'";
			$result['style'][]  = "'nonce-" . self::$nonce . "'";

		}

		return array_map( 'array_unique', $result );

	}

	/**
	 * Whether inline code is contained in what the visitor sent, the signature of reflected XSS.
	 *
	 * @param string $code Inline text.
	 * @return bool
	 */
	private static function reflected( $code ) {

		if ( null === self::$input ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared only; sanitizing would hide the payload we look for.
			self::$input = isset( $_SERVER['REQUEST_URI'] ) ? urldecode( substr( (string) wp_unslash( $_SERVER['REQUEST_URI'] ), 0, 8192 ) ) : '';

			// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read-only comparison.
			foreach ( array_slice( $_POST, 0, 200 ) as $value ) {

				if ( is_string( $value ) && strlen( self::$input ) < 65536 ) {

					self::$input .= "\n" . substr( wp_unslash( $value ), 0, 65536 );

				}

			}

		}

		$code = trim( $code );

		return '' !== $code && false !== strpos( self::$input, $code );

	}

	/**
	 * Decide one piece of inline code where it is printed.
	 *
	 * @param string   $type    Code kind.
	 * @param string   $code    Inline text as printed.
	 * @param callable $resolve Returns the source key of the code's producer.
	 * @return array<string,string> Attributes to print on the element.
	 */
	private static function decide( $type, $code, $resolve ) {

		$key = $type . ':' . CSPInlineRules::digest( $code );

		if ( ! isset( self::$decided[ $key ] ) ) {

			// Finding the producer costs a lookup, so it is skipped while nobody asks for it.
			$source = self::$blocked || self::$capture ? (string) $resolve() : '';

			self::$decided[ $key ] = [ ! isset( self::$blocked[ $source ] ) && ! isset( self::$denied[ $key ] ) && ! self::reflected( $code ), $source ];

		}

		list( $allowed, $source ) = self::$decided[ $key ];

		if ( '' === self::$nonce ) {

			return [];

		}

		if ( $allowed ) {

			return [ 'nonce' => self::$nonce ];

		}

		// The scan lists this element; the token proves the label is ours and not page content.
		return self::$capture && '' !== $source ? [ self::LABEL => self::$nonce . ':' . $source ] : [];

	}

	/**
	 * Authorize inline output registered through the WordPress script and style APIs.
	 *
	 * @param string $type Code kind.
	 * @param string $id Renderer id.
	 * @param string $code Exact inline text.
	 * @return array<string,string> Attributes to print on the element.
	 */
	public static function authorize( $type, $id, $code ) {

		return self::decide(
			$type,
			$code,
			static function () use ( $type, $id ) {

				return CSPInlineSources::for_element( $type, $id );

			}
		);

	}

	/**
	 * Add the response nonce to a registered handle's inline style element.
	 *
	 * @param string $handle Stylesheet handle.
	 * @param string $html Markup printed for the handle.
	 * @return string
	 */
	public static function stamp_style( $handle, $html ) {

		if ( false === stripos( $html, '<style' ) ) {

			return $html;

		}

		$tags = new \WP_HTML_Tag_Processor( $html );

		while ( $tags->next_tag( 'STYLE' ) ) {

			if ( $handle . '-inline-css' !== $tags->get_attribute( 'id' ) ) {

				continue;

			}

			foreach ( self::authorize( 'style', $handle . '-inline-css', $tags->get_modifiable_text() ) as $name => $value ) {

				$tags->set_attribute( $name, $value );

			}

		}

		return $tags->get_updated_html();

	}

	/**
	 * Filter trusted WordPress script output.
	 *
	 * @param array  $attributes Attributes supplied by WordPress.
	 * @param string $data Inline script text.
	 * @return array
	 */
	public static function script_attributes( $attributes, $data ) {

		return array_merge( $attributes, self::authorize( 'script', $attributes['id'] ?? '', "\n" . trim( $data, "\n\r " ) . "\n" ) );

	}

	/**
	 * Remember the host of a script WordPress prints from an installed theme or plugin.
	 *
	 * @param string $tag Script tag.
	 * @param string $handle Script handle.
	 * @param string $src Script URL.
	 * @return string Unmodified tag.
	 */
	public static function track_script( $tag, $handle, $src ) {

		self::track_host( 'script', $src );

		return $tag;

	}

	/**
	 * Remember the host of a stylesheet WordPress prints from an installed theme or plugin.
	 *
	 * @param string $tag Link tag.
	 * @param string $handle Style handle.
	 * @param string $href Stylesheet URL.
	 * @return string Unmodified tag.
	 */
	public static function track_style( $tag, $handle, $href ) {

		self::track_host( 'style', $href );

		return $tag;

	}

	/**
	 * Add an enqueued asset's external host to this response's policy.
	 *
	 * @param string $type Script or style.
	 * @param string $url Asset URL.
	 * @return void
	 */
	private static function track_host( $type, $url ) {

		if ( isset( self::$blocked[ CSPInlineSources::EXTERNAL ] ) ) {

			return;

		}

		$source = self::external_source( $url, (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );

		if ( 0 === strpos( $source, 'http' ) ) {

			self::$runtime[ $type ][] = $source;

		}

	}

	/**
	 * Authorize what hook callbacks print. Tags go through the callback wrapper, so post content is never included.
	 *
	 * @return void
	 */
	public static function trace_hooks() {

		global $wp_filter;

		$tracer = [ __CLASS__, 'trace_hooks' ];

		foreach ( [ 'wp_head', 'wp_body_open', 'wp_footer', 'wp_print_footer_scripts' ] as $hook ) {

			// Shortcodes and blocks add footer callbacks while the page renders, so look again
			// when each hook starts. Bounded by the callbacks registered on four hooks.
			if ( false === has_action( $hook, $tracer ) ) {

				add_action( $hook, $tracer, PHP_INT_MIN );

			}

			foreach ( $wp_filter[ $hook ]->callbacks as $priority => $callbacks ) {

				foreach ( $callbacks as $id => $callback ) {

					$original = $callback['function'];

					if ( $original === $tracer || ( self::$traced[ $hook ][ $priority ][ $id ] ?? null ) === $original ) {

						continue;

					}

					$wrapper = static function ( ...$args ) use ( $original ) {

						ob_start();

						$result = call_user_func_array( $original, $args );

						// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Passing through what the original callback printed.
						echo self::stamp_output( (string) ob_get_clean(), $original );

						return $result;

					};

					self::$traced[ $hook ][ $priority ][ $id ] = $wrapper;

					$wp_filter[ $hook ]->callbacks[ $priority ][ $id ]['function'] = $wrapper;

				}

			}

		}

	}

	/**
	 * Decide the inline code one hook callback printed.
	 *
	 * @param string   $html Printed markup.
	 * @param callable $callback Hook callback.
	 * @return string Markup, with the response token on trusted code.
	 */
	public static function stamp_output( $html, $callback ) {

		if ( false === stripos( $html, '<script' ) && false === stripos( $html, '<style' ) ) {

			return $html;

		}

		$tags = new \WP_HTML_Tag_Processor( $html );

		while ( $tags->next_tag() ) {

			$type = self::code_type( $tags );

			if ( '' === $type || null !== $tags->get_attribute( 'nonce' ) || null !== $tags->get_attribute( self::LABEL ) ) {

				continue;

			}

			$code = $tags->get_modifiable_text();

			if ( '' === trim( $code ) ) {

				continue;

			}

			$attributes = self::decide(
				$type,
				$code,
				static function () use ( $callback ) {

					return CSPInlineSources::from_callback( $callback );

				}
			);

			foreach ( $attributes as $name => $value ) {

				$tags->set_attribute( $name, $value );

			}

		}

		return $tags->get_updated_html();

	}

	/**
	 * Classify the tag under the tokenizer.
	 *
	 * @param \WP_HTML_Tag_Processor $tags Tokenizer positioned on a tag.
	 * @return string script or style for inline code a policy governs, otherwise empty.
	 */
	private static function code_type( $tags ) {

		$tag = $tags->get_tag();

		if ( 'STYLE' === $tag ) {

			return 'style';

		}

		if ( 'SCRIPT' !== $tag || ! in_array( strtolower( (string) $tags->get_attribute( 'type' ) ), [ '', 'module', 'text/javascript', 'application/javascript', 'importmap', 'speculationrules' ], true ) ) {

			return '';

		}

		$src = $tags->get_attribute( 'src' );

		return is_string( $src ) && '' !== $src ? '' : 'script';

	}

	/**
	 * Record what a verified scan request found on the finished page.
	 *
	 * @param string $html Complete response body.
	 * @return void
	 */
	private static function capture_html( $html ) {

		$key = CSPInlineScan::request_key();

		if ( '' === $key ) {

			return;

		}

		$rows = array_filter(
			self::inspect_html( $html, self::$path, self::$nonce ),
			static function ( $row ) {

				$type = CSPInlineRules::HOST_TYPES[ $row['type'] ] ?? '';

				return '' === $type || ! in_array( $row['digest'], self::$runtime[ $type ] ?? [], true );

			}
		);

		set_transient( 'securefusion_inline_result_' . $key, array_values( $rows ), MINUTE_IN_SECONDS );

	}

	/**
	 * Reduce an external URL to the source a policy would allow.
	 *
	 * @param string $url Resource address from the page.
	 * @param string $home_host This site's host.
	 * @return string Origin or scheme, empty for this site and anything else.
	 */
	public static function external_source( $url, $home_host ) {

		$url = trim( (string) $url );

		if ( 0 === stripos( $url, 'data:' ) ) {

			return 'data:';

		}

		if ( 0 === strpos( $url, '//' ) ) {

			$url = 'https:' . $url;

		}

		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || empty( $parts['host'] ) || ! in_array( strtolower( $parts['scheme'] ?? '' ), [ 'http', 'https' ], true ) || 0 === strcasecmp( $parts['host'], (string) $home_host ) ) {

			return '';

		}

		$source = strtolower( $parts['scheme'] . '://' . $parts['host'] ) . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );

		return CSP::validate_host_source( $source ) ? $source : '';

	}

	/**
	 * Fingerprint a page with the HTML tokenizer WordPress ships.
	 *
	 * It reads script and style text as browsers do, so the hash matches what they compute.
	 *
	 * @param string $html  Response body.
	 * @param string $path  Exact public path.
	 * @param string $token Token this response printed on the code it trusts, when we produced it.
	 * @return array Items only the site owner can judge.
	 */
	public static function inspect_html( $html, $path, $token = '' ) {

		if ( strlen( $html ) > 2 * MB_IN_BYTES || false === stripos( $html, '<html' ) ) {

			return [];

		}

		$home         = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		$tags         = new \WP_HTML_Tag_Processor( $html );
		$observations = [];
		$hosts        = [];

		while ( $tags->next_tag() ) {

			if ( count( $observations ) >= CSPInlineRules::LIMIT ) {

				break;

			}

			$tag  = $tags->get_tag();
			$url  = null;
			$kind = '';

			$code = self::code_type( $tags );

			if ( '' !== $code ) {

				$row = self::observation( $code, $tags, $path, $token );

				if ( $row ) {

					$observations[] = $row;

				}

			} elseif ( 'SCRIPT' === $tag ) {

				$src = $tags->get_attribute( 'src' );

				if ( is_string( $src ) && '' !== $src ) {

					$url  = $src;
					$kind = 'host_script';

				}

			} elseif ( 'LINK' === $tag && false !== stripos( (string) $tags->get_attribute( 'rel' ), 'stylesheet' ) ) {

				$url  = $tags->get_attribute( 'href' );
				$kind = 'host_style';

			} elseif ( 'IFRAME' === $tag ) {

				$url  = $tags->get_attribute( 'src' );
				$kind = 'host_frame';

			}

			if ( ! is_string( $url ) ) {

				continue;

			}

			$source = self::external_source( $url, $home );

			// Approving data: for scripts would allow any injected script, so it is never proposed.
			if ( 'host_script' === $kind && 'data:' === $source ) {

				continue;

			}

			if ( '' !== $source && ! isset( $hosts[ $kind . $source ] ) ) {

				$hosts[ $kind . $source ] = true;
				$observations[]           = [
					'type'   => $kind,
					'digest' => $source,
					'origin' => '',
					'label'  => $source,
					'source' => CSPInlineSources::EXTERNAL,
					'path'   => $path,
				];

			}

		}

		return $observations;

	}

	/**
	 * Describe the inline element at the tokenizer's position.
	 *
	 * @param string                 $type Script or style.
	 * @param \WP_HTML_Tag_Processor $tags Tokenizer positioned on the element.
	 * @param string                 $path Exact public path.
	 * @param string                 $token Token printed on trusted code, or empty.
	 * @return array|null Null for empty elements and for code trusted where it was printed.
	 */
	private static function observation( $type, $tags, $path, $token ) {

		$code = $tags->get_modifiable_text();

		if ( '' === trim( $code ) || ( '' !== $token && $token === $tags->get_attribute( 'nonce' ) ) ) {

			return null;

		}

		$digest = CSPInlineRules::digest( $code );
		$label  = $tags->get_attribute( self::LABEL );
		$source = CSPInlineSources::UNKNOWN;

		// Only a label carrying this response's token was printed by us.
		if ( '' !== $token && is_string( $label ) && 0 === strpos( $label, $token . ':' ) ) {

			$source = substr( $label, strlen( $token ) + 1 );

		}

		$id = (string) $tags->get_attribute( 'id' );

		return [
			'type'    => $type,
			'digest'  => $digest,
			'origin'  => '',
			'label'   => sanitize_text_field( '' !== $id ? $id : $type . ' ' . substr( $digest, 0, 12 ) ),
			'source'  => $source,
			'excerpt' => wp_check_invalid_utf8( mb_substr( trim( $code ), 0, 160, 'UTF-8' ), true ),
			'path'    => $path,
		];

	}

}
