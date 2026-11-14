<?php
/**
 * Site-scoped inline code inventory and explicit authorization rules.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * Keep observations separate from administrator approval.
 */
class CSPInlineRules {

	const OPTION = 'securefusion_inline_rules';
	const LIMIT  = 200;

	/**
	 * Sources excluded from automatic trust. Everything installed is trusted unless listed here.
	 */
	const BLOCK_OPTION = 'securefusion_inline_blocked_sources';

	/**
	 * External host record types and the directive each one extends.
	 */
	const HOST_TYPES = [
		'host_script' => 'script',
		'host_style'  => 'style',
		'host_frame'  => 'frame',
	];

	/**
	 * Most exact paths one record keeps; code seen on more pages is proposed for every page.
	 */
	const PATH_LIMIT = 10;

	/**
	 * Longest inline text the owner can approve from a notification.
	 */
	const MAX_CODE = 65536;

	/**
	 * Bytes a needle may hold: printable ASCII and tab. The tokenizer changes none of them.
	 */
	const NEEDLE_BYTES = "\t" . ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';

	/**
	 * Shortest needle worth storing; shorter code is always looked up with the tokenizer.
	 */
	const NEEDLE_MIN = 16;

	/**
	 * Longest needle stored, to keep the inventory small.
	 */
	const NEEDLE_MAX = 32;

	/**
	 * Most characters of the code a record shows the owner.
	 */
	const EXCERPT = 160;

	/**
	 * Read the bounded inventory.
	 *
	 * @return array
	 */
	public static function all() {

		$rows = get_option( self::OPTION, [] );

		return is_array( $rows ) ? array_slice( $rows, 0, self::LIMIT, true ) : [];

	}

	/**
	 * Hosts the owner approved in the review, by the source type each one extends.
	 *
	 * @return array<string,string[]>
	 */
	public static function approved_hosts() {

		$result = [];

		foreach ( self::all() as $row ) {

			$type = self::HOST_TYPES[ $row['type'] ?? '' ] ?? '';

			if ( '' !== $type && ! empty( $row['approved'] ) && is_string( $row['digest'] ?? null ) ) {

				$result[ $type ][] = $row['digest'];

			}

		}

		return $result;

	}

	/**
	 * Hash the exact browser-visible text, including whitespace.
	 *
	 * @param string $code Inline text.
	 * @return string
	 */
	public static function digest( $code ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- CSP requires base64-encoded SHA-256 digests.
		return base64_encode( hash( 'sha256', str_replace( [ "\r\n", "\r" ], "\n", $code ), true ) );

	}

	/**
	 * A short piece of the code that any page holding it as inline text contains byte for byte.
	 *
	 * The tokenizer changes inline text before it is hashed in only three ways: line breaks become
	 * "\n", NUL becomes U+FFFD, and a leading line break may be dropped. Every other byte comes from
	 * the page unchanged and in order. The needle is cut from the text digest() hashes and holds only
	 * printable ASCII and tabs, none of which those changes produce, so a page whose text has this
	 * digest holds the needle verbatim: a page without it cannot hold the code inline. Code moved
	 * into a data: address is encoded and is checked separately.
	 *
	 * @param string $code Inline text.
	 * @return string Needle, or empty when the code has no run of NEEDLE_MIN such bytes.
	 */
	public static function needle( $code ) {

		$text   = str_replace( [ "\r\n", "\r" ], "\n", (string) $code );
		$length = strlen( $text );
		$start  = 0;
		$best   = 0;

		// Bounded by the text length: every step passes one run and the byte that ends it.
		for ( $at = 0; $at < $length; ) {

			$run = strspn( $text, self::NEEDLE_BYTES, $at );

			if ( $run > $best ) {

				$start = $at;
				$best  = $run;

			}

			$at += $run + 1;

		}

		// Indentation and padding say little about the code; the rest of the run stays contiguous.
		$run = trim( substr( $text, $start, $best ), " \t" );

		if ( strlen( $run ) < self::NEEDLE_MIN ) {

			return '';

		}

		return substr( $run, intdiv( max( 0, strlen( $run ) - self::NEEDLE_MAX ), 2 ), self::NEEDLE_MAX );

	}

	/**
	 * The start of the code as valid UTF-8 text the owner can read, for any byte sequence.
	 *
	 * Inline code may hold invalid UTF-8. wp_check_invalid_utf8() strips it with iconv() on older
	 * WordPress, which raises a notice on such bytes, so the text is repaired here without any call
	 * that can raise. Invalid sequences are scrubbed before cutting because mb_substr() treats them
	 * differently across PHP versions. Without mbstring, invalid text keeps only its ASCII bytes.
	 *
	 * @param string $code Inline text.
	 * @return string Trimmed valid UTF-8 of at most EXCERPT characters.
	 */
	public static function excerpt( $code ) {

		// A character takes at most four bytes, so this prefix holds the first EXCERPT characters.
		$text = substr( trim( (string) $code ), 0, self::EXCERPT * 4 );

		if ( '' === $text ) {

			return '';

		}

		if ( function_exists( 'mb_scrub' ) && function_exists( 'mb_substr' ) ) {

			return (string) mb_substr( (string) mb_scrub( $text, 'UTF-8' ), 0, self::EXCERPT, 'UTF-8' );

		}

		if ( 1 !== preg_match( '//u', $text ) ) {

			return substr( (string) preg_replace( '/[\x80-\xFF]+/', '', $text ), 0, self::EXCERPT );

		}

		return 1 === preg_match( '/^.{0,' . self::EXCERPT . '}/su', $text, $match ) ? $match[0] : '';

	}

	/**
	 * Fields that give a record the needle of its own code, when it lacks one.
	 *
	 * @param array|null $row    Stored record, or null for a new one.
	 * @param string     $digest Digest of the code the needle was cut from.
	 * @param string     $needle Needle from needle(), or empty.
	 * @return array<string,string>
	 */
	private static function with_needle( $row, $digest, $needle ) {

		if ( '' === $needle || ( null !== $row && ( isset( $row['needle'] ) || ( $row['digest'] ?? '' ) !== $digest ) ) ) {

			return [];

		}

		return [ 'needle' => $needle ];

	}

	/**
	 * The needle a record stores, when it can be relied on.
	 *
	 * @param array $row Inventory record.
	 * @return string Needle, or empty for records without one (older or added by digest).
	 */
	public static function needle_of( $row ) {

		$needle = $row['needle'] ?? '';

		if ( ! is_string( $needle ) || strlen( $needle ) < self::NEEDLE_MIN || strlen( $needle ) !== strspn( $needle, self::NEEDLE_BYTES ) ) {

			return '';

		}

		return $needle;

	}

	/**
	 * Identify a record: registered output by its producer, everything else by its content.
	 *
	 * @param string $type Record type.
	 * @param string $digest Content digest, or host for host records.
	 * @param string $origin Registered producer identity, or empty.
	 * @return string
	 */
	public static function key( $type, $digest, $origin ) {

		return hash( 'sha256', $type . ':' . ( '' !== (string) $origin ? $origin : $digest ) );

	}

	/**
	 * Read the sources excluded from automatic trust.
	 *
	 * @return array<string,bool>
	 */
	public static function blocked() {

		$value = get_option( self::BLOCK_OPTION, [] );

		return is_array( $value ) ? $value : [];

	}

	/**
	 * Exclude a source from automatic trust, or restore it.
	 *
	 * @param string $source Source key.
	 * @param bool   $blocked New state.
	 * @return void
	 */
	public static function set_blocked( $source, $blocked ) {

		$value = self::blocked();

		if ( $blocked ) {

			$value[ $source ] = true;

		} else {

			unset( $value[ $source ] );

		}

		update_option( self::BLOCK_OPTION, $value, false );

	}

	/**
	 * Read a record's path scope; a new observation holds only the single path it was seen on.
	 *
	 * @param array $row Inventory record.
	 * @return string[] Exact paths, or a single '*'.
	 */
	public static function paths( $row ) {

		if ( ! empty( $row['paths'] ) && is_array( $row['paths'] ) ) {

			return array_values( $row['paths'] );

		}

		return isset( $row['path'] ) && '' !== $row['path'] ? [ $row['path'] ] : [];

	}

	/**
	 * Whether an approved exact-text record applies on a path.
	 *
	 * @param array  $row Inventory record.
	 * @param string $path Request path without query parameters.
	 * @return bool
	 */
	public static function allows( $row, $path ) {

		if ( empty( $row['approved'] ) || ! empty( $row['origin'] ) || ! in_array( $row['type'] ?? '', [ 'script', 'style' ], true ) ) {

			return false;

		}

		$paths = self::paths( $row );

		return in_array( '*', $paths, true ) || in_array( $path, $paths, true );

	}

	/**
	 * Approve or revoke every record of one source, or of all sources with "*".
	 *
	 * @param string $source Source key or "*".
	 * @param bool   $approved New state.
	 * @return bool Whether the inventory was updated.
	 */
	public static function bulk( $source, $approved ) {

		return self::update(
			static function ( $rows ) use ( $source, $approved ) {

				foreach ( $rows as $id => $row ) {

					$key = $row['source'] ?? CSPInlineSources::UNKNOWN;

					if ( '*' !== $source && $key !== $source ) {

						continue;

					}

					$rows[ $id ] = self::with_approval( $row, $approved );

					unset( $rows[ $id ]['revoked'] );

				}

				return $rows;

			}
		);

	}

	/**
	 * Apply an approval decision. An approved record covers every page unless the owner edited its scope.
	 *
	 * @param array $row Inventory record.
	 * @param bool  $approved New state.
	 * @return array
	 */
	public static function with_approval( $row, $approved ) {

		$row['approved'] = $approved;

		if ( $approved && empty( $row['scoped'] ) ) {

			$row['paths'] = [ '*' ];
			$row['path']  = '*';

		}

		return $row;

	}

	/**
	 * Approve exact inline text for every page, because the owner asked for it.
	 *
	 * Only called for an explicit request, so it also takes back an earlier revocation.
	 *
	 * @param string $type Record type: script or style.
	 * @param string $code Inline text as the browser received it.
	 * @return bool Whether the text is now approved.
	 */
	public static function approve_code( $type, $code ) {

		if ( ! in_array( $type, [ 'script', 'style' ], true ) || '' === trim( $code ) || strlen( $code ) > self::MAX_CODE ) {

			return false;

		}

		$digest   = self::digest( $code );
		$id       = self::key( $type, $digest, '' );
		$needle   = self::needle( $code );
		$approved = false;

		$saved = self::update(
			static function ( $rows ) use ( $id, $type, $digest, $code, $needle, &$approved ) {

				$row = $rows[ $id ] ?? null;

				if ( null === $row && count( $rows ) >= self::LIMIT ) {

					return $rows;

				}

				$row = array_merge(
					$row ?? [
						'type'    => $type,
						'digest'  => $digest,
						'origin'  => '',
						'label'   => $type . ' ' . substr( $digest, 0, 12 ),
						'source'  => CSPInlineSources::UNKNOWN,
						'excerpt' => self::excerpt( $code ),
						'path'    => '*',
					],
					[ 'last_seen' => time() ],
					self::with_needle( $row, $digest, $needle )
				);

				unset( $row['revoked'] );

				$rows[ $id ] = self::with_approval( $row, true );
				$approved    = true;

				return $rows;

			}
		);

		return $saved && $approved;

	}

	/**
	 * Forget pending records a completed scan no longer found.
	 *
	 * @param int $since Scan start time.
	 * @return bool Whether the inventory was updated.
	 */
	public static function prune( $since ) {

		return self::update(
			static function ( $rows ) use ( $since ) {

				return array_filter(
					$rows,
					static function ( $row ) use ( $since ) {

						return ! empty( $row['approved'] ) || (int) ( $row['last_seen'] ?? 0 ) >= $since;

					}
				);

			}
		);

	}

	/**
	 * Persist a mutation against the latest inventory, under an atomic lease.
	 *
	 * @param callable $callback Receives the latest rows and returns the new rows.
	 * @return bool Whether the mutation acquired the lease.
	 */
	public static function update( $callback ) {

		return CSPInlineLock::run(
			'rules',
			static function () use ( $callback ) {

				wp_cache_delete( self::OPTION, 'options' );

				$rows = $callback( self::all() );

				if ( ! is_array( $rows ) ) {

					return false;

				}

				update_option( self::OPTION, $rows, false );

				return true;

			}
		);

	}

	/**
	 * Add one observed page to a pending record's scope.
	 *
	 * @param array  $row  Pending inventory record.
	 * @param string $path Page where the code was seen.
	 * @return array
	 */
	private static function with_observed_path( $row, $path ) {

		$paths = self::paths( $row );

		if ( in_array( '*', $paths, true ) || in_array( $path, $paths, true ) ) {

			return $row;

		}

		$paths[]      = $path;
		$row['paths'] = count( $paths ) > self::PATH_LIMIT ? [ '*' ] : $paths;
		$row['path']  = $row['paths'][0];

		return $row;

	}

	/**
	 * Add pending observations, preserving approvals and scopes the administrator saved.
	 *
	 * Discovery widens only pending records nobody has edited, and never approves one.
	 *
	 * @param array $observations Captured records.
	 * @return bool Whether the inventory was updated.
	 */
	public static function observe( $observations ) {

		return self::update(
			static function ( $rows ) use ( $observations ) {

				foreach ( $observations as $row ) {

					$id = self::key( $row['type'], $row['digest'], $row['origin'] );

					if ( isset( $rows[ $id ] ) ) {

						$rows[ $id ]              = array_merge( $rows[ $id ], self::with_needle( $rows[ $id ], $row['digest'], self::needle_of( $row ) ) );
						$rows[ $id ]['last_seen'] = time();
						$rows[ $id ]['source']    = $row['source'] ?? ( $rows[ $id ]['source'] ?? CSPInlineSources::UNKNOWN );

						if ( empty( $rows[ $id ]['approved'] ) && empty( $rows[ $id ]['scoped'] ) ) {

							$rows[ $id ] = self::with_observed_path( $rows[ $id ], $row['path'] );

						}

					} elseif ( count( $rows ) < self::LIMIT ) {

						$rows[ $id ] = array_merge(
							$row,
							[
								'approved'  => false,
								'source'    => $row['source'] ?? CSPInlineSources::UNKNOWN,
								'last_seen' => time(),
							]
						);

					}

				}

				return $rows;

			}
		);

	}

}
