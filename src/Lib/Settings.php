<?php
/**
 * Settings Class
 *
 * Single source of truth for SecureFusion settings.
 *
 * Single site (or multisite with per-site activation): settings live in the
 * `securefusion_settings` option, exactly as before.
 *
 * Multisite with network activation: values are resolved in layers
 *   1. factory defaults
 *   2. network settings   (`securefusion_network_settings` site option)
 *   3. site overrides     (`securefusion_settings` option, only the keys a site changed)
 * Network-only keys always come from the network layer.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit; // Exit if accessed directly.

}

/**
 * Layered settings resolver.
 */
class Settings {

	/**
	 * Per-site option: all settings (single site) or overrides (network mode).
	 *
	 * @var string
	 */
	const SITE_OPTION = 'securefusion_settings';

	/**
	 * Network option holding the network defaults.
	 *
	 * @var string
	 */
	const NETWORK_OPTION = 'securefusion_network_settings';

	/**
	 * Per-site flag set once the site option has been converted to overrides.
	 *
	 * @var string
	 */
	const LAYER_FLAG = 'securefusion_settings_layer';

	/**
	 * Per-site backup of the settings as they were before the conversion.
	 *
	 * @var string
	 */
	const BACKUP_OPTION = 'securefusion_settings_backup_premultisite';

	/**
	 * Network policy key: '1' lets sub-site administrators customize their site.
	 *
	 * @var string
	 */
	const POLICY_SITE_ADMINS = 'allow_site_admins';

	/**
	 * Keys that only the network can set. Brute-force thresholds protect every
	 * site of the network, so a single sub-site must not weaken them.
	 *
	 * @var string[]
	 */
	const NETWORK_ONLY = [
		'ip_time_limit',
		'ip_login_limit',
		'ip_attempt_window',
		'cleanup_ip_days',
		'cleanup_ip_attempts',
		self::POLICY_SITE_ADMINS,
	];

	/**
	 * Factory defaults.
	 *
	 * @var array
	 */
	protected static $defaults = [];

	/**
	 * Resolved settings, keyed by blog ID.
	 *
	 * @var array
	 */
	protected static $cache = [];

	/**
	 * Cached network mode.
	 *
	 * @var bool|null
	 */
	protected static $network_mode = null;

	/**
	 * Whether hooks are registered.
	 *
	 * @var bool
	 */
	protected static $booted = false;



	/**
	 * Registers factory defaults and cache invalidation hooks.
	 *
	 * @param array $defaults Factory defaults.
	 * @return void
	 */
	public static function boot( array $defaults ) {

		self::$defaults = $defaults;

		if ( self::$booted || ! function_exists( 'add_action' ) ) {

			return;

		}

		self::$booted = true;

		foreach ( [ 'add_option_', 'update_option_', 'delete_option_' ] as $prefix ) {

			add_action( $prefix . self::SITE_OPTION, [ __CLASS__, 'flush' ] );

		}

		foreach ( [ 'add_site_option_', 'update_site_option_', 'delete_site_option_' ] as $prefix ) {

			add_action( $prefix . self::NETWORK_OPTION, [ __CLASS__, 'flush' ] );

		}

		add_action( 'activated_plugin', [ __CLASS__, 'reset_mode' ] );
		add_action( 'deactivated_plugin', [ __CLASS__, 'reset_mode' ] );

	}



	/**
	 * Returns the factory defaults.
	 *
	 * @return array
	 */
	public static function defaults() {

		return self::$defaults;

	}



	/**
	 * Whether the plugin runs in layered (network) mode.
	 *
	 * @return bool
	 */
	public static function is_network_mode() {

		if ( null !== self::$network_mode ) {

			return self::$network_mode;

		}

		$mode = false;

		if ( function_exists( 'is_multisite' ) && is_multisite() && defined( 'SECUREFUSION_BASENAME' ) ) {

			$sitewide = get_site_option( 'active_sitewide_plugins', [] );
			$mode     = is_array( $sitewide ) && isset( $sitewide[ SECUREFUSION_BASENAME ] );

		}

		/**
		 * Filters whether SecureFusion uses network defaults with per-site overrides.
		 *
		 * @param bool $mode True when the plugin is network-activated on multisite.
		 */
		self::$network_mode = (bool) apply_filters( 'securefusion_network_mode', $mode );

		return self::$network_mode;

	}



	/**
	 * Forces the network mode (used during network activation, before WordPress
	 * records the plugin as network-active).
	 *
	 * @param bool|null $mode Mode, or null to detect again.
	 * @return void
	 */
	public static function set_network_mode( $mode ) {

		self::$network_mode = ( null === $mode ) ? null : (bool) $mode;
		self::$cache        = [];

	}



	/**
	 * Drops the cached mode and values.
	 *
	 * @return void
	 */
	public static function reset_mode() {

		self::set_network_mode( null );

	}



	/**
	 * Changes some of the current site's stored values outside the settings form.
	 *
	 * The caller validates the values and ends the request afterwards: the form's sanitizer expects
	 * a whole submitted form, so it is taken off this option for the rest of the request.
	 *
	 * @param array $changes Values by setting name.
	 * @return void
	 */
	public static function update_site( array $changes ) {

		$values = get_option( self::SITE_OPTION, [] );

		remove_all_filters( 'sanitize_option_' . self::SITE_OPTION );
		update_option( self::SITE_OPTION, array_merge( is_array( $values ) ? $values : [], $changes ) );

		self::flush();

	}



	/**
	 * Clears resolved values.
	 *
	 * @return void
	 */
	public static function flush() {

		self::$cache = [];

	}



	/**
	 * Returns the stored network values.
	 *
	 * @return array
	 */
	public static function network_values() {

		$values = get_site_option( self::NETWORK_OPTION, [] );

		return CSPPolicy::upgrade_values( is_array( $values ) ? $values : [] );

	}



	/**
	 * Returns the values a site inherits: defaults merged with network values.
	 *
	 * @return array
	 */
	public static function inherited_values() {

		return array_merge( self::$defaults, self::network_values() );

	}



	/**
	 * Returns the current site's own stored values.
	 *
	 * @return array
	 */
	public static function site_values() {

		$values = get_option( self::SITE_OPTION, [] );

		return CSPPolicy::upgrade_values( is_array( $values ) ? $values : [] );

	}



	/**
	 * Returns all resolved settings for the current site.
	 *
	 * @return array
	 */
	public static function all() {

		$blog_id = function_exists( 'get_current_blog_id' ) ? get_current_blog_id() : 0;

		if ( isset( self::$cache[ $blog_id ] ) ) {

			return self::$cache[ $blog_id ];

		}

		if ( self::is_network_mode() ) {

			$overrides = array_diff_key( self::site_values(), array_flip( self::NETWORK_ONLY ) );
			$resolved  = array_merge( self::inherited_values(), $overrides );

		} else {

			$resolved = array_merge( self::$defaults, self::site_values() );

		}

		self::$cache[ $blog_id ] = $resolved;

		return $resolved;

	}



	/**
	 * Returns one resolved setting.
	 *
	 * @param string $name Setting name.
	 * @return mixed|null
	 */
	public static function get( $name ) {

		$all = self::all();

		return array_key_exists( $name, $all ) ? $all[ $name ] : null;

	}



	/**
	 * Whether sub-site administrators may customize their own site.
	 *
	 * @return bool
	 */
	public static function site_admins_can_customize() {

		$network = self::network_values();

		return isset( $network[ self::POLICY_SITE_ADMINS ] ) && '1' === (string) $network[ self::POLICY_SITE_ADMINS ];

	}



	/**
	 * Capability required to change a site's settings.
	 *
	 * @return string
	 */
	public static function site_capability() {

		if ( self::is_network_mode() && ! self::site_admins_can_customize() ) {

			return 'manage_network_options';

		}

		return 'manage_options';

	}



	/**
	 * Creates the network option from the main site's settings, once.
	 *
	 * @return array The network values.
	 */
	public static function maybe_seed_network() {

		$existing = get_site_option( self::NETWORK_OPTION, false );

		if ( is_array( $existing ) ) {

			return $existing;

		}

		$main_id = function_exists( 'get_main_site_id' ) ? (int) get_main_site_id() : 1;
		$source  = ( get_current_blog_id() === $main_id )
			? get_option( self::SITE_OPTION, [] )
			: get_blog_option( $main_id, self::SITE_OPTION, [] );

		$values = array_merge( self::$defaults, is_array( $source ) ? $source : [] );

		// A new network starts with sub-site customization limited to super admins.
		if ( ! isset( $values[ self::POLICY_SITE_ADMINS ] ) ) {

			$values[ self::POLICY_SITE_ADMINS ] = '0';

		}

		add_site_option( self::NETWORK_OPTION, $values );

		self::flush();

		return $values;

	}



	/**
	 * Converts the current site's stored settings into overrides, once per site.
	 *
	 * Before network mode, every site stored a full copy of all settings (with
	 * defaults merged in). Keeping that copy would make every key an override and
	 * the network settings would never apply. A key stays an override only if the
	 * site changed it from the factory default and it differs from the network
	 * value. The main site's values become the network values, so it keeps no
	 * overrides. The original copy is kept in a non-autoloaded backup option.
	 *
	 * Cost: one autoloaded option read per request after the conversion.
	 *
	 * @return void
	 */
	public static function maybe_migrate_site() {

		if ( ! self::is_network_mode() || '1' === get_option( self::LAYER_FLAG ) ) {

			return;

		}

		$network = array_merge( self::$defaults, self::maybe_seed_network() );
		$own     = self::site_values();

		if ( ! empty( $own ) && false === get_option( self::BACKUP_OPTION, false ) ) {

			add_option( self::BACKUP_OPTION, $own, '', false );

		}

		$overrides = [];
		$main_id   = function_exists( 'get_main_site_id' ) ? (int) get_main_site_id() : 1;

		if ( get_current_blog_id() !== $main_id ) {

			foreach ( $own as $key => $value ) {

				if ( in_array( $key, self::NETWORK_ONLY, true ) ) {

					continue;

				}

				$default = array_key_exists( $key, self::$defaults ) ? self::$defaults[ $key ] : null;

				if ( self::same_value( $value, $default ) || ( array_key_exists( $key, $network ) && self::same_value( $value, $network[ $key ] ) ) ) {

					continue;

				}

				$overrides[ $key ] = $value;

			}

		}

		update_option( self::SITE_OPTION, $overrides );
		update_option( self::LAYER_FLAG, '1' );

		self::flush();

	}



	/**
	 * Compares two stored values the way the settings form saves them (strings).
	 *
	 * @param mixed $a First value.
	 * @param mixed $b Second value.
	 * @return bool
	 */
	public static function same_value( $a, $b ) {

		if ( ( is_scalar( $a ) || null === $a ) && ( is_scalar( $b ) || null === $b ) ) {

			return (string) $a === (string) $b;

		}

		// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- Arrays of strings saved by the form.
		return $a == $b;

	}

}
