<?php
/**
 * AdminSettingsView responsibility.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

/**
 * AdminSettingsView methods.
 *
 * @mixin Admin
 * @property \WaspCreators\Wasp|null  $settings_page Settings form, set in Admin::init().
 * @property string                   $context       Settings form used: 'site' or 'network'.
 * @property bool                     $layered       Whether network defaults are active.
 * @property array<string,string[]>   $section_keys  Setting keys per section.
 * @method void render_header( string $title, string $description, array $custom_actions = [] ) Page header.
 */
trait AdminSettingsView {

	/**
	 * Get settings HTML.
	 *
	 * @return void
	 */
	public function get_settings_html() {

		$has_ssl     = is_array( get_transient( 'securefusion_ssl_cert_data' ) );
		$sub_site    = $this->layered && 'site' === $this->context;
		$customized  = $this->customized_counts();
		$total       = array_sum( $customized );
		$allowed_ssl = array(
			'a'      => array(
				'href'   => array(),
				'target' => array(),
				'rel'    => array(),
			),
			'strong' => array(),
		);

		if ( $has_ssl ) {

			$ssl_notice = esc_html__( 'Turn these on only after your site opens without warnings at https://.', 'secuplug' );

		} else {

			$ssl_notice = '<strong>' . esc_html__( 'No valid SSL certificate was found for this site, so HTTPS options cannot be turned on.', 'secuplug' ) . '</strong> ' .
				esc_html__( 'Many hosts install a free certificate for you. Free providers:', 'secuplug' ) . ' ' .
				'<a href="https://letsencrypt.org/" target="_blank" rel="noopener">Let&#8217;s Encrypt</a>, ' .
				'<a href="https://www.cloudflare.com/" target="_blank" rel="noopener">Cloudflare</a>. ' .
				esc_html__( 'Paid providers:', 'secuplug' ) . ' ' .
				'<a href="https://sectigo.com/" target="_blank" rel="noopener">Sectigo</a>, ' .
				'<a href="https://www.digicert.com/" target="_blank" rel="noopener">DigiCert</a>.';

		}

		$tabs = array(
			'xmlrpc'            => array( 'xmlrpc_settings', esc_html__( 'XML-RPC', 'secuplug' ) ),
			'login'             => array( 'login_settings', esc_html__( 'Login', 'secuplug' ) ),
			'ssl'               => array( 'ssl_settings', esc_html__( 'HTTPS', 'secuplug' ) ),
			'active_guard'      => array( 'active_guard_settings', esc_html__( 'Firewall', 'secuplug' ) ),
			'security_policies' => array( 'security_policies_settings', esc_html__( 'Content Security Policy', 'secuplug' ) ),
			'recaptcha'         => array( 'recaptcha_settings', esc_html__( 'reCAPTCHA', 'secuplug' ) ),
			'notifications'     => array( 'notification_settings', esc_html__( 'Notifications', 'secuplug' ) ),
			'advanced'          => array( 'advanced_settings', esc_html__( 'Advanced', 'secuplug' ) ),
		);

		if ( 'network' === $this->context ) {

			$tabs['network_policy'] = array( 'network_policy_settings', esc_html__( 'Network policy', 'secuplug' ) );

		}

		?>
		<div class="wrap fynd-sf-settings fsf">

			<?php
			/*
			 * WordPress injects admin_notices after the first <h1> inside .wrap.
			 * We place a screen-reader-only <h1> here so WP notices render
			 * outside our styled header component.
			 */
			?>
			<h1 class="fynd-sf-sr-only"><?php esc_html_e( 'SecureFusion settings', 'secuplug' ); ?></h1>

			<?php
			if ( 'network' === $this->context ) {

				$this->render_header(
					esc_html__( 'Network security settings', 'secuplug' ),
					esc_html__( 'Defaults for every site in the network.', 'secuplug' )
				);

			} else {

				$this->render_header(
					esc_html__( 'Security settings', 'secuplug' ),
					esc_html__( 'Choose which protections run on this site.', 'secuplug' )
				);

			}

			if ( $sub_site ) {

				?>
				<div class="fsf-context" role="note">
					<span class="fsf-context__title"><?php esc_html_e( 'This site follows the network settings.', 'secuplug' ); ?></span>
					<span class="fsf-context__text">
						<?php
						if ( $total > 0 ) {

							/* translators: %s: number of settings customized for this site. */
							echo esc_html( sprintf( _n( '%s setting is customized for this site.', '%s settings are customized for this site.', $total, 'secuplug' ), number_format_i18n( $total ) ) ) . ' ';

						}
						esc_html_e( 'Change a value to customize it for this site only. "Use network setting" brings the network value back.', 'secuplug' );
						?>
					</span>
				</div>
				<?php
			}

			if ( $this->settings_page instanceof \WaspCreators\Wasp && $this->settings_page->is_ready() ) {

				?>
				<div class="fsf-panel">
					<h2 class="nav-tab-wrapper fsf-tabs">
						<?php foreach ( $tabs as $tab_id => $tab ) : ?>
							<a href="#<?php echo esc_attr( $tab_id ); ?>" class="nav-tab">
								<?php echo esc_html( $tab[1] ); ?>
								<?php if ( ! empty( $customized[ $tab[0] ] ) ) : ?>
									<span class="fsf-tab__count" title="<?php esc_attr_e( 'Customized for this site', 'secuplug' ); ?>">
										<?php echo esc_html( number_format_i18n( $customized[ $tab[0] ] ) ); ?>
										<span class="screen-reader-text"><?php esc_html_e( 'customized for this site', 'secuplug' ); ?></span>
									</span>
								<?php endif; ?>
							</a>
						<?php endforeach; ?>
					</h2>

					<div class="content-box" data-fsf-unsaved>
						<?php $this->settings_page->form_start(); ?>
						<div class="content-tab-wrapper">
							<?php foreach ( $tabs as $tab_id => $tab ) : ?>
								<div class="tab-content hidden" id="fynd-sf-<?php echo esc_attr( $tab_id ); ?>">
									<?php SettingsExperience::summary( $tab_id ); ?>
									<?php $this->settings_page->run_section( $tab[0] ); ?>
									<?php
									if ( 'security_policies' === $tab_id ) {

										CSPInlineAdmin::render( 'network' === $this->context );

									}
									?>
									<?php if ( 'notifications' !== $tab_id ) : ?>
									<details class="fsf-settings-advanced">
									<summary><?php esc_html_e( 'Advanced settings', 'secuplug' ); ?></summary>
									<p><?php esc_html_e( 'Opening this panel does not change your settings. Adjust only what this site needs.', 'secuplug' ); ?></p>
									<label><?php esc_html_e( 'Find a setting', 'secuplug' ); ?><input type="search" class="fsf-settings-search"></label>
										<?php if ( 'security_policies' === $tab_id ) : ?>
									<p class="fsf-field-warning"><span class="fsf-field-warning__label"><?php esc_html_e( 'These settings can block parts of your pages.', 'secuplug' ); ?></span> <?php esc_html_e( 'Each one is marked. Use Test before you enforce a change.', 'secuplug' ); ?></p>
									<?php endif; ?>
										<?php $this->settings_page->run_section( $tab[0] . '_advanced' ); ?>
										<?php
										if ( 'security_policies' === $tab_id ) {

											$this->settings_page->run_section( $tab[0] . '_services' );
											$this->settings_page->run_section( $tab[0] . '_limits' );

										}
										?>

									</details>
									<?php endif; ?>
									<?php if ( 'ssl' === $tab_id ) : ?>
										<div class="<?php echo esc_attr( $has_ssl ? 'fynd-sf-tab-notice' : 'fynd-sf-tab-notice fynd-sf-tab-notice-error' ); ?>">
											<p><?php echo wp_kses( $ssl_notice, $allowed_ssl ); ?></p>
										</div>
									<?php elseif ( 'advanced' === $tab_id ) : ?>
										<div class="fynd-sf-tab-notice fynd-sf-tab-notice-error">
											<p><?php esc_html_e( 'Wrong patterns can block normal visitors or let attacks through. Change them only if you know regular expressions.', 'secuplug' ); ?></p>
										</div>
									<?php endif; ?>
								</div>
							<?php endforeach; ?>
						</div>

						<div class="fsf-foot">
							<button type="submit" name="submit" id="submit" class="fsf-btn fsf-btn--primary"><?php esc_html_e( 'Save settings', 'secuplug' ); ?></button>
							<span class="fsf-foot__hint">
								<?php
								if ( $sub_site ) {

									esc_html_e( 'Saves every tab. Settings that follow the network are not stored for this site.', 'secuplug' );

								} else {

									esc_html_e( 'Saves every tab.', 'secuplug' );

								}
								?>
							</span>
						</div>
						</form>
					</div>
				</div>
				<?php
			}
			?>
		</div>
		<?php
	}


	/**
	 * Number of settings this site customizes, per settings section.
	 *
	 * Only meaningful on a sub-site of a network; empty otherwise. Bounded by the
	 * number of settings (a few dozen keys).
	 *
	 * @return array<string,int> Section name => count.
	 */
	protected function customized_counts() {

		$counts = array();

		if ( ! $this->layered || 'site' !== $this->context ) {

			return $counts;

		}

		$own = array_diff( array_keys( Settings::site_values() ), Settings::NETWORK_ONLY );

		foreach ( $this->section_keys as $section => $keys ) {

			$counts[ $section ] = count( array_intersect( $keys, $own ) );

		}

		return $counts;

	}


	/**
	 * Network-only settings section.
	 *
	 * @return array
	 */
	protected function get_network_policy_section() {

		return [
			'name'  => 'network_policy_settings',
			'title' => esc_html__( 'Network policy', 'secuplug' ),
			'desc'  => esc_html__( 'Settings on this page are the defaults for every site in the network.', 'secuplug' ),
			'items' => [
				[
					'type'    => 'radio',
					'name'    => Settings::POLICY_SITE_ADMINS,
					'label'   => esc_html__( 'Site administrators can customize their site', 'secuplug' ),
					'options' => [
						[
							'value' => '0',
							'label' => esc_html__( 'No', 'secuplug' ),
						],
						[
							'value' => '1',
							'label' => esc_html__( 'Yes', 'secuplug' ),
						],
					],
					'after'   => '<span class="description">' . esc_html__( 'When off, only network administrators can change settings for a single site. Brute-force limits are always set here, for all sites.', 'secuplug' ) . '</span>',
				],
			],
		];

	}

}
