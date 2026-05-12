<?php

/**
 * Login Class
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

class Login {
	use WPCommon;



	public function __construct()
	{
		$admin_id = $this->get_settings('change_admin_id');

		if ($admin_id > 1) {
			add_action('plugins_loaded', [$this, 'change_admin_id']);
		}
	}



	public function change_admin_id()
	{
		global $wpdb;

		$admin_id	= get_current_user_id();
		$new_id		= $this->get_settings('change_admin_id');

		if (! \current_user_can('manage_options') || $admin_id < 1) {
			return;
		}

		if ($admin_id == $new_id || $new_id < 1) {
			return;
		}

		$user = get_userdata($admin_id);

		if (in_array('administrator', $user->roles, true)) {
			$wpdb->update($wpdb->users, ['ID' => $new_id], ['ID' => $admin_id]);
			$wpdb->update($wpdb->usermeta, ['user_id' => $new_id], ['user_id' => $admin_id]);
			$wpdb->update($wpdb->posts, ['post_author' => $new_id], ['post_author' => $admin_id]);
			$wpdb->update($wpdb->comments, ['user_id' => $new_id], ['user_id' => $admin_id]);

			wp_set_current_user($new_id, $user->user_login);
			wp_set_auth_cookie($new_id);
			do_action('wp_login', $user->user_login);
		}
	}



	function hide_wp_login()
	{
		global $pagenow;

		if ($pagenow === 'admin-ajax.php') {
			return false;
		}

		if ($this->is_login_page() || is_admin()) {

			if (is_user_logged_in()) {
				return false;
			}
			return true;
		}

		return false;
	}



	function redirect_to_login_page()
	{
		if (! SECUREFUSION_HIDE_LOGIN_DISABLE) {
			if ($this->hide_wp_login()) {
				if (isset($_GET['loggedout']) && $_GET['loggedout'] === 'true') {
					wp_redirect(home_url(), 302);
					exit;
				}

				wp_die('No access!');
			}

			// if url is equal to new login page
			if ($this->is_login_page(false)) {
				global $error, $pagenow, $interim_login;
				require_once(ABSPATH . 'wp-login.php');
				exit;
			}
		}
	}



	function custom_login_url($login_url, $redirect, $force_reauth)
	{
		$custom_link = $this->get_new_login_url();

		if ($this->hide_wp_login()) {
			return $login_url;
		}

		if (! empty($custom_link)) {
			$login_url = site_url($custom_link, 'https');
		}

		if (! empty($redirect)) {
			$login_url = add_query_arg('redirect_to', urlencode( $redirect ), $login_url);
		}

		if ($force_reauth) {
			$login_url = add_query_arg('reauth', '1', $login_url);
		}

		return $login_url;
	}



	function custom_login_url_replace( $text )
	{
		$custom_link	= $this->get_new_login_url();
		$text			= str_replace('wp-login.php', $custom_link, $text);

		return $text;
	}



	function custom_login_url_action($classes, $action)
	{
		$action = $this->custom_login_url_replace($action);

		return array($classes, $action);
	}



	function custom_login_url_script()
	{
		wp_register_script('securefusion-replace-submit', plugin_dir_url(SECUREFUSION_BASENAME) . 'assets/js/login.js', array('jquery'), '1.1', true);
		wp_enqueue_script('securefusion-replace-submit');
		wp_add_inline_script(
			'securefusion-replace-submit',
			"let new_url = '" . esc_attr($this->get_settings('custom_login_url')) . "';",
			'before'
		);

	}



	function init()
	{
		if (! empty($this->get_new_login_url())) {
			$this->change_login_url();
		}

		add_filter('login_errors', [$this, 'my_show_login_error'], 10, 1);
	}



	function my_show_login_error($param)
	{
		$login_err_msg = $this->get_settings( 'change_login_error' );

		if (empty($login_err_msg) || empty($_REQUEST['log']) || empty($_REQUEST['pwd'])) {
			return $param;
		} else {
			return '<strong>ERROR:</strong> ' . $login_err_msg;
		}

		return false;
	}



	function change_login_url()
	{
		add_action('login_enqueue_scripts', [$this, 'custom_login_url_script'], 10);
		add_action('wp_loaded', [$this, 'redirect_to_login_page']);

		add_filter('login_url', [$this, 'custom_login_url'], 10, 3);
		add_filter('logout_url', [$this, 'custom_login_url_replace'], 10, 3);
		add_filter('register_url', [$this, 'custom_login_url_replace'], 10, 3);
		add_filter('lostpassword_url', [$this, 'custom_login_url_replace'], 10, 3);
	}
}
