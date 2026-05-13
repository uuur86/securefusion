<?php

/**
 * Middleware Class
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

class Middleware
{

    use WPCommon;



    function init()
    {
        global $wp;

        if (!function_exists('wp_get_current_user')) {
            include(ABSPATH . '/wp-includes/pluggable.php');
        }

        if (\current_user_can('manage_options')) {
            return;
        }

        if ($this->get_settings('filter_bad_requests')) {
            $this->filter_bad_requests();
        }

        if ($this->get_settings('disable_rest_api')) {
            $service_regex = 'users';
            $controlling = \preg_match('#(^\/?wp\-json\/wp\/v[12]\/?$|^\/?wp\-json\/wp\/v[12]\/?(' . $service_regex . ')\/?.*$)#siu', esc_url($_SERVER["REQUEST_URI"]));

            if ($controlling) {
                if (version_compare(get_bloginfo('version'), '4.7', '>=')) {
                    add_filter('rest_authentication_errors', [$this, 'disable_rest_api']);
                } else {
                    $this->disable_rest_api_manually();
                }
            }
        }
    }



    public function headers()
    {
        // Do not apply security headers in the admin area to avoid conflicts with plugins.
        if (is_admin()) {
            return;
        }

        $hide_versions = $this->get_settings('hide_versions');
        $bad_bots = $this->get_settings('bad_bots');
        $http_headers = $this->get_settings('http_headers');

        // CSP
        $csp_allowed_style_sources = $this->get_settings('csp_allowed_style_sources');
        $csp_allowed_style_sources = str_replace(array("\r\n", "\n"), ' ', $csp_allowed_style_sources);
        $csp_allowed_script_sources = $this->get_settings('csp_allowed_script_sources');
        $csp_allowed_script_sources = str_replace(array("\r\n", "\n"), ' ', $csp_allowed_script_sources);
        $csp_allowed_font_sources = $this->get_settings('csp_allowed_font_sources');
        $csp_allowed_font_sources = str_replace(array("\r\n", "\n"), ' ', $csp_allowed_font_sources);
        $csp_allowed_frame_sources = $this->get_settings('csp_allowed_frame_sources');
        $csp_allowed_frame_sources = str_replace(array("\r\n", "\n"), ' ', $csp_allowed_frame_sources);
        $csp_allowed_worker_sources = $this->get_settings('csp_allowed_worker_sources');
        $csp_allowed_worker_sources = str_replace(array("\r\n", "\n"), ' ', $csp_allowed_worker_sources);
        $csp_allowed_img_sources = $this->get_settings('csp_allowed_img_sources');
        $csp_allowed_img_sources = str_replace(array("\r\n", "\n"), ' ', $csp_allowed_img_sources);

        if ($bad_bots) {
            $bad_bots = get_option('bad_bots_list', '^libwww-perl.*');
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

            if (preg_match("/{$bad_bots}/i", $user_agent)) {
                status_header(403);
                exit('Access Denied');
            }
        }

        if ($hide_versions) {
            header('Server: ');
            header_remove('X-Powered-By');
        }

        if ($http_headers) {
            // Cross-Origin Opener Policy (COOP)
            header('Cross-Origin-Opener-Policy: same-origin');

            // Clickjacking Mitigation & Other Headers
            header('X-Frame-Options: SAMEORIGIN');
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: no-referrer-when-downgrade');
            header('X-XSS-Protection: 1; mode=block');
            header('Strict-Transport-Security: max-age=31536000');
            header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

            /** 
             * Content Security Policy (CSP) 
             * Helps prevent Cross-Site Scripting (XSS) and data injection attacks.
             * This policy is more specific to reduce risks highlighted by security scanners.
             */
            $csp_policy = "default-src 'self'; ";
            $csp_policy .= "frame-src 'self' " . $csp_allowed_frame_sources . "; ";
            $csp_policy .= "worker-src 'self' " . $csp_allowed_worker_sources . "; ";
            $csp_policy .= "script-src 'self' " . $csp_allowed_script_sources . "; ";
            $csp_policy .= "style-src 'self' " . $csp_allowed_style_sources . "; ";
            $csp_policy .= "img-src 'self' " . $csp_allowed_img_sources . "; ";
            $csp_policy .= "font-src 'self' " . $csp_allowed_font_sources . "; ";

            // Disallows plugins like Flash.
            $csp_policy .= "object-src 'none'; ";

            // Mitigates clickjacking.
            $csp_policy .= "frame-ancestors 'self'; ";
            $csp_policy .= "upgrade-insecure-requests; ";

            header('Content-Security-Policy: ' . $csp_policy);

            /**
             * HTTP Strict Transport Security (HSTS)
             * Enforces secure (HTTPS) connections.
             * To fix the "No 'preload' directive found" warning, you can add the 'preload' directive.
             * WARNING: Only add 'preload' if you understand the consequences and are certain
             * that your entire site and ALL its subdomains can be served over HTTPS permanently.
             * This cannot be easily undone. More info: https://hstspreload.org/
             */
            $hsts_max_age = 60 * 60 * 24 * 30 * 24; // 2 year

            header('Strict-Transport-Security: max-age=' . $hsts_max_age . '; includeSubDomains; preload');
        }
    }



    public function filter_bad_requests()
    {
        global $wp, $pagenow;

        // http://vulnsite.com/script.php etc.
        // wp-config.php etc.
        // ../../../../etc/pwd etc.
        // ../../../unwanted.php

        if (!$this->get_settings('filter_bad_requests')) {
            return;
        }

        if (current_user_can('manage_options')) {
            return;
        }

        // If REQUEST_METHOD is not set or empty, it means there is no security concern
        if (!isset($_SERVER['REQUEST_METHOD']) || empty($_SERVER['REQUEST_METHOD'])) {
            return;
        }

        // All HTTP Methods: GET / POST / PUT / HEAD / DELETE / PATCH / OPTIONS / CONNECT / TRACE
        $method = in_array(
            $_SERVER['REQUEST_METHOD'],
            // Methods that have the same function as POST
            array('POST', 'PUT', 'PATCH')
        ) ? 'POST' : 'GET';

        $custom_cookie_patterns = $this->get_settings('cookie_patterns');
        $custom_request_patterns = $this->get_settings('request_patterns');

        $pattern_arr = array('/[\#]/', '/[\|]/');
        $replace_arr = array('\\\\#', '\\\\|');

        if ($custom_cookie_patterns) {
            $custom_cookie_patterns = preg_split('/\r\n|\n/', $custom_cookie_patterns);
            $custom_cookie_patterns = array_map(function ($val) use ($pattern_arr, $replace_arr) {
                return preg_replace($pattern_arr, $replace_arr, $val);
            }, $custom_cookie_patterns);
        }

        if ($custom_request_patterns) {
            $custom_request_patterns = preg_split('/\r\n|\n/', $custom_request_patterns);
            $custom_request_patterns = array_map(function ($val) use ($pattern_arr, $replace_arr) {
                return preg_replace($pattern_arr, $replace_arr, $val);
            }, $custom_request_patterns);
        }

        $custom_cookie_patterns = is_array($custom_cookie_patterns) ? $custom_cookie_patterns : array();
        $custom_request_patterns = is_array($custom_request_patterns) ? $custom_request_patterns : array();

        // Cookie security
        $cookie_filter_items = apply_filters('securefusion_cookie_filter_items', $custom_cookie_patterns);

        if (!empty($cookie_filter_items)) {
            $cookie_pattern = '#' . implode('|', $cookie_filter_items) . '#siu';
        }

        if (!empty($_COOKIE)) {
            if (!empty($cookie_pattern)) {
                if ($this->bad_request_control($_COOKIE, $cookie_pattern)) {
                    wp_die(
                        esc_html__('SecureFusion Firewall has been denied this cookie request.', 'securefusion'),
                        esc_html__('Cookie Failure', 'securefusion'),
                        [
                            'response' => 403,
                            'back_link' => true,
                        ]
                    );
                }
            }
        }

        if ($method === 'GET' && empty($_GET))
            return;

        // GET and POST security
        $http_pattern = '(?:(?:http|https)?\:\/\/)?';
        $url_pattern = $http_pattern . '(?:[a-z0-9_\-\.]+\/+)([a-z0-9_\-\.\/]+)?';

        $default_regex_arr = [
            // SQL Global Variables
            '@@[\w\.\$]+',
            'eval\(\s*[\'\"][\w\s\(\)]+[\'\"]\s*\)',
            'base64_(encode|decode)\s*\(',
            'shell_exec\(\s*[\'\"][\w\s\-\.\/]+[\'\"]\s*\)',
            'phpinfo\(\s*\)',
            '^file_get_contents\(\s*[\'\"][\w\s\-\.\/]+[\'\"]\s*\)',
            $url_pattern . '\.(htaccess|exe|run|cgi)',
            $url_pattern . '(config|boot|vuln|load)\.(php|ini)',
            'mosConfig_[a-zA-Z_]{1,20}',
            // sql injections
            '(union\s+)?(select|insert|delete)\s+\w+(\s*,\s*\w+)*\s+from\s+\w+(\s+where\s+\w+\s*(=|<|>|\!=)\s*[\w\'\"]+)?',
            // special characters " ' < > \ { |
            '.*(&\#x22;|&\#x27;|&\#x3C;|&\#x3E;|&\#x5C;|&\#x7B;|&\#x7C;).*',
            // prevents ../ url patterns
            $http_pattern . '(\/*[a-z0-9_\-\.]+)?(\.\.\/)+([a-z0-9_\-\.])*',
        ];

        $request_regex_arr = array_merge($default_regex_arr, $custom_request_patterns);

        $request_filter_items = apply_filters('securefusion_request_filter_items', $request_regex_arr);

        $request_pattern = '#' . implode('|', $request_filter_items) . '#siu';

        if ($method === 'POST' && !empty($_POST)) {
            $input = $_POST;
        } else {
            $input = $_SERVER['QUERY_STRING'];
        }

        if ($this->bad_request_control($input, $request_pattern)) {
            // Comments
            if ($pagenow == 'wp-comments-post.php') {
                wp_die(
                    esc_html__('SecureFusion Firewall has been denied this comment submission.', 'securefusion'),
                    esc_html__('Comment Submission Failure'),
                    [
                        'response' => 403,
                        'back_link' => true,
                    ]
                );
            }

            wp_die(
                esc_html__('SecureFusion Firewall has been denied this request.', 'securefusion'),
                esc_html__('Request Failure', 'securefusion'),
                [
                    'response' => 403,
                    'back_link' => true,
                ]
            );
        }

        if (empty($wp->query_vars))
            return;

        // WP Query security
        if ($this->bad_request_control($wp->query_vars, $request_pattern)) {
            wp_die(
                esc_html__('SecureFusion Firewall has been denied this WP Queries.', 'securefusion'),
                esc_html__('WP Query Failure', 'securefusion'),
                [
                    'response' => 403,
                    'back_link' => true,
                ]
            );
        }
    }



    private function bad_request_control($input, $pattern)
    {
        if (is_array($input)) {
            $input = http_build_query($input);
        }

        $input = urldecode($input);

        // detect unwanted requests
        if (preg_match($pattern, $input) != false) {
            return true;
        }

        return false;
    }



    public function disable_rest_api($access)
    {
        return new \WP_Error(
            'rest_disabled',
            esc_html__('The REST API on this site has been disabled.', 'securefusion'),
            array('status' => rest_authorization_required_code())
        );
    }



    public function disable_rest_api_manually()
    {
        // v 1.x
        add_filter('json_enabled', '__return_false');
        add_filter('json_jsonp_enabled', '__return_false');

        // v 2.x
        add_filter('rest_enabled', '__return_false');
        add_filter('rest_jsonp_enabled', '__return_false');
    }


    function track_authenticate_user($user, $password)
    {
        // check if the login attempt was not successful
        if ($user instanceof \WP_User && wp_check_password($password, $user->user_pass, $user->ID)) {
            return $user;
        }

        global $wpdb;

        $bf_table = $wpdb->prefix . 'securefusion_brute_force_table';

        // get client IP
        $ip = $this->get_client_ip();

        if (!$ip) {
            return $user;
        }

        // check if IP exists in the table
        $row = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM $bf_table WHERE ip = %s", $ip)
        );

        if ($row) {
            // if IP exists, increment attempts and update last_attempt
            $wpdb->update(
                $bf_table,
                array(
                    'attempts' => $row->attempts + 1,
                    'last_attempt' => time(),
                ),
                array('ip' => $ip),
                array('%d', '%d'),
                array('%s')
            );
        } else {
            // if IP does not exist, insert a new row
            $wpdb->insert(
                $bf_table,
                array(
                    'ip' => $ip,
                    'attempts' => 1,
                    'last_attempt' => time(),
                ),
                array('%s', '%d', '%d')
            );
        }

        // return the original result
        return $user;
    }


    function track_limit_login_attempts($username)
    {
        global $wpdb;

        $bf_table = $wpdb->prefix . 'securefusion_brute_force_table';

        // get client IP
        $ip = $this->get_client_ip();

        // Check the IP pool
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $bf_table WHERE ip = %s", $ip));

        $ip_time_limit = $this->get_settings('ip_time_limit');
        $ip_login_limit = $this->get_settings('ip_login_limit');

        if (!$ip_login_limit || !$ip_time_limit) {
            return $username;
        }

        $ip_time_limit *= HOUR_IN_SECONDS;

        if ($row) {
            $current_time = time();
            $time_difference = $current_time - $row->last_attempt;

            // Failed login attempt
            if ($time_difference <= $ip_time_limit && $row->attempts >= $ip_login_limit) {
                wp_die(
                    esc_html__('<strong>ERROR</strong>: You have reached the login attempts limit.', 'securefusion'),
                    esc_html__('Too many failed login attempts', 'securefusion'),
                    [
                        'response' => 403,
                        'back_link' => true,
                    ]
                );
            }
        }
    }
}
