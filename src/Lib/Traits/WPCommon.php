<?php

/**
 * WPCommon Trait
 * Common wordpress methods
 * @package securefusion
 */

namespace SecureFusion\Lib\Traits;

use Exception;

trait WPCommon
{

    protected $wp_settings = false;



    /**
     * Only runs while we're on this plugin pages
     *
     * in admin_init function
     * add_action | current_screen
     */
    public function check_admin_menu_screen( $menu_pages )
    {
        $screen = get_current_screen();

        if ( !is_array( $menu_pages ) ) return;

        if ( in_array( $screen->id, $menu_pages ) ) {
            return true;
        }

        return false;
    }



    function get_settings( $name = null )
    {
        $value = null;

        if ( $this->wp_settings === false ) {
            $this->wp_settings = get_option( 'securefusion_settings', null );
        }

        if ( !empty( $name ) ) {
            if ( isset( $this->wp_settings[$name] ) ) {
                $value = $this->wp_settings[$name];
            }
        } else {
            $value = $this->wp_settings;
        }

        return $value;
    }



    function set_settings( $name, $value )
    {
        $settings = $this->get_settings();
        $settings[ $name ] = $value;

        return update_option( 'securefusion_settings', $settings );
    }



    function get_requested_page()
    {
        $requests       = parse_url( esc_url( $_SERVER['REQUEST_URI'] ) );
        $requested_page = trim( basename( $requests['path'] ), '\\/' );

        return $requested_page;
    }



    function get_new_login_url()
    {
        return trim( $this->get_settings( 'custom_login_url' ), '\\/' );
    }



    function is_login_page( $old = true )
    {
        global $pagenow;

        $login_dir      = ['wp-admin', 'admin', 'login'];
        $requested_page = $this->get_requested_page();

        $wp_login      = strpos( $pagenow, 'wp-login.php' ) !== false;
        $is_login_page = in_array( $requested_page, $login_dir );
        $is_login_page = ( $wp_login || $is_login_page );

        if ( $old ) return $is_login_page;

        return ( $requested_page == $this->get_new_login_url() );
    }



    function filesystem()
    {
        global $wp_filesystem;

        if ( empty( $wp_filesystem ) ) {
            require_once( ABSPATH . '/wp-admin/includes/file.php' );
            \WP_Filesystem();
        }

        if ( empty( $wp_filesystem ) ) {
            throw new Exception( "There is no filesystem in this WordPress version" );
        }

        return $wp_filesystem;
    }



    function get_htaccess_path()
    {
        if ( $this->get_server_type() == 'apache' ) {
            return \get_home_path() . '.htaccess';
        }

        return '';
    }



    function get_server_type()
    {
        $name = strtolower( $_SERVER["SERVER_SOFTWARE"] );

        if ( strpos( $name, 'nginx' ) > -1 ) {
            return 'nginx';
        } else if ( strpos( $name, 'apache' ) > -1 ) {
            return 'apache';
        } else if ( strpos( $name, 'litespeed' ) > -1 ) {
            return 'litespeed';
        }
    }



    protected function read_htaccess_file()
    {
        $filesystem  = $this->filesystem();
        $config_file = $this->get_htaccess_path();

        if (! empty($config_file) && $filesystem->is_readable($config_file)) {
            return $filesystem->get_contents($config_file);
        }

        return false;
    }



    protected function write_htaccess_file( $content )
    {
        $filesystem  = $this->filesystem();
        $config_file = $this->get_htaccess_path();
        $backup_file = $config_file . '-backup';

        if ( !$filesystem->exists( $backup_file ) ) {
            if ( !$filesystem->put_contents( $backup_file, $this->read_htaccess_file() ) ) {
                return false;
            }
        }

        if ( !empty( $config_file ) && $filesystem->is_writable( $config_file ) ) {
            return $filesystem->put_contents( $config_file, $content );
        }

        return false;
    }



    protected function append_htaccess( $lines, $override = false )
    {
        $line_end = "\r\n";

        if ( empty( $lines ) ) {
            return;
        } else if ( !is_array( $lines ) ) {
            $lines = $lines . $line_end;
        } else {
            $lines_ = '';

            foreach ( $lines as $line ) {
                $lines_ .= $line . $line_end;
            }

            $lines = $lines_;
            unset( $lines_ );
        }

        $file_content = $this->read_htaccess_file();
        $start_tag    = '# BEGIN SecureFusion';
        $end_tag      = '# END SecureFusion';

        // migrate - delete old htaccess settings
        $old_start_tag = '# BEGIN Secuplug';
        $old_end_tag   = '# END Secuplug';

        if ( substr_count( $file_content, $old_start_tag ) > 0 ) {
            $file_content = preg_replace( "@({$old_start_tag}[\s\S]*{$old_end_tag})@ui", "", $file_content );
        }

        $start = strpos($file_content, $start_tag);
        $end   = strpos($file_content, $end_tag);

        if ( $start > -1 ) {
            if ( $end > -1 ) {
                if ( $override ) {
                    $new_content = substr( $file_content, 0, $start ) . $start_tag . $line_end;
                } else {
                    $new_content = substr( $file_content, 0, $end ) . $line_end;
                }

                $new_content .= $lines;
                $new_content .= substr( $file_content, $end );
            } else {
                throw new Exception( "Your htaccess file is deformed!" );
            }
        } else {
            $new_content = $start_tag . $line_end;
            $new_content .= $lines;
            $new_content .= $end_tag . $line_end . $line_end;
            $new_content .= $file_content;
        }

        if ( !empty( $new_content ) ) {
            return $this->write_htaccess_file( $new_content );
        }

        return false;
    }



    protected function array_merge_values( Array $arrays )
    {
        $result = [];

        foreach ( $arrays as $array ) {
            $result = array_merge( $result, $array );
        }

        return $result;
    }


    protected function get_client_ip() {
        $ipaddress = '';

        if ( isset( $_SERVER['HTTP_CLIENT_IP'] ) ) {
            $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
        } elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif ( isset( $_SERVER['HTTP_X_FORWARDED'] ) ) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
        } elseif ( isset( $_SERVER['HTTP_FORWARDED_FOR'] ) ) {
            $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif ( isset( $_SERVER['HTTP_FORWARDED'] ) ) {
            $ipaddress = $_SERVER['HTTP_FORWARDED'];
        } else {
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        }

        // Multiple IP addresses can be returned, so let's take the first one
        if ( strpos( $ipaddress, ',' ) !== false ) {
            $ipaddress = explode( ',', $ipaddress );
            $ipaddress = $ipaddress[0] ?? false;
        }

        $ipaddress = filter_var( $ipaddress, FILTER_VALIDATE_IP );

        return $ipaddress;
    }
}
