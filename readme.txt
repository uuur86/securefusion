=== SecureFusion: Ultimate Security - Firewall, SSL Control, Anti Spam, Login Security ===
Contributors: codeplusdev, ugurbicer
Tags: firewall, security, anti-spam, ssl, xml-rpc
Requires at least: 4.9
Tested up to: 7.0
Stable tag: 1.5.0
License: GPLv3 or later
License URI: http://www.gnu.org/licenses/gpl-3.0.html
Requires PHP: 7.4

A high-performance, lightweight WordPress security suite. Protect your site from brute-force logins, DDoS pingbacks, bad request injections, and control Content Security Policies.

== Description ==

Are you tired of bloated security plugins that slow down your website and clutter your database?

SecureFusion is designed for WordPress site administrators, developers, and agency owners who demand lightweight, robust, and performance-optimized protection. It acts as an active shield against brute-force attacks, remote XML-RPC exploits, and malicious injections, while keeping your loading speeds lightning fast.

SecureFusion helps you enforce strict Content Security Policies (CSP), hide standard administrative entry points, block automated traffic clusters, and monitor unauthorized access patterns via a clean, modern dashboard.

== Features ==

= 1. Login Protection & Interactive Monitoring =
* **Failed Login Attempts Log:** Visually tracks unauthorized login attempts, displaying timestamps, IP addresses, and lockouts.
* **IP Range Clustering (/24 Subnets):** Groups attacking IPs into standard /24 subnets. Admins can view individual subnet IPs and copy the CIDR lists to a firewall or Cloudflare blacklist.
* **Custom Login URL:** Obfuscates `wp-login.php` and `wp-admin` access by changing it to a secret URL, stopping automated bots instantly.
* **Brute-Force Lockout:** Restricts login attempts and locks out offending IPs.
* **Modify Login Errors:** Alters generic authentication errors so hackers cannot verify whether they got the username or password correct.

= 2. Firewall & Active Guard =
* **Filter Bad Requests:** Screens URL requests to block XSS, CSRF, and code injection attempts before they reach your theme or database.
* **REST API Control:** Restricts public endpoint scraping, preventing attackers from harvesting user lists or plugin info.
* **Content Security Policy (CSP):** Easily configure and inject headers to control script, style, and media execution sources in the client browser.

= 3. XML-RPC Shield =
* **DDoS Amplification Defense:** Fully disable XML-RPC, or selectively disable pingbacks, preventing your server from participating in DDoS botnets.
* **XML-RPC Login Protection:** Specifically blocks remote credentials verification through XML-RPC.

= 4. Enforced SSL / HTTPS =
* **Secure Protocol Redirection:** Forces HTTP to HTTPS redirection across admin screens, login pages, or the entire site to guarantee secure data transmission.

For complete information, please visit our website [the SecureFusion website](https://fyndsoft.com/securefusion).

== Installation ==

1. Download and unzip the plugin into your WordPress plugins directory (usually `/wp-content/plugins/`).
2. Activate the plugin through the 'Plugins' menu in your WordPress Admin.
3. Go to the Plugin's settings page and then it's up to you.

== Screenshots ==

1. The SecureFusion dashboard overview screen showing status cards for active modules.
2. The Failed Login Attempts log showing active filters and toolbar actions.
3. The IP Ranges management screen showing subnet CIDR blocks and the "View IPs" modal popup.
4. The Security settings panel showing custom login URL configurations and CSP headers control.

== Frequently Asked Questions ==

If you have any question, you can post [a support request](https://wordpress.org/support/plugin/secuplug/)

== Changelog ==
= 1.5.0 =
* Updated: Wasp library to v3.0.0
* Added: Intrusion log table to track and list unauthorized access attempts
* Added: New Content Security Policy (CSP) control fields
* Improvement: Enhanced UI and usability for the CSP configuration section
* Fixed: Issues related to missing CSP directives

= 1.4.4 =
* Fixed: Fixed a PHP Fatal Error during initial plugin activation

= 1.4.3 =
* Fixed: CSP bugs and optimized
* Fixed: Prevented cache plugins from corrupting header assignments

= 1.4.2 =
* Fixed: The issue that caused the 500 error in Apache 2.4 has been resolved. htaccess is no longer used.
* Added: New CSP features
* Updated: Header settings in the firewall properties are now supported for NGINX and LiteSpeed ​​servers.

= 1.4.1 =
* Tested on the latest WordPress version

= 1.4.0 =
* Added: Updates default settings on activate
* Updated: Dashboard and settings pages have been redesigned 

= 1.3.8 =
* Fixed: a bug in the 'Filter Bad Requests' feature that was preventing login. Users can now log in without issues.
* Updated: dashboard design and new plugin logo

= 1.3.7.1 =
* Hotfix: deleted test codes

= 1.3.7 =
* Fixed: "Filter Bad Requests" block cookie problem
* Added: Custom cookie and request regex fields added along with the Advanced tab.

= 1.3.6 =
* Updated: Plugin name to "SecureFusion"
* Added: Auto settings migration code
* Added: Block IP address feature on failed login

= 1.3.5 =
* Added: New firewall settings
* Updated: Disable Rest API feature will disable only users service and main service any more. (Plugin issues are solved)

= 1.3.4.1 =
* incomplete and forgotten cookie security code that lead to problem has disabled

= 1.3.4 =
* Added new firewall features

= 1.3.3 =
* Fixed errors in js files

= 1.3.2 =
* Fixed https and login page protect issues on admin-ajax.php

= 1.3.1 =
* Fixed an exceptional circumstance in the "hide admin login url" link.
* Added no valid SSL certificate and get an SSL warning in the settings page
* Improved user experience for admin settings form

= 1.3 =
* Improved SSL / HTTPS implementation
* Added settings notification
* Removed useless Run the scanner menu for now
* Visual enhancements

= 1.2.11 =
* fixed access denied issue when changing schema https to http on admin page

= 1.2.10 =
* testing for version 1.2.11

= 1.2.9 =
* Fixed auto loading of fix ssl js file without enable it
* Fixed SSL URL replacement and redirection
* Added ssl enable and forge ssl options
* Added self pingback disable feature
* Visual enhancements

= 1.2.8 =
* Fixed some HTTPS issues in wp-admin and wp-login

= 1.2.7 =
* fixed infinity redirection

= 1.2.6 =
* fixed admin auth-fallback login screen issue
* fixed some typos
* some minor changes

= 1.2.4 =
* fixed https redirect

= 1.2.3 =
* fixed https issue

= 1.2.1 =
* Fixed some issues

= 1.2.0 =
* Added composer autoload
* Fixed some typos
* added new functions to wp_common trait
