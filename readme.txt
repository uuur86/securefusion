=== SecureFusion - Security and Firewall by Fyndsoft ===
Contributors: codeplusdev, ugurbicer
Tags: firewall, security, anti-spam, ssl, xml-rpc
Requires at least: 4.9
Tested up to: 7.0
Stable tag: 2.0.0
License: GPLv3 or later
License URI: http://www.gnu.org/licenses/gpl-3.0.html
Requires PHP: 7.4

Lightweight, high-performance security suite. Protects from brute-force logins, DDoS pingbacks, bad request injections, and manages CSP headers.

== Description ==

Are you tired of bloated security plugins that slow down your website and clutter your database?

SecureFusion is designed for WordPress site administrators, developers, and agency owners who demand lightweight, robust, and performance-optimized protection. It acts as an active shield against brute-force attacks, remote XML-RPC exploits, and malicious injections, while keeping your loading speeds lightning fast.

SecureFusion helps you enforce strict Content Security Policies (CSP), hide standard administrative entry points, block automated traffic clusters, track successful/failed logins, block spam comment IPs directly, and monitor unauthorized access patterns via a clean, modern dashboard.

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

= 5. Comments IP Blocking & Bulk Shield =
* **Individual Commenter IP Blocking:** Block or unblock comment author IP addresses directly from the WordPress Comments list page.
* **Bulk Spam IP Blocking:** Instantly block all IP addresses associated with spam comments currently in the Spam directory.
* **Smart CIDR Range Calculation:** Option to block entire /24 IPv4 subnets or /64 IPv6 ranges of spam comments automatically based on IP distribution to stop persistent spam networks.

= 6. IP Spoofing Prevention & Successful Login Tracking =
* **Successful Login Logging:** Tracks successful logins to audit administrator and user access alongside failed login attempts.
* **IP Spoofing Prevention:** Performs strict public vs. private IP checks on client headers (like HTTP_X_FORWARDED_FOR) to prevent attackers from spoofing their IP addresses when behind load balancers or proxies.

For complete information, please visit our website [the SecureFusion website](https://fyndsoft.com/securefusion).

== Credits ==

This plugin bundles and/or utilizes the following third-party libraries:

* **Chart.js** (v4.5.1)
  * License: MIT
  * License URI: https://github.com/chartjs/Chart.js/blob/master/LICENSE.md
  * Source: https://www.chartjs.org

* **persist-admin-notices-dismissal**
  * License: GPLv3
  * Source: https://github.com/collizo4sky/persist-admin-notices-dismissal

* **wasp**
  * License: GPLv3
  * Source: https://github.com/uuur86/wasp


== Installation ==

1. Download and unzip the plugin into your WordPress plugins directory (usually `/wp-content/plugins/`).
2. Activate the plugin through the 'Plugins' menu in your WordPress Admin.
3. Go to the Plugin's settings page and then it's up to you.


== Screenshots ==

1. The WordPress Comments list integration allowing admins to block spam IPs and ranges directly.
2. The IP Rules management screen for manually blocking or whitelisting specific IPs and CIDR ranges.
3. The Failed and Successful Login Attempts log showing active filters and toolbar actions.
4. The SecureFusion dashboard overview screen showing status cards for active modules and graphs of security events.
5. The Security settings panel showing custom login URL configurations and CSP headers control.
6. The IP Ranges management screen showing subnet CIDR blocks and the "View IPs" modal popup.


== Frequently Asked Questions ==

If you have any questions, you can post [a support request](https://wordpress.org/support/plugin/secuplug/)


== Changelog ==

= 2.0.0 =
* Added: Comments Block module to block spam IPs directly from the edit-comments.php screen.
* Added: Support for bulk blocking spam comments and calculating CIDR subnets (IPv4 /24 and IPv6 /64).
* Added: Successful Login tracking to the Security Log.
* Added: Security log page with interactive filters, search, and CSV/JSON export.
* Added: IP Range subnet grouping and manual IP/CIDR blocking rules.
* Improved: Client IP detection with private/public IP checking to prevent IP spoofing.
* Improved: Upgraded CSP configurations to use interactive tag-inputs with common presets (Google Fonts, Cloudflare, etc.).
* Updated: Text Domain to secuplug to match the plugin slug.
* Updated: Wasp library to v3.0.0
* Added: Intrusion log table to track and list unauthorized access attempts
* Added: New Content Security Policy (CSP) control fields
* Fixed: Issues related to missing CSP directives

= 1.4.4 =
* Fixed: Fixed a PHP Fatal Error during initial plugin activation

= 1.4.3 =
* Fixed: CSP bugs and optimized
* Fixed: Prevented cache plugins from corrupting header assignments

= 1.4.2 =
* Fixed: The issue that caused the 500 error in Apache 2.4 has been resolved. htaccess is no longer used.
* Added: New CSP features
* Updated: Header settings in the firewall properties are now supported for NGINX and LiteSpeed servers.

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
* Updated: Disable Rest API feature will disable only the users service and the main service anymore. (Plugin issues are solved)

= 1.3.4.1 =
* An incomplete and forgotten cookie security code that led to a problem has been disabled.

= 1.3.4 =
* Added new firewall features

= 1.3.3 =
* Fixed errors in js files

= 1.3.2 =
* Fixed https and login page protect issues on admin-ajax.php

= 1.3.1 =
* Fixed an exceptional case in the "hide admin login url" link.
* Added warning for no valid SSL certificate on the settings page
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
* Fixed auto loading of fix ssl js file without enabling it
* Fixed SSL URL replacement and redirection
* Added ssl enable and force SSL options
* Added self pingback disable feature
* Visual enhancements

= 1.2.8 =
* Fixed some HTTPS issues in wp-admin and wp-login

= 1.2.7 =
* fixed infinite redirection

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
