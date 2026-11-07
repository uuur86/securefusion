=== SecureFusion - Security and Firewall by Fyndsoft ===
Contributors: codeplusdev, ugurbicer
Tags: firewall, security, anti-spam, ssl, xml-rpc
Requires at least: 6.6
Tested up to: 7.0
Stable tag: 2.0.3
License: GPLv3 or later
License URI: http://www.gnu.org/licenses/gpl-3.0.html
Requires PHP: 7.4
Donate link: https://github.com/sponsors/uuur86

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

See CHANGELOG.md in the plugin package for the full version history.

== Upgrade Notice ==

= 2.0.2 =
This version introduces Content Security Policy (CSP) enhancements, automated domain normalization, Google reCAPTCHA integrations, and advanced security header configurations.
IMPORTANT NOTE FOR 1.X.X UPGRADERS: Since 2.x.x introduces significant architectural changes to firewall settings and security policies, please make sure to take a complete database backup before upgrading. Verify your security settings and CSP rules after the update.
