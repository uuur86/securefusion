=== SecureFusion: Ultimate Security - Firewall, SSL Control, Anti Spam, Login Security ===
Contributors: codeplusdev, ugurbicer
Tags: firewall, security, anti-spam, ssl, xml-rpc
Requires at least: 4.9
Tested up to: 6.8
Stable tag: 1.4.4
License: GPLv3 or later
License URI: http://www.gnu.org/licenses/gpl-3.0.html
Requires PHP: 7.4

Firewall, XML-RPC Security, Spam Protection, Redirect HTTP traffic to HTTPS, Login Page Security.

== Description ==
SecureFusion acts as a robust shield against many common attack types, including login attempts and DDoS attacks via XML-RPC.
It not only enhances security but also significantly improves your site's performance.
By helping to prevent unauthorized access and collection of sensitive information from your site, it neutralizes many attack vectors.
This is an effective solution for ensuring user safety and maintaining the speed of your site.

Features:

= XMLRPC =
SecureFusion aids in managing your critical XML-RPC services, often a prime target for WordPress hack attempts and spam comments.
The plugin allows you to selectively disable specific XML-RPC services, defending your site from XML-RPC attacks like spam comments without entirely disabling all XML-RPC services.
However, be aware that blocking all XML-RPC requests may impact the interaction of certain applications and services with WordPress.

* XML-RPC FULL PROTECTION (Disable all XML-RPC)
This feature blocks all incoming XML-RPC requests, offering an effective countermeasure against various remote attacks.
Remember, this might impact certain functionalities that rely on XML-RPC.

* XML-RPC LOGIN PROTECTION
This feature denies remote login requests made via XML-RPC, providing an extra line of defense against brute force login attempts.

* XML-RPC PINGBACK PROTECTION
This feature blocks remote pingback requests, assisting in the prevention of DDoS attacks.

* SELF PINGBACK PROTECTION
This feature prevents remote self pingback requests, further strengthening your defenses against DDoS attacks.

= SSL =
SecureFusion facilitates SSL integration into your site, provided you have an SSL certificate purchased from any SSL dealer or acquired through a free SSL service like Cloudflare.
The plugin forces the redirection of selected zone URLs on your site to HTTPS/SSL.
Note that SSL certificates must always be valid and correctly configured; otherwise, users may face issues accessing the site.

* Enable HTTPS / SSL
Enforces the use of HTTPS/SSL across your site, ensuring that data is encrypted during transmission.

* Force HTTPS Login
Redirects login page protocol from HTTP to HTTPS.

* Force HTTPS Admin
Redirects admin page protocol from HTTP to HTTPS.

* Force HTTPS Front Page
Redirects front page protocol from HTTP to HTTPS.

= Login =

* Login Attempt Limit
Set the maximum number of login attempts and the waiting time after reaching this limit to prevent brute force attacks on your login page.

* Change Login Error
SecureFusion allows you to modify default login errors, making it harder for potential attackers to gather information.

* Change Admin Username
This feature lets you change your administrator's username (e.g., the default 'admin' username), making it more difficult to guess user credentials. This provides an obscurity layer rather than direct protection from SQL vulnerabilities. (Note: This changes the username, not the numerical User ID).

* New Custom Login URL
This feature lets you change your login page URL name.
Be aware that if your site uses SSL/HTTPS, ensure your overall SSL configuration is correct and all resources load securely after any URL changes to avoid potential issues.

= Firewall =

* Filter Bad Requests
The plugin helps secure your site against various attacks such as XSS, CSRF, and Code Injections.

* Disable Rest API
SecureFusion helps safeguard sensitive information by allowing you to disable REST API endpoints, which can prevent them from being used by attackers for information disclosure or exploitation.
However, keep in mind that disabling the REST API can restrict the functionality of your WordPress site since some plugins and themes depend on it.

For complete information, please visit our website [the SecureFusion website](https://fyndsoft.com/securefusion).

== Installation ==

1. Download and unzip the plugin into your WordPress plugins directory (usually `/wp-content/plugins/`).
2. Activate the plugin through the 'Plugins' menu in your WordPress Admin.
3. Go to the Plugin's settings page and then it's up to you.

== Screenshots ==

1. SecureFusion admin XML-RPC settings page
2. SecureFusion admin Login settings page
3. SecureFusion admin SSL/HTTPS settings page

== Frequently Asked Questions ==

If you have any question, you can post [a support request](https://wordpress.org/support/plugin/secuplug/)

== Changelog ==
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
