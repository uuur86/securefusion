# Changelog

## 2.0.4 (unreleased)
* Added: Warn before leaving settings with unsaved edits; respect cancelled saves, inherited values and immediately saved single-field resets.
* Fixed: Remove nested radio control borders and refresh cached styles after CSS updates.
* Improved: Move account transition guidance into an expandable Dashboard card, shown only for a site administrator with ID 1.
* Improved: Prepare database identifiers and values, remove blanket coding-standard suppressions, and enforce LF line endings.
* Fixed: Verify database columns and indexes before marking installation complete; surface failures and retry after a cooldown, including previously unverified installations.
* Fixed: Shorten SSL connection timeout, cache failed checks, close certificate streams and avoid treating failure markers as valid certificates.
* Fixed: Consistent Yes/No selected states and label spacing for network-inherited settings.
* Changed: Replaced direct administrator ID rewriting with an account transition guide using WordPress user management. Legacy ID settings are ignored; existing accounts are preserved.
* Fixed: "Disable REST API for Visitors" could be bypassed on multisite sub-directory sites (`/site/wp-json/wp/v2/users`) and with `?rest_route=/wp/v2/users`. Requests are now checked by REST route.
* Improved: Removed a DNS lookup that ran on every REST API request from visitors.
* Added: `securefusion_rest_protected_services` and `securefusion_rest_allow_request` filters.
* Added: "Hide Usernames from Visitors" (on by default). `?author=N` answers 404 instead of redirecting to the author archive, anonymous visitors cannot read the REST users endpoint (also through `_embed`), administrators are left out of the users sitemap, and oEmbed author data and comment CSS classes no longer reveal login names. Author archives keep working.
* Improved: Settings page redesign. On network sub-sites every setting shows the network value; changing a value customizes it for this site and "Use network setting" brings the network value back. Clearer names and descriptions for every setting.

## 2.0.3
* Fixed: Google reCAPTCHA not displaying and preventing login on custom login paths.
* Fixed: WP-CLI warning and redirect loops during plugin deactivation and initialization.
* Fixed: CSP settings input validation to allow wildcard (`*`) and wildcard subdomains.
* Fixed: Removed automatic `www` and apex domain normalizations from CSP sources.
* Fixed: Excluded whitelisted IPs and authenticated API requests (with credentials/cookies) from the Max Payload Size limit.
* Improved: Added CIDR range checks for whitelisted IPs in the firewall database.

## 2.0.2
* Added: Google reCAPTCHA Integration supporting v2 Checkbox, v2 Invisible, and v3 versions.
* Added: Performance-optimized dynamic lazy-loading for Google reCAPTCHA.
* Added: Native reCAPTCHA integrations with Contact Form 7, Mailchimp for WP (MC4WP), Login, Register, Lost Password, and Comment forms.
* Added: New CSP directives for `connect-src`, `media-src`, `form-action`, and `base-uri`.
* Added: Automatic `www` and apex/root domain normalization helper inside CSP settings.
* Added: CSP Report-Only mode support and custom Report URI field.
* Added: Advanced HSTS configurations with options for `preload` and `includeSubDomains`.
* Added: Cross-Origin-Opener-Policy (COOP) configuration toggle (off by default) to keep external pop-up logins functional.
* Fixed: Duplicate Strict-Transport-Security header output.
* Removed: Deprecated `X-XSS-Protection` header and hardcoded `Permissions-Policy` header.

## 2.0.1
* Resolved compatibility issues with the "Disable REST API for Visitors" feature to prevent conflicts and improve third-party plugin integration.

## 2.0.0
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

## 1.4.4
* Fixed: Fixed a PHP Fatal Error during initial plugin activation

## 1.4.3
* Fixed: CSP bugs and optimized
* Fixed: Prevented cache plugins from corrupting header assignments

## 1.4.2
* Fixed: The issue that caused the 500 error in Apache 2.4 has been resolved. htaccess is no longer used.
* Added: New CSP features
* Updated: Header settings in the firewall properties are now supported for NGINX and LiteSpeed servers.

## 1.4.1
* Tested on the latest WordPress version

## 1.4.0
* Added: Updates default settings on activate
* Updated: Dashboard and settings pages have been redesigned 

## 1.3.8
* Fixed: a bug in the 'Filter Bad Requests' feature that was preventing login. Users can now log in without issues.
* Updated: dashboard design and new plugin logo

## 1.3.7.1
* Hotfix: deleted test codes

## 1.3.7
* Fixed: "Filter Bad Requests" block cookie problem
* Added: Custom cookie and request regex fields added along with the Advanced tab.

## 1.3.6
* Updated: Plugin name to "SecureFusion"
* Added: Auto settings migration code
* Added: Block IP address feature on failed login

## 1.3.5
* Added: New firewall settings
* Updated: Disable Rest API feature will disable only the users service and the main service anymore. (Plugin issues are solved)

## 1.3.4.1
* An incomplete and forgotten cookie security code that led to a problem has been disabled.

## 1.3.4
* Added new firewall features

## 1.3.3
* Fixed errors in js files

## 1.3.2
* Fixed https and login page protect issues on admin-ajax.php

## 1.3.1
* Fixed an exceptional case in the "hide admin login url" link.
* Added warning for no valid SSL certificate on the settings page
* Improved user experience for admin settings form

## 1.3
* Improved SSL / HTTPS implementation
* Added settings notification
* Removed useless Run the scanner menu for now
* Visual enhancements

## 1.2.11
* fixed access denied issue when changing schema https to http on admin page

## 1.2.10
* testing for version 1.2.11

## 1.2.9
* Fixed auto loading of fix ssl js file without enabling it
* Fixed SSL URL replacement and redirection
* Added ssl enable and force SSL options
* Added self pingback disable feature
* Visual enhancements

## 1.2.8
* Fixed some HTTPS issues in wp-admin and wp-login

## 1.2.7
* fixed infinite redirection

## 1.2.6
* fixed admin auth-fallback login screen issue
* fixed some typos
* some minor changes

## 1.2.4
* fixed https redirect

## 1.2.3
* fixed https issue

## 1.2.1
* Fixed some issues

## 1.2.0
* Added composer autoload
* Fixed some typos
* added new functions to wp_common trait
