# Changelog

## 3.0.0 (unreleased)
* Changed: Content Security Policy is one switch with a test mode. Scripts run only from the site, from hosts that WordPress, the theme or active plugins load, from allowed services, or when approved; `eval` is blocked unless a page needs it. Earlier settings are mapped, and updated sites start in test mode.
* Added: Service lists (reCAPTCHA, Turnstile, Google Fonts, Cloudflare, tag managers and more). Services that serve code from any account need approval.
* Added: Page cache support: hashes behind a detected page cache, an optional cache driver in `wp-config.php` for fresh nonces, and cache clearing when the policy changes.
* Added: Administrator notifications for blocked hosts and features, with one-click fixes. Visitors never load them.
* Added: Optional site scan that lists only what needs a decision.
* Added: Hide usernames from visitors, on by default.
* Added: Network defaults with per-site overrides on multisite, and a redesigned settings screen.
* Added: Filters for notices, page builders, `eval` handles, page caches, policy size and REST access.
* Changed: Allow lists accept hosts only. Oversized policies are reduced in steps instead of risking a 502 error.
* Changed: HSTS moved to the HTTPS tab with a selectable duration. Referrer-Policy is strict-origin-when-cross-origin.
* Changed: Administrator ID rewriting is replaced by an account transition guide.
* Fixed: Adding `?embed=1` to an address removed framing protection.
* Fixed: The REST API block could be bypassed on sub-directory multisite and with `?rest_route=`.
* Fixed: `data:` could become a script source through an allow list or the site scan.
* Fixed: Inline hashes broke behind HTML optimizers, and the policy was cut short when output buffers closed early.
* Fixed: Bundled translations were not loaded. German, French, Spanish and Turkish are complete, and other German locales use the German translation.
* Fixed: Database tables are verified before installation is marked complete; SSL checks time out sooner.
* Improved: No DNS lookup on REST API requests from visitors.

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
