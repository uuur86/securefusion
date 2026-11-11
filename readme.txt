=== SecureFusion - Security and Firewall by Fyndsoft ===
Contributors: codeplusdev, ugurbicer
Tags: security, firewall, login security, brute force, content security policy
Requires at least: 6.6
Tested up to: 7.0
Stable tag: 2.0.3
Requires PHP: 7.4
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html
Donate link: https://github.com/sponsors/uuur86

Lightweight security: firewall, brute-force login protection, Content Security Policy, security headers, XML-RPC and REST API hardening, HTTPS.

== Description ==

SecureFusion protects a WordPress site at the places attackers try first: the login page, XML-RPC, the REST API, request parameters and the browser. It is built to stay light. It makes no remote calls on page views, keeps its own data in indexed tables, and tells administrators on the page itself when something was blocked.

Works on Apache, Nginx and LiteSpeed, on single sites and on multisite with sub-directories or sub-domains.

= Login protection =

* Blocks an IP address after a number of failed logins within a time window you set, for a duration you set.
* Custom login page address. `wp-login.php` and `wp-admin` stop answering visitors who do not know it.
* A neutral login error message, so an attacker cannot tell a wrong username from a wrong password.
* Addresses of signed-in administrators are never blocked.

= Firewall =

* Request filter (beta): blocks requests whose parameters or cookies match attack patterns such as script injection, SQL keywords and path traversal. The patterns are editable.
* Request size limit: oversized requests are logged, and can block an address after repeated attempts. File uploads are excluded.
* Bad bot blocking by user agent.
* Hides the Server and X-Powered-By headers.
* Reads the visitor address from proxy headers only when the request really comes from a proxy.

= Content Security Policy =

A Content Security Policy tells browsers what a page may load and run, which limits what injected code can do.

* **On** (default): a script runs only from your site, a host your theme or plugins load, an allowed service, or when approved for the page. Code that WordPress, your theme and active plugins print is approved as the page is built. `eval` is blocked except on pages that load WordPress templates.
* **Notifications**: administrators allow a blocked host, service or feature with one click. Visitors never load this.
* **Test mode**: nothing is blocked, only reported. Sites updating from older versions start here.
* **Services**: host lists for Google, Cloudflare, Meta, PayPal, Stripe and others. Services found on the site are allowed, Cloudflare when it forwards requests. Tag managers and public code libraries wait for your approval.
* **Extra limits** for styles, fonts, images, embeds, connections, media, workers and form targets.
* **Page caches**: behind a page cache, hashes are used so pages stay cached. An optional cache driver gives cached pages a fresh nonce on each visit instead.

Page builder editors and the Customizer are never restricted.

= Security headers and HTTPS =

* X-Frame-Options, X-Content-Type-Options, Referrer-Policy, optional Cross-Origin-Opener-Policy.
* HTTPS redirects for the login page, the admin area, the front page or the whole site.
* HSTS with a duration from 1 day to 2 years, optional subdomains and preload. Preload is never sent on its own.

= XML-RPC, REST API and usernames =

* Turn off XML-RPC completely, or only its logins and pingbacks.
* Close the core REST API (`/wp/v2/`) to visitors who are not logged in. Endpoints of other plugins stay open.
* Hide usernames: `?author=1` links, the REST users list, administrators in the users sitemap and oEmbed author data. Author pages keep working.

= Security log, IP rules and comments =

* Security log with filters for failed logins, blocked requests and bots.
* Block or allow single addresses and CIDR ranges. Attacking addresses are grouped into ranges you can block together.
* Block the address or range of a commenter, or of everything in the spam folder, from the Comments screen.

= reCAPTCHA =

Optional Google reCAPTCHA (v2 or v3) on the login, registration, lost password and comment forms, and on Contact Form 7 and Mailchimp for WP forms.


Network administrators set defaults for all sites and decide whether site administrators may change them. Each site shows the network value and can return to it.

== Installation ==

1. Install SecureFusion from Plugins > Add New, or upload the folder to `/wp-content/plugins/`.
2. Activate it. Protections that are safe everywhere are on from the start.
3. Open SecureFusion in the admin menu to review the settings. Read the note next to an option before turning on anything marked "Can break pages".

== Frequently Asked Questions ==

= I changed the login address and cannot log in. What now? =

Add `define( 'SECUREFUSION_HIDE_LOGIN_DISABLE', true );` to `wp-config.php`. The standard `wp-login.php` works again and you can correct the setting.

= Will it slow my site down? =

It is designed not to. Page views cause no remote calls and no file scans, checks run cheapest first, and logs are cleaned up on a schedule.

= Will it affect SEO? =

No. It does not change robots rules, canonical tags or sitemaps, apart from leaving administrators out of the users sitemap. Blocked requests answer 403 or 404, never 200.

= Does it work with page caches and CDNs? =

Yes. Behind a known page cache the policy uses hashes, so pages stay cached. The settings screen shows the detected cache and what happens to cached pages.

= What is the cache driver and what does it change? =

It is optional. It adds five marked lines to `wp-config.php` that load one file of this plugin before your page cache answers, so every response gets its own nonce. It is tested after installing and used only if the test passes. Removing the driver, deactivating or deleting the plugin removes the lines.

= A page broke after I changed the Content Security Policy. =

Open the page as an administrator: a notification names what was blocked and offers to allow it. Or switch "When a rule is broken" to Test, which blocks nothing.

= What data leaves my site? =

None, unless you turn on reCAPTCHA. See External services.

== Screenshots ==

1. Blocking spam comment addresses and ranges from the Comments screen.
2. IP Rules: blocked and allowed addresses and CIDR ranges.
3. Failed and successful logins with filters.
4. Dashboard with module status and security event charts.
5. Settings: login page address and Content Security Policy.
6. IP ranges with the addresses inside each range.

== External services ==

**Google reCAPTCHA** – only if you turn on reCAPTCHA and enter your own keys; off by default. On the forms you select, the visitor's browser loads the reCAPTCHA script from Google. When such a form is submitted, your server sends the reCAPTCHA response token, your secret key and the visitor's IP address to `https://www.google.com/recaptcha/api/siteverify` to check it. [Terms of Service](https://policies.google.com/terms), [Privacy Policy](https://policies.google.com/privacy).

**Your own site** – the Content Security Policy scan and the cache driver test request pages of your own site, and the HTTPS screen reads your own site's certificate. Nothing is sent to a third party.

== Credits ==

* Chart.js 4.5.1, MIT, bundled minified as `assets/lib/chartjs/chart.umd.min.js`. Source: https://github.com/chartjs/Chart.js
* persist-admin-notices-dismissal, GPLv3. Source: https://github.com/collizo4sky/persist-admin-notices-dismissal
* wasp, GPLv3. Source: https://github.com/uuur86/wasp

== Changelog ==

= 3.0.0 =
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
* Fixed: Bundled translations were not loaded.
* Fixed: Database tables are verified before installation is marked complete; SSL checks time out sooner.
* Improved: No DNS lookup on REST API requests from visitors.

Older versions: see CHANGELOG.md in the plugin folder.

== Upgrade Notice ==

= 3.0.0 =
Major update. The Content Security Policy is rebuilt and starts in test mode on updated sites; review it in the SecureFusion settings. Includes security fixes for framing protection and REST API access.
