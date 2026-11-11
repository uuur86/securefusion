<?php
/**
 * CSP integration module.
 *
 * @package securefusion
 */

namespace SecureFusion\Lib;

if ( ! defined( 'ABSPATH' ) ) {

	exit;

}

return [
	'paypal'       => [
		'label'         => 'PayPal / Venmo',
		'group'         => 'Payments',
		'plugins'       => [ 'woocommerce-paypal-payments/woocommerce-paypal-payments.php' ],
		'sources'       => [
			'script'      => [ 'https://*.paypal.com', 'https://*.paypalobjects.com', 'https://*.venmo.com' ],
			'style'       => [ 'https://*.paypal.com', 'https://*.paypalobjects.com', 'https://*.venmo.com' ],
			'frame'       => [ 'https://*.paypal.com', 'https://*.paypalobjects.com', 'https://*.venmo.com' ],
			'connect'     => [ 'https://*.paypal.com', 'https://*.paypalobjects.com', 'https://*.venmo.com' ],
			'img'         => [ 'https://*.paypal.com', 'https://*.paypalobjects.com', 'https://*.venmo.com' ],
			'form_action' => [ 'https://*.paypal.com', 'https://*.paypalobjects.com', 'https://*.venmo.com' ],
		],
		'documentation' => 'https://developer.paypal.com/sdk/js/csp/',
	],
	'stripe'       => [
		'label'         => 'Stripe / WooPayments',
		'group'         => 'Payments',
		'plugins'       => [ 'woocommerce-gateway-stripe/woocommerce-gateway-stripe.php', 'woocommerce-payments/woocommerce-payments.php' ],
		'sources'       => [
			'script'      => [ 'https://js.stripe.com', 'https://*.js.stripe.com' ],
			'frame'       => [ 'https://js.stripe.com', 'https://*.js.stripe.com', 'https://hooks.stripe.com', 'https://checkout.stripe.com', 'https://*.link.com' ],
			'connect'     => [ 'https://api.stripe.com', 'https://*.stripe.com' ],
			'img'         => [ 'https://*.stripe.com' ],
			'form_action' => [ 'https://checkout.stripe.com' ],
		],
		'documentation' => 'https://docs.stripe.com/security/guide',
	],
	'paddle'       => [
		'label'         => 'Paddle',
		'group'         => 'Payments',
		'plugins'       => [],
		'sources'       => [
			'script'      => [ 'https://cdn.paddle.com' ],
			'frame'       => [ 'https://buy.paddle.com', 'https://sandbox-buy.paddle.com', 'https://checkout.paddle.com' ],
			'connect'     => [ 'https://*.paddle.com' ],
			'img'         => [ 'https://*.paddle.com' ],
			'form_action' => [ 'https://buy.paddle.com', 'https://checkout.paddle.com' ],
		],
		'documentation' => 'https://developer.paddle.com/paddlejs/overview',
	],
	'lemon'        => [
		'label'         => 'Lemon Squeezy',
		'group'         => 'Payments',
		'plugins'       => [],
		'sources'       => [
			'script'      => [ 'https://app.lemonsqueezy.com' ],
			'frame'       => [ 'https://*.lemonsqueezy.com' ],
			'connect'     => [ 'https://app.lemonsqueezy.com' ],
			'form_action' => [ 'https://*.lemonsqueezy.com' ],
		],
		'documentation' => 'https://docs.lemonsqueezy.com/guides/developer-guide/lemonjs',
	],
	'freemius'     => [
		'label'         => 'Freemius',
		'group'         => 'Payments',
		'plugins'       => [],
		'sources'       => [
			'script'  => [ 'https://checkout.freemius.com' ],
			'style'   => [ 'https://checkout.freemius.com' ],
			'frame'   => [ 'https://checkout.freemius.com', 'https://users.freemius.com' ],
			'connect' => [ 'https://checkout.freemius.com', 'https://api.freemius.com' ],
		],
		'documentation' => 'https://freemius.com/help/documentation/checkout/integration/overlay-checkout/',
	],
	'mollie'       => [
		'label'         => 'Mollie',
		'group'         => 'Payments',
		'plugins'       => [ 'mollie-payments-for-woocommerce/mollie-payments-for-woocommerce.php' ],
		'sources'       => [
			'script'      => [ 'https://js.mollie.com' ],
			'frame'       => [ 'https://js.mollie.com' ],
			'connect'     => [ 'https://api.mollie.com' ],
			'form_action' => [ 'https://www.mollie.com' ],
		],
		'documentation' => 'https://docs.mollie.com/docs/mollie-components',
	],
	'paytr'        => [
		'label'         => 'PayTR',
		'group'         => 'Payments',
		'plugins'       => [],
		'sources'       => [
			'script'      => [ 'https://www.paytr.com' ],
			'frame'       => [ 'https://www.paytr.com' ],
			'form_action' => [ 'https://www.paytr.com' ],
		],
		'documentation' => 'https://dev.paytr.com/en/iframe-api/iframe-api-1-adim',
	],
	'razorpay'     => [
		'label'         => 'Razorpay',
		'group'         => 'Payments',
		'plugins'       => [ 'woo-razorpay/woo-razorpay.php' ],
		'sources'       => [
			'script'      => [ 'https://checkout.razorpay.com' ],
			'frame'       => [ 'https://api.razorpay.com', 'https://checkout.razorpay.com' ],
			'connect'     => [ 'https://api.razorpay.com' ],
			'img'         => [ 'https://cdn.razorpay.com' ],
			'form_action' => [ 'https://api.razorpay.com' ],
		],
		'documentation' => 'https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/integration-steps/',
	],
	'ga4'          => [
		'label'         => 'Google Analytics',
		'trusted'       => 'basic',
		'group'         => 'Analytics',
		'plugins'       => [ 'google-analytics-for-wordpress/googleanalytics.php', 'google-analytics-dashboard-for-wp/gadwp.php' ],
		'sources'       => [
			'script'  => [ 'https://*.googletagmanager.com', 'https://*.google-analytics.com' ],
			'img'     => [ 'https://*.google-analytics.com', 'https://*.googletagmanager.com' ],
			'connect' => [ 'https://*.google-analytics.com', 'https://*.analytics.google.com', 'https://*.googletagmanager.com' ],
		],
		'documentation' => 'https://developers.google.com/tag-platform/security/guides/csp',
	],
	'gtm'          => [
		'label'         => 'Google Tag Manager',
		'trusted'       => 'basic',
		'group'         => 'Analytics',
		'plugins'       => [ 'duracelltomi-google-tag-manager/duracelltomi-google-tag-manager-for-wordpress.php' ],
		'sources'       => [
			'script'  => [ 'https://www.googletagmanager.com' ],
			'frame'   => [ 'https://www.googletagmanager.com' ],
			'img'     => [ 'https://www.googletagmanager.com' ],
			'connect' => [ 'https://www.googletagmanager.com' ],
		],
		'documentation' => 'https://developers.google.com/tag-platform/security/guides/csp',
	],
	'google_ads'   => [
		'label'         => 'Google Ads',
		'trusted'       => 'basic',
		'group'         => 'Analytics',
		'plugins'       => [],
		'sources'       => [
			'script'  => [ 'https://www.googleadservices.com', 'https://www.google.com', 'https://www.googletagmanager.com', 'https://googleads.g.doubleclick.net', 'https://pagead2.googlesyndication.com' ],
			'img'     => [ 'https://www.google.com', 'https://www.googleadservices.com', 'https://googleads.g.doubleclick.net', 'https://www.google.com.tr' ],
			'connect' => [ 'https://www.google.com', 'https://www.googleadservices.com', 'https://googleads.g.doubleclick.net', 'https://pagead2.googlesyndication.com', 'https://*.g.doubleclick.net' ],
			'frame'   => [ 'https://td.doubleclick.net' ],
		],
		'documentation' => 'https://developers.google.com/tag-platform/security/guides/csp',
	],
	'clarity'      => [
		'label'         => 'Microsoft Clarity',
		'group'         => 'Analytics',
		'plugins'       => [ 'microsoft-clarity/clarity.php' ],
		'sources'       => [
			'script'  => [ 'https://*.clarity.ms' ],
			'connect' => [ 'https://*.clarity.ms' ],
			'img'     => [ 'https://*.clarity.ms', 'https://c.bing.com' ],
		],
		'documentation' => 'https://learn.microsoft.com/clarity/setup-and-installation/clarity-csp',
	],
	'plausible'    => [
		'label'         => 'Plausible Cloud',
		'group'         => 'Analytics',
		'plugins'       => [ 'plausible-analytics/plausible-analytics.php' ],
		'sources'       => [
			'script'  => [ 'https://plausible.io' ],
			'connect' => [ 'https://plausible.io' ],
		],
		'documentation' => 'https://plausible.io/docs/plausible-script',
	],
	'recaptcha'    => [
		'label'         => 'Google reCAPTCHA',
		'trusted'       => 'strict',
		'group'         => 'Content',
		'plugins'       => [],
		'sources'       => [
			'script'  => [ 'https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/', 'https://www.recaptcha.net/recaptcha/' ],
			'frame'   => [ 'https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/', 'https://www.recaptcha.net/recaptcha/' ],
			'connect' => [ 'https://www.google.com/recaptcha/', 'https://www.recaptcha.net/recaptcha/' ],
		],
		'documentation' => 'https://developers.google.com/recaptcha/docs/faq',
	],
	'turnstile'    => [
		'label'         => 'Cloudflare Turnstile',
		'trusted'       => 'strict',
		'group'         => 'Content',
		'plugins'       => [ 'simple-cloudflare-turnstile/simple-cloudflare-turnstile.php' ],
		'sources'       => [
			'script' => [ 'https://challenges.cloudflare.com' ],
			'frame'  => [ 'https://challenges.cloudflare.com' ],
		],
		'documentation' => 'https://developers.cloudflare.com/turnstile/reference/content-security-policy/',
	],
	'google_fonts' => [
		'label'         => 'Google Fonts',
		'trusted'       => 'strict',
		'group'         => 'Content',
		'plugins'       => [],
		'sources'       => [
			'style' => [ 'https://fonts.googleapis.com' ],
			'font'  => [ 'https://fonts.gstatic.com' ],
		],
		'documentation' => 'https://developers.google.com/fonts/docs/getting_started',
	],
	'youtube'      => [
		'label'         => 'YouTube',
		'trusted'       => 'basic',
		'group'         => 'Content',
		'plugins'       => [],
		'sources'       => [
			'frame'  => [ 'https://www.youtube.com', 'https://www.youtube-nocookie.com' ],
			'img'    => [ 'https://i.ytimg.com' ],
			'script' => [ 'https://www.youtube.com' ],
		],
		'documentation' => 'https://developers.google.com/youtube/iframe_api_reference',
	],
	'vimeo'        => [
		'label'         => 'Vimeo',
		'trusted'       => 'basic',
		'group'         => 'Content',
		'plugins'       => [],
		'sources'       => [
			'frame'  => [ 'https://player.vimeo.com' ],
			'script' => [ 'https://player.vimeo.com' ],
		],
		'documentation' => 'https://developer.vimeo.com/player/sdk',
	],
	'google_maps'  => [
		'label'         => 'Google Maps',
		'trusted'       => 'basic',
		'group'         => 'Content',
		'plugins'       => [],
		'sources'       => [
			'script'  => [ 'https://maps.googleapis.com', 'https://maps.gstatic.com' ],
			'frame'   => [ 'https://www.google.com/maps/' ],
			'img'     => [ 'https://maps.googleapis.com', 'https://maps.gstatic.com', 'https://*.ggpht.com' ],
			'connect' => [ 'https://maps.googleapis.com' ],
			'style'   => [ 'https://fonts.googleapis.com' ],
			'font'    => [ 'https://fonts.gstatic.com' ],
		],
		'documentation' => 'https://developers.google.com/maps/documentation/javascript/content-security-policy',
	],
	'cloudflare'   => [
		'label'         => 'Cloudflare (Web Analytics, Rocket Loader)',
		'group'         => 'Analytics',
		'plugins'       => [ 'cloudflare/cloudflare.php' ],
		'sources'       => [
			'script'  => [ 'https://static.cloudflareinsights.com', 'https://ajax.cloudflare.com' ],
			'connect' => [ 'https://cloudflareinsights.com', 'https://*.cloudflareinsights.com' ],
		],
		'documentation' => 'https://developers.cloudflare.com/fundamentals/reference/policies-compliances/content-security-policies/',
	],
	'cdn'          => [
		'label'         => 'Public code libraries (jsDelivr, cdnjs, UNPKG, Google, jQuery)',
		'trusted'       => 'basic',
		'group'         => 'Content',
		'plugins'       => [],
		'sources'       => [
			'script' => [ 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://unpkg.com', 'https://ajax.googleapis.com', 'https://code.jquery.com' ],
			'style'  => [ 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://unpkg.com', 'https://ajax.googleapis.com', 'https://code.jquery.com' ],
			'font'   => [ 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://unpkg.com' ],
		],
		'documentation' => 'https://www.jsdelivr.com/documentation',
	],
	'meta'         => [
		'label'         => 'Meta (Facebook Pixel, Like and Share)',
		'trusted'       => 'basic',
		'group'         => 'Analytics',
		'plugins'       => [ 'facebook-for-woocommerce/facebook-for-woocommerce.php', 'official-facebook-pixel/facebook-for-wordpress.php' ],
		'sources'       => [
			'script'  => [ 'https://connect.facebook.net' ],
			'frame'   => [ 'https://www.facebook.com', 'https://web.facebook.com' ],
			'img'     => [ 'https://www.facebook.com' ],
			'connect' => [ 'https://www.facebook.com', 'https://connect.facebook.net' ],
		],
		'documentation' => 'https://developers.facebook.com/docs/meta-pixel/advanced/',
	],
	'jetpack'      => [
		'label'         => 'Jetpack / WordPress.com',
		'group'         => 'Content',
		'plugins'       => [ 'jetpack/jetpack.php' ],
		'sources'       => [
			'script'  => [ 'https://stats.wp.com', 'https://c0.wp.com', 'https://s0.wp.com', 'https://widgets.wp.com', 'https://secure.gravatar.com' ],
			'style'   => [ 'https://c0.wp.com', 'https://s0.wp.com' ],
			'frame'   => [ 'https://widgets.wp.com', 'https://jetpack.wordpress.com' ],
			'img'     => [ 'https://pixel.wp.com', 'https://*.wp.com', 'https://secure.gravatar.com' ],
			'connect' => [ 'https://public-api.wordpress.com', 'https://pixel.wp.com' ],
		],
		'documentation' => 'https://jetpack.com/support/',
	],
];
