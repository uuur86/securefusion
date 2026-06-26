/**
 * SecureFusion reCAPTCHA Lazyload Script
 *
 * Loads Google reCAPTCHA dynamically upon user interaction to optimize PageSpeed scores.
 */
(function() {
	var recaptchaLoaded = false;

	function loadRecaptcha() {
		if (recaptchaLoaded) {
			return;
		}
		recaptchaLoaded = true;

		// Remove interaction event listeners
		removeListeners();

		// Check for v3 sitekey in placeholders
		var sitekey = '';
		var isV3 = false;
		var placeholders = document.querySelectorAll('.securefusion-recaptcha-placeholder');
		for (var i = 0; i < placeholders.length; i++) {
			var el = placeholders[i];
			var ver = el.getAttribute('data-version');
			var key = el.getAttribute('data-sitekey');
			if (key) {
				sitekey = key;
			}
			if (ver === 'v3') {
				isV3 = true;
			}
		}

		// Inject Google reCAPTCHA API script
		var script = document.createElement('script');
		if (isV3 && sitekey) {
			script.src = 'https://www.google.com/recaptcha/api.js?onload=secureFusionRecaptchaInit&render=' + encodeURIComponent(sitekey);
		} else {
			script.src = 'https://www.google.com/recaptcha/api.js?onload=secureFusionRecaptchaInit&render=explicit';
		}
		script.async = true;
		script.defer = true;
		document.head.appendChild(script);
	}

	function removeListeners() {
		var events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'focusin'];
		events.forEach(function(e) {
			window.removeEventListener(e, loadRecaptcha, { passive: true });
		});
	}

	function addListeners() {
		var events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'focusin'];
		events.forEach(function(e) {
			window.addEventListener(e, loadRecaptcha, { passive: true });
		});
	}

	// Wait for user interaction
	addListeners();
})();

/**
 * Render all reCAPTCHA placeholders once the Google API script has loaded.
 */
window.secureFusionRecaptchaInit = function() {
	var placeholders = document.querySelectorAll('.securefusion-recaptcha-placeholder');
	placeholders.forEach(function(el) {
		var sitekey = el.getAttribute('data-sitekey');
		var version = el.getAttribute('data-version');

		if (!sitekey) {
			return;
		}

		if (version === 'v2_checkbox') {
			grecaptcha.render(el, {
				'sitekey': sitekey,
				'theme': 'light'
			});
		} else if (version === 'v2_invisible') {
			var widgetId = grecaptcha.render(el, {
				'sitekey': sitekey,
				'size': 'invisible',
				'callback': function(token) {
					var form = el.closest('form');
					if (form) {
						var hiddenInput = form.querySelector('input[name="g-recaptcha-response"]');
						if (!hiddenInput) {
							hiddenInput = document.createElement('input');
							hiddenInput.type = 'hidden';
							hiddenInput.name = 'g-recaptcha-response';
							form.appendChild(hiddenInput);
						}
						hiddenInput.value = token;
						form.dataset.recaptchaSubmitting = 'true';

						var submitBtn = form.querySelector('input[type="submit"], button[type="submit"], #submit');
						if (submitBtn) {
							submitBtn.click();
						} else {
							form.submit();
						}
					}
				}
			});

			if (form) {
				var submitBtn = form.querySelector('input[type="submit"], button[type="submit"], #submit');
				if (submitBtn) {
					submitBtn.addEventListener('click', function(event) {
						if (form.dataset.recaptchaSubmitting === 'true') {
							return;
						}
						event.preventDefault();
						grecaptcha.execute(widgetId);
					});
				} else {
					form.addEventListener('submit', function(event) {
						if (form.dataset.recaptchaSubmitting === 'true') {
							return;
						}
						event.preventDefault();
						grecaptcha.execute(widgetId);
					});
				}
			}
		} else if (version === 'v3') {
			var refreshV3Token = function() {
				grecaptcha.ready(function() {
					grecaptcha.execute(sitekey, { action: 'submit' }).then(function(token) {
						var form = el.closest('form');
						if (form) {
							var hiddenInput = form.querySelector('input[name="g-recaptcha-response"]');
							if (!hiddenInput) {
								hiddenInput = document.createElement('input');
								hiddenInput.type = 'hidden';
								hiddenInput.name = 'g-recaptcha-response';
								form.appendChild(hiddenInput);
							}
							hiddenInput.value = token;
						}
					});
				});
			};

			// Initial token fetch on load
			refreshV3Token();

			// Refresh token every 90 seconds (reCAPTCHA v3 tokens expire in 2 minutes)
			setInterval(refreshV3Token, 90000);
		}
	});
};
