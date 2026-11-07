/**
 * Warn before leaving a settings form with unsaved changes.
 *
 * @package securefusion
 */
(function () {
	'use strict';

	function initialize() {
		document.querySelectorAll('[data-fsf-unsaved] form').forEach(function (form) {
			var baseline = new Map();
			var submission = null;

			function controls() {
				return Array.from(form.querySelectorAll('.content-tab-wrapper input, .content-tab-wrapper select, .content-tab-wrapper textarea'))
					.filter(function (control) {
						return !['button', 'submit', 'reset'].includes(control.type);
					});
			}

			function value(control) {
				if (control.type === 'checkbox' || control.type === 'radio') {
					return JSON.stringify([control.value, control.checked]);
				}
				if (control.tagName === 'SELECT' && control.multiple) {
					return JSON.stringify(Array.from(control.selectedOptions, function (option) {
						return option.value;
					}));
				}
				return control.value;
			}

			controls().forEach(function (control) {
				baseline.set(control, value(control));
			});

			function changed() {
				var current = controls();
				return current.length !== baseline.size || current.some(function (control) {
					return !baseline.has(control) || baseline.get(control) !== value(control);
				});
			}

			window.addEventListener('beforeunload', function (event) {
				// A validated native submit is the intentional save action. A cancelled
				// submit (including one cancelled by another handler) must stay protected.
				if (submission && !submission.defaultPrevented) {
					return;
				}
				if (changed()) {
					event.preventDefault();
					event.returnValue = '';
				}
			});

			form.addEventListener('submit', function (event) {
				submission = event;
			});
			form.addEventListener('input', function () { submission = null; });
			form.addEventListener('change', function () { submission = null; });
			window.addEventListener('pageshow', function () { submission = null; });

			// Wasp's single-field reset saves immediately via AJAX. Only that field
			// becomes clean; other unsaved edits must still warn before its reload.
			if (window.jQuery) {
				window.jQuery(document).on('ajaxSuccess.fsfUnsaved', function (event, xhr, settings, response) {
					var data = typeof settings.data === 'string'
						? Object.fromEntries(new URLSearchParams(settings.data))
						: (settings.data || {});
					if (data.action !== 'wasp_reset_field' || !response || !response.success) {
						return;
					}
					var name = data.settings_name + '[' + data.field_name + ']';
					controls().forEach(function (control) {
						if (control.name === name) {
							baseline.set(control, value(control));
						}
					});
				});
			}
		});
	}

	// Capture values after the form widgets and inheritance controls initialize.
	if (document.readyState === 'complete') {
		initialize();
	} else {
		window.addEventListener('load', initialize, { once: true });
	}
})();
