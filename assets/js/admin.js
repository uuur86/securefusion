/**
 * SecureFusion Admin Settings JS
 *
 * Handles tab switching, _wp_http_referer synchronization for reliable
 * post-save redirection, and tag-input component logic.
 *
 * @package securefusion
 */

(function ($) {

	$(document).ready(function () {
		var STORAGE_KEY = 'securefusion_active_tab';

		/**
		 * Derive the initial tab ID from (in priority order):
		 * 1. URL hash
		 * 2. localStorage
		 * 3. First tab
		 */
		function get_initial_tab_id() {
			var hash = window.location.hash.replace('#', '');

			if (hash && $('a[href="#' + hash + '"]').length) {
				return hash;
			}

			var stored = localStorage.getItem(STORAGE_KEY);
			if (stored && $('a[href="#' + stored + '"]').length) {
				return stored;
			}

			var $first = $('.nav-tab-wrapper > a').first();
			if ($first.length) {
				return $first.attr('href').split('#')[1];
			}

			return null;
		}

		/**
		 * Update the _wp_http_referer hidden field so that WordPress
		 * redirects back to the correct tab after saving.
		 */
		function sync_referer(tab_id) {
			var $referer = $('input[name="_wp_http_referer"]');
			if ($referer.length && tab_id) {
				var url = window.location.pathname + window.location.search + '#' + tab_id;
				$referer.val(url);
			}
		}

		function securefusion_reset_tab_nav() {
			$('.content-tab-wrapper > .tab-content').addClass('hidden');
			$('.nav-tab-wrapper > a').removeClass('nav-tab-active');
		}

		function securefusion_tab_activate(selected_id) {
			if (!selected_id) {
				return;
			}

			var content_id = '#fynd-sf-' + selected_id;
			var nav_id = 'a[ href = "#' + selected_id + '" ]';

			$(nav_id).addClass('nav-tab-active');
			$(content_id).removeClass('hidden');

			// Persist the active tab.
			localStorage.setItem(STORAGE_KEY, selected_id);

			// Immediately sync the referer for save redirection.
			sync_referer(selected_id);

			// Update URL hash without scrolling.
			if (history.pushState) {
				history.pushState(null, null, '#' + selected_id);
			}
		}

		// --- Initial activation ---
		var initial_tab = get_initial_tab_id();
		securefusion_reset_tab_nav();
		securefusion_tab_activate(initial_tab);

		// --- Tab click handler ---
		$('.nav-tab-wrapper > a').click(function (e) {
			e.preventDefault();
			securefusion_reset_tab_nav();

			var selected_id = $(this).attr('href').split('#')[1];
			securefusion_tab_activate(selected_id);
		});

		// --- Handle browser back/forward ---
		$(window).on('popstate', function () {
			var hash = window.location.hash.replace('#', '');
			if (hash && $('a[href="#' + hash + '"]').length) {
				securefusion_reset_tab_nav();
				securefusion_tab_activate(hash);
			}
		});

		// Taginput for CSP and regex pattern fields
		$('.taginput-wrapper').each(function () {
			var $wrapper = $(this);
			var $inputRow = $wrapper.find('.taginput-input-row');
			var $input = $wrapper.find('.taginput-input');
			var $addBtn = $wrapper.find('.taginput-add-btn');
			var $tags = $wrapper.find('.taginput-tags');
			var $hidden = $wrapper.find('.taginput-hidden');
			var $error = $wrapper.find('.taginput-error');
			var $presets = $wrapper.find('.taginput-presets');

			var fieldType = $wrapper.data('field-type') || 'url';
			// The hidden value separates tags with "|" (legacy: &#10;); see renderFromHidden().
			var tags = [];

			// Render the tags stored in the hidden field.
			function renderFromHidden() {
				var value = ($hidden.val() || '').replace(/\|/g, '\n').replace(/&#10;/g, '\n');

				tags = [];
				$tags.empty();

				value.split('\n').forEach(function (tag) {
					tag = tag.trim();
					if (tag && tags.indexOf(tag) === -1) {
						tags.push(tag);
						appendTag(tag);
					}
				});
			}

			renderFromHidden();

			// "Use network setting" restored the hidden value: show the restored tags.
			$wrapper.closest('.wasp-inheritable').on('wasp:inherit-revert', renderFromHidden);

			function appendTag(tag) {
				// Build the tag with text nodes: values come from settings and must not become markup.
				var $tag = $('<span class="taginput-tag"></span>').text(tag);
				$tag.append($('<span class="taginput-remove"></span>').attr('title', 'Remove').text('\u00d7'));
				$tag.find('.taginput-remove').on('click', function () {
					removeTag(tag);
					$(this).parent().remove();
					updateHidden();
				});
				$tags.append($tag);
			}

			function addTag(tag) {
				if (tags.indexOf(tag) !== -1) return;
				tags.push(tag);
				appendTag(tag);
			}

			function removeTag(tag) {
				tags = tags.filter(function (t) { return t !== tag; });
			}

			function updateHidden() {
				var unique = tags.filter(function (t, i, arr) { return arr.indexOf(t) === i; });
				tags = unique;
				$hidden.val(tags.join("|"));

				// Let listeners (wasp auto override) know the value changed.
				$hidden[0].dispatchEvent(new Event('change', { bubbles: true }));
			}

			function validateUrl(value) {
				if (!value) return false;

				// CSP quoted keywords.
				var csp_keywords = [
					"'self'",
					"'unsafe-inline'",
					"'unsafe-eval'",
					"'none'",
					"'strict-dynamic'",
					"'unsafe-hashes'",
					"'report-sample'",
					"'wasm-unsafe-eval'"
				];
				if (csp_keywords.indexOf(value) !== -1) {
					return true;
				}

				// Wildcard.
				if (value === '*') {
					return true;
				}

				// Nonces.
				if (/^'nonce-[A-Za-z0-9+\/=]+'$/.test(value)) {
					return true;
				}

				// Hashes.
				if (/^'sha(256|384|512)-[A-Za-z0-9+\/=]+'$/.test(value)) {
					return true;
				}

				// Scheme-only.
				if (/^[a-z][a-z0-9+\-.]*:$/i.test(value)) {
					return true;
				}

				// Full URL with scheme (including potential wildcard in host: e.g. https://*.example.com)
				if (/^https?:\/\/.+/i.test(value)) {
					return true;
				}

				// Host source with optional wildcard subdomain: example.com, *.example.com.
				// Must not contain whitespace or semicolons.
				if (!/[\s;]/.test(value) && /^(\*\.)?[a-z0-9][a-z0-9.\-]*[a-z0-9]$/i.test(value)) {
					return true;
				}

				return false;
			}

			function validateRegex(value) {
				if (!value) return false;
				try { new RegExp(value); return true; } catch (e) { return false; }
			}

			function showError(msg) {
				$error.text(msg).addClass('show');
				setTimeout(function () { $error.removeClass('show'); }, 3000);
			}

			function addFromInput() {
				var val = $input.val().trim();
				if (!val) return;

				if (fieldType === 'url') {
					// Allow quoted CSP values (like 'self', 'unsafe-inline', 'unsafe-eval', etc.)
					if (val === "'self'" || val === "self") {
						showError('Self is already in list!');
						return;
					} else if (val.charAt(0) === "'" || val === 'blob:' || val === 'filesystem:' || val === 'https:' || val === 'http:' || val.indexOf('data:') === 0) {
						// Accept as-is
					} else if (!validateUrl(val)) {
						showError('Invalid URL format');
						return;
					} else if (val.indexOf('http') !== 0) {
						// Auto-add https if it looks like a domain
						val = 'https://' + val;
					}
				} else if (fieldType === 'regex') {
					if (!validateRegex(val)) {
						showError('Invalid regex pattern');
						return;
					}
				}

				addTag(val);
				$input.val('');
				updateHidden();
			}

			$addBtn.on('click', function (e) {
				e.preventDefault();
				addFromInput();
			});

			$input.on('keydown', function (e) {
				if (e.key === 'Enter') {
					e.preventDefault();
					addFromInput();
				}
			});

			// Preset buttons
			$presets.find('.fynd-sf-taginput-preset-btn').on('click', function () {
				var preset = $(this).data('preset');
				if (preset) addTag(preset);
				updateHidden();
			});
		});
	});
})(jQuery);