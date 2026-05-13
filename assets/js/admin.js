/**
 * @package securefusion
 */

(function ($) {

	$(document).ready(function () {
		let loc_href = $(location).attr('href').split('#');

		function securefusion_reset_tab_nav() {
			$('.content-tab-wrapper > .tab-content').addClass('hidden');
			$('.nav-tab-wrapper > a').removeClass('nav-tab-active');
		}

		function securefusion_tab_activate(selected_id = null) {

			if (selected_id === null) {

				if (loc_href.length > 1) {
					selected_id = loc_href[1];
				}

				if (selected_id === null) {
					selected_obj = $('.nav-tab-wrapper > a').first();

					if (selected_obj.is('a')) {
						selected_id = selected_obj.attr('href').split('#')[1];
					}
				}
			}

			var content_id = '#securefusion-' + selected_id;
			var nav_id = 'a[ href = "#' + selected_id + '" ]';

			$(nav_id).addClass('nav-tab-active');
			$(content_id).removeClass('hidden');
		}

		securefusion_reset_tab_nav();
		securefusion_tab_activate();

		$('.nav-tab-wrapper > a').click(function () {
			securefusion_reset_tab_nav();

			let selected_id = $(this).attr('href').split('#')[1];

			securefusion_tab_activate(selected_id);

			setTimeout(function () {
				$('input[name="_wp_http_referer"]').val($(location).attr('href'));
			}, 100);
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
			var currentValue = $hidden.val() || '';
			// Replace pipe separator back to actual newline for tag display
			// Also handle legacy &#10; HTML entities for backwards compatibility
			currentValue = currentValue.replace(/\|/g, '\n').replace(/&#10;/g, '\n');
			var tags = currentValue ? currentValue.split("\n") : [];

			// Render existing tags
			tags.forEach(function (tag) {
				if (tag.trim()) {
					appendTag(tag.trim());
				}
			});

			function appendTag(tag) {
				var $tag = $('<span class="taginput-tag">' + tag + '<span class="taginput-remove" title="Remove">&times;</span></span>');
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
			}

			function validateUrl(value) {
				if (!value) return false;
				if (value === "'self'" || value === "'none'" || value.indexOf('data:') === 0) return true;
				return /^(https?:\/\/)?[\w\-\.]+(\.\w{2,})+$/.test(value);
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
			$presets.find('.taginput-preset-btn').on('click', function () {
				var preset = $(this).data('preset');
				if (preset) addTag(preset);
				updateHidden();
			});
		});
	});
})(jQuery);