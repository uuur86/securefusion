/**
 * Login Log Page Scripts
 *
 * Handles reset, export, import, and IP range detail/copy AJAX actions.
 *
 * @package securefusion
 */

/* global jQuery, securefusionLog */

(function ($) {
	'use strict';

	/**
	 * Show a dismissible notice.
	 *
	 * @param {string} message Notice message.
	 * @param {string} type    Notice type (success|error|info).
	 */
	function showNotice(message, type) {
		var $notice = $('#sf-log-notice');

		$notice
			.removeClass('sf-notice-success sf-notice-error sf-notice-info')
			.addClass('sf-notice-' + type)
			.text(message)
			.fadeIn(200);

		setTimeout(function () {
			$notice.fadeOut(300);
		}, 5000);
	}

	/**
	 * Toggle processing state on elements.
	 *
	 * @param {boolean} state True to enable processing.
	 */
	function setProcessing(state) {
		$('.sf-log-toolbar').toggleClass('sf-processing', state);
	}

	/**
	 * Trigger file download from blob data.
	 *
	 * @param {string} content  File content.
	 * @param {string} filename File name.
	 * @param {string} mime     MIME type.
	 */
	function downloadFile(content, filename, mime) {
		var blob = new Blob([content], { type: mime });
		var url  = URL.createObjectURL(blob);
		var link = document.createElement('a');

		link.href     = url;
		link.download = filename;
		document.body.appendChild(link);
		link.click();
		document.body.removeChild(link);
		URL.revokeObjectURL(url);
	}

	$(document).ready(function () {

		// Reset handler with double confirmation.
		$('#sf-log-reset').on('click', function () {
			if (!window.confirm(securefusionLog.confirmReset)) {
				return;
			}

			var typed = window.prompt(
				'Type "DELETE" to confirm permanent data deletion:'
			);

			if (typed !== 'DELETE') {
				showNotice('Reset cancelled.', 'info');
				return;
			}

			setProcessing(true);

			$.post(securefusionLog.ajaxUrl, {
				action: 'securefusion_log_reset',
				nonce: securefusionLog.nonce
			})
			.done(function (response) {
				if (response.success) {
					showNotice(securefusionLog.resetSuccess, 'success');
					setTimeout(function () {
						window.location.reload();
					}, 1500);
				} else {
					showNotice(response.data.message, 'error');
				}
			})
			.fail(function () {
				showNotice('Request failed.', 'error');
			})
			.always(function () {
				setProcessing(false);
			});
		});

		// Export handler.
		$('#sf-log-export').on('click', function () {
			setProcessing(true);

			$.post(securefusionLog.ajaxUrl, {
				action: 'securefusion_log_export',
				nonce: securefusionLog.nonce
			})
			.done(function (response) {
				if (response.success) {
					if (!response.data.data || response.data.data.length === 0) {
						showNotice(securefusionLog.exportEmpty, 'info');
						return;
					}

					var jsonStr = JSON.stringify(response.data.data, null, 2);
					downloadFile(jsonStr, response.data.filename, 'application/json');
					showNotice('Export completed.', 'success');
				} else {
					showNotice(response.data.message, 'error');
				}
			})
			.fail(function () {
				showNotice('Export failed.', 'error');
			})
			.always(function () {
				setProcessing(false);
			});
		});

		// Import handler.
		$('#sf-log-import-file').on('change', function (e) {
			var file = e.target.files[0];

			if (!file) {
				return;
			}

			if (!file.name.endsWith('.json')) {
				showNotice(securefusionLog.invalidFile, 'error');
				$(this).val('');
				return;
			}

			if (!window.confirm(securefusionLog.confirmImport)) {
				$(this).val('');
				return;
			}

			var reader = new FileReader();

			reader.onload = function (event) {
				var content = event.target.result;

				try {
					JSON.parse(content);
				} catch (ex) {
					showNotice(securefusionLog.invalidFile, 'error');
					return;
				}

				setProcessing(true);

				$.post(securefusionLog.ajaxUrl, {
					action: 'securefusion_log_import',
					nonce: securefusionLog.nonce,
					import_data: content
				})
				.done(function (response) {
					if (response.success) {
						showNotice(response.data.message, 'success');
						setTimeout(function () {
							window.location.reload();
						}, 1500);
					} else {
						showNotice(response.data.message, 'error');
					}
				})
				.fail(function () {
					showNotice(securefusionLog.importError, 'error');
				})
				.always(function () {
					setProcessing(false);
				});
			};

			reader.readAsText(file);
			$(this).val('');
		});


		// ===== IP Range Detail Modal =====

		var $modal    = $('#sf-range-modal');
		var $textarea = $('#sf-range-modal-textarea');
		var $title    = $('#sf-range-modal-title');
		var $copyBtn  = $('#sf-range-copy-btn');
		var $copyStatus = $('#sf-range-copy-status');

		/**
		 * Open the range detail modal with IP list.
		 *
		 * @param {string} rangePrefix The /24 range prefix (e.g. '192.168.1').
		 */
		function openRangeModal(rangePrefix) {
			$title.text('Loading...');
			$textarea.val('');
			$copyStatus.text('');
			$modal.fadeIn(200);

			$.post(securefusionLog.ajaxUrl, {
				action: 'securefusion_log_range_ips',
				nonce: securefusionLog.nonce,
				range_prefix: rangePrefix
			})
			.done(function (response) {
				if (response.success) {
					$title.text(response.data.title);
					$textarea.val(response.data.ips.join('\n'));

					// Auto-resize textarea to fit content (max 20 rows).
					var lineCount = Math.min(response.data.ips.length, 20);
					$textarea.attr('rows', Math.max(lineCount, 3));
				} else {
					$title.text('Error');
					$textarea.val(response.data.message);
				}
			})
			.fail(function () {
				$title.text('Error');
				$textarea.val('Failed to load IP list.');
			});
		}

		// Detail button click.
		$('.sf-range-detail-btn').on('click', function (e) {
			e.preventDefault();
			var rangePrefix = $(this).data('range');
			if (rangePrefix) {
				openRangeModal(rangePrefix);
			}
		});

		// Close modal.
		$('#sf-range-modal-close').on('click', function () {
			$modal.fadeOut(200);
		});

		// Close modal on backdrop click.
		$modal.on('click', function (e) {
			if (e.target === this) {
				$modal.fadeOut(200);
			}
		});

		// Close modal on Escape key.
		$(document).on('keydown', function (e) {
			if (e.key === 'Escape' && $modal.is(':visible')) {
				$modal.fadeOut(200);
			}
		});

		// Copy to clipboard.
		$copyBtn.on('click', function () {
			var text = $textarea.val();

			if (!text) {
				return;
			}

			// Modern Clipboard API with fallback.
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(text).then(function () {
					$copyStatus.text(securefusionLog.copied).fadeIn(100);
					setTimeout(function () {
						$copyStatus.fadeOut(300);
					}, 2000);
				}).catch(function () {
					fallbackCopy();
				});
			} else {
				fallbackCopy();
			}
		});

		/**
		 * Fallback copy: select textarea content for manual copy.
		 */
		function fallbackCopy() {
			$textarea[0].select();
			$textarea[0].setSelectionRange(0, 99999);

			try {
				document.execCommand('copy');
				$copyStatus.text(securefusionLog.copied).fadeIn(100);
				setTimeout(function () {
					$copyStatus.fadeOut(300);
				}, 2000);
			} catch (err) {
				$copyStatus.text(securefusionLog.copyFailed).fadeIn(100);
				setTimeout(function () {
					$copyStatus.fadeOut(300);
				}, 3000);
			}
		}
	});
})(jQuery);
