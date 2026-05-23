/**
 * Login Log Page Scripts
 *
 * Handles type filter, reset, export, import, IP block/unblock,
 * and IP range detail/copy AJAX actions.
 *
 * @package securefusion
 */

/* global jQuery, securefusionLog */

(function ($) {
	'use strict';

	/**
	 * Get the currently selected log type from the filter dropdown.
	 *
	 * @return {string} The selected log type value (empty string for 'all').
	 */
	function getSelectedLogType() {
		return $('#fynd-sf-filter-log-type').val() || '';
	}

	/**
	 * Show a dismissible notice.
	 *
	 * @param {string} message Notice message.
	 * @param {string} type    Notice type (success|error|info).
	 */
	function showNotice(message, type) {
		var $notice = $('#fynd-sf-log-notice');

		$notice
			.removeClass('fynd-sf-notice-success fynd-sf-notice-error fynd-sf-notice-info')
			.addClass('fynd-sf-notice-' + type)
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
		$('.fynd-sf-log-toolbar').toggleClass('fynd-sf-processing', state);
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

		// ===== Type Filter Change =====
		$('#fynd-sf-filter-log-type').on('change', function () {
			var selectedType = $(this).val();
			var url = new URL(window.location.href);

			if (selectedType) {
				url.searchParams.set('log_type', selectedType);
			} else {
				url.searchParams.delete('log_type');
			}

			// Reset to page 1 on filter change.
			url.searchParams.set('paged', '1');
			window.location.href = url.toString();
		});

		// ===== Reset handler with double confirmation =====
		$('#fynd-sf-log-reset').on('click', function () {
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
				nonce: securefusionLog.nonce,
				log_type: getSelectedLogType()
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

		// ===== Export handler =====
		$('#fynd-sf-log-export').on('click', function () {
			setProcessing(true);

			$.post(securefusionLog.ajaxUrl, {
				action: 'securefusion_log_export',
				nonce: securefusionLog.nonce,
				log_type: getSelectedLogType()
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

		// ===== Import handler =====
		$('#fynd-sf-log-import-file').on('change', function (e) {
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


		// ===== IP Block/Unblock Handler =====
		$(document).on('click', '.fynd-sf-btn-block, .fynd-sf-btn-unblock', function () {
			var $btn       = $(this);
			var ip         = $btn.data('ip');
			var blockAction = $btn.data('action');

			if (blockAction === 'block' && !window.confirm(securefusionLog.confirmBlock)) {
				return;
			}

			$btn.prop('disabled', true).addClass('fynd-sf-processing');

			$.post(securefusionLog.ajaxUrl, {
				action: 'securefusion_toggle_ip_block',
				nonce: securefusionLog.nonce,
				ip: ip,
				block_action: blockAction
			})
			.done(function (response) {
				if (response.success) {
					showNotice(response.data.message, 'success');
					setTimeout(function () {
						window.location.reload();
					}, 1000);
				} else {
					showNotice(response.data.message, 'error');
					$btn.prop('disabled', false).removeClass('fynd-sf-processing');
				}
			})
			.fail(function () {
				showNotice(securefusionLog.blockFailed, 'error');
				$btn.prop('disabled', false).removeClass('fynd-sf-processing');
			});
		});


		// ===== IP Range Detail Modal =====

		var $modal    = $('#fynd-sf-range-modal');
		var $textarea = $('#fynd-sf-range-modal-textarea');
		var $title    = $('#fynd-sf-range-modal-title');
		var $copyBtn  = $('#fynd-sf-range-copy-btn');
		var $copyStatus = $('#fynd-sf-range-copy-status');

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
		$('.fynd-sf-range-detail-btn').on('click', function (e) {
			e.preventDefault();
			var rangePrefix = $(this).data('range');
			if (rangePrefix) {
				openRangeModal(rangePrefix);
			}
		});

		// Close modal.
		$('#fynd-sf-range-modal-close').on('click', function () {
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

		// ===== Payload Detail Modal =====
		var $payloadModal      = $('#fynd-sf-payload-modal');
		var $payloadTextarea   = $('#fynd-sf-payload-text');
		var $copyPayloadBtn    = $('#fynd-sf-copy-payload-modal-btn');

		// View Payload Details button click
		$(document).on('click', '.fynd-sf-view-payload-btn', function (e) {
			e.preventDefault();
			var payload = $(this).data('payload') || '';
			$payloadTextarea.val(payload);
			$payloadModal.fadeIn(200);
		});

		// Close payload modal
		$payloadModal.on('click', '.fynd-sf-modal-close, .fynd-sf-modal-close-btn', function () {
			$payloadModal.fadeOut(200);
		});

		// Close payload modal on backdrop click
		$payloadModal.on('click', function (e) {
			if (e.target === this) {
				$payloadModal.fadeOut(200);
			}
		});

		// Close payload modal on Escape key
		$(document).on('keydown', function (e) {
			if (e.key === 'Escape' && $payloadModal.is(':visible')) {
				$payloadModal.fadeOut(200);
			}
		});

		// Copy payload to clipboard
		$copyPayloadBtn.on('click', function () {
			var text = $payloadTextarea.val();
			if (!text) {
				return;
			}

			var $btn = $(this);
			var originalHTML = $btn.html();

			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(text).then(function () {
					showCopySuccess($btn, originalHTML);
				}).catch(function () {
					fallbackCopyPayload($btn, originalHTML);
				});
			} else {
				fallbackCopyPayload($btn, originalHTML);
			}
		});

		function showCopySuccess($btn, originalHTML) {
			$btn.html('<span class="dashicons dashicons-yes"></span> ' + securefusionLog.copied);
			setTimeout(function () {
				$btn.html(originalHTML);
			}, 2000);
		}

		function fallbackCopyPayload($btn, originalHTML) {
			$payloadTextarea[0].select();
			$payloadTextarea[0].setSelectionRange(0, 99999);
			try {
				document.execCommand('copy');
				showCopySuccess($btn, originalHTML);
			} catch (err) {
				$btn.html('<span class="dashicons dashicons-no"></span> ' + securefusionLog.copyFailed);
				setTimeout(function () {
					$btn.html(originalHTML);
				}, 2000);
			}
		}

		// ===== IP Rules page logic =====
		if (typeof securefusionRules !== 'undefined') {
			// ===== IP Rules Form Submission =====
			$('#fynd-sf-add-rule-form').on('submit', function (e) {
				e.preventDefault();
				var $form = $(this);
				var $submitBtn = $form.find('button[type="submit"]');
				var ip = $('#fynd-sf-rule-ip').val();
				var ruleType = $('#fynd-sf-rule-type').val();

				if (!ip) {
					return;
				}

				$submitBtn.prop('disabled', true).addClass('fynd-sf-processing');

				$.post(securefusionRules.ajaxUrl, {
					action: 'securefusion_add_ip_rule',
					nonce: securefusionRules.nonce,
					ip: ip,
					rule_type: ruleType
				})
				.done(function (response) {
					if (response.success) {
						showRulesNotice(securefusionRules.addSuccess, 'success');
						setTimeout(function () {
							window.location.reload();
						}, 1000);
					} else {
						showRulesNotice(response.data.message || securefusionRules.addFailed, 'error');
						$submitBtn.prop('disabled', false).removeClass('fynd-sf-processing');
					}
				})
				.fail(function () {
					showRulesNotice(securefusionRules.addFailed, 'error');
					$submitBtn.prop('disabled', false).removeClass('fynd-sf-processing');
				});
			});

			// ===== IP Rules Deletion =====
			$(document).on('click', '.fynd-sf-remove-rule-btn', function () {
				var $btn = $(this);
				var ip = $btn.data('ip');

				if (!window.confirm(securefusionRules.confirmDelete)) {
					return;
				}

				$btn.prop('disabled', true).addClass('fynd-sf-processing');

				$.post(securefusionRules.ajaxUrl, {
					action: 'securefusion_delete_ip_rule',
					nonce: securefusionRules.nonce,
					ip: ip
				})
				.done(function (response) {
					if (response.success) {
						showRulesNotice(securefusionRules.deleteSuccess, 'success');
						setTimeout(function () {
							window.location.reload();
						}, 1000);
					} else {
						showRulesNotice(response.data.message || securefusionRules.deleteFailed, 'error');
						$btn.prop('disabled', false).removeClass('fynd-sf-processing');
					}
				})
				.fail(function () {
					showRulesNotice(securefusionRules.deleteFailed, 'error');
					$btn.prop('disabled', false).removeClass('fynd-sf-processing');
				});
			});

			function showRulesNotice(message, type) {
				var $notice = $('#fynd-sf-rules-notice');
				$notice
					.removeClass('fynd-sf-notice-success fynd-sf-notice-error fynd-sf-notice-info')
					.addClass('fynd-sf-notice-' + type)
					.text(message)
					.fadeIn(200);

				setTimeout(function () {
					$notice.fadeOut(300);
				}, 5000);
			}
		}
	});
})(jQuery);

