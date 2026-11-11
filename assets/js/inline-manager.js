/**
 * Site scan and approval of what a site loads, grouped by source.
 *
 * @package securefusion
 */
(function ($) {
	'use strict';

	// Cache driver panel: one request per button, the server answers with the new panel.
	$(document).on('click', '.fsf-csp-cache [data-cache-action]', function () {
		var $panel = $(this).closest('.fsf-csp-cache');
		var $status = $panel.find('.fsf-csp-cache__status');

		$panel.find('button').prop('disabled', true);
		$panel.attr('aria-busy', 'true');
		$status.text(securefusionInline.saving);

		$.ajax({
			url: securefusionInline.url,
			method: 'POST',
			timeout: 45000,
			data: {
				action: 'securefusion_csp_cache',
				nonce: $panel.attr('data-nonce'),
				operation: $(this).attr('data-cache-action')
			}
		}).done(function (response) {
			if (!response.success) {
				$status.text(response.data && response.data.message || securefusionInline.error);
				return;
			}

			var $next = $(response.data.html);
			$panel.replaceWith($next);
			$next.filter('.fsf-csp-cache').find('.fsf-csp-cache__status').text(securefusionInline.saved).trigger('focus');
		}).fail(function (xhr) {
			var response = xhr.responseJSON;
			$status.text(response && response.data && response.data.message || securefusionInline.error);
		}).always(function () {
			$panel.find('button').prop('disabled', false);
			$panel.attr('aria-busy', 'false');
		});
	});

	$(function () {
		$('.fsf-inline-manager').each(function () {
			var $manager = $(this);
			var $tab = $manager.closest('.tab-content');
			var $status = $manager.find('.fsf-inline-status');
			var $rows = $manager.find('.fsf-inline-rows');
			var busy = false;
			var finished = $manager.attr('data-scan-status') !== 'running';
			var failures = 0;
			var known = $rows.find('[data-inline-id]').length;
			var pending = [];
			var timer;

			function filterRows() {
				var query = ($manager.find('.fsf-inline-search').val() || '').toLowerCase().trim();
				var onlyPending = $manager.find('.fsf-inline-only-pending').prop('checked');

				$rows.find('.fsf-inline-group').each(function () {
					var $group = $(this);
					var groupMatches = !query || $group.children('summary').text().toLowerCase().indexOf(query) !== -1;
					var visible = 0;

					$group.find('.fsf-inline-record').each(function () {
						var $record = $(this);
						var match = (groupMatches || $record.text().toLowerCase().indexOf(query) !== -1) && (!onlyPending || $record.attr('data-pending') === '1');
						$record.prop('hidden', !match);
						visible += match ? 1 : 0;
					});

					$group.prop('hidden', visible === 0);
				});
			}
			$manager.on('input change', '.fsf-inline-search, .fsf-inline-only-pending', filterRows);

			function showScan(scan) {
				if (!scan) {
					return;
				}

				$manager.find('.fsf-inline-scan-status').text(scan.message);
				$manager.find('.fsf-inline-scan-current').text(scan.status === 'running' ? scan.current : '');
				$manager.find('.fsf-inline-issues').prop('hidden', !(scan.errors || []).length);
				var $errors = $manager.find('.fsf-inline-scan-errors').empty();

				(scan.errors || []).forEach(function (error) {
					$('<li>').text(error).appendTo($errors);
				});

				finished = scan.status !== 'running';
			}

			// Replacing the list must not close what the person has open.
			function replaceRows(html) {
				var open = $rows.find('details[open]').map(function () {
					return $(this).attr('data-inline-id') || $(this).attr('data-inline-source');
				}).get();

				$rows.html(html).find('details').each(function () {
					var key = $(this).attr('data-inline-id') || $(this).attr('data-inline-source');
					$(this).prop('open', open.indexOf(key) !== -1);
				});
			}

			function schedule() {
				window.clearTimeout(timer);

				if (!finished && !busy && !$tab.hasClass('hidden') && !document.hidden) {
					timer = window.setTimeout(function () {
						request('scan');
					}, Math.min(30000, 1200 * Math.pow(2, failures)));
				}
			}

			function request(operation, $button) {
				if (busy) {
					if (operation !== 'scan') { pending.push([operation, $button]); }
					return;
				}

				busy = true;
				window.clearTimeout(timer);

				var $record = $button ? $button.closest('[data-inline-id]') : $();
				var $group = $button ? $button.closest('.fsf-inline-actions') : $();
				var $scope = operation === 'add' ? $button.closest('.fsf-inline-manual') : ($record.length ? $record : $group);
				var data = {
					action: 'securefusion_inline',
					nonce: $manager.attr('data-nonce'),
					operation: operation,
					id: $record.attr('data-inline-id') || ''
				};

				$scope.find('[data-inline-field]').each(function () {
					data[$(this).attr('data-inline-field')] = $(this).val();
				});

				if (operation !== 'scan') {
					$manager.find('button').prop('disabled', true);
					$status.text(securefusionInline.saving);
				}

				$manager.attr('aria-busy', 'true');

				$.ajax({ url: securefusionInline.url, method: 'POST', data: data, timeout: 15000 }).done(function (response) {
					if (!response.success) {
						finished = true;
						$status.text(response.data && response.data.message || securefusionInline.error);
						return;
					}

					failures = 0;

					if (operation !== 'scan' || response.data.count !== known) {
						replaceRows(response.data.html);
						filterRows();
					}

					known = response.data.count;
					showScan(response.data.scan);

					if (operation !== 'scan') {
						$status.text(securefusionInline.saved).trigger('focus');
					}
				}).fail(function (xhr) {
					var response = xhr.responseJSON;
					failures += 1;
					finished = operation !== 'scan' || (xhr.status >= 400 && xhr.status < 500 && xhr.status !== 409 && xhr.status !== 429);
					$status.text(response && response.data && response.data.message || securefusionInline.error);
				}).always(function () {
					busy = false;
					$manager.attr('aria-busy', 'false');

					if (operation !== 'scan') { $manager.find('button').prop('disabled', false); }

					if (pending.length) {
						var next = pending.shift();
						request(next[0], next[1]);
					} else { schedule(); }
				});
			}

			$manager.on('keydown', 'input', function (event) {
				if (event.key === 'Enter') {
					event.preventDefault();
				}
			});

			$manager.on('click', '[data-inline-action]', function () {
				var question = $(this).attr('data-confirm');

				// eslint-disable-next-line no-alert -- Approving everything needs an explicit decision.
				if (question && !window.confirm(question)) {
					return;
				}

				request($(this).attr('data-inline-action'), $(this));
			});

			new MutationObserver(schedule).observe($tab[0], { attributes: true, attributeFilter: ['class'] });
			document.addEventListener('visibilitychange', schedule);
			filterRows();
			schedule();
		});
	});
}(jQuery));
