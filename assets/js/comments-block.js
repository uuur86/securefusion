/**
 * comments-block.js
 *
 * AJAX handlers for blocking spam comment IPs.
 */

jQuery(document).ready(function($) {
	if (typeof sfCommentsBlock === 'undefined') {
		return;
	}

	// 1. Single-row Block/Unblock toggle
	$(document).on('click', '.sf-comment-toggle-ip-btn', function(e) {
		e.preventDefault();
		var $btn = $(this);
		var ip = $btn.data('ip');
		var currentAction = $btn.data('action'); // 'block' or 'unblock'

		var confirmMsg = currentAction === 'block' ? sfCommentsBlock.confirmBlock : sfCommentsBlock.confirmUnblock;
		if (!confirm(confirmMsg + ' (' + ip + ')')) {
			return;
		}

		$btn.addClass('sf-loading').text(sfCommentsBlock.processing);

		$.post(sfCommentsBlock.ajaxUrl, {
			action: 'securefusion_toggle_comment_ip_block',
			nonce: sfCommentsBlock.nonce,
			ip: ip,
			block_action: currentAction
		}, function(response) {
			if (response.success) {
				// Success, toggle action state
				if (currentAction === 'block') {
					// Switch to unblock
					$btn.data('action', 'unblock')
						.text(sfCommentsBlock.unblockText)
						.css('color', '#2271b1')
						.removeClass('sf-loading');
				} else {
					// Switch to block
					$btn.data('action', 'block')
						.text(sfCommentsBlock.blockText)
						.css('color', '#d63638')
						.removeClass('sf-loading');
				}
				showNotice('success', response.data.message || sfCommentsBlock.successText);
			} else {
				$btn.removeClass('sf-loading').text(currentAction === 'block' ? sfCommentsBlock.blockText : sfCommentsBlock.unblockText);
				showNotice('error', response.data.message || sfCommentsBlock.errorText);
			}
		}).fail(function() {
			$btn.removeClass('sf-loading').text(currentAction === 'block' ? sfCommentsBlock.blockText : sfCommentsBlock.unblockText);
			showNotice('error', sfCommentsBlock.errorText);
		});
	});

	// 2. Bulk Block Spam IPs/Ranges
	$(document).on('click', '#sf-block-spam-btn', function(e) {
		e.preventDefault();
		var $btn = $(this);
		var blockRanges = $('#sf-block-ranges-chk').is(':checked') ? '1' : '0';

		if (!confirm(sfCommentsBlock.confirmBulk)) {
			return;
		}

		$btn.prop('disabled', true).text(sfCommentsBlock.processing);

		$.post(sfCommentsBlock.ajaxUrl, {
			action: 'securefusion_block_all_spam_ips',
			nonce: sfCommentsBlock.nonce,
			block_ranges: blockRanges
		}, function(response) {
			$btn.prop('disabled', false).html('<span class="dashicons dashicons-shield-alt"></span> ' + $btn.text().replace(sfCommentsBlock.processing, '').trim());
			if (response.success) {
				showNotice('success', response.data.message || sfCommentsBlock.successText);
				// Reload page after 2 seconds to show updated row actions
				setTimeout(function() {
					window.location.reload();
				}, 1800);
			} else {
				showNotice('error', response.data.message || sfCommentsBlock.errorText);
			}
		}).fail(function() {
			$btn.prop('disabled', false).html('<span class="dashicons dashicons-shield-alt"></span> ' + $btn.text().replace(sfCommentsBlock.processing, '').trim());
			showNotice('error', sfCommentsBlock.errorText);
		});
	});

	// Helper to display dismissible admin notice at the top of the wrap
	function showNotice(type, message) {
		// Remove existing notice
		$('.sf-dynamic-notice').remove();

		var noticeHtml = '<div class="notice notice-' + type + ' is-dismissible sf-dynamic-notice" style="margin-top: 15px;"><p>' + message + '</p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>';
		
		// Insert notice before the main h1/h2 header page container or list table
		var $target = $('.wrap h1, .wrap h2').first();
		if ($target.length) {
			$target.after(noticeHtml);
		} else {
			$('#wpbody-content .wrap').prepend(noticeHtml);
		}

		// Handle dismiss button click
		$(document).on('click', '.sf-dynamic-notice .notice-dismiss', function() {
			$(this).parent().fadeOut('fast', function() {
				$(this).remove();
			});
		});
	}
});
