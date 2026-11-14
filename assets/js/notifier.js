/**
 * Security notifications at the bottom right, for administrators only.
 *
 * Blocked content comes from the browser's own securitypolicyviolation event and is gathered into
 * one box per kind and page, so a page with ten blocked hosts asks once, not ten times. A violation
 * never causes a request: nothing is sent and nothing changes until a button is pressed, and one
 * press sends one request. Server notices are asked for at most once per interval.
 *
 * @package securefusion
 */
(function () {
	'use strict';

	var config = window.securefusionNotifier;

	if (!config || !config.text) {
		return;
	}

	var text = config.text;
	var VISIBLE = 3;
	var QUEUE_LIMIT = 12;
	var IGNORE_LIMIT = 200;
	var EVENT_LIMIT = 200;
	var LIST_LIMIT = 4;
	var CODE_LIMIT = 65536;
	var HOST_LIMIT = config.maxHosts || 20;
	var INLINE_LIMIT = config.maxCodes || 10;
	var IGNORE_KEY = 'securefusionIgnored';
	var CLOSED_KEY = 'securefusionClosed';
	var FETCHED_KEY = 'securefusionNoticesAt';
	var TYPES = {
		'script-src': 'script',
		'script-src-elem': 'script',
		'style-src': 'style',
		'style-src-elem': 'style',
		'img-src': 'img',
		'font-src': 'font',
		'frame-src': 'frame',
		'child-src': 'frame',
		'connect-src': 'connect',
		'media-src': 'media',
		'worker-src': 'worker',
		'form-action': 'form_action'
	};

	var root = null;
	var queue = [];
	var known = {};
	var visible = 0;
	var handled = 0;
	var groups = {};

	function wants(category) {
		return config.categories.indexOf(category) !== -1;
	}

	function format(template, value) {
		return String(template).replace('%s', value);
	}

	// Storage can be unavailable (private mode, blocked cookies); notifications then simply repeat.
	function read(store, key) {
		try {
			var list = JSON.parse(window[store].getItem(key));

			return list && typeof list === 'object' ? list : {};
		} catch (error) {
			return {};
		}
	}

	// Each store is read once; remember() keeps the copy and the store in step.
	var stores = {
		localStorage: { key: IGNORE_KEY, list: read('localStorage', IGNORE_KEY) },
		sessionStorage: { key: CLOSED_KEY, list: read('sessionStorage', CLOSED_KEY) }
	};

	function remember(store, name) {
		var entry = stores[store];
		var names = Object.keys(entry.list);

		if (names.length >= IGNORE_LIMIT) {
			delete entry.list[names[0]];
		}

		entry.list[name] = 1;

		try {
			window[store].setItem(entry.key, JSON.stringify(entry.list));
		} catch (error) {
			// Nothing to do.
		}
	}

	function seen(key) {
		return known[key] || stores.localStorage.list[key] || stores.sessionStorage.list[key];
	}

	function request(data) {
		var body = new URLSearchParams();

		body.append('action', 'securefusion_notices');
		body.append('nonce', config.nonce);

		Object.keys(data).forEach(function (name) {
			body.append(name, data[name]);
		});

		return fetch(config.url, { method: 'POST', credentials: 'same-origin', body: body })
			.then(function (response) {
				return response.json();
			})
			.then(function (answer) {
				if (!answer || !answer.success) {
					throw new Error(answer && answer.data && answer.data.message || text.error);
				}

				return answer.data || {};
			});
	}

	// Only links to web pages; anything else (javascript:, data:) is not rendered.
	function safeUrl(url) {
		try {
			return /^https?:$/.test(new URL(url, window.location.href).protocol);
		} catch (error) {
			return false;
		}
	}

	function element(tag, className, content) {
		var node = document.createElement(tag);

		node.className = className;

		if (content) {
			node.textContent = content;
		}

		return node;
	}

	function close(toast) {
		if (!toast.parentNode) {
			return;
		}

		toast.parentNode.removeChild(toast);
		visible--;
		show();
	}

	function button(label, primary, onClick) {
		var control = element('button', 'securefusion-toast__button' + (primary ? ' securefusion-toast__button--primary' : ''), label);

		control.type = 'button';
		control.addEventListener('click', onClick);

		return control;
	}

	// Replace a toast's content with the outcome of its action.
	function settle(toast, message, reload) {
		var actions = toast.querySelector('.securefusion-toast__actions');
		var mute = toast.querySelector('.securefusion-toast__mute');
		var subject = toast.querySelector('.securefusion-toast__subject');

		toast.querySelector('.securefusion-toast__text').textContent = message;
		actions.textContent = '';

		if (mute) {
			mute.parentNode.removeChild(mute);
		}

		if (subject) {
			subject.parentNode.removeChild(subject);
		}

		if (reload) {
			actions.appendChild(button(text.reload, true, function () {
				window.location.reload();
			}));

			return;
		}

		window.setTimeout(function () {
			close(toast);
		}, 6000);
	}

	// One request for one press; the box keeps the answer.
	function run(toast, data, reloadable) {
		var buttons = toast.querySelectorAll('button');

		toast.dataset.busy = '1';

		Array.prototype.forEach.call(buttons, function (control) {
			control.disabled = true;
		});

		toast.setAttribute('aria-busy', 'true');

		request(data).then(function (answer) {
			toast.removeAttribute('aria-busy');
			settle(toast, answer.message || '', reloadable && answer.reload);
		}).catch(function (error) {
			toast.removeAttribute('aria-busy');
			delete toast.dataset.busy;
			toast.querySelector('.securefusion-toast__text').textContent = error.message || text.error;

			Array.prototype.forEach.call(buttons, function (control) {
				control.disabled = false;
			});
		});
	}

	function build(notice) {
		var toast = element('div', 'securefusion-toast securefusion-toast--' + notice.tone);
		var head = element('div', 'securefusion-toast__head');
		var dismiss = element('button', 'securefusion-toast__close', '×');
		var actions = element('div', 'securefusion-toast__actions');

		toast.setAttribute('role', 'status');
		dismiss.type = 'button';
		dismiss.setAttribute('aria-label', text.dismiss);
		dismiss.addEventListener('click', function () {
			if (notice.onClose) {
				notice.onClose();
			}

			close(toast);
		});

		head.appendChild(element('strong', 'securefusion-toast__title', notice.title));
		head.appendChild(dismiss);
		toast.appendChild(head);
		toast.appendChild(element('p', 'securefusion-toast__subject', notice.subject || ''));
		toast.appendChild(element('p', 'securefusion-toast__text', notice.text));

		(notice.actions || []).forEach(function (action) {
			var control;

			if (action.url) {
				if (!safeUrl(action.url)) {
					return;
				}

				control = element('a', 'securefusion-toast__button' + (action.primary ? ' securefusion-toast__button--primary' : ''), action.label);
				control.href = action.url;
			} else if (action.run) {
				control = button(action.label, action.primary, function () {
					action.run(toast);
				});
			} else {
				return;
			}

			actions.appendChild(control);
		});

		toast.appendChild(actions);

		if (notice.mutable !== false) {
			var mute = element('button', 'securefusion-toast__mute', text.mute);

			mute.type = 'button';
			mute.addEventListener('click', function () {
				config.categories = config.categories.filter(function (category) {
					return category !== notice.category;
				});
				run(toast, { operation: 'mute', category: notice.category }, false);
			});
			toast.appendChild(mute);
		}

		notice.toast = toast;

		return toast;
	}

	function show() {
		if (!document.body) {
			return;
		}

		while (visible < VISIBLE && queue.length) {
			var notice = queue.shift();

			if (!wants(notice.category)) {
				continue;
			}

			if (!root) {
				root = element('div', 'securefusion-toasts');
				root.setAttribute('role', 'region');
				root.setAttribute('aria-label', text.region);
				document.body.appendChild(root);
			}

			root.appendChild(build(notice));
			visible++;
		}
	}

	function push(notice) {
		if (queue.length >= QUEUE_LIMIT) {
			return;
		}

		notice.tone = notice.tone || notice.category;
		queue.push(notice);
		show();
	}

	// Short lines for a list of items, with a count for the rest.
	function listing(lines) {
		var shown = lines.slice(0, LIST_LIMIT);

		if (lines.length > LIST_LIMIT) {
			shown.push(format(text.more, lines.length - LIST_LIMIT));
		}

		return shown.join('\n');
	}

	/*
	 * One box per kind on this page. It is created with the first item and grows with the next ones,
	 * up to limit items (what one request accepts); make(group) returns the notice, describe(group)
	 * refreshes its list.
	 */
	function grouped(name, item, limit, make, describe) {
		var group = groups[name];

		// A box that already acted keeps its answer; what comes later starts a new one.
		if (group && group.notice.toast && group.notice.toast.dataset.busy) {
			group = null;
		}

		if (!group) {
			group = groups[name] = { name: name, items: [], notice: null };
		}

		if (group.items.length >= limit) {
			return;
		}

		group.items.push(item);

		if (!group.notice) {
			group.notice = make(group);
			describe(group);
			push(group.notice);

			return;
		}

		describe(group);

		var toast = group.notice.toast;

		if (toast && !toast.dataset.busy) {
			toast.querySelector('.securefusion-toast__subject').textContent = group.notice.subject;
		}
	}

	function ignoreAll(group) {
		group.items.forEach(function (item) {
			remember('localStorage', item.key);
		});
	}

	function closeAll(group) {
		group.items.forEach(function (item) {
			remember('sessionStorage', item.key);
		});

		if (groups[group.name] === group) {
			delete groups[group.name];
		}
	}

	function host(item, title) {
		grouped('host', item, HOST_LIMIT, function (group) {
			return {
				category: 'csp',
				title: title,
				text: text.hint,
				onClose: function () {
					closeAll(group);
				},
				actions: [
					{
						label: text.allow,
						primary: true,
						run: function (toast) {
							run(toast, {
								operation: 'allow_hosts',
								items: JSON.stringify(group.items.map(function (entry) {
									return { type: entry.type, url: entry.url };
								}))
							}, true);
						}
					},
					{
						label: text.ignore,
						run: function (toast) {
							ignoreAll(group);
							close(toast);
						}
					}
				]
			};
		}, function (group) {
			group.notice.subject = listing(group.items.map(function (entry) {
				return text.types[entry.type] + ': ' + entry.host;
			}));
		});
	}

	function inline(item, title) {
		grouped('inline', item, INLINE_LIMIT, function (group) {
			return {
				category: 'csp',
				title: title,
				text: text.inline,
				onClose: function () {
					closeAll(group);
				},
				actions: [
					{
						label: text.allowCode,
						primary: true,
						run: function (toast) {
							run(toast, {
								operation: 'allow_inline',
								items: JSON.stringify(group.items.map(function (entry) {
									return { type: entry.type, code: entry.code };
								}))
							}, true);
						}
					},
					{ label: text.review, url: config.review }
				]
			};
		}, function (group) {
			group.notice.subject = listing(group.items.map(function (entry) {
				var line = entry.code.replace(/\s+/g, ' ').trim();

				return (entry.type === 'style' ? 'CSS: ' : 'JS: ') + (line.length > 70 ? line.slice(0, 70) + '…' : line);
			}));
		});
	}

	// A small, stable key for code, so the same block is recognized on the next page.
	function fingerprint(code) {
		var hash = 5381;

		for (var i = 0; i < code.length; i++) {
			hash = ((hash << 5) + hash + code.charCodeAt(i)) | 0;
		}

		return code.length + '.' + (hash >>> 0).toString(36);
	}

	function blockedWhole(whole, title) {
		var key = whole + ' ' + window.location.pathname;

		if (seen(key)) {
			return;
		}

		known[key] = 1;

		push({
			category: 'csp',
			title: title,
			subject: text[whole + 'Type'],
			text: text[whole],
			onClose: function () {
				remember('sessionStorage', key);
			},
			actions: [
				{
					label: text.allow,
					primary: true,
					run: function (toast) {
						run(toast, { operation: whole === 'eval' ? 'allow_eval' : 'allow_handlers' }, true);
					}
				},
				{
					label: text.ignore,
					run: function (toast) {
						remember('localStorage', key);
						close(toast);
					}
				}
			]
		});
	}

	function blockedInline(event, directive, title) {
		var target = event.target;
		var tag = target && target.tagName ? target.tagName.toLowerCase() : '';
		var type = /^script-src/.test(directive) ? 'script' : (/^style-src/.test(directive) ? 'style' : '');
		var code = (tag === 'script' || tag === 'style') && !target.src ? target.textContent : '';

		// Attributes such as style="" cannot be approved by their text; the review lists them.
		if (!type || type !== tag || !code || !code.trim() || code.length > CODE_LIMIT) {
			var key = 'inline ' + window.location.pathname;

			if (seen(key)) {
				return;
			}

			known[key] = 1;

			push({
				category: 'csp',
				title: title,
				subject: text.inlineType,
				text: text.inlineReview,
				onClose: function () {
					remember('sessionStorage', key);
				},
				actions: [{ label: text.review, url: config.review, primary: true }]
			});

			return;
		}

		var item = { type: type, code: code, key: 'code ' + type + ' ' + fingerprint(code) };

		if (seen(item.key)) {
			return;
		}

		known[item.key] = 1;
		inline(item, title);
	}

	function blockedHost(directive, uri, title) {
		var type = TYPES[directive];
		var link;

		if (!type || config.limited.indexOf(type) === -1) {
			return;
		}

		try {
			link = new URL(uri);
		} catch (error) {
			return;
		}

		if (!/^(https?|wss?):$/.test(link.protocol) || link.origin === window.location.origin) {
			return;
		}

		var item = { type: type, host: link.host, url: link.origin + link.pathname, key: type + ' ' + link.origin };

		if (seen(item.key)) {
			return;
		}

		known[item.key] = 1;
		host(item, title);
	}

	function blocked(event) {
		// A page that keeps violating (a loop, a broken widget) costs a bounded amount of work.
		if (++handled > EVENT_LIMIT) {
			document.removeEventListener('securitypolicyviolation', blocked);

			return;
		}

		var directive = String(event.effectiveDirective || event.violatedDirective || '').split(' ')[0];
		var uri = String(event.blockedURI || '');
		var title = event.disposition !== 'report' ? text.blocked : text.wouldBlock;

		// Two things the policy can only allow as a whole: runtime code and handler attributes.
		if (/eval$/.test(uri)) {
			blockedWhole('eval', title);
		} else if (uri === 'inline' && directive === 'script-src-attr') {
			blockedWhole('handler', title);
		} else if (uri === 'inline') {
			if (config.strict) {
				blockedInline(event, directive, title);
			}
		} else {
			blockedHost(directive, uri, title);
		}
	}

	function server_notices() {
		var last = 0;

		try {
			last = parseInt(window.localStorage.getItem(FETCHED_KEY), 10) || 0;

			if (Date.now() - last < config.interval * 1000) {
				return;
			}

			window.localStorage.setItem(FETCHED_KEY, String(Date.now()));
		} catch (error) {
			// Without storage the interval cannot be kept, so these notices are skipped.
			return;
		}

		request({ operation: 'list', activity: wants('activity') ? '1' : '' }).then(function (answer) {
			(answer.notices || []).forEach(function (notice) {
				push({
					category: notice.category,
					title: notice.title,
					text: notice.text,
					onClose: function () {
						request({ operation: 'dismiss', id: notice.id }).catch(function () {});
					},
					actions: (notice.actions || []).map(function (action) {
						if (action.url) {
							return { label: action.label, primary: action.primary, url: action.url };
						}

						return {
							label: action.label,
							primary: action.primary,
							run: function (toast) {
								run(toast, { operation: action.operation }, true);
							}
						};
					})
				});
			});
		}).catch(function () {});
	}

	if (wants('csp') && (config.limited.length || config.strict)) {
		document.addEventListener('securitypolicyviolation', blocked);
	}

	function ready() {
		show();

		if (wants('status') || wants('activity')) {
			// After the page settled: these notices are never urgent.
			window.setTimeout(server_notices, 2000);
		}
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', ready);
	} else {
		ready();
	}
})();
