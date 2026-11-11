/**
 * Security notifications at the bottom right, for administrators only.
 *
 * Blocked content comes from the browser's own securitypolicyviolation event, so nothing is
 * requested until a button is pressed. Server notices are asked for at most once per interval.
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

	function wants(category) {
		return config.categories.indexOf(category) !== -1;
	}

	// Storage can be unavailable (private mode, blocked cookies); notifications then simply repeat.
	function read(store, key) {
		try {
			return JSON.parse(window[store].getItem(key)) || {};
		} catch (error) {
			return {};
		}
	}

	function remember(store, key, name) {
		try {
			var list = read(store, key);
			var names = Object.keys(list);

			if (names.length >= IGNORE_LIMIT) {
				delete list[names[0]];
			}

			list[name] = 1;
			window[store].setItem(key, JSON.stringify(list));
		} catch (error) {
			// Nothing to do.
		}
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

	// Replace a toast's content with the outcome of its action.
	function settle(toast, message, reload) {
		toast.querySelector('.securefusion-toast__text').textContent = message;

		var actions = toast.querySelector('.securefusion-toast__actions');
		var mute = toast.querySelector('.securefusion-toast__mute');

		actions.textContent = '';

		if (mute) {
			mute.parentNode.removeChild(mute);
		}

		if (reload) {
			var button = element('button', 'securefusion-toast__button securefusion-toast__button--primary', text.reload);

			button.type = 'button';
			button.addEventListener('click', function () {
				window.location.reload();
			});
			actions.appendChild(button);

			return;
		}

		window.setTimeout(function () {
			close(toast);
		}, 6000);
	}

	function run(toast, data, reloadable) {
		var buttons = toast.querySelectorAll('button');

		Array.prototype.forEach.call(buttons, function (button) {
			button.disabled = true;
		});

		toast.setAttribute('aria-busy', 'true');

		request(data).then(function (answer) {
			toast.removeAttribute('aria-busy');
			settle(toast, answer.message || '', reloadable && answer.reload);
		}).catch(function (error) {
			toast.removeAttribute('aria-busy');
			toast.querySelector('.securefusion-toast__text').textContent = error.message || text.error;

			Array.prototype.forEach.call(buttons, function (button) {
				button.disabled = false;
			});
		});
	}

	function build(notice) {
		var toast = element('div', 'securefusion-toast securefusion-toast--' + notice.category);
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

		if (notice.subject) {
			toast.appendChild(element('p', 'securefusion-toast__subject', notice.subject));
		}

		toast.appendChild(element('p', 'securefusion-toast__text', notice.text));

		(notice.actions || []).forEach(function (action) {
			var control;

			if (action.url) {
				control = element('a', 'securefusion-toast__button', action.label);
				control.href = action.url;
			} else {
				control = element('button', 'securefusion-toast__button', action.label);
				control.type = 'button';
				control.addEventListener('click', function () {
					action.run(toast);
				});
			}

			if (action.primary) {
				control.className += ' securefusion-toast__button--primary';
			}

			actions.appendChild(control);
		});

		toast.appendChild(actions);

		var mute = element('button', 'securefusion-toast__mute', text.mute);

		mute.type = 'button';
		mute.addEventListener('click', function () {
			config.categories = config.categories.filter(function (category) {
				return category !== notice.category;
			});
			run(toast, { operation: 'mute', category: notice.category }, false);
		});
		toast.appendChild(mute);

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

		queue.push(notice);
		show();
	}

	function blocked(event) {
		var directive = String(event.effectiveDirective || event.violatedDirective || '').split(' ')[0];
		var uri = String(event.blockedURI || '');
		var title = event.disposition === 'report' ? text.wouldBlock : text.blocked;
		var key;

		// Two things the policy can only allow as a whole: runtime code and handler attributes.
		var whole = /eval$/.test(uri) ? 'eval' : (uri === 'inline' && directive === 'script-src-attr' ? 'handler' : '');

		if (whole) {
			key = whole + ' ' + window.location.pathname;

			if (known[key] || read('localStorage', IGNORE_KEY)[key] || read('sessionStorage', CLOSED_KEY)[key]) {
				return;
			}

			known[key] = 1;

			push({
				category: 'csp',
				title: title,
				subject: text[whole + 'Type'],
				text: text[whole],
				onClose: function () {
					remember('sessionStorage', CLOSED_KEY, key);
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
							remember('localStorage', IGNORE_KEY, key);
							close(toast);
						}
					}
				]
			});

			return;
		}

		if (uri === 'inline') {
			key = 'inline ' + window.location.pathname;

			if (!config.strict || known[key] || read('sessionStorage', CLOSED_KEY)[key]) {
				return;
			}

			known[key] = 1;

			push({
				category: 'csp',
				title: title,
				subject: text.inlineType,
				text: text.inline,
				onClose: function () {
					remember('sessionStorage', CLOSED_KEY, key);
				},
				actions: [{ label: text.review, url: config.review, primary: true }]
			});

			return;
		}

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

		key = type + ' ' + link.origin;

		if (known[key] || read('localStorage', IGNORE_KEY)[key] || read('sessionStorage', CLOSED_KEY)[key]) {
			return;
		}

		known[key] = 1;

		push({
			category: 'csp',
			title: title,
			subject: text.types[type] + ': ' + link.host,
			text: text.hint,
			onClose: function () {
				remember('sessionStorage', CLOSED_KEY, key);
			},
			actions: [
				{
					label: text.allow,
					primary: true,
					run: function (toast) {
						run(toast, { operation: 'allow', type: type, url: link.origin + link.pathname }, true);
					}
				},
				{
					label: text.ignore,
					run: function (toast) {
						remember('localStorage', IGNORE_KEY, key);
						close(toast);
					}
				}
			]
		});
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

		request({ operation: 'list' }).then(function (answer) {
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
							return action;
						}

						return {
							label: action.label,
							primary: action.primary,
							run: function (toast) {
								run(toast, { operation: action.operation }, false);
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
