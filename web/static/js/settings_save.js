/**
 * Amnezia Nexus - commit for the staged Settings cards.
 *
 * Appearance, SSL, Captcha, Connection limits, Telegram and the Gigahost
 * credentials are each committed by the control inside their own card. The
 * endpoint is unchanged: POST /api/settings/save.
 *
 * The server owns what a card may change: it writes only the sections a request
 * carries and leaves the rest as stored, and it keeps a stored secret when the
 * field arrives empty or masked. A card therefore posts exactly its own section
 * and nothing else, so a save here cannot restore another card's older value,
 * whatever another tab saved in the meantime.
 *
 * Commits are still queued, one after another in this document, so a card never
 * starts while another card's request is in flight and the status regions
 * report in the order the operator clicked.
 */
(function (root) {
    'use strict';

    var SAVE_URL = '/api/settings/save';
    var NAVIGATE_DELAY_MS = 800;
    var SECRET_MASK = '********';

    var CARDS = {
        appearance: 'appearanceCard',
        captcha: 'captchaCard',
        ssl: 'sslCard',
        limits: 'limitsCard',
        telegram: 'telegramCard',
        gigahost: 'gigahostCard'
    };

    var chain = Promise.resolve();
    var loadedLanguage = null;
    var loadedTitle = '';

    function tr(key) {
        return typeof root._ === 'function' ? root._(key) : key;
    }

    function field(id) {
        return root.document.getElementById(id);
    }

    function text(id) {
        var node = field(id);
        return node ? node.value : '';
    }

    function trimmed(id) {
        return text(id).trim();
    }

    function checked(id) {
        var node = field(id);
        return node ? node.checked : false;
    }

    // collectors read one card's fields exactly as the page-level save used to.
    var collectors = {
        appearance: function () {
            return {
                title: text('app_title'),
                logo: text('app_logo'),
                subtitle: text('app_subtitle'),
                language: text('appearance_language')
            };
        },
        captcha: function () {
            return { enabled: checked('captcha_enabled') };
        },
        ssl: function () {
            return {
                enabled: checked('ssl_enabled'),
                domain: trimmed('ssl_domain'),
                cert_path: trimmed('ssl_cert_path'),
                key_path: trimmed('ssl_key_path'),
                cert_text: trimmed('ssl_cert_text'),
                key_text: trimmed('ssl_key_text'),
                panel_port: parseInt(text('panel_port') || '5000')
            };
        },
        limits: function () {
            return {
                max_connections_per_user: parseInt(text('max_connections_per_user')) || 10,
                connection_rate_limit_count: parseInt(text('connection_rate_limit_count')) || 5,
                connection_rate_limit_window: parseInt(text('connection_rate_limit_window')) || 60
            };
        },
        telegram: function () {
            return {
                enabled: checked('telegram_enabled'),
                bot_token: trimmed('telegram_bot_token'),
                chat_id: trimmed('telegram_chat_id')
            };
        },
        gigahost: function () {
            return { api_key: trimmed('gigahost_api_key') };
        }
    };

    function cards() {
        return root.SettingsCards;
    }

    function cardNode(key) {
        return field(CARDS[key]);
    }

    function failure(err) {
        return (err && err.message) || tr('error');
    }

    // buildBody returns the request for one card: its own section, read from the
    // screen, and no other.
    function buildBody(key) {
        var body = {};
        body[key] = collectors[key]();
        return body;
    }

    // secrets are write-only: the server keeps the stored one when it receives an
    // empty or masked value, so the field goes back to what a fresh load shows.
    function resetSecrets(card) {
        Array.prototype.forEach.call(card.querySelectorAll('[data-secret]'), function (control) {
            if (control.getAttribute('data-secret') === 'clear') {
                control.value = '';
            } else if (control.value !== '') {
                control.value = SECRET_MASK;
            }
        });
    }

    function languageChanged(key, body) {
        return key === 'appearance' && loadedLanguage !== null && body.appearance.language !== loadedLanguage;
    }

    // showAppearance brings the server-rendered shell in line with what was just
    // saved, so the sidebar does not keep showing the old title until a reload.
    function showAppearance(appearance) {
        var doc = root.document;
        var oldTitle = loadedTitle;
        loadedTitle = appearance.title;
        if (oldTitle && appearance.title && doc.title.indexOf(oldTitle) === 0) {
            doc.title = appearance.title + doc.title.slice(oldTitle.length);
        }
        ['.logo-title', '.logo-text'].forEach(function (selector) {
            Array.prototype.forEach.call(doc.querySelectorAll('.app-logo ' + selector), function (node) {
                if (appearance.title) node.textContent = appearance.title;
            });
        });
        Array.prototype.forEach.call(doc.querySelectorAll('.app-logo .logo-badge'), function (node) {
            if (appearance.subtitle) node.textContent = appearance.subtitle;
        });
        // An empty logo keeps the shell's built-in icon, which is not text.
        Array.prototype.forEach.call(doc.querySelectorAll('.app-logo .logo-icon'), function (node) {
            if (appearance.logo) node.textContent = appearance.logo;
        });
    }

    function succeed(key, body, sent) {
        var card = cardNode(key);
        var move = languageChanged(key, body);
        if (key === 'appearance') {
            loadedLanguage = body.appearance.language;
            showAppearance(body.appearance);
        }
        if (cards().changedSince(card, sent)) {
            // The operator kept typing while the request was in flight. What was
            // sent is saved; what is on screen now is not, and must stay marked.
            cards().rebase(card, sent);
        } else {
            resetSecrets(card);
            cards().rebase(card);
        }
        cards().report(card, 'success', tr('settings_saved'));
        // Only a document load re-renders the dictionary, so a language change is
        // the one save that leaves the page. Every other save stays where it is.
        if (move) {
            root.setTimeout(function () { api.navigate('/settings'); }, NAVIGATE_DELAY_MS);
        }
    }

    async function run(key) {
        var card = cardNode(key);
        if (!card || !collectors[key]) return false;
        cards().clearReport(card);
        cards().busy(card, true);
        try {
            var body = buildBody(key);
            var sent = cards().capture(card);
            try {
                await root.API.post(SAVE_URL, body, { silent: true });
            } catch (err) {
                cards().report(card, 'error', failure(err));
                return false;
            }
            succeed(key, body, sent);
            return true;
        } finally {
            cards().busy(card, false);
        }
    }

    // commit queues one card's save behind any save already running.
    function commit(key) {
        var result = chain.then(function () { return run(key); });
        chain = result["catch"](function () { return false; });
        return result;
    }

    function bind(key) {
        var card = cardNode(key);
        var button = card ? card.querySelector('[data-commit]') : null;
        if (button) {
            button.addEventListener('click', function () { commit(key); });
        }
    }

    function init() {
        if (!root.document) return;
        var select = field('appearance_language');
        if (select) loadedLanguage = select.value;
        var title = field('app_title');
        if (title) loadedTitle = title.defaultValue;
        Object.keys(CARDS).forEach(bind);
    }

    var api = {
        init: init,
        commit: commit,
        collect: function (key) { return collectors[key] ? collectors[key]() : null; },
        navigate: function (url) { root.location.assign(url); }
    };
    root.SettingsSave = api;

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }
}(typeof window !== 'undefined' ? window : this));
