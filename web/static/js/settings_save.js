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
 *
 * Collectors read what the operator entered. They do not fill in a value: a field
 * that cannot be read as the number it declares stops the commit, because a
 * substituted default is what let a card report success for a setting it never
 * stored. The card module rejects an entry the card's markup rejects before any
 * collector runs; the check here is what keeps a card that never reaches it
 * honest. A field the operator left alone holds the stored value, which is sent
 * back as it is: only an entry has to satisfy the range its markup declares.
 * After a save the numeric fields are filled in from the accepted values, so the
 * card shows the setting that was stored.
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
    // The commit already queued or running for each card. A second click, or an
    // Enter that reaches the card before the first request has started, joins it
    // instead of queueing a duplicate.
    var pending = {};
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

    // numberOf reads a field this card sends as a number. What the operator
    // entered is what is sent, or nothing is: a field that cannot be read as the
    // number it declares stops the commit instead of falling back to a default. A
    // default is how a card came to report success for a value it never stored -
    // an entered 0 was read as absent and sent as 10, and the card went on showing
    // the 0 it had.
    function numberOf(id) {
        var node = field(id);
        if (!node) throw new Error(tr('settings_field_invalid'));
        var raw = trimmed(id);
        var value = Number(raw);
        if (raw === '' || !isFinite(value) || !parses(node)) {
            throw new Error(cards() && cards().fieldMessage ? cards().fieldMessage(node) : tr('settings_field_invalid'));
        }
        return value;
    }

    // parses asks the control itself whether the value it holds satisfies the
    // constraints its markup declares. A value the card loaded is exempt: it is
    // already what the server stores, the operator did not type it, and refusing
    // it would leave a card that cannot be saved for a reason nobody caused. The
    // number itself still has to be readable, which numberOf checks before this.
    function parses(node) {
        if (unchanged(node)) return true;
        return typeof node.checkValidity !== 'function' || node.checkValidity();
    }

    // unchanged reports whether a field still holds the value its card loaded, as
    // the card module records it.
    function unchanged(node) {
        var module = cards();
        return !!(module && typeof module.unchanged === 'function' && module.unchanged(node));
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
                panel_port: numberOf('panel_port')
            };
        },
        limits: function () {
            return {
                max_connections_per_user: numberOf('max_connections_per_user'),
                connection_rate_limit_count: numberOf('connection_rate_limit_count'),
                connection_rate_limit_window: numberOf('connection_rate_limit_window')
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

    // STORED_FIELDS names, per card, the fields whose stored value is the number
    // the request carried. They are filled in from the accepted values after a
    // save, so the field shows the setting that was stored rather than the text
    // that produced it: an entry of 007 is stored as 7 and is shown as 7.
    var STORED_FIELDS = {
        limits: ['max_connections_per_user', 'connection_rate_limit_count', 'connection_rate_limit_window'],
        ssl: ['panel_port']
    };

    // showStored writes the accepted values back into the fields the card sent. The
    // server stores the number it decoded from the request unchanged, so the value
    // the card sent is the value it now shows.
    function showStored(key, body) {
        var ids = STORED_FIELDS[key];
        if (!ids) return;
        ids.forEach(function (id) {
            var node = field(id);
            if (node) node.value = String(body[key][id]);
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

    // classify turns what a request threw into the outcome the card module
    // understands. A refusal carries a status from the server; a request that
    // never got an answer has none.
    function classify(err) {
        var answered = err && typeof err.status === 'number' && err.status > 0;
        return { outcome: answered ? 'refused' : 'failed', message: failure(err) };
    }

    // afterStored is what only this module knows to do once a card's section is
    // stored, whether or not the operator kept typing: the shell shows the new
    // title, and a language change is the one save that leaves the page. The move
    // is decided against the language that was loaded before this save.
    function afterStored(key, body) {
        var move = languageChanged(key, body);
        if (key === 'appearance') {
            loadedLanguage = body.appearance.language;
            showAppearance(body.appearance);
        }
        if (move) {
            root.setTimeout(function () { api.navigate('/settings'); }, NAVIGATE_DELAY_MS);
        }
    }

    function run(key) {
        var card = cardNode(key);
        if (!card || !collectors[key]) return Promise.resolve(false);
        return cards().submit(card, function () {
            var body = buildBody(key);
            return root.API.post(SAVE_URL, body, { silent: true }).then(function () {
                afterStored(key, body);
                return {
                    outcome: 'saved',
                    message: tr('settings_saved'),
                    // Only when nothing was typed meanwhile: secrets go back to their
                    // masks, which is what a fresh load shows, and the numeric fields
                    // show the value the save stored.
                    reconcile: function () { resetSecrets(card); showStored(key, body); }
                };
            }, classify);
        }).then(function (settled) { return settled.outcome === 'saved'; });
    }

    // commit queues one card's save behind any save already running.
    function commit(key) {
        if (pending[key]) return pending[key];
        var result = chain.then(function () { return run(key); });
        pending[key] = result;
        chain = result["catch"](function () { return false; });
        var release = function () { delete pending[key]; };
        result.then(release, release);
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
