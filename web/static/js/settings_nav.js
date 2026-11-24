/**
 * Amnezia Nexus - in-page navigation for the Settings page.
 *
 * The page is four groups of cards in one document. Every group is a landmark
 * with a stable id, and the sub-navigation is a plain list of anchors pointing
 * at them, so with script off the page still jumps to the group a reader picks.
 * This controller adds the two things an anchor cannot do by itself:
 *
 *   Current group. After any scroll and on every hash change, exactly one link
 *   carries aria-current="true": the last group whose top edge has passed the
 *   line the stuck navigation occupies. No group is ever marked twice, and a
 *   page whose navigation is absent (another page) is left alone.
 *
 *   Focus handoff. Following a link moves focus to the group's heading, which
 *   carries tabindex="-1" and is therefore focusable without joining the tab
 *   order. Without that, the next Tab would go to the link after the one just
 *   used instead of into the group that was asked for.
 *
 * The marking is idempotent: it is a comparison of the current geometry with the
 * links, not a toggle, so running it twice in a row changes nothing.
 */
(function (root) {
    'use strict';

    // The line a group's top edge must pass to count as the current one. It is
    // the height of the stuck navigation (40 px) plus the space around it, which
    // is also the scroll-margin-top the stylesheet gives every group.
    var SETTLE = 88;

    // Following a link lands the group's top edge exactly on SETTLE. A comparison
    // against the exact value then leaves the previous group marked whenever the
    // scroll position lands a fraction of a pixel short, so an exact hit has to
    // count. One pixel is below anything the eye can see and far below a group.
    var TOLERANCE = 1;

    function byId(doc, id) {
        return doc ? doc.getElementById(id) : null;
    }

    function groups(doc) {
        if (!doc || !doc.querySelectorAll) return [];
        return Array.prototype.slice.call(doc.querySelectorAll('.settings-group'));
    }

    function links(doc) {
        if (!doc || !doc.querySelectorAll) return [];
        return Array.prototype.slice.call(doc.querySelectorAll('.settings-subnav-link'));
    }

    // currentGroup returns the group the reader is looking at: the last one whose
    // top edge has passed SETTLE, or the first group when none has (the top of
    // the page).
    function currentGroup(doc) {
        var all = groups(doc);
        if (!all.length) return null;
        var current = all[0];
        for (var i = 0; i < all.length; i++) {
            if (all[i].getBoundingClientRect().top <= SETTLE + TOLERANCE) current = all[i];
        }
        return current;
    }

    // mark writes aria-current on the matching link and removes it from every
    // other one. It returns the id it marked, so a caller (or a test) can see
    // what the page decided.
    function mark(doc) {
        if (!byId(doc, 'settingsSubnav')) return null;
        var current = currentGroup(doc);
        if (!current) return null;
        var href = '#' + current.id;
        links(doc).forEach(function (link) {
            if (link.getAttribute('href') === href) link.setAttribute('aria-current', 'true');
            else link.removeAttribute('aria-current');
        });
        return current.id;
    }

    // The policy surface is its own page. A bookmark, a shared link or a saved
    // browser entry written before the move still names one of the anchors it used
    // to have here, and every one of those fragments now matches nothing in this
    // document. This table is the whole allowed set, keyed by the literal fragment:
    // anything not listed — an ordinary Settings group, a query-only URL, an
    // unknown hash — is left alone for the browser to handle.
    //
    // The target is a fixed same-origin path, so a fragment can never decide where
    // the browser goes: the value is a constant, not something built from the hash.
    // location.replace() rather than assign() is what keeps Back usable — the old
    // URL is replaced in place, so going back reaches the page the reader came
    // from instead of this one, which would hand off again and trap them.
    //
    // The old group fragment is consumed here rather than forwarded as a fragment:
    // the group does not exist on the new page, so the reader arrives at its
    // heading instead of at a fragment that would match nothing there either.
    var LEGACY_POLICY_FRAGMENTS = {
        '#group-network': '/routing',
        '#group-network-title': '/routing',
        '#policyRoutingCard': '/routing#policyRoutingCard',
        '#policyClientCard': '/routing#policyClientCard'
    };

    // handOffLegacyFragment replaces a Settings document whose fragment names a
    // policy surface that has moved. It answers whether it took over, so a caller
    // stops treating the location as a position on this page.
    function handOffLegacyFragment(loc) {
        if (!loc || loc.pathname !== '/settings') return false;
        var hash = loc.hash || '';
        if (!Object.prototype.hasOwnProperty.call(LEGACY_POLICY_FRAGMENTS, hash)) return false;
        loc.replace(LEGACY_POLICY_FRAGMENTS[hash]);
        return true;
    }

    // focusGroup moves focus to the group's own heading. The heading is the
    // landmark's accessible name, so the reader arrives at "Portal, heading
    // level 2" instead of at the first field with no context.
    //
    // The focus call must not scroll: the anchor already scrolls to the group,
    // and a scrolling focus cancels that jump halfway, leaving the heading part
    // way down the viewport instead of at the top of the group.
    function focusGroup(doc, groupId) {
        var heading = byId(doc, groupId + '-title');
        if (!heading || typeof heading.focus !== 'function') return false;
        heading.focus({ preventScroll: true });
        return true;
    }

    function init() {
        var doc = root.document;
        if (!doc) return;
        var nav = byId(doc, 'settingsSubnav');
        if (!nav) return;

        nav.addEventListener('click', function (event) {
            var link = event.target && event.target.closest
                ? event.target.closest('.settings-subnav-link')
                : null;
            if (!link) return;
            var href = link.getAttribute('href') || '';
            if (href.charAt(0) !== '#') return;
            // The browser follows the anchor itself (so the jump and the URL stay
            // the browser's), and this adds the focus handoff the anchor lacks.
            focusGroup(doc, href.slice(1));
            mark(doc);
        });

        root.addEventListener('hashchange', function () {
            // A change to one of the old policy fragments is a handoff, not a
            // position on this page: the document is being replaced, so there is no
            // group here to focus or to mark.
            if (handOffLegacyFragment(root.location)) return;
            var id = (root.location.hash || '').slice(1);
            if (id) focusGroup(doc, id);
            mark(doc);
        });

        // Scroll is throttled to one frame: the handler reads layout, and reading
        // it on every scroll event would make the page janky on a long document.
        var scheduled = false;
        root.addEventListener('scroll', function () {
            if (scheduled) return;
            scheduled = true;
            var run = function () {
                scheduled = false;
                mark(doc);
            };
            if (typeof root.requestAnimationFrame === 'function') root.requestAnimationFrame(run);
            else root.setTimeout(run, 16);
        }, { passive: true });

        mark(doc);
    }

    root.SettingsNav = {
        init: init,
        mark: mark,
        currentGroup: currentGroup,
        handOffLegacyFragment: handOffLegacyFragment
    };

    // The check runs before init, at parse time: an old bookmark must be on its way
    // to the page that owns that surface before this document draws anything the
    // reader could act on.
    handOffLegacyFragment(root.location);

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }
}(typeof window !== 'undefined' ? window : this));
