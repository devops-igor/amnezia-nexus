/* Boot for the merged VPN page.
 *
 * /vpn is one document with three sections. This module owns the three things that
 * are only true because the sections share a document:
 *
 *   Activation. A section's controllers are loaded and started only when its surface
 *   approaches the visible viewport, receives focus, is jumped to, or is named by a
 *   fragment or an Inspect target. The Overview controllers load with the page, so
 *   the four signals and the health headline never wait for the inventory, the
 *   diagnostics read or the chart module. Nothing a section owns is requested on
 *   ordinary arrival.
 *
 *   One status stream. Overview and the health headline are two renderings of one
 *   measurement, so they read it once per tick: the status sample the Overview load
 *   returns is the same object the health renderer is given. Nothing else is awaited
 *   on that path - the sessions read belongs to the sessions stream, and a slow or
 *   failing sessions request must not hold the health sample or the next tick.
 *   Branding the inventory traffic or a second diagnostics loop onto the same sample
 *   is exactly how the two surfaces start disagreeing about what the dataplane is
 *   doing.
 *
 *   Landing. The jump rail, a cold fragment and a browser Back/Forward all end at
 *   the same function: mount the owning section, open only the disclosures the
 *   target needs, scroll it clear of the shell bars and the stuck rail, and put
 *   focus on the heading (or the target when it can take focus). The landing always
 *   uses the resolver's CANONICAL target, so a legacy id whose node no longer exists
 *   still lands where the id means. Polling never lands anywhere, so a tick cannot
 *   move the reader.
 */
(function () {
    'use strict';

    var SECTION_IDS = {
        overview: 'overview-region',
        backends: 'backends',
        diagnostics: 'diagnostics-region'
    };

    // Which sections have been activated. Overview and diagnostics are not here:
    // the status tick paints the Overview, and the diagnostics section's own
    // controllers are loaded by name when the section is activated.
    var mounted = { backends: false, diagnostics: false };

    // The in-flight activation of each section. A second jump, a second fragment or
    // a re-entry returns the same promise instead of loading or starting twice.
    var mounting = { backends: null, diagnostics: null };

    // Modules this page loaded already, by the name the section declared. A module
    // registers itself with vpnMarkModule (common.js), so a harness or a shell that
    // included it up front is not fetched a second time.
    var moduleLoads = {};

    // The surfaces this boot observed, so activation can read the section metadata from
    // the element it watches instead of searching the document again.
    var observedSurfaces = [];

    var statusPollStarted = false;
    var sessionPollStarted = false;
    var backendPollStarted = false;
    var railMarked = false;

    // The first landing waits for the first completed tick. Landing at
    // DOMContentLoaded races the browser's own fragment handling: the reader's focus
    // is placed on the destination and then cleared again in the same frame, which
    // leaves it on the document body. Waiting for the tick the page needs anyway is
    // what the per-document pages did, and one tick is not a poll landing - the
    // landing runs once, guarded below.
    var firstLandingDone = false;
    var firstTickWaiters = [];

    // Classes of landing that are allowed to move focus. A poll is never one.
    var LANDING_CLICK = 'click';
    var LANDING_FRAGMENT = 'fragment';

    function byId(id) {
        return document.getElementById(id);
    }

    // vpnLocation is the window's location, or null where the host has none. A page
    // boot can run before a location exists; landing is then simply not possible,
    // and nothing else about the page depends on it.
    function vpnLocation() {
        return (typeof window !== 'undefined' && window.location) ? window.location : null;
    }

    // on binds a listener only where the target can hold one. A harness that renders
    // the page's markup without an event-capable window still gets a usable module:
    // nothing can dispatch to a listener it never took.
    function on(target, type, handler, options) {
        if (target && typeof target.addEventListener === 'function') {
            target.addEventListener(type, handler, options);
        }
    }

    function sectionElement(section) {
        var id = SECTION_IDS[section];
        return id ? byId(id) : null;
    }

    // ---- Deferred module loading ---------------------------------------------

    // vpnDeclaredModules reads the "name=url" pairs an element declares in
    // data-vpn-modules. The URL comes from the template's asset_url, so a deferred
    // module is requested under the digest of its own bytes exactly like an eager
    // one; this loader never spells an asset path or a version of its own.
    function vpnDeclaredModules(el) {
        var declared = el && el.getAttribute ? el.getAttribute('data-vpn-modules') : null;
        if (!declared) return [];
        var parts = String(declared).split(/\s+/);
        var modules = [];
        for (var i = 0; i < parts.length; i++) {
            var pair = parts[i];
            if (!pair) continue;
            var cut = pair.indexOf('=');
            if (cut <= 0) continue;
            modules.push({ name: pair.slice(0, cut), url: pair.slice(cut + 1) });
        }
        return modules;
    }

    // vpnLoadModules loads each declared module once, in declaration order, and
    // resolves when they are all present. A module that is already registered - by
    // an earlier load, or because the shell included it - resolves immediately, so a
    // repeat activation costs no request and a double include cannot happen.
    function vpnLoadModules(modules) {
        var pending = [];
        for (var i = 0; i < modules.length; i++) {
            pending.push(vpnLoadModule(modules[i]));
        }
        return Promise.all(pending).then(function () { return true; });
    }

    // vpnLoadModule loads one declared module and resolves when it is present.
    //
    // The DECISION lives here - already registered, already in flight, otherwise fetch -
    // and only the fetch is behind the seam. A case can then hold the fetch open and
    // still see the same idempotency the page relies on: a module that is present is
    // never requested again, whoever performs the request.
    function vpnLoadModule(module) {
        if (!module || !module.name) return Promise.resolve(false);
        if (typeof vpnModuleRegistered === 'function' && vpnModuleRegistered(module.name)) {
            return Promise.resolve(true);
        }
        if (moduleLoads[module.name]) return moduleLoads[module.name];
        var impl = (typeof window !== 'undefined' && typeof window.vpnLoadModuleImpl === 'function')
            ? window.vpnLoadModuleImpl
            : vpnLoadScriptModule;
        var promise = Promise.resolve(impl(module));
        moduleLoads[module.name] = promise;
        return promise;
    }

    function vpnLoadScriptModule(module) {
        if (!module || !module.url || typeof document === 'undefined' || !document.createElement) {
            return Promise.resolve(false);
        }
        return new Promise(function (resolve) {
            var script = document.createElement('script');
            script.src = module.url;
            // A classic blocking script, like the ones the shell ships: the module
            // must be evaluated before the controller that uses it, and the order of
            // the declared pairs is the dependency order.
            var done = function (ok) {
                moduleLoads[module.name] = null;
                resolve(ok);
            };
            script.onload = function () { done(true); };
            script.onerror = function () { done(false); };
            (document.body || document.documentElement).appendChild(script);
        });
    }

    // vpnModulesReady reports whether every module a section declares is already
    // evaluated. It is the difference between "this press landed on a live control"
    // and "this press landed on markup whose controller has not arrived": only the
    // second one needs replaying, and replaying the first would run the action twice.
    function vpnModulesReady(modules) {
        for (var i = 0; i < modules.length; i++) {
            if (typeof vpnModuleRegistered !== 'function' || !vpnModuleRegistered(modules[i].name)) return false;
        }
        return true;
    }

    // ---- Rail geometry -------------------------------------------------------

    // vpnRailHeight is the stuck rail's own height, which changes when its labels
    // wrap onto a second line. It is measured rather than assumed: a fixed offset
    // breaks in exactly the case that matters, a long translation.
    function vpnRailHeight() {
        var rail = byId('vpnSubnav');
        if (!rail || typeof rail.getBoundingClientRect !== 'function') return 0;
        var box = rail.getBoundingClientRect();
        var height = box && typeof box.height === 'number' ? Math.round(box.height) : 0;
        return height > 0 ? height : 0;
    }

    // vpnTopChromeHeight is the shell's own sticky top bar. Below 1024 the rail
    // sticks BENEATH it, so a landing has to clear both; from 1024 the sidebar is in
    // flow and the rail is the whole chrome. A bar that is not displayed measures
    // nothing, which is how the desktop case falls out of the same expression.
    function vpnTopChromeHeight() {
        if (typeof document === 'undefined' || typeof getComputedStyle !== 'function') return 0;
        var bar = document.querySelector ? document.querySelector('.mobile-topbar') : null;
        if (!bar || typeof bar.getBoundingClientRect !== 'function') return 0;
        var style = getComputedStyle(bar);
        if (!style || style.display === 'none') return 0;
        var box = bar.getBoundingClientRect();
        return box && box.height > 0 ? Math.round(box.height) : 0;
    }

    // vpnPublishRailHeight publishes ONE landing offset: the space the shell's
    // chrome occupies at the landing point. The stylesheet consumes it as a scroll
    // margin, so a jump, a cold fragment and a browser Back all land clear of the
    // bars by construction, rather than by two fixed offsets that have to agree with
    // each other. It re-measures whenever the rail's box changes.
    function vpnPublishRailHeight() {
        if (typeof document === 'undefined' || !document.documentElement) return;
        var rail = vpnRailHeight();
        var offset = vpnTopChromeHeight() + rail;
        document.documentElement.style.setProperty('--vpn-rail-height', rail + 'px');
        if (offset > 0) {
            document.documentElement.style.setProperty('--vpn-landing-offset', offset + 'px');
        }
    }

    function vpnWatchRailHeight() {
        if (typeof ResizeObserver !== 'function') return;
        var rail = byId('vpnSubnav');
        if (!rail) return;
        var observer = new ResizeObserver(vpnPublishRailHeight);
        observer.observe(rail);
    }

    // vpnCurrentSection answers which section the reader is looking at.
    //
    // The primary rule is the last section whose top edge has passed the line, where
    // the line is the rail's OWN current bottom: reading the rect rather than a fixed
    // number keeps it honest at both widths (the rail sits at the viewport top on a
    // desktop and under the sticky top bar on a phone) and while the page is not
    // scrolled, when the rail is still in flow.
    //
    // That rule alone cannot mark a SHORT last section. A jump to the final section
    // scrolls to the end of the document, so a section whose body is taller than the
    // remaining scroll sits with its heading far below the line; the reader is in it,
    // and the rail would still name its predecessor. So the scroll end is its own
    // case: when the document cannot scroll any further, the last section is current.
    function vpnCurrentSection() {
        var sections = ['overview', 'backends', 'diagnostics'];
        var rail = byId('vpnSubnav');
        var line = 1;
        if (rail && typeof rail.getBoundingClientRect === 'function') {
            var box = rail.getBoundingClientRect();
            if (box && typeof box.bottom === 'number') line = box.bottom + 1;
        }
        var atEnd = false;
        if (typeof window !== 'undefined' && typeof window.scrollY === 'number' &&
            typeof window.innerHeight === 'number' && document.documentElement) {
            var maxScroll = document.documentElement.scrollHeight - window.innerHeight;
            atEnd = maxScroll > 0 && window.scrollY >= maxScroll - 2;
        }
        var current = sections[0];
        for (var i = 0; i < sections.length; i++) {
            var el = sectionElement(sections[i]);
            if (!el || typeof el.getBoundingClientRect !== 'function') continue;
            var rect = el.getBoundingClientRect();
            if (!rect) continue;
            if (rect.top <= line) {
                current = sections[i];
                continue;
            }
            // The section's body is what occupies the band under the rail: its top is
            // at the line while the next section has not started.
            if (rect.top <= line + 8) current = sections[i];
        }
        if (atEnd) current = sections[sections.length - 1];
        return current;
    }

    // vpnMarkSection writes aria-current on the one link whose section is in view and
    // removes it from the others. It is a comparison, not a toggle, so running it
    // twice changes nothing; it never touches the URL or focus.
    function vpnMarkSection() {
        var rail = byId('vpnSubnav');
        if (!rail) return null;
        var current = vpnCurrentSection();
        var links = rail.querySelectorAll('.settings-subnav-link');
        for (var i = 0; i < links.length; i++) {
            var link = links[i];
            if (link.getAttribute('href') === '#' + current) link.setAttribute('aria-current', 'true');
            else link.removeAttribute('aria-current');
        }
        railMarked = true;
        return current;
    }

    // ---- Activation ----------------------------------------------------------

    // vpnSectionElementFor finds the element that CARRIES a section's activation
    // metadata. It is the same element whose data-vpn-section names the section, so
    // an observer, a focus target and a declared module list all read one node. The
    // heading is a different element: it is the landing destination, not the surface.
    function vpnSectionElementFor(section) {
        if (typeof document === 'undefined') return null;
        // The boot already knows the surfaces it observes; falling back to a query keeps
        // this usable when a section is mounted without having been observed.
        for (var i = 0; i < observedSurfaces.length; i++) {
            var candidate = observedSurfaces[i].el;
            if (candidate && candidate.getAttribute && candidate.getAttribute('data-vpn-section') === section) {
                return candidate;
            }
        }
        if (typeof document.querySelectorAll !== 'function') return null;
        var candidates = document.querySelectorAll('[data-vpn-section]');
        for (var j = 0; j < candidates.length; j++) {
            if (candidates[j].getAttribute('data-vpn-section') === section) return candidates[j];
        }
        return null;
    }

    // vpnMountSection loads a section's controllers and starts them once. A second
    // jump, a second fragment or a re-entry returns the existing work instead of
    // binding a second listener or starting a second poll over the same elements.
    function vpnMountSection(section) {
        if (section !== 'backends' && section !== 'diagnostics') return Promise.resolve();
        if (mounting[section]) return mounting[section];
        var surface = vpnSectionElementFor(section);
        var modules = vpnDeclaredModules(surface);
        var activation = vpnLoadModules(modules).then(function () {
            if (modules.length && !vpnModulesReady(modules)) {
                // The controllers never arrived, so nothing can be started: the stream
                // would poll an endpoint no renderer consumes. The activation is
                // released so a later arrival retries instead of finding the section
                // permanently (and silently) marked active.
                mounting[section] = null;
                return false;
            }
            mounted[section] = true;
            return section === 'backends' ? vpnStartBackends() : vpnStartDiagnostics();
        });
        mounting[section] = activation;
        return activation;
    }

    function vpnStartBackends() {
        if (backendPollStarted) return Promise.resolve();
        backendPollStarted = true;
        // The server names the rows are enriched with are read once, not on every
        // tick; the add dialog refreshes that list itself when it opens.
        if (typeof API !== 'undefined' && typeof API.get === 'function') {
            API.get('/api/servers').then(function (servers) {
                if (Array.isArray(servers) && typeof vpnCachedServers !== 'undefined') vpnCachedServers = servers;
            }).catch(function () {});
        }
        if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
            NexusTelemetry.poll('vpn-backends', async function () {
                await vpnLoadBackends();
            }, 5000);
        }
        return Promise.resolve();
    }

    function vpnStartDiagnostics() {
        if (sessionPollStarted) return Promise.resolve();
        sessionPollStarted = true;
        if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
            // Sessions are the only read this section adds; the forwarder health it
            // renders comes from the Overview's status sample. This stream is also
            // the only sessions consumer, so one request per cadence serves every
            // surface that shows the table.
            NexusTelemetry.poll('vpn-sessions', async function () {
                await vpnLoadSessions();
                vpnRenderSessionsFromCache();
            }, 5000);
        }
        return Promise.resolve();
    }

    // vpnActivateAdvanced loads the module the Advanced Diagnostics panel declares
    // and nothing else. The panel is closed on ordinary arrival, so its chart module
    // is not requested until the operator (or a deep link) actually opens it.
    function vpnActivateAdvanced() {
        var panel = byId('vpn-diagnostics');
        return vpnLoadModules(vpnDeclaredModules(panel));
    }

    // ---- The single status tick ---------------------------------------------

    // vpnTickOnce is one pass of the page's shared measurement: the Overview load
    // reads the status and the configuration, and the same status object paints the
    // health headline immediately.
    //
    // The sessions read is deliberately NOT awaited here. It belongs to the sessions
    // stream, which renders its own table when it completes; awaiting it made the
    // health headline and the whole tick wait on another section's request, so a
    // slow or failing sessions read froze the essential picture.
    async function vpnTickOnce() {
        var status = null;
        try {
            status = await vpnLoadOverview();
        } catch (_) {
            status = null;
        }
        if (typeof vpnRenderForwarderHealth === 'function') {
            vpnRenderForwarderHealth(status);
        }
        releaseFirstTickWaiters();
        return status;
    }

    // releaseFirstTickWaiters unblocks the pending landing. It runs once per page:
    // a later tick never re-lands, so polling cannot move the reader.
    function releaseFirstTickWaiters() {
        var pending = firstTickWaiters;
        firstTickWaiters = [];
        for (var i = 0; i < pending.length; i++) pending[i]();
    }

    function awaitFirstTick() {
        if (firstLandingDone) return Promise.resolve();
        return new Promise(function (resolve) {
            firstTickWaiters.push(resolve);
            // A tick that never completes must not strand the page: the timeout lands
            // anyway, with whatever the document shows.
            if (typeof window !== 'undefined' && typeof window.setTimeout === 'function') {
                window.setTimeout(resolve, 4000);
            }
        });
    }

    function vpnStartStatusPoll() {
        if (statusPollStarted) return;
        statusPollStarted = true;
        if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
            NexusTelemetry.poll('vpn-overview', function () {
                return vpnTickOnce();
            }, 5000);
        }
    }

    // ---- Landing -------------------------------------------------------------

    // vpnRevealAncestors opens every disclosure between the target and the page.
    // The Advanced Diagnostics panel is opened through its own setter, so the entry
    // button's aria-expanded and the panel's visibility cannot disagree.
    function vpnRevealAncestors(el) {
        if (!el) return;
        var panel = byId('vpn-diagnostics');
        if (panel && typeof panel.contains === 'function' && panel.contains(el) &&
            typeof vpnSetDiagnosticsOpen === 'function') {
            vpnSetDiagnosticsOpen(true, null);
        }
        var node = el.parentElement;
        while (node && node !== document.body) {
            if (node.tagName && String(node.tagName).toLowerCase() === 'details') node.open = true;
            node = node.parentElement;
        }
    }

    // vpnLandOn resolves where a landing should put the reader for one id, opening
    // the disclosures it needs. It returns the focused node, or null when the
    // document has no such target.
    function vpnLandOn(id) {
        var el = byId(id);
        if (!el) return null;
        vpnRevealAncestors(el);
        var target = el;
        if (typeof vpnIsFocusable === 'function' && !vpnIsFocusable(el)) {
            target = (typeof vpnNearestHeading === 'function') ? vpnNearestHeading(el, null) : el;
        }
        if (typeof vpnScrollToTarget === 'function') vpnScrollToTarget(el);
        if (typeof vpnFocusIfFocusable === 'function') vpnFocusIfFocusable(target);
        return target;
    }

    // vpnLandOnInspect honours a one-shot Inspect arrival. The fragment names a
    // navigation identity rather than a node, so only a completed successful
    // inventory read can say whether the named backend is there: the section is
    // mounted, the inventory is read, and the landing that consumes the request runs
    // from that read. A fragment whose request is gone (a reload, a bookmark, Back)
    // leaves the reader on the inventory heading.
    async function vpnLandOnInspect() {
        await vpnMountSection('backends');
        if (typeof vpnLoadBackends !== 'function') return null;
        await vpnLoadBackends();
        return 'inspect';
    }

    // vpnLandOnFragment mounts the owning section, then lands on the resolver's
    // canonical target. A section id (the rail's own href) lands on the section
    // heading even though the section element itself is not focusable.
    async function vpnLandOnFragment(hash, source) {
        if (typeof vpnIsInspectFragment === 'function' && vpnIsInspectFragment(hash)) {
            return vpnLandOnInspect();
        }
        if (typeof vpnResolveFragment !== 'function') return null;
        var resolved = vpnResolveFragment(hash);
        if (!resolved) return null;
        await vpnMountSection(resolved.section);

        // Each section's own landing function owns the details only it knows: the
        // configuration reveal and the dialog-opener canonicalisation for Overview,
        // the table reveal and Inspect consumption for Backends, the panel and fold
        // reveal for Diagnostics. The CANONICAL target travels with the call: a
        // legacy id whose node this document no longer has still lands where the id
        // means, instead of being looked up by its removed raw id.
        if (resolved.section === 'backends' && typeof vpnApplyBackendsLanding === 'function') {
            vpnApplyBackendsLanding(resolved.target);
            vpnMarkSection();
            return resolved.target;
        }
        if (resolved.section === 'diagnostics' && typeof vpnApplyDiagnosticsAnchor === 'function') {
            vpnApplyDiagnosticsAnchor(resolved.target);
            vpnMarkSection();
            return resolved.target;
        }
        if (resolved.section === 'overview' && typeof vpnLandOverviewAnchor === 'function') {
            vpnLandOverviewAnchor(resolved.target);
            vpnMarkSection();
            return resolved.target;
        }
        vpnLandOn(resolved.target);
        vpnMarkSection();
        return resolved.target;
    }

    // vpnLandOnSection is the rail's own landing: the section heading is the
    // destination, because "show me Backends" means the top of Backends.
    async function vpnLandOnSection(section) {
        await vpnMountSection(section);
        var headingId = (typeof vpnSectionHeadingId === 'function')
            ? vpnSectionHeadingId(section)
            : section;
        var target = vpnLandOn(headingId);
        if (!target) vpnLandOn(section);
        vpnMarkSection();
        return headingId;
    }

    // ---- Legacy child routes -------------------------------------------------

    // vpnConsumeSectionMarker reads the transient marker a retired child route left
    // behind and rewrites the address bar to the canonical fragment. The marker is
    // consumed with replaceState, so a refresh, a bookmark or Back never carries it
    // again and the reader keeps a shareable /vpn#… URL.
    function vpnConsumeSectionMarker() {
        var loc = vpnLocation();
        if (!loc || !window.history) return null;
        var section = (typeof vpnSectionFromMarker === 'function')
            ? vpnSectionFromMarker(loc.search)
            : null;
        if (!section) return null;
        var hash = loc.hash || '';
        var resolved = (typeof vpnResolveFragment === 'function') ? vpnResolveFragment(hash) : null;
        var canonical = '#' + (resolved ? resolved.target : (hash.length > 1 ? hash.slice(1) : section));
        var search = loc.search.replace(/[?&]section=[A-Za-z]+/, '').replace(/^&/, '');
        if (search === '?') search = '';
        window.history.replaceState(window.history.state, '', loc.pathname + search + canonical);
        return { section: section, hash: canonical };
    }

    // ---- Wiring --------------------------------------------------------------

    function vpnBindRail() {
        var rail = byId('vpnSubnav');
        if (!rail) return;
        on(rail, 'click', function (event) {
            var link = event.target && event.target.closest
                ? event.target.closest('.settings-subnav-link')
                : null;
            if (!link) return;
            var href = link.getAttribute('href') || '';
            if (href.charAt(0) !== '#') return;
            // The browser follows the anchor, so the URL and the jump stay the
            // browser's; this adds the section mount and the focus handoff an
            // anchor cannot do by itself. Selecting the current section after
            // scrolling away lands again rather than doing nothing.
            event.preventDefault();
            var section = href.slice(1);
            if (window.history && typeof window.history.pushState === 'function') {
                window.history.pushState(window.history.state, '', href);
            }
            vpnLandOnSection(section);
        });
    }

    function vpnBindScrollMarker() {
        var scheduled = false;
        on(window, 'scroll', function () {
            if (scheduled) return;
            scheduled = true;
            var run = function () {
                scheduled = false;
                vpnMarkSection();
            };
            if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(run);
            else window.setTimeout(run, 16);
        }, { passive: true });
        on(window, 'resize', vpnPublishRailHeight);
    }

    function vpnBindHashChange() {
        on(window, 'hashchange', function () {
            // A marker arriving from a child route is consumed before it is treated
            // as a position on this page: the URL is about to be canonicalised.
            vpnConsumeSectionMarker();
            var hash = (vpnLocation() && vpnLocation().hash) || '';
            if (!hash || hash.length < 2) {
                vpnMarkSection();
                return;
            }
            vpnLandOnFragment(hash, LANDING_FRAGMENT);
        });
    }

    // vpnActiveSection activates the section a node belongs to. Focus and press
    // activation go through the SAME idempotent mount a jump uses, so a keyboard
    // reader tabbing into the inventory gets real rows rather than a control that
    // answers a press with nothing.
    function vpnActiveSection(node) {
        if (!node || typeof node.closest !== 'function') return null;
        var surface = node.closest('[data-vpn-section]');
        if (!surface || typeof surface.getAttribute !== 'function') return null;
        var section = surface.getAttribute('data-vpn-section');
        if (!section) return null;
        vpnMountSection(section);
        return section;
    }

    // vpnBindEarlyActivation activates a section as soon as the reader reaches it
    // without scrolling into range: focus or a press that lands inside a section is
    // an arrival at that section, whether or not the observer has fired yet.
    //
    // A press that arrives while its section's controllers are still being fetched
    // would otherwise be answered by nobody - the control looks live and does
    // nothing. It is replayed ONCE the module that owns it is present, through the
    // element's own click, so the action runs exactly as the reader asked.
    function vpnBindEarlyActivation() {
        on(document, 'focusin', function (event) {
            vpnActiveSection(event.target);
        });
        on(document, 'click', function (event) {
            var control = event.target && event.target.closest
                ? event.target.closest('[data-action]')
                : null;
            if (!control) return;
            var surface = control.closest ? control.closest('[data-vpn-section]') : null;
            if (!surface || typeof surface.getAttribute !== 'function') return;
            var section = surface.getAttribute('data-vpn-section');
            if (!section || mounted[section]) return;
            // Only a press whose handler is genuinely ABSENT is replayed. A section whose
            // controllers are already evaluated handles the press itself, and replaying
            // would run its action twice.
            var replay = !vpnModulesReady(vpnDeclaredModules(surface));
            vpnMountSection(section).then(function () {
                if (!replay) return;
                if (!control.isConnected) return;
                if (typeof control.click === 'function') control.click();
            });
        }, true);
    }

    // vpnObserveSections starts a section's controllers when its surface comes near
    // the viewport. It observes the element that CARRIES the section metadata and
    // reads the section name from that same element: observing a heading that
    // carries no attribute is how the inventory stayed on its loading row. The
    // observer never lands or focuses; only a jump, a fragment or an Inspect does.
    function vpnObserveSections() {
        if (typeof IntersectionObserver !== 'function') {
            // Without an observer there is no cheap "is it near" test, so the two
            // sections start with the page rather than leaving their controls dead.
            vpnMountSection('backends');
            vpnMountSection('diagnostics');
            return;
        }
        var observer = new IntersectionObserver(function (entries) {
            for (var i = 0; i < entries.length; i++) {
                if (!entries[i].isIntersecting) continue;
                var el = entries[i].target;
                var section = el.getAttribute ? el.getAttribute('data-vpn-section') : null;
                if (!section) continue;
                vpnMountSection(section);
                observer.unobserve(el);
            }
        }, { rootMargin: '300px 0px 300px 0px' });
        var surfaces = (typeof document.querySelectorAll === 'function')
            ? document.querySelectorAll('[data-vpn-section]')
            : [];
        for (var i = 0; i < surfaces.length; i++) {
            observedSurfaces.push({ el: surfaces[i] });
            observer.observe(surfaces[i]);
        }
    }

    async function vpnBoot() {
        if (typeof vpnBindSharedActions === 'function') vpnBindSharedActions();
        vpnPublishRailHeight();
        vpnWatchRailHeight();
        vpnBindRail();
        vpnBindScrollMarker();
        vpnBindHashChange();
        vpnBindEarlyActivation();

        // A retired child route's marker is consumed before anything reads the
        // fragment, so this arrival has exactly one destination.
        var marker = vpnConsumeSectionMarker();

        vpnStartStatusPoll();
        vpnObserveSections();
        vpnMarkSection();

        var hash = (vpnLocation() && vpnLocation().hash) || '';
        var wanted = marker ? marker.hash : (hash && hash.length > 1 ? hash : '');
        if (wanted) {
            await awaitFirstTick();
            if (!firstLandingDone) {
                firstLandingDone = true;
                await vpnLandOnFragment(wanted, LANDING_FRAGMENT);
            }
        }
        // The first tick lands nothing on its own: the landing above runs once and
        // no later tick moves the reader.
        vpnMarkSection();
    }

    if (typeof window !== 'undefined') {
        window.vpnBoot = vpnBoot;
        window.vpnMountSection = vpnMountSection;
        window.vpnLoadModules = vpnLoadModules;
        window.vpnLoadModule = vpnLoadModule;
        window.vpnModulesReady = vpnModulesReady;
        window.vpnDeclaredModules = vpnDeclaredModules;
        window.vpnActivateAdvanced = vpnActivateAdvanced;
        window.vpnSectionElementFor = vpnSectionElementFor;
        window.vpnLandOnSection = vpnLandOnSection;
        window.vpnLandOnFragment = vpnLandOnFragment;
        window.vpnMarkSection = vpnMarkSection;
        window.vpnCurrentSection = vpnCurrentSection;
        window.vpnConsumeSectionMarker = vpnConsumeSectionMarker;
        window.vpnTickOnce = vpnTickOnce;
        window.vpnPublishRailHeight = vpnPublishRailHeight;
        window.vpnRailHeight = vpnRailHeight;
        // Read by the tests and by the section controllers that need to know whether
        // this document has already mounted their peers.
        window.vpnSectionsMounted = mounted;
        window.vpnRailMarked = function () { return railMarked; };
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            on(document, 'DOMContentLoaded', function () { vpnBoot(); });
        } else {
            vpnBoot();
        }
    }
})();
