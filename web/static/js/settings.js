    document.getElementById('ssl_enabled').addEventListener('change', (e) => {
        document.getElementById('sslFields').style.display = e.target.checked ? 'block' : 'none';
    });

    const tgEnabledCheck = document.getElementById('telegram_enabled');
    if (tgEnabledCheck) {
        tgEnabledCheck.addEventListener('change', (e) => {
            const tgFields = document.getElementById('telegramFields');
            if (tgFields) tgFields.style.display = e.target.checked ? 'block' : 'none';
        });
    }

    async function handleRestore(e) {
        const file = e.target.files[0];
        if (!file) return;

        const confirmed = await UI.confirm({
            title: _('restore_backup'),
            message: _('restore_confirm'),
            confirmText: _('restore_backup'),
            // A restore overwrites the current data and restarts the panel, so the
            // confirming control carries the destructive variant, not a warning.
            confirmVariant: 'danger'
        });

        if (!confirmed) {
            e.target.value = '';
            return;
        }

        const btn = document.getElementById('restoreBtn');
        const text = document.getElementById('restoreBtnText');
        const spinner = document.getElementById('restoreSpinner');
        btn.disabled = true;
        text.textContent = _('loading');
        spinner.classList.remove('hidden');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const data = await API.post('/api/settings/backup/restore', formData);
            if (data.status === 'success') {
                UI.toast(_('restore_success'), 'success');
                setTimeout(() => window.location.reload(), 2000);
            } else {
                UI.toast(data.error || _('invalid_backup_file'), 'error');
            }
        } catch (err) {
            UI.toast(`${_('error')}: ` + (err.message || err), 'error');
        } finally {
            btn.disabled = false;
            text.textContent = _('restore_backup');
            spinner.classList.add('hidden');
            e.target.value = '';
        }
    }

    async function checkUpstreamStatus(force) {
        const btn = document.getElementById('upstreamCheckBtn');
        const spinner = document.getElementById('upstreamSpinner');
        const overallBadge = document.getElementById('upstreamOverallBadge');
        const banner = document.getElementById('upstreamUpdateBanner');
        const checkedAtSpan = document.getElementById('upstreamCheckedAt');

        if (btn) btn.disabled = true;
        if (spinner) spinner.classList.remove('hidden');

        try {
            const url = force ? '/api/system/upstream-status?refresh=true' : '/api/system/upstream-status';
            const data = await API.get(url, {silent: true});

            if (!data) return;

            if (data.checked_at && checkedAtSpan) {
                const date = new Date(data.checked_at);
                checkedAtSpan.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            }

            if (data.base_image && document.getElementById('upstreamBaseImage')) {
                document.getElementById('upstreamBaseImage').textContent = data.base_image;
            }

            if (data.components && Array.isArray(data.components)) {
                data.components.forEach(comp => {
                    const pinnedEl = document.getElementById('pinned-' + comp.name);
                    const latestEl = document.getElementById('latest-' + comp.name);
                    const badgeEl = document.getElementById('badge-' + comp.name);
                    const linkEl = document.getElementById('repoLink-' + comp.name);

                    if (pinnedEl && comp.pinned_version) pinnedEl.textContent = comp.pinned_version;
                    if (latestEl && comp.latest_version) latestEl.textContent = comp.latest_version;
                    if (linkEl && comp.release_url) linkEl.href = comp.release_url;

                    if (badgeEl) {
                        if (comp.error) {
                            badgeEl.className = 'badge badge-secondary';
                            badgeEl.textContent = 'Error';
                            badgeEl.title = comp.error;
                        } else if (comp.update_available) {
                            badgeEl.className = 'badge badge-warning';
                            badgeEl.textContent = _('update_available') || 'Update available';
                            badgeEl.title = '';
                        } else {
                            badgeEl.className = 'badge badge-success';
                            badgeEl.textContent = _('up_to_date') || 'Up to date';
                            badgeEl.title = '';
                        }
                    }
                });
            }

            if (overallBadge) {
                if (data.status === 'degraded') {
                    overallBadge.className = 'badge badge-secondary';
                    overallBadge.textContent = _('status_degraded') || 'Degraded';
                } else if (data.status === 'error') {
                    overallBadge.className = 'badge badge-secondary';
                    overallBadge.textContent = _('error') || 'Error';
                } else if (data.update_available) {
                    overallBadge.className = 'badge badge-warning';
                    overallBadge.textContent = _('update_available') || 'Update available';
                } else {
                    overallBadge.className = 'badge badge-success';
                    overallBadge.textContent = _('up_to_date') || 'Up to date';
                }
            }

            if (banner) {
                banner.style.display = data.update_available ? 'block' : 'none';
            }
        } catch (err) {
            console.error('Failed to fetch upstream status:', err);
            if (overallBadge) {
                overallBadge.className = 'badge badge-secondary';
                overallBadge.textContent = _('error') || 'Error';
            }
        } finally {
            if (btn) btn.disabled = false;
            if (spinner) spinner.classList.add('hidden');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        checkUpstreamStatus(false);
    });

    // Gigahost catalog and deployment workflow
    const btnRefreshCatalog = document.getElementById('btnRefreshCatalog');
    const btnDeployVPS = document.getElementById('btnDeployVPS');
    const deployPlanSelect = document.getElementById('deployPlanSelect');
    const deployRegionSelect = document.getElementById('deployRegionSelect');
    const deployPlacementSelect = document.getElementById('deployPlacementSelect');
    const deployPlacementHint = document.getElementById('deployPlacementHint');
    const deployOSSelect = document.getElementById('deployOSSelect');

    let cachedPlans = [];

    // A confirmation the operator has not answered yet blocks a second request, so
    // two rapid presses cannot become two orders. It is not a button state: the
    // form stays exactly as it was while the dialog is open.
    let deployConfirmationOpen = false;

    // The rule lives in the module so it cannot drift between rebuilds and choice.
    const deploymentPlacementIntent = placementNewIntent();

    // Recomputed per call, so a catalog refresh is always the authority.
    function deployPlacementChoices() {
        return placementChoices(deployPlanAt(), deployRegionSelect ? deployRegionSelect.value : null);
    }

    // Explains a refusal or dropped choice; never enables ordering.
    function showDeployPlacementHint(text) {
        if (!deployPlacementHint) return;
        deployPlacementHint.textContent = text || '';
        deployPlacementHint.style.display = text ? 'block' : 'none';
    }
    // Rebuilds from the provider's facts; may only ARM the latch, never release it.
    function rebuildDeployPlacement(previous) {
        const choices = deployPlacementChoices();
        if (!deployPlacementSelect) return {value: '', cleared: false, reason: ''};
        deployPlacementSelect.innerHTML = '';

        const managed = document.createElement('option');
        managed.value = choices.managed.value;
        managed.textContent = choices.managed.label;
        deployPlacementSelect.appendChild(managed);

        choices.options.forEach(option => {
            const opt = document.createElement('option');
            // A refused datacenter still carries a distinct value, so choosing it is
            // an explicit refusal rather than a silent default.
            opt.value = option.value;
            opt.textContent = placementLabel(option);
            opt.disabled = !option.selectable;
            deployPlacementSelect.appendChild(opt);
        });

        const decision = placementSelection(choices, previous);
        deployPlacementSelect.value = decision.value;
        deployPlacementSelect.disabled = false;
        showDeployPlacementHint(decision.cleared ? decision.reason : (choices.note || ''));
        // Automatic rebuild: this can only arm the outstanding-choice latch.
        deploymentPlacementIntent.rebind(decision);
        return decision;
    }

    // deployPlacementNeedsChoice reports whether a dropped pin still needs a choice.
    function deployPlacementNeedsChoice() {
        return deploymentPlacementIntent.needed();
    }

    // deployPlanAt returns the plan the plan selector currently points at, or
    // null. The selector's value is the plan index into cachedPlans; an empty
    // value means the catalog had nothing selectable.
    function deployPlanAt() {
        if (!deployPlanSelect || cachedPlans.length === 0) return null;
        if (deployPlanSelect.value === '') return null;
        const idx = parseInt(deployPlanSelect.value, 10);
        if (!Number.isInteger(idx) || idx < 0 || idx >= cachedPlans.length) return null;
        return cachedPlans[idx];
    }

    // deployPlanLabel renders the authoritative provider price facts: the hourly
    // rate, the currency and the monthly ceiling the provider documents. Nothing
    // is converted or capped.
    function deployPlanLabel(p) {
        const parts = [];
        if (p.cpu_cores) parts.push(p.cpu_cores + ' vCPU');
        if (p.ram_mb) parts.push(Math.round(p.ram_mb / 1024) + 'GB RAM');
        if (p.disk_gb) parts.push(p.disk_gb + 'GB NVMe');
        const currency = p.currency || 'NOK';
        const price = [];
        if (p.hourly_rate_nok > 0) price.push(p.hourly_rate_nok + ' ' + currency + '/hr');
        if (p.monthly_ceiling_nok > 0) price.push('max ' + p.monthly_ceiling_nok + ' ' + currency + '/mo');
        const spec = parts.join(', ');
        return p.name + (spec ? ' — ' + spec : '') + (price.length ? ' (' + price.join(', ') + ')' : '');
    }

    // revealDeploySelection puts the first control the confirmation names below the
    // fixed mobile top bar, so the plan it is checked against is not clipped by the
    // shell when the dialog opens. On a viewport where that control is already clear
    // (no top bar, or it sits below one) it moves nothing. The settings page scrolls
    // smoothly; an animated scroll would still be running when the dialog freezes the
    // page, so this one is applied instantly.
    function revealDeploySelection() {
        if (!deployPlanSelect || typeof deployPlanSelect.getBoundingClientRect !== 'function') return;
        const bar = document.querySelector('.mobile-topbar');
        if (!bar || typeof window.scrollBy !== 'function') return;
        const margin = 8;
        const covered = bar.getBoundingClientRect().bottom + margin
            - deployPlanSelect.getBoundingClientRect().top;
        if (covered <= 0) return;
        const root = document.documentElement;
        const previous = root.style.scrollBehavior;
        root.style.scrollBehavior = 'auto';
        window.scrollBy(0, -covered);
        root.style.scrollBehavior = previous;
    }

    // deployCostText renders the provider's own price facts for the confirmation:
    // the hourly rate it charges and the monthly ceiling it documents. A plan the
    // provider quoted no rate for says so instead of reading as a free order; no
    // figure here is computed, converted or capped by the page.
    function deployCostText(plan) {
        const currency = plan.currency || 'NOK';
        const parts = [];
        if (plan.hourly_rate_nok > 0) {
            parts.push(_('deploy_vps_cost_hourly')
                .replace('{rate}', plan.hourly_rate_nok)
                .replace('{currency}', currency));
        }
        if (plan.monthly_ceiling_nok > 0) {
            parts.push(_('deploy_vps_cost_ceiling')
                .replace('{ceiling}', plan.monthly_ceiling_nok)
                .replace('{currency}', currency));
        }
        return parts.length ? parts.join(', ') : _('deploy_vps_cost_unknown');
    }

    // deployOrderMessage names the five facts the operator approves: the plan, the
    // region and datacenter the selectors are showing, the image, and the cost. The
    // names are read from the same options the payload's ids came from, so the
    // summary cannot describe a different selection than the one being ordered. The
    // datacenter option's own label already says when the provider chooses it.
    function deployOrderMessage(plan) {
        const selectedText = select => (select && select.selectedIndex >= 0)
            ? select.options[select.selectedIndex].textContent
            : '';
        return _('deploy_vps_confirm_body')
            .replace('{plan}', plan.name || '')
            .replace('{region}', selectedText(deployRegionSelect))
            .replace('{datacenter}', selectedText(deployPlacementSelect))
            .replace('{os}', selectedText(deployOSSelect))
            .replace('{cost}', deployCostText(plan));
    }

    // appendDeployOption adds one disabled-by-default placeholder option, used
    // when the provider returned nothing selectable. It carries no id, so
    // nothing can be ordered from it.
    function appendDeployOption(select, text) {
        if (!select) return;
        select.innerHTML = '';
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = text;
        select.appendChild(opt);
        select.disabled = true;
    }

    async function loadGigahostCatalog() {
        if (!deployPlanSelect) return;
        const loading = document.getElementById('deployCatalogLoading');
        if (loading) loading.style.display = 'block';
        try {
            const res = await API.get('/api/admin/hosting/gigahost/catalog', {silent: true});
            renderDeployCatalogStale(res);
            cachedPlans = (res && res.plans) ? res.plans : [];
            if (cachedPlans.length === 0) {
                // An empty result destroys the pin, so record the loss first: the
                // operator's explicit choice must not evaporate into a later
                // recovery that looks like a fresh managed selection.
                deploymentPlacementIntent.lost(deployPlacementSelect ? deployPlacementSelect.value : null);
                appendDeployOption(deployPlanSelect, _('deploy_vps_no_plans'));
                appendDeployOption(deployRegionSelect, _('deploy_vps_no_plans'));
                if (deployPlacementSelect) appendDeployOption(deployPlacementSelect, _('deploy_vps_no_plans'));
                appendDeployOption(deployOSSelect, _('deploy_vps_no_plans'));
                // Automatic event: an outstanding choice survives it.
                updateDeployButtonState();
                return;
            }
            deployPlanSelect.innerHTML = '';
            deployPlanSelect.disabled = false;
            cachedPlans.forEach((p, idx) => {
                const opt = document.createElement('option');
                opt.value = idx;
                opt.textContent = deployPlanLabel(p);
                deployPlanSelect.appendChild(opt);
            });
            // Re-examine the CURRENT choices, so a datacenter whose stock vanished
            // between reads is dropped rather than re-defaulted to region-managed.
            updateDeploySelections({
                region: deployRegionSelect ? deployRegionSelect.value : null,
                os: deployOSSelect ? deployOSSelect.value : null,
                placement: deployPlacementSelect ? deployPlacementSelect.value : null
            });
        } catch (err) {
            // A failed read destroys the pin and the displayed catalog answer, so
            // record the loss before the selectors are replaced.
            deploymentPlacementIntent.lost(deployPlacementSelect ? deployPlacementSelect.value : null);
            renderDeployCatalogStale(null);
            cachedPlans = [];
            const message = _('deploy_vps_catalog_unavailable');
            appendDeployOption(deployPlanSelect, message);
            appendDeployOption(deployRegionSelect, message);
            if (deployPlacementSelect) appendDeployOption(deployPlacementSelect, message);
            appendDeployOption(deployOSSelect, message);
            // No pin survives a failed read, but the latch stays armed so the
            // recovery cannot become an unchosen region-managed purchase.
            showDeployPlacementHint('');
            updateDeployButtonState();
        } finally {
            if (loading) loading.style.display = 'none';
        }
    }

    // updateDeploySelections rebuilds the region and image selectors from the
    // plan the provider actually returned. It keeps a selection only when that
    // value is still valid for the new plan, so a plan change cannot leave an
    // incompatible region or image selected. previous holds the values the user
    // had chosen; pass null to take the provider's first valid choice.
    function updateDeploySelections(previous) {
        const plan = deployPlanAt();
        const keepRegion = previous ? previous.region : null;
        const keepOS = previous ? previous.os : null;

        if (!plan) {
            appendDeployOption(deployRegionSelect, _('deploy_vps_no_plans'));
            if (deployPlacementSelect) appendDeployOption(deployPlacementSelect, _('deploy_vps_no_plans'));
            appendDeployOption(deployOSSelect, _('deploy_vps_no_plans'));
            // Automatic rebuild: never clears an outstanding choice.
            updateDeployButtonState();
            return;
        }

        const regions = (plan.regions || []).filter(r => r.available && r.in_stock !== false);
        if (deployRegionSelect) {
            deployRegionSelect.innerHTML = '';
            regions.forEach(r => {
                const opt = document.createElement('option');
                opt.value = r.id;
                const label = r.name || String(r.id);
                opt.textContent = r.country ? (label + ' (' + r.country + ')') : label;
                if (keepRegion !== null && String(r.id) === String(keepRegion)) opt.selected = true;
                deployRegionSelect.appendChild(opt);
            });
            if (regions.length === 0) {
                appendDeployOption(deployRegionSelect, _('deploy_vps_no_region_stock'));
            } else {
                deployRegionSelect.disabled = false;
            }
        }

        // Rebuild from the new plan and the surviving region, so a pin the new pair
        // cannot honour is dropped rather than reaching the payload.
        // The rebuild sets the latch itself when it drops a pin; it never clears it.
        rebuildDeployPlacement(previous ? previous.placement : null);

        const images = plan.os_options || [];
        if (deployOSSelect) {
            deployOSSelect.innerHTML = '';
            images.forEach(os => {
                const opt = document.createElement('option');
                opt.value = os.os_id;
                opt.textContent = os.os_name || String(os.os_id);
                if (keepOS !== null && String(os.os_id) === String(keepOS)) opt.selected = true;
                deployOSSelect.appendChild(opt);
            });
            if (images.length === 0) {
                appendDeployOption(deployOSSelect, _('deploy_vps_no_os'));
            } else {
                deployOSSelect.disabled = false;
            }
        }

        updateDeployButtonState();
    }

    // updateDeployButtonState disables ordering unless the plan, region and image
    // selectors all carry a real provider value. A disabled button cannot post a
    // guessed selection.
    function updateDeployButtonState() {
        if (!btnDeployVPS) return;
        const ready = !!deployPlanAt()
            && !!deployRegionSelect && deployRegionSelect.value !== ''
            && !!deployOSSelect && deployOSSelect.value !== ''
            // A dropped pin blocks ordering until the operator chooses again. The
            // stored choice is not silently read as region-managed placement.
            && !deployPlacementNeedsChoice();
        btnDeployVPS.disabled = !ready;
    }

    async function handleDeployVPS() {
        const plan = deployPlanAt();
        if (!plan) return;

        // The payload is built only from values the provider returned. Each
        // selector is re-read here rather than defaulted, so an empty selector
        // stops the order instead of posting a guess.
        const regionID = deployRegionSelect ? parseInt(deployRegionSelect.value, 10) : NaN;
        const osID = deployOSSelect ? parseInt(deployOSSelect.value, 10) : NaN;
        if (!Number.isInteger(regionID) || regionID <= 0 || !Number.isInteger(osID) || osID <= 0) {
            UI.toast(_('deploy_vps_select_required'), 'error');
            return;
        }

        // A dropped pin must be re-chosen before anything is bought.
        if (deployPlacementNeedsChoice()) {
            UI.toast(_('deploy_vps_placement_choice_cleared'), 'error');
            return;
        }

        // The placement half of the payload comes from the module, which returns
        // null for any choice it cannot send. A null therefore stops the order
        // instead of falling back to a different location.
        //
        // A vanished option reads as '' (which a <select> produces for an unknown
        // value), and '' means region-managed. That is the silent downgrade this
        // path forbids, so the value is verified against the option list.
        const placementValue = placementReadValue(deployPlacementSelect);
        if (placementValue === null) {
            UI.toast(_('deploy_vps_placement_choice_cleared'), 'error');
            return;
        }
        const placementField = placementPayloadField(
            deployPlacementChoices(),
            placementValue,
            regionID
        );
        if (!placementField) {
            UI.toast(_('deploy_vps_select_required'), 'error');
            return;
        }

        // A paid action is confirmed before the request leaves the page. The
        // summary is built from the values the payload below already carries and
        // the labels the operator is looking at, so it cannot describe a different
        // order. Cancelling returns here: nothing is sent, nothing is disabled and
        // the form keeps every selection.
        if (deployConfirmationOpen) return;
        // The confirmation is checked against the form, so the first control it
        // names is brought clear of the fixed top bar before the dialog opens (the
        // dialog itself docks to the bottom edge). Nothing moves when that control
        // is already fully visible.
        revealDeploySelection();
        deployConfirmationOpen = true;
        let confirmed = false;
        try {
            confirmed = await UI.confirm({
                title: _('deploy_vps_confirm_title'),
                message: deployOrderMessage(plan),
                confirmText: _('deploy_vps_btn'),
                confirmVariant: 'primary'
            });
        } finally {
            deployConfirmationOpen = false;
        }
        if (!confirmed) return;

        const btn = document.getElementById('btnDeployVPS');
        const spinner = document.getElementById('deployVPSSpinner');
        if (btn) btn.disabled = true;
        if (spinner) spinner.classList.remove('hidden');

        try {
            // region_id is always sent to the panel: it is the region the operator
            // saw, the duplicate-guard key and the ledger field. A pin adds dc_id
            // beside it; the provider client drops region_id on the outbound wire.
            const payload = Object.assign({
                pid: plan.product_id,
                price_id: plan.price_id,
                region_id: regionID,
                os_id: osID,
                hourly_price_nok: plan.hourly_rate_nok
            }, placementField);
            const res = await API.post('/api/admin/hosting/gigahost/order', payload);
            UI.toast(res.message || _('deploy_vps_order_placed'), 'success');
            loadRecentOrders();
        } catch (err) {
            UI.toast(err.message || _('error'), 'error');
        } finally {
            updateDeployButtonState();
            if (spinner) spinner.classList.add('hidden');
        }
    }

    if (deployPlanSelect) {
        deployPlanSelect.addEventListener('change', () => {
            // Plan change rebuilds both dependent selectors from the new plan. The
            // values selected so far are offered back so a choice the new plan
            // still supports is preserved, and one it does not support is dropped.
            updateDeploySelections({
                region: deployRegionSelect ? deployRegionSelect.value : null,
                os: deployOSSelect ? deployOSSelect.value : null,
                placement: deployPlacementSelect ? deployPlacementSelect.value : null
            });
        });
    }
    if (deployRegionSelect) {
        deployRegionSelect.addEventListener('change', () => {
            // A region change can invalidate a pin; rebuild so the drop is visible.
            rebuildDeployPlacement(deployPlacementSelect ? deployPlacementSelect.value : null);
            updateDeployButtonState();
        });
    }
    if (deployPlacementSelect) {
        deployPlacementSelect.addEventListener('change', () => {
            // The only place the latch may be released: the operator acting on the
            // selector itself. placementHandleChoice owns every part of that rule.
            const outcome = placementHandleChoice(
                deploymentPlacementIntent, deployPlacementSelect, deployPlacementChoices());
            deployPlacementSelect.value = outcome.value;
            showDeployPlacementHint(outcome.hint);
            // The outcome reports whether ordering stays blocked; it is applied here
            // rather than re-derived, so a refusal cannot be lost between the two.
            deploymentPlacementIntent.apply(outcome.blocked);
            updateDeployButtonState();
        });
    }
    if (deployOSSelect) {
        deployOSSelect.addEventListener('change', updateDeployButtonState);
    }
    if (btnRefreshCatalog) {
        btnRefreshCatalog.addEventListener('click', () => {
            // The manual refresh re-reads the catalog and then the orders, and it
            // restarts the one refresh timer so the manual read also counts as the
            // start of the next 30-second interval instead of racing it.
            loadGigahostCatalog();
            loadRecentOrders();
            startGigahostOrderStatusRefresh(loadRecentOrders);
        });
    }
    if (btnDeployVPS) {
        btnDeployVPS.addEventListener('click', handleDeployVPS);
    }

    if (deployPlanSelect) {
        loadGigahostCatalog();
        // One initial read, then the status view owns the only repeating read. It
        // is registered once here, and starting it again would replace it rather
        // than add a second timer.
        loadRecentOrders();
        startGigahostOrderStatusRefresh(loadRecentOrders);
        loadSetupIntents();
    }
