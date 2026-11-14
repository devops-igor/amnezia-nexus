/* Catalog freshness display for the Gigahost ordering page.
 *
 * The catalog the ordering page shows comes from a bounded server-side cache. When
 * the last refresh failed the server keeps serving the last complete snapshot and
 * marks it stale; this module is what tells the administrator that, instead of
 * letting an old snapshot look current.
 *
 * It states only the freshness fact the server reported. It never decides whether
 * a selection may be ordered: the order handler revalidates price, stock,
 * placement and operating system against the live provider catalog, and a stale
 * snapshot there is refused server-side regardless of what this banner shows. */

/* renderDeployCatalogStale shows or clears the stale-catalog banner.
 *
 * A fresh answer clears it, so a recovered provider never still looks stale. An
 * absent answer (an error response) clears it too: this banner describes the
 * freshness of a snapshot that was served, not the absence of one, and the
 * ordering form already shows its own unavailable state. */
function renderDeployCatalogStale(res) {
    const banner = document.getElementById('deployCatalogStale');
    if (!banner) return;
    if (!res || !res.stale) {
        banner.style.display = 'none';
        banner.textContent = '';
        return;
    }
    const age = Number(res.age_seconds);
    const ageText = Number.isFinite(age) && age >= 0 ? formatDeployCatalogAge(age) : '';
    banner.textContent = _('deploy_vps_catalog_stale').replace('{age}', ageText);
    banner.style.display = 'block';
}

/* formatDeployCatalogAge renders a snapshot age in the coarsest useful unit, so
 * the banner shows elapsed time rather than a machine timestamp. */
function formatDeployCatalogAge(seconds) {
    if (seconds < 60) return Math.round(seconds) + 's';
    if (seconds < 3600) return Math.round(seconds / 60) + 'm';
    return Math.round(seconds / 3600) + 'h';
}
