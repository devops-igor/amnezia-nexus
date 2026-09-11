/**
 * Amnezia Nexus — Interactive Table Engine
 * Provides client-side instant search, multi-type column sorting, status filtering,
 * responsive pagination, and dynamic telemetry refresh.
 */
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        const NexusTable = factory();
        root.NexusTable = NexusTable;
        root.DataTable = NexusTable; // Backward-compatible alias
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Unit multipliers for byte parsing
    const BYTE_UNITS = {
        'b': 1,
        'byte': 1,
        'bytes': 1,
        'kb': 1024,
        'kib': 1024,
        'mb': 1024 * 1024,
        'mib': 1024 * 1024,
        'gb': 1024 * 1024 * 1024,
        'gib': 1024 * 1024 * 1024,
        'tb': 1024 * 1024 * 1024 * 1024,
        'tib': 1024 * 1024 * 1024 * 1024,
        'pb': 1024 * 1024 * 1024 * 1024 * 1024,
        'pib': 1024 * 1024 * 1024 * 1024 * 1024
    };

    /**
     * Safely parse human-readable bytes (e.g. "1.2 GB", "820 KB", "500 B") into numeric bytes.
     * Returns NaN if not a byte string.
     */
    function parseBytes(val) {
        if (typeof val !== 'string') return NaN;
        const match = val.trim().match(/^([\d.,]+)\s*([a-zA-Z]+)(?:\/s)?$/);
        if (!match) return NaN;
        const num = parseFloat(match[1].replace(/,/g, ''));
        const unit = match[2].toLowerCase();
        if (isNaN(num) || !(unit in BYTE_UNITS)) return NaN;
        return num * BYTE_UNITS[unit];
    }

    /**
     * Parse cell value for sorting (bytes, numbers, dates, strings)
     */
    function parseSortValue(cell, declaredType) {
        if (!cell) return '';

        // 1. Explicit data attribute override
        const explicitVal = cell.getAttribute('data-sort-val') || cell.getAttribute('data-sort-value');
        if (explicitVal !== null) {
            const num = Number(explicitVal);
            return !isNaN(num) ? num : explicitVal.toLowerCase();
        }

        const rawText = cell.textContent ? cell.textContent.trim() : '';
        if (!rawText) return '';

        // 2. Type-guided or auto-detected parsing
        if (declaredType === 'bytes') {
            const bytes = parseBytes(rawText);
            if (!isNaN(bytes)) return bytes;
        }

        // Try byte string first even if not declared
        const autoBytes = parseBytes(rawText);
        if (!isNaN(autoBytes)) return autoBytes;

        if (declaredType === 'number' || declaredType === 'numeric') {
            const cleaned = rawText.replace(/[^\d.-]/g, '');
            const num = parseFloat(cleaned);
            return isNaN(num) ? rawText.toLowerCase() : num;
        }

        if (declaredType === 'date') {
            const ts = Date.parse(rawText);
            if (!isNaN(ts)) return ts;
        }

        // Auto-detect pure number (or currency/percentage)
        const cleanNumber = rawText.replace(/^[^\d.-]+|[^\d.-]+$/g, '').replace(/,/g, '');
        if (cleanNumber !== '' && !isNaN(Number(cleanNumber))) {
            return Number(cleanNumber);
        }

        // Auto-detect standard ISO date or date format
        if (rawText.length >= 8 && /^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}/.test(rawText)) {
            const ts = Date.parse(rawText);
            if (!isNaN(ts)) return ts;
        }

        return rawText.toLowerCase();
    }

    /**
     * Default options for NexusTable
     */
    const DEFAULT_OPTIONS = {
        searchable: true,
        sortable: true,
        paginate: true,
        pageSize: 10,
        filterSelector: null,
        searchSelector: null,
        toolbarSelector: null,
        emptyMessage: 'No matching records found',
        searchPlaceholder: 'Search...',
        statusAttribute: 'data-status'
    };

    /**
     * Interactive NexusTable class
     */
    class NexusTable {
        constructor(tableElementOrSelector, options = {}) {
            this.table = typeof tableElementOrSelector === 'string'
                ? document.querySelector(tableElementOrSelector)
                : tableElementOrSelector;

            if (!this.table || this.table.tagName !== 'TABLE') {
                throw new Error('NexusTable: Invalid table element provided.');
            }

            this.options = Object.assign({}, DEFAULT_OPTIONS, options);
            this.tbody = this.table.querySelector('tbody') || (typeof this.table.createTBody === 'function' ? this.table.createTBody() : null);
            if (!this.tbody) {
                this.tbody = document.createElement('tbody');
                this.table.appendChild(this.tbody);
            }

            this.rowRecords = [];
            this.filteredRecords = [];
            this.currentPage = 1;
            this.searchQuery = '';
            this.currentStatusFilter = 'all';
            this.sortColumnIndex = null;
            this.sortDirection = 'none'; // 'asc' | 'desc' | 'none'

            // UI Elements
            this.toolbarEl = null;
            this.searchInputEl = null;
            this.searchClearBtn = null;
            this.paginationEl = null;
            this.emptyRowEl = null;

            this._init();
        }

        /**
         * Initialize table wrapper, headers, toolbar, and data rows
         */
        _init() {
            this.table.classList.add('nexus-table');

            // Find or build table container
            this.container = this.table.closest('.table-container') || this.table.parentElement;

            this._buildToolbar();
            this._setupHeaders();
            this._setupStatusFilters();
            this._buildPagination();
            this._indexRows();
            this._applyFiltersAndSort();
            this._render();
        }

        /**
         * Index rows from DOM
         */
        _indexRows() {
            this.rowRecords = [];
            const trs = Array.from(this.tbody.querySelectorAll('tr'));

            trs.forEach((tr, index) => {
                // Ignore empty state row or loading rows
                if (tr.classList.contains('table-empty-state') || tr.classList.contains('table-loading-row') || tr.id?.includes('loading')) {
                    return;
                }

                // Gather cell text content
                const cells = Array.from(tr.cells);
                const searchableText = cells.map(td => {
                    if (td.getAttribute('data-searchable') === 'false') return '';
                    return (td.textContent || '').trim().toLowerCase();
                }).join(' ');

                // Extract status
                let status = tr.getAttribute(this.options.statusAttribute) || '';
                if (!status) {
                    const statusBadge = tr.querySelector('[data-status]');
                    if (statusBadge) {
                        status = statusBadge.getAttribute('data-status') || '';
                    }
                }
                status = status.trim().toLowerCase();

                this.rowRecords.push({
                    el: tr,
                    originalIndex: index,
                    searchableText: searchableText,
                    status: status,
                    cells: cells
                });
            });
        }

        /**
         * Setup sortable table headers
         */
        _setupHeaders() {
            if (!this.options.sortable) return;

            const thead = this.table.querySelector('thead');
            if (!thead) return;

            const headers = Array.from(thead.querySelectorAll('th'));
            headers.forEach((th, colIdx) => {
                // Check if sortable
                const isExplicitlySortable = th.classList.contains('sortable') || th.hasAttribute('data-sort');
                const isExplicitlyDisabled = th.getAttribute('data-sortable') === 'false';

                if (isExplicitlyDisabled) return;
                if (!isExplicitlySortable && !this.options.sortable) return;

                th.classList.add('sortable');
                th.setAttribute('role', 'columnheader');
                th.setAttribute('tabindex', '0');
                if (!th.getAttribute('aria-sort')) {
                    th.setAttribute('aria-sort', 'none');
                }

                // Add or locate sort icon
                let sortIcon = th.querySelector('.sort-icon');
                if (!sortIcon) {
                    sortIcon = document.createElement('span');
                    sortIcon.className = 'sort-icon';
                    sortIcon.setAttribute('aria-hidden', 'true');
                    sortIcon.innerHTML = `
                        <svg class="sort-icon-svg sort-icon-asc" viewBox="0 0 24 24"><use href="#icon-arrow-up"></use></svg>
                        <svg class="sort-icon-svg sort-icon-desc" viewBox="0 0 24 24"><use href="#icon-arrow-down"></use></svg>
                    `;
                    th.appendChild(sortIcon);
                }

                // Event listener
                const triggerSort = (e) => {
                    e.preventDefault();
                    this._handleHeaderClick(colIdx, th);
                };

                th.addEventListener('click', triggerSort);
                th.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        triggerSort(e);
                    }
                });
            });
        }

        /**
         * Handle column header sort toggle
         */
        _handleHeaderClick(colIdx, th) {
            const currentAria = th.getAttribute('aria-sort');
            let nextDirection = 'asc';

            if (this.sortColumnIndex === colIdx) {
                if (currentAria === 'ascending') {
                    nextDirection = 'desc';
                } else if (currentAria === 'descending') {
                    nextDirection = 'none';
                } else {
                    nextDirection = 'asc';
                }
            } else {
                nextDirection = 'asc';
            }

            // Reset all other headers
            const thead = this.table.querySelector('thead');
            thead.querySelectorAll('th.sortable').forEach(header => {
                header.setAttribute('aria-sort', 'none');
                header.classList.remove('sort-active', 'sort-asc', 'sort-desc');
            });

            this.sortColumnIndex = nextDirection === 'none' ? null : colIdx;
            this.sortDirection = nextDirection;

            if (nextDirection !== 'none') {
                th.setAttribute('aria-sort', nextDirection === 'asc' ? 'ascending' : 'descending');
                th.classList.add('sort-active', nextDirection === 'asc' ? 'sort-asc' : 'sort-desc');
            }

            this._applyFiltersAndSort();
            this.currentPage = 1;
            this._render();
        }

        /**
         * Build or bind search and filter toolbar
         */
        _buildToolbar() {
            // Check if user specified an existing search input
            if (this.options.searchSelector) {
                this.searchInputEl = document.querySelector(this.options.searchSelector);
                if (this.searchInputEl) {
                    this.searchInputEl.addEventListener('input', (e) => this._onSearchInput(e.target.value));
                }
            }

            if (!this.options.searchable && !this.options.filterSelector) {
                return;
            }

            // Check if toolbar already exists before table
            let toolbar = this.options.toolbarSelector ? document.querySelector(this.options.toolbarSelector) : null;
            if (!toolbar && this.container) {
                const prev = this.table.previousElementSibling;
                if (prev && prev.classList.contains('table-toolbar')) {
                    toolbar = prev;
                }
            }

            if (!toolbar && this.options.searchable && !this.searchInputEl) {
                toolbar = document.createElement('div');
                toolbar.className = 'table-toolbar';

                const searchWrapper = document.createElement('div');
                searchWrapper.className = 'table-search-box';

                searchWrapper.innerHTML = `
                    <svg class="table-search-icon" aria-hidden="true"><use href="#icon-search"></use></svg>
                    <input type="text" class="table-search-input" placeholder="${this.options.searchPlaceholder}" aria-label="${this.options.searchPlaceholder}">
                    <button type="button" class="table-search-clear" aria-label="Clear search" style="display: none;">&times;</button>
                `;

                toolbar.appendChild(searchWrapper);
                this.table.parentNode.insertBefore(toolbar, this.table);

                this.searchInputEl = searchWrapper.querySelector('.table-search-input');
                this.searchClearBtn = searchWrapper.querySelector('.table-search-clear');

                if (this.searchInputEl) {
                    this.searchInputEl.addEventListener('input', (e) => {
                        const val = e.target.value;
                        if (this.searchClearBtn) {
                            this.searchClearBtn.style.display = val ? 'flex' : 'none';
                        }
                        this._onSearchInput(val);
                    });
                }

                if (this.searchClearBtn && this.searchInputEl) {
                    this.searchClearBtn.addEventListener('click', () => {
                        this.searchInputEl.value = '';
                        this.searchClearBtn.style.display = 'none';
                        this.searchInputEl.focus();
                        this._onSearchInput('');
                    });
                }
            }

            this.toolbarEl = toolbar;
        }

        /**
         * Setup status filter chips or dropdowns
         */
        _setupStatusFilters() {
            let filterRoot = null;
            if (this.options.filterSelector) {
                filterRoot = typeof this.options.filterSelector === 'string'
                    ? document.querySelector(this.options.filterSelector)
                    : this.options.filterSelector;
            } else if (this.toolbarEl) {
                filterRoot = this.toolbarEl.querySelector('.table-filter-chips');
            }

            if (!filterRoot) return;

            // Handle dropdown <select>
            if (filterRoot.tagName === 'SELECT') {
                filterRoot.addEventListener('change', (e) => {
                    this.setFilter(e.target.value);
                });
                return;
            }

            // Handle button/chip group
            const chips = filterRoot.querySelectorAll('.filter-chip, [data-status]');
            chips.forEach(chip => {
                chip.addEventListener('click', (e) => {
                    e.preventDefault();
                    chips.forEach(c => c.classList.remove('active'));
                    chip.classList.add('active');
                    const status = chip.getAttribute('data-status') || 'all';
                    this.setFilter(status);
                });
            });
        }

        /**
         * Build or locate pagination controls
         */
        _buildPagination() {
            if (!this.options.paginate) return;

            // Check if pagination container exists after table
            let pagination = this.container ? this.container.querySelector('.table-pagination') : null;
            if (!pagination) {
                const next = this.table.nextElementSibling;
                if (next && next.classList.contains('table-pagination')) {
                    pagination = next;
                }
            }

            if (!pagination) {
                pagination = document.createElement('div');
                pagination.className = 'table-pagination';
                if (this.table.parentNode) {
                    this.table.parentNode.insertBefore(pagination, this.table.nextSibling);
                }
            }

            this.paginationEl = pagination;
        }

        /**
         * Search input handler with micro-debounce
         */
        _onSearchInput(query) {
            clearTimeout(this._searchDebounceTimer);
            this._searchDebounceTimer = setTimeout(() => {
                this.searchQuery = (query || '').trim().toLowerCase();
                this.currentPage = 1;
                this._applyFiltersAndSort();
                this._render();
            }, 80);
        }

        /**
         * Programmatic search
         */
        search(query) {
            if (this.searchInputEl) {
                this.searchInputEl.value = query;
                if (this.searchClearBtn) {
                    this.searchClearBtn.style.display = query ? 'flex' : 'none';
                }
            }
            this.searchQuery = (query || '').trim().toLowerCase();
            this.currentPage = 1;
            this._applyFiltersAndSort();
            this._render();
        }

        /**
         * Programmatic status filter
         */
        setFilter(status) {
            this.currentStatusFilter = (status || 'all').trim().toLowerCase();
            this.currentPage = 1;
            this._applyFiltersAndSort();
            this._render();
        }

        /**
         * Apply search, status filter, and multi-type sorting
         */
        _applyFiltersAndSort() {
            const hasSearch = Boolean(this.searchQuery);
            const hasFilter = this.currentStatusFilter !== 'all' && this.currentStatusFilter !== '';

            // 1. Filter rows
            this.filteredRecords = this.rowRecords.filter(rec => {
                // Status filter
                if (hasFilter) {
                    if (rec.status !== this.currentStatusFilter) return false;
                }
                // Search query
                if (hasSearch) {
                    if (!rec.searchableText.includes(this.searchQuery)) return false;
                }
                return true;
            });

            // 2. Sort rows
            if (this.sortColumnIndex !== null && this.sortDirection !== 'none') {
                const colIdx = this.sortColumnIndex;
                const dir = this.sortDirection === 'asc' ? 1 : -1;

                // Detect declared type from th
                const thead = this.table.querySelector('thead');
                const th = thead ? thead.querySelectorAll('th')[colIdx] : null;
                const declaredType = th ? th.getAttribute('data-sort-type') || th.getAttribute('data-sort') : null;

                this.filteredRecords.sort((a, b) => {
                    const cellA = a.cells[colIdx];
                    const cellB = b.cells[colIdx];

                    const valA = parseSortValue(cellA, declaredType);
                    const valB = parseSortValue(cellB, declaredType);

                    if (valA === valB) return a.originalIndex - b.originalIndex;

                    if (typeof valA === 'number' && typeof valB === 'number') {
                        return (valA - valB) * dir;
                    }

                    return String(valA).localeCompare(String(valB), undefined, { numeric: true, sensitivity: 'base' }) * dir;
                });
            } else {
                // Restore original DOM insertion order
                this.filteredRecords.sort((a, b) => a.originalIndex - b.originalIndex);
            }
        }

        /**
         * Render visible rows, pagination, and empty state
         */
        _render() {
            const total = this.filteredRecords.length;
            const pageSize = Math.max(1, parseInt(this.options.pageSize, 10) || 10);
            const totalPages = Math.max(1, Math.ceil(total / pageSize));

            // Clamp current page
            if (this.currentPage > totalPages) {
                this.currentPage = totalPages;
            }
            if (this.currentPage < 1) {
                this.currentPage = 1;
            }

            const startIndex = this.options.paginate ? (this.currentPage - 1) * pageSize : 0;
            const endIndex = this.options.paginate ? Math.min(startIndex + pageSize, total) : total;

            // Set of elements that should be visible
            const visibleSet = new Set();
            for (let i = startIndex; i < endIndex; i++) {
                visibleSet.add(this.filteredRecords[i].el);
            }

            // Hide/show rows and reorder in DOM to match sort
            this.rowRecords.forEach(rec => {
                if (visibleSet.has(rec.el)) {
                    rec.el.style.display = '';
                } else {
                    rec.el.style.display = 'none';
                }
            });

            // Re-order visible elements in tbody according to sort order
            for (let i = startIndex; i < endIndex; i++) {
                this.tbody.appendChild(this.filteredRecords[i].el);
            }

            // Handle empty state
            this._renderEmptyState(total === 0);

            // Handle pagination controls
            if (this.options.paginate && this.paginationEl) {
                this._renderPagination(total, startIndex, endIndex, totalPages);
            }
        }

        /**
         * Render empty state row
         */
        _renderEmptyState(isEmpty) {
            if (isEmpty) {
                if (!this.emptyRowEl) {
                    const colCount = Math.max(1, this.table.querySelectorAll('thead th').length || 1);
                    const tr = document.createElement('tr');
                    tr.className = 'table-empty-state';
                    tr.innerHTML = `
                        <td colspan="${colCount}">
                            <div class="empty-state-content">
                                <svg class="empty-state-icon" aria-hidden="true"><use href="#icon-search"></use></svg>
                                <div class="empty-state-text">${this.options.emptyMessage}</div>
                            </div>
                        </td>
                    `;
                    this.emptyRowEl = tr;
                }
                if (!this.tbody.contains(this.emptyRowEl)) {
                    this.tbody.appendChild(this.emptyRowEl);
                }
                this.emptyRowEl.style.display = '';
            } else if (this.emptyRowEl) {
                this.emptyRowEl.style.display = 'none';
            }
        }

        /**
         * Render pagination UI
         */
        _renderPagination(total, startIndex, endIndex, totalPages) {
            if (!this.paginationEl) return;

            const from = total === 0 ? 0 : startIndex + 1;
            const to = endIndex;

            const infoHtml = `<div class="page-info">Showing <span class="page-count">${from}</span>–<span class="page-count">${to}</span> of <span class="page-total">${total}</span> entries</div>`;

            // Build page buttons
            let buttonsHtml = '<div class="page-buttons" role="navigation" aria-label="Pagination">';

            // Prev button
            const prevDisabled = this.currentPage <= 1;
            buttonsHtml += `<button type="button" class="page-btn page-prev" ${prevDisabled ? 'disabled' : ''} aria-label="Previous page">Prev</button>`;

            // Page numbers
            const maxVisibleButtons = 7;
            if (totalPages <= maxVisibleButtons) {
                for (let p = 1; p <= totalPages; p++) {
                    const isActive = p === this.currentPage;
                    buttonsHtml += `<button type="button" class="page-btn ${isActive ? 'active' : ''}" data-page="${p}" ${isActive ? 'aria-current="page"' : ''}>${p}</button>`;
                }
            } else {
                // Smart ellipsis
                const pages = [];
                pages.push(1);

                if (this.currentPage > 3) {
                    pages.push('...');
                }

                const start = Math.max(2, this.currentPage - 1);
                const end = Math.min(totalPages - 1, this.currentPage + 1);

                for (let p = start; p <= end; p++) {
                    pages.push(p);
                }

                if (this.currentPage < totalPages - 2) {
                    pages.push('...');
                }

                pages.push(totalPages);

                pages.forEach(p => {
                    if (p === '...') {
                        buttonsHtml += `<span class="page-ellipsis">&hellip;</span>`;
                    } else {
                        const isActive = p === this.currentPage;
                        buttonsHtml += `<button type="button" class="page-btn ${isActive ? 'active' : ''}" data-page="${p}" ${isActive ? 'aria-current="page"' : ''}>${p}</button>`;
                    }
                });
            }

            // Next button
            const nextDisabled = this.currentPage >= totalPages;
            buttonsHtml += `<button type="button" class="page-btn page-next" ${nextDisabled ? 'disabled' : ''} aria-label="Next page">Next</button>`;
            buttonsHtml += '</div>';

            this.paginationEl.innerHTML = infoHtml + buttonsHtml;

            // Attach event listeners
            const prevBtn = this.paginationEl.querySelector('.page-prev');
            if (prevBtn && !prevDisabled) {
                prevBtn.addEventListener('click', () => this.goToPage(this.currentPage - 1));
            }

            const nextBtn = this.paginationEl.querySelector('.page-next');
            if (nextBtn && !nextDisabled) {
                nextBtn.addEventListener('click', () => this.goToPage(this.currentPage + 1));
            }

            this.paginationEl.querySelectorAll('.page-btn[data-page]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const page = parseInt(btn.getAttribute('data-page'), 10);
                    if (!isNaN(page)) this.goToPage(page);
                });
            });
        }

        /**
         * Navigate to specific page
         */
        goToPage(page) {
            const pageSize = Math.max(1, parseInt(this.options.pageSize, 10) || 10);
            const totalPages = Math.max(1, Math.ceil(this.filteredRecords.length / pageSize));
            if (page < 1 || page > totalPages) return;
            this.currentPage = page;
            this._render();
        }

        /**
         * Dynamic update method when rows are added, removed, or updated via API / telemetry
         */
        refresh() {
            this._indexRows();
            this._applyFiltersAndSort();
            this._render();
        }

        /**
         * Alias for refresh
         */
        updateRows() {
            this.refresh();
        }

        /**
         * Teardown table listeners and injected UI elements
         */
        destroy() {
            if (this.toolbarEl && this.toolbarEl.parentNode) {
                this.toolbarEl.parentNode.removeChild(this.toolbarEl);
            }
            if (this.paginationEl && this.paginationEl.parentNode) {
                this.paginationEl.parentNode.removeChild(this.paginationEl);
            }
            if (this.emptyRowEl && this.emptyRowEl.parentNode) {
                this.emptyRowEl.parentNode.removeChild(this.emptyRowEl);
            }
            this.rowRecords.forEach(rec => {
                rec.el.style.display = '';
            });
        }

        /**
         * Static helper to initialize single table
         */
        static init(selector, options) {
            return new NexusTable(selector, options);
        }

        /**
         * Static helper to auto-initialize all tables matching a selector
         */
        static initAll(selector = 'table[data-nexus-table], table.interactive-table', options = {}) {
            const tables = Array.from(document.querySelectorAll(selector));
            return tables.map(tbl => new NexusTable(tbl, options));
        }
    }

    return NexusTable;
}));
