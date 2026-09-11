/**
 * Amnezia Nexus — Modern Interactive UI Utilities
 * Accessible modals, toast notifications, clipboard utilities, confirmation dialogs, and formatters.
 */
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.UI = factory();
        // Backward-compatible global exports
        root.showToast = function (message, type) {
            return root.UI.toast(message, type);
        };
        root.openModal = function (id, focusSelector) {
            return root.UI.modal.open(id, focusSelector);
        };
        root.closeModal = function (id) {
            return root.UI.modal.close(id);
        };
        root.copyToClipboard = function (text, triggerElement) {
            return root.UI.copy(text, triggerElement);
        };
        root.confirmModal = function (options) {
            return root.UI.confirm(options);
        };
        root.formatBytes = function (bytes) {
            return root.UI.formatBytes(bytes);
        };
        root.downloadFile = function (content, filename) {
            return root.UI.downloadFile(content, filename);
        };
        root.escapeHtml = function (str) {
            return root.UI.escapeHtml(str);
        };
        root.escapeJs = function (str) {
            return root.UI.escapeJs(str);
        };
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /* ===== Debounce helper for notifications ===== */
    const recentToasts = new Map();

    /* ===== Toast Notification Manager ===== */
    function getToastIconHtml(type) {
        if (type === 'success') {
            return '<svg class="icon" style="width:1.15rem;height:1.15rem;flex-shrink:0;" aria-hidden="true"><use href="#icon-check"></use></svg>';
        } else if (type === 'error') {
            return '<svg class="icon" style="width:1.15rem;height:1.15rem;flex-shrink:0;" aria-hidden="true"><use href="#icon-x"></use></svg>';
        } else if (type === 'warning') {
            return '<span style="font-weight:bold;font-size:1.1rem;line-height:1;flex-shrink:0;" aria-hidden="true">⚠</span>';
        }
        return '<span style="font-weight:bold;font-size:1.1rem;line-height:1;flex-shrink:0;" aria-hidden="true">ℹ</span>';
    }

    /**
     * Show modern toast notification
     * @param {string} message
     * @param {'info'|'success'|'error'|'warning'} [type='info']
     * @param {number} [duration=4000]
     */
    function toast(message, type = 'info', duration = 4000) {
        if (typeof document === 'undefined') return;

        const safeMessage = String(message || '');
        const toastType = type || 'info';

        // Debounce identical toasts within 600ms
        const debounceKey = toastType + ':' + safeMessage;
        const now = Date.now();
        if (recentToasts.has(debounceKey) && (now - recentToasts.get(debounceKey) < 600)) {
            return;
        }
        recentToasts.set(debounceKey, now);

        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        const el = document.createElement('div');
        el.className = 'toast toast-' + toastType;
        el.setAttribute('role', 'alert');
        el.style.cursor = 'pointer';

        const iconSpan = document.createElement('span');
        iconSpan.className = 'toast-icon';
        iconSpan.innerHTML = getToastIconHtml(toastType);

        const msgSpan = document.createElement('span');
        msgSpan.className = 'toast-message';
        msgSpan.textContent = safeMessage;

        el.appendChild(iconSpan);
        el.appendChild(msgSpan);
        container.appendChild(el);

        let isDismissed = false;
        function dismiss() {
            if (isDismissed) return;
            isDismissed = true;
            el.classList.add('toast-exit');
            setTimeout(function () {
                if (el.parentNode) {
                    el.parentNode.removeChild(el);
                }
            }, 300);
        }

        el.addEventListener('click', dismiss);
        setTimeout(dismiss, duration);
    }

    /* ===== Accessible Modal Manager ===== */
    let previousActiveElement = null;

    /**
     * Open modal by DOM id and auto-focus target
     * @param {string} modalId
     * @param {string} [focusSelector]
     */
    function openModal(modalId, focusSelector) {
        if (typeof document === 'undefined') return;
        const modal = document.getElementById(modalId);
        if (!modal) return;

        previousActiveElement = document.activeElement;
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';

        const focusTarget = focusSelector
            ? modal.querySelector(focusSelector)
            : modal.querySelector('input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])');

        if (focusTarget && typeof focusTarget.focus === 'function') {
            setTimeout(function () {
                focusTarget.focus();
            }, 80);
        }

        modal.dispatchEvent(new CustomEvent('modal:open', { bubbles: true, detail: { modalId: modalId } }));
    }

    /**
     * Close modal by DOM id or close topmost active modal
     * @param {string} [modalId]
     */
    function closeModal(modalId) {
        if (typeof document === 'undefined') return;
        let modal = null;
        if (modalId) {
            modal = document.getElementById(modalId);
        } else {
            const activeModals = document.querySelectorAll('.modal-backdrop.active');
            if (activeModals.length > 0) {
                modal = activeModals[activeModals.length - 1];
                modalId = modal.id;
            }
        }

        if (modal) {
            modal.classList.remove('active');
            const remaining = document.querySelectorAll('.modal-backdrop.active');
            const sidebar = document.getElementById('appSidebar');
            const isDrawerOpen = sidebar && sidebar.classList.contains('drawer-open');
            if (remaining.length === 0 && !isDrawerOpen) {
                document.body.style.overflow = '';
            }

            if (previousActiveElement && typeof previousActiveElement.focus === 'function') {
                try {
                    previousActiveElement.focus();
                } catch (_) {}
            }

            modal.dispatchEvent(new CustomEvent('modal:close', { bubbles: true, detail: { modalId: modalId } }));
        }
    }

    /* Set up global modal events once */
    if (typeof document !== 'undefined') {
        // Backdrop click to dismiss
        document.addEventListener('click', function (e) {
            if (e.target && e.target.classList && e.target.classList.contains('modal-backdrop') && e.target.classList.contains('active')) {
                closeModal(e.target.id);
            }
        });

        // Escape key closes topmost modal or mobile drawer
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                const activeModals = document.querySelectorAll('.modal-backdrop.active');
                if (activeModals.length > 0) {
                    const topModal = activeModals[activeModals.length - 1];
                    closeModal(topModal.id);
                } else if (typeof window !== 'undefined' && typeof window.toggleMobileDrawer === 'function') {
                    window.toggleMobileDrawer(false);
                }
            }
        });

        // Focus trap
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Tab') return;
            const activeModals = document.querySelectorAll('.modal-backdrop.active');
            if (activeModals.length === 0) return;
            const topModal = activeModals[activeModals.length - 1];
            const focusable = topModal.querySelectorAll(
                'input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"]), a[href]'
            );
            if (focusable.length === 0) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];

            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        });
    }

    /* ===== Clipboard Utility ===== */
    /**
     * Copy text to clipboard with feedback
     * @param {string} text
     * @param {HTMLElement} [triggerElement]
     * @returns {Promise<boolean>}
     */
    async function copy(text, triggerElement) {
        let success = false;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                success = true;
            } else {
                throw new Error('Clipboard API not supported');
            }
        } catch (_) {
            if (typeof document !== 'undefined') {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.left = '-9999px';
                ta.style.top = '0';
                ta.setAttribute('readonly', '');
                document.body.appendChild(ta);
                ta.select();
                try {
                    success = document.execCommand('copy');
                } catch (cmdErr) {
                    success = false;
                }
                document.body.removeChild(ta);
            }
        }

        const msg = (typeof window !== 'undefined' && typeof window._ === 'function')
            ? window._('copied_to_clipboard')
            : 'Copied to clipboard';

        if (success) {
            toast(msg, 'success');
            if (triggerElement && triggerElement.nodeType === 1) {
                triggerElement.classList.add('copied');
                const origContent = triggerElement.innerHTML;
                triggerElement.innerHTML = '<svg class="icon icon-check" style="color:var(--success);" aria-hidden="true"><use href="#icon-check"></use></svg>';
                setTimeout(function () {
                    triggerElement.innerHTML = origContent;
                    triggerElement.classList.remove('copied');
                }, 2000);
            }
        } else {
            toast('Failed to copy to clipboard', 'error');
        }

        return success;
    }

    /* ===== Reusable Async Confirmation Modal ===== */
    /**
     * Reusable async confirmation modal
     * @param {Object} options
     * @param {string} [options.title='Confirm Action']
     * @param {string} [options.message='']
     * @param {string} [options.confirmText='Confirm']
     * @param {string} [options.cancelText='Cancel']
     * @param {'danger'|'warning'|'primary'} [options.confirmVariant='danger']
     * @returns {Promise<boolean>}
     */
    function confirm(options = {}) {
        return new Promise(function (resolve) {
            if (typeof document === 'undefined') {
                resolve(false);
                return;
            }

            const modal = document.getElementById('nexusConfirmModal');
            if (!modal) {
                const nativeResult = window.confirm(options.message || 'Are you sure?');
                resolve(nativeResult);
                return;
            }

            const titleEl = document.getElementById('nexusConfirmTitle');
            const bodyEl = document.getElementById('nexusConfirmBody');
            const okBtn = document.getElementById('nexusConfirmOkBtn');
            const cancelBtn = document.getElementById('nexusConfirmCancelBtn');
            const closeBtn = document.getElementById('nexusConfirmCloseBtn');

            const defaultTitle = (typeof window !== 'undefined' && typeof window._ === 'function')
                ? window._('confirm_action')
                : 'Confirm Action';
            const defaultConfirm = (typeof window !== 'undefined' && typeof window._ === 'function')
                ? window._('confirm')
                : 'Confirm';
            const defaultCancel = (typeof window !== 'undefined' && typeof window._ === 'function')
                ? window._('cancel')
                : 'Cancel';

            const title = options.title || defaultTitle || 'Confirm Action';
            const message = options.message || '';
            const confirmText = options.confirmText || defaultConfirm || 'Confirm';
            const cancelText = options.cancelText || defaultCancel || 'Cancel';
            const variant = options.confirmVariant || 'danger';

            if (titleEl) titleEl.textContent = title;
            if (bodyEl) bodyEl.textContent = message;

            if (okBtn) {
                okBtn.textContent = confirmText;
                okBtn.className = 'btn btn-' + variant;
            }
            if (cancelBtn) {
                cancelBtn.textContent = cancelText;
            }

            let resolved = false;
            function finish(result) {
                if (resolved) return;
                resolved = true;
                cleanup();
                closeModal('nexusConfirmModal');
                resolve(result);
            }

            function onOk(e) {
                e.preventDefault();
                finish(true);
            }

            function onCancel(e) {
                e.preventDefault();
                finish(false);
            }

            function onModalClose(e) {
                if (e.detail && e.detail.modalId === 'nexusConfirmModal') {
                    finish(false);
                }
            }

            function cleanup() {
                if (okBtn) okBtn.removeEventListener('click', onOk);
                if (cancelBtn) cancelBtn.removeEventListener('click', onCancel);
                if (closeBtn) closeBtn.removeEventListener('click', onCancel);
                modal.removeEventListener('modal:close', onModalClose);
            }

            if (okBtn) okBtn.addEventListener('click', onOk);
            if (cancelBtn) cancelBtn.addEventListener('click', onCancel);
            if (closeBtn) closeBtn.addEventListener('click', onCancel);
            modal.addEventListener('modal:close', onModalClose);

            openModal('nexusConfirmModal', '#nexusConfirmOkBtn');
        });
    }

    /* ===== Format & Helper Utilities ===== */
    function formatBytes(bytes) {
        if (!bytes || Number.isNaN(bytes) || bytes < 0) return '0 B';
        bytes = Math.max(0, bytes);
        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const k = 1024;
        const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + units[i];
    }

    function downloadFile(content, filename) {
        if (typeof document === 'undefined') return;
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () {
            if (a.parentNode) {
                document.body.removeChild(a);
            }
            URL.revokeObjectURL(url);
        }, 100);
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function escapeJs(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r');
    }

    return {
        toast: toast,
        modal: {
            open: openModal,
            close: closeModal,
        },
        copy: copy,
        confirm: confirm,
        formatBytes: formatBytes,
        downloadFile: downloadFile,
        escapeHtml: escapeHtml,
        escapeJs: escapeJs,
    };
}));
