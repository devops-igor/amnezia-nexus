/* Self-contained slide puzzle controller for the login page. */
(function () {
    'use strict';

    const root = document.getElementById('captchaPuzzle');
    if (!root) return;
    const image = document.getElementById('captchaImage');
    const piece = document.getElementById('captchaPiece');
    const track = document.getElementById('captchaTrack');
    const handle = document.getElementById('captchaHandle');
    const fill = document.getElementById('captchaFill');
    const status = document.getElementById('captchaStatus');
    const refreshButton = document.getElementById('captchaRefresh');
    const width = 300;
    const maxPieceX = width - 64;

    let challenge = null;
    let verifiedTicket = '';
    let x = 0;
    let startClientX = 0;
    let startX = 0;
    let activePointer = null;
    let pending = false;
    let generation = 0;

    function message(key, kind) {
        status.textContent = window._(key);
        status.className = 'captcha-status' + (kind ? ' ' + kind : '');
    }

    function setX(next) {
        x = Math.max(challenge.thumb_x, Math.min(maxPieceX, Math.round(next)));
        const progress = (x - challenge.thumb_x) / (maxPieceX - challenge.thumb_x);
        const handlePosition = progress * (track.clientWidth - handle.offsetWidth);
        handle.style.left = handlePosition + 'px';
        fill.style.width = (handlePosition + handle.offsetWidth / 2) + 'px';
        piece.style.left = (x / width * 100) + '%';
        handle.setAttribute('aria-valuemin', String(challenge.thumb_x));
        handle.setAttribute('aria-valuenow', String(x));
    }

    async function refresh() {
        const current = ++generation;
        if (activePointer !== null && handle.hasPointerCapture(activePointer)) {
            handle.releasePointerCapture(activePointer);
        }
        activePointer = null;
        challenge = null;
        verifiedTicket = '';
        pending = false;
        handle.disabled = true;
        refreshButton.disabled = true;
        image.removeAttribute('src');
        piece.removeAttribute('src');
        message('captcha_slide_prompt');
        try {
            const response = await window.API.get('/api/auth/captcha', { cache: 'no-store', silent: true });
            if (current !== generation) return;
            if (!response.captcha_id || !response.image || !response.thumb) throw new Error('Invalid challenge');
            challenge = response;
            image.src = response.image;
            piece.src = response.thumb;
            piece.style.top = (response.thumb_y / 160 * 100) + '%';
            setX(response.thumb_x);
            handle.disabled = false;
        } catch (_) {
            if (current === generation) message('captcha_failed', 'error');
        } finally {
            if (current === generation) refreshButton.disabled = false;
        }
    }

    async function verify() {
        if (!challenge || pending || verifiedTicket) return;
        const current = generation;
        pending = true;
        handle.disabled = true;
        try {
            const response = await window.API.post('/api/auth/captcha/verify', {
                captcha_id: challenge.captcha_id,
                point: { x: x, y: challenge.thumb_y },
            }, { silent: true });
            if (current !== generation) return;
            if (!response.captcha_ticket) throw new Error('Missing ticket');
            verifiedTicket = response.captcha_ticket;
            message('captcha_verified', 'success');
        } catch (_) {
            if (current === generation) {
                message('captcha_failed', 'error');
                await refresh();
            }
        } finally {
            pending = false;
        }
    }

    handle.addEventListener('pointerdown', function (event) {
        if (!challenge || pending || verifiedTicket) return;
        event.preventDefault();
        activePointer = event.pointerId;
        startClientX = event.clientX;
        startX = x;
        handle.setPointerCapture(activePointer);
    });

    handle.addEventListener('pointermove', function (event) {
        if (event.pointerId !== activePointer || !challenge) return;
        const range = track.clientWidth - handle.offsetWidth;
        if (range > 0) setX(startX + (event.clientX - startClientX) * (maxPieceX - challenge.thumb_x) / range);
    });

    handle.addEventListener('pointerup', function (event) {
        if (event.pointerId !== activePointer) return;
        activePointer = null;
        handle.releasePointerCapture(event.pointerId);
        void verify();
    });

    handle.addEventListener('pointercancel', function (event) {
        if (event.pointerId !== activePointer) return;
        activePointer = null;
        if (challenge) setX(challenge.thumb_x);
    });

    handle.addEventListener('keydown', function (event) {
        if (!challenge || pending || verifiedTicket) return;
        if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
            event.preventDefault();
            setX(x + (event.key === 'ArrowRight' ? 4 : -4));
        } else if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            void verify();
        }
    });

    refreshButton.addEventListener('click', function () { void refresh(); });
    window.CaptchaSlider = { refresh: refresh, ticket: function () { return verifiedTicket; } };
    void refresh();
}());
