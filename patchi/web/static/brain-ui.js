/**
 * brain-ui.js — shared UI helpers (loaded on every page via base.html).
 *
 * One styled hover tooltip (#brain-tooltip) used consistently across:
 *   - the 2D/3D brain map node hover (canvas.js / brain3d.js call the window
 *     API directly)
 *   - ANY element carrying a data-tooltip="..." attribute — search dropdown
 *     rows, compare tiles, heatmap tiles, table cells — via document-level
 *     delegation, so dynamically re-rendered content works with no rebinding.
 */
(function() {
  function show(text, clientX, clientY) {
    var t = document.getElementById('brain-tooltip');
    if (!t) {
      t = document.createElement('div');
      t.id = 'brain-tooltip';
      t.className = 'brain-tooltip';
      document.body.appendChild(t);
    }
    t.textContent = text || '';
    t.style.display = 'block';
    var pad = 14, off = 12;
    var w = t.offsetWidth, h = t.offsetHeight;
    var x = clientX + off, y = clientY + off;
    if (x + w > window.innerWidth - pad) x = clientX - w - off;
    if (y + h > window.innerHeight - pad) y = clientY - h - off;
    t.style.left = Math.max(pad, x) + 'px';
    t.style.top = Math.max(pad, y) + 'px';
  }
  function hide() {
    var t = document.getElementById('brain-tooltip');
    if (t) t.style.display = 'none';
  }

  window.showBrainTooltip = show;
  window.hideBrainTooltip = hide;

  // ── Delegated data-tooltip handling ────────────────────────
  // One listener pair on document covers every current and future
  // [data-tooltip] element (search dropdowns, compare tiles, heatmap tiles,
  // table rows) with the same instant styled tooltip as the maps.
  document.addEventListener('pointerover', function(e) {
    var el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    var content = el.getAttribute('data-tooltip');
    if (content === null || content === '') return;
    show(content, e.clientX, e.clientY);
  });
  document.addEventListener('pointerout', function(e) {
    if (!e.target) return;
    var el = e.target.closest ? e.target.closest('[data-tooltip]') : null;
    var next = e.relatedTarget && e.relatedTarget.closest ? e.relatedTarget.closest('[data-tooltip]') : null;
    // Hide only when actually leaving the tooltip element (not when moving
    // between its children or on to another data-tooltip element).
    if (el && el !== next) hide();
  });
  // Safety: hide on any page scroll/resize so stale tooltips never linger.
  window.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
})();