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
  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function show(text, clientX, clientY, color) {
    var t = document.getElementById('brain-tooltip');
    if (!t) {
      t = document.createElement('div');
      t.id = 'brain-tooltip';
      t.className = 'brain-tooltip';
      document.body.appendChild(t);
    }
    // A small colored dot (node health color / row severity) sits next to the
    // filename when a color is known; otherwise the content stays plain text.
    if (color) {
      t.innerHTML =
        '<span class="brain-tt-dot" style="background:' + color + '"></span>' +
        '<span class="brain-tt-body">' + esc(text || '') + '</span>';
    } else {
      t.textContent = text || '';
    }
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
    show(content, e.clientX, e.clientY, el.getAttribute('data-tt-color') || undefined);
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

  // ── Adaptive brain-map render cap ───────────────────────────
  // A ~30ms WebGL benchmark picks a per-device node cap for the brain maps:
  //   low (software renderer / very slow)   -> 150 nodes
  //   medium (integrated / modest)          -> 300 nodes (the default)
  //   high (decent discrete GPU)            -> 600 nodes
  //   ultra (high-end GPU, 16K textures)    -> 1200 nodes
  // The result is cached in sessionStorage (the GPU does not change mid
  // session) and only runs on pages that actually render a brain map.
  function _gpuBenchmark() {
    var out = { cap: 300, tier: 'medium', ms: 0, maxTex: 0, software: false };
    var canvas = document.createElement('canvas');
    var gl = null;
    try {
      gl = canvas.getContext('webgl2') || canvas.getContext('webgl') ||
           canvas.getContext('experimental-webgl');
    } catch (e) { gl = null; }
    if (!gl) return out;  // no WebGL at all: keep the default cap

    try {
      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      var rname = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '') : '';
      out.software = /swiftshader|llvmpipe|software|basic render/i.test(rname);
      out.maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0;
      if (!out.software) {
        // Draw benchmark: 6000 triangles, 24 frames. Software renderers skip
        // this — running it on SwiftShader would stall the page for seconds.
        var vsSrc = 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}';
        var fsSrc = 'precision mediump float;void main(){gl_FragColor=vec4(0.5);}';
        function mkShader(type, src) {
          var s = gl.createShader(type);
          gl.shaderSource(s, src);
          gl.compileShader(s);
          return s;
        }
        var prog = gl.createProgram();
        gl.attachShader(prog, mkShader(gl.VERTEX_SHADER, vsSrc));
        gl.attachShader(prog, mkShader(gl.FRAGMENT_SHADER, fsSrc));
        gl.linkProgram(prog);
        if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return out;
        gl.useProgram(prog);
        var verts = new Float32Array(6000 * 6);
        for (var vi = 0; vi < 6000; vi++) {
          verts[vi * 6] = (vi % 100) / 50 - 1;
          verts[vi * 6 + 1] = ((vi / 100 | 0) % 60) / 30 - 1;
          verts[vi * 6 + 2] = verts[vi * 6] + 0.02;
          verts[vi * 6 + 3] = verts[vi * 6 + 1];
          verts[vi * 6 + 4] = verts[vi * 6];
          verts[vi * 6 + 5] = verts[vi * 6 + 1] + 0.02;
        }
        var buf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buf);
        gl.bufferData(gl.ARRAY_BUFFER, verts, gl.STATIC_DRAW);
        var loc = gl.getAttribLocation(prog, 'p');
        gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
        gl.viewport(0, 0, 256, 256);
        var t0 = performance.now();
        for (var f = 0; f < 24; f++) gl.drawArrays(gl.TRIANGLES, 0, 18000);
        gl.finish();
        out.ms = performance.now() - t0;
        if (out.ms <= 12 && out.maxTex >= 16384) { out.cap = 1200; out.tier = 'ultra'; }
        else if (out.ms <= 35 && out.maxTex >= 8192) { out.cap = 600; out.tier = 'high'; }
        else if (out.ms <= 90) { out.cap = 300; out.tier = 'medium'; }
        else { out.cap = 150; out.tier = 'low'; }
      } else {
        out.cap = 150; out.tier = 'low';
      }
      var lose = gl.getExtension('WEBGL_lose_context');
      if (lose) lose.loseContext();
    } catch (e) { /* any failure keeps the default cap */ }
    return out;
  }

  if (document.getElementById('brain-map') || document.getElementById('brain-map-3d')) {
    var _gpu = null;
    try {
      var _cached = sessionStorage.getItem('patchi:gpu-bench');
      if (_cached) _gpu = JSON.parse(_cached);
    } catch (e) { _gpu = null; }
    if (!_gpu || typeof _gpu.cap !== 'number') {
      _gpu = _gpuBenchmark();
      try { sessionStorage.setItem('patchi:gpu-bench', JSON.stringify(_gpu)); } catch (e) {}
    }
    window._PATCHI_RENDER_CAP = Math.max(150, Math.min(1500, (_gpu.cap | 0) || 300));
    window._PATCHI_GPU_TIER = _gpu.tier || 'medium';
    // Tell the page the adaptive cap is known (the benchmark runs async,
    // after inline scripts that may have already synced UI text).
    try {
      window.dispatchEvent(new CustomEvent('patchi:gpu-ready',
        { detail: { cap: window._PATCHI_RENDER_CAP, tier: window._PATCHI_GPU_TIER } }));
    } catch (e) {}
  }
})();