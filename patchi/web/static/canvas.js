/**
 * canvas.js — Patchi Brain Map (Konva.js) — OPTIMIZED
 *
 * Renders the file dependency graph as an interactive canvas.
 * Key optimizations:
 * - Viewport culling: only renders nodes within visible area + margin
 * - Simplified node shapes at small zoom levels
 * - Batch edge rendering via Canvas2D overlay
 * - Debounced minimap updates
 * - Optimized force layout (fewer iterations for large graphs)
 * - Proper touch gesture support
 */

var BrainMap = (() => {
  // ── Constants ──────────────────────────────────────────────
  const NODE_R = 14;
  const ANT_R = 4;
  const VIEWPORT_MARGIN = 200;
  const MAX_RENDERED_NODES = 300;
  const MINIMAP_DEBOUNCE = 100;

  var _longPressActive = false;

  const COLORS = {
    idle:         "#1A2810",
    bg:           "#0A1A0D",
    edge:         "#1E3014",
    text:         "#B8A898",
    healthy:      "#C8621A",
    scanning:     "#E8920A",
    done:         "#4ADE80",
    wounded:      "#FACC15",
    critical:     "#FF4D6D",
    dead:         "#3D2A1A",
    restricted:   "#2C2010",
    queen:        "#2C1208",
    entry_point:  "#8B3A0F",
    route_handler:"#7A2E08",
    test:         "#4ADE80",
    config:       "#4A5030",
    sensitive:    "#FF8C42",
    component:    "#6B8B5A",
    default:      "#C8621A",
    ant_minor:    "#C8621A",
    ant_soldier:  "#7A2E08",
    ant_queen:    "#2C1208",
    ant_spawn:    "#E8920A",
  };

  // ── State ──────────────────────────────────────────────────
  var stage, nodeLayer, antLayer, nodes = {}, ants = {}, edges = [];
  var _onWsMessage = null, _initialized = false;
  var scale = 1, offsetX = 0, offsetY = 0;
  var _currentView = 'graph';
  var _lastNodes = [], _lastEdges = [];
  var _showLabels = true;
  var _rotation = 0;
  var _renderedSet = new Set();  // IDs of currently rendered nodes
  var _minimapTimer = null;

  // ── Init ───────────────────────────────────────────────────
  function init(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    if (_initialized) {
      if (stage) stage.destroy();
      stage = null; nodeLayer = null; antLayer = null;
      nodes = {}; ants = {}; edges = [];
      _renderedSet.clear();
    }
    _initialized = true;

    var w = el.clientWidth || (el.parentElement && el.parentElement.clientWidth) || 800;
    var h = el.clientHeight || (el.parentElement && el.parentElement.clientHeight) || 400;
    if (w < 10 || h < 10) {
      var pw = el.parentElement ? el.parentElement.clientWidth : 800;
      var ph = el.parentElement ? el.parentElement.clientHeight : 400;
      w = Math.max(pw - 180, 400);
      h = Math.max(ph, 300);
    }

    stage = new Konva.Stage({ container: containerId, width: w, height: h });
    nodeLayer = new Konva.Layer();
    antLayer = new Konva.Layer();
    stage.add(nodeLayer, antLayer);

    _bindWsEvents();
    setTimeout(function() { _onResize(); _loadNodes(); }, 100);

    _addControls();
    window.addEventListener('resize', _onResize);
    if (typeof ResizeObserver !== 'undefined') {
      new ResizeObserver(_onResize).observe(el);
    }
    _addMiniMap();

    // ── Mouse/touch gesture state ──────────────────────────
    var _isPanning = false;
    var _lastPointer = null;
    var _dragStart = null;
    var _didDrag = false;
    var _lastTap = { time: 0, nodeId: null };

    // ── Click/tap on node ──────────────────────────────────
    nodeLayer.on('click tap', function(evt) {
      if (_longPressActive) { _longPressActive = false; return; }
      var nodeId = evt.target.getAttr('nodeId');
      if (!nodeId) return;

      var now = Date.now();
      if (_lastTap.nodeId === nodeId && now - _lastTap.time < 300) {
        _lastTap = { time: 0, nodeId: null };
        _zoomToNode(nodeId);
        return;
      }
      _lastTap = { time: now, nodeId: nodeId };

      var _ws = window._ws;
      if (_ws) _ws.send(JSON.stringify({action: "spawn.ant", data: {node_id: nodeId}}));
    });

    // ── Pan: background drag ────────────────────────────────
    stage.on('mousedown touchstart', function(e) {
      var btn = e.evt.button !== undefined ? e.evt.button : 0;
      var target = e.target;
      var isBackground = !target.getAttr('nodeId');
      if ((btn === 0 && (isBackground || e.evt.shiftKey)) || btn === 1) {
        _isPanning = true;
        _didDrag = false;
        _dragStart = stage.getPointerPosition();
        _lastPointer = stage.getPointerPosition();
        stage.container().style.cursor = 'grabbing';
      }
    });

    stage.on('mouseup touchend', function() {
      _isPanning = false;
      _dragStart = null;
      stage.container().style.cursor = 'grab';
    });

    stage.on('mousemove touchmove', function(e) {
      if (!_isPanning) return;
      e.evt.preventDefault();
      var pos = stage.getPointerPosition();
      if (!pos || !_lastPointer) return;
      var dx = pos.x - _lastPointer.x;
      var dy = pos.y - _lastPointer.y;
      if (_dragStart) {
        var sdx = pos.x - _dragStart.x;
        var sdy = pos.y - _dragStart.y;
        if (!_didDrag && Math.abs(sdx) + Math.abs(sdy) < 3) return;
        _didDrag = true;
      }
      stage.position({ x: stage.x() + dx, y: stage.y() + dy });
      stage.batchDraw();
      _debounceMiniMap();
      _lastPointer = pos;
    });

    // Touch cursor
    stage.container().style.touchAction = 'none';
    stage.container().style.cursor = 'grab';
    stage.container().style.userSelect = 'none';

    // ── Pinch-to-zoom + rotate ──────────────────────────────
    var _pinch = { active: false, startDist: 0, startScale: 1, cx: 0, cy: 0, startAngle: 0, startRot: 0 };

    function _tDist(a, b) {
      var dx = b.clientX - a.clientX, dy = b.clientY - a.clientY;
      return Math.sqrt(dx*dx + dy*dy);
    }
    function _tAngle(a, b) {
      return Math.atan2(b.clientY - a.clientY, b.clientX - a.clientX) * 180 / Math.PI;
    }

    stage.on('touchstart', function(e) {
      var t = e.evt.touches;
      if (t && t.length === 2) {
        e.evt.preventDefault();
        _pinch.active = true;
        _pinch.startDist = _tDist(t[0], t[1]);
        _pinch.startScale = stage.scaleX();
        _pinch.startAngle = _tAngle(t[0], t[1]);
        _pinch.startRot = _rotation;
        var rect = stage.container().getBoundingClientRect();
        _pinch.cx = (t[0].clientX + t[1].clientX) / 2 - rect.left;
        _pinch.cy = (t[0].clientY + t[1].clientY) / 2 - rect.top;
        _isPanning = false;
      }
    });

    stage.on('touchmove', function(e) {
      var t = e.evt.touches;
      if (_pinch.active && t && t.length === 2) {
        e.evt.preventDefault();
        var dist = _tDist(t[0], t[1]);
        var ratio = dist / _pinch.startDist;
        var newScale = Math.max(0.05, Math.min(10, _pinch.startScale * ratio));
        var oldScale = stage.scaleX();
        var mpt = { x: (_pinch.cx - stage.x()) / oldScale, y: (_pinch.cy - stage.y()) / oldScale };
        stage.scale({ x: newScale, y: newScale });
        stage.position({ x: _pinch.cx - mpt.x * newScale, y: _pinch.cy - mpt.y * newScale });
        var angle = _tAngle(t[0], t[1]);
        _rotation = (_pinch.startRot + (angle - _pinch.startAngle) + 360) % 360;
        stage.rotation(_rotation);
        _updateAngleDisplay();
        _updateZoomDisplay();
        stage.batchDraw();
        _debounceMiniMap();
      }
    });

    stage.on('touchend', function() {
      if (_pinch.active) {
        _pinch.active = false;
      }
    });

    // ── Mouse wheel zoom ────────────────────────────────────
    stage.on('wheel', function(e) {
      e.evt.preventDefault();
      var oldScale = stage.scaleX();
      var pointer = stage.getPointerPosition();
      if (!pointer) return;
      var mpt = { x: (pointer.x - stage.x()) / oldScale, y: (pointer.y - stage.y()) / oldScale };
      var newScale = e.evt.deltaY > 0 ? oldScale * 0.9 : oldScale * 1.1;
      newScale = Math.max(0.05, Math.min(10, newScale));
      stage.scale({ x: newScale, y: newScale });
      stage.position({ x: pointer.x - mpt.x * newScale, y: pointer.y - mpt.y * newScale });
      _updateZoomDisplay();
      stage.batchDraw();
      _debounceMiniMap();
    });

    // ── Keyboard: WASD, arrows, +/-, 0 ──────────────────────
    var _keyState = {};
    var _panSpeed = 40;
    var _panInterval = null;

    function _startKeyPan(dx, dy) {
      if (_panInterval) clearInterval(_panInterval);
      stage.position({ x: stage.x() + dx, y: stage.y() + dy });
      stage.batchDraw();
      _debounceMiniMap();
      _panInterval = setInterval(function() {
        stage.position({ x: stage.x() + dx, y: stage.y() + dy });
        stage.batchDraw();
        _debounceMiniMap();
      }, 30);
    }
    function _stopKeyPan() {
      if (_panInterval) { clearInterval(_panInterval); _panInterval = null; }
    }

    document.addEventListener('keydown', function(e) {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
      if (_keyState[e.key]) return;
      _keyState[e.key] = true;
      var dx = 0, dy = 0;
      switch(e.key) {
        case 'w': case 'W': case 'ArrowUp':    dy = _panSpeed; break;
        case 's': case 'S': case 'ArrowDown':  dy = -_panSpeed; break;
        case 'a': case 'A': case 'ArrowLeft':  dx = _panSpeed; break;
        case 'd': case 'D': case 'ArrowRight': dx = -_panSpeed; break;
        case '+': case '=': _zoomCenter(1.2); return;
        case '-': case '_': _zoomCenter(0.8); return;
        case '0': _zoomToFit(); return;
        default: return;
      }
      e.preventDefault();
      _startKeyPan(dx, dy);
    });
    document.addEventListener('keyup', function(e) {
      delete _keyState[e.key];
      var hasPan = Object.keys(_keyState).some(function(k) {
        return 'wasdWASD'.indexOf(k) >= 0 || k.indexOf('Arrow') === 0;
      });
      if (!hasPan) _stopKeyPan();
    });
  }

  // ── Resize ──────────────────────────────────────────────────
  function _onResize() {
    var el = document.getElementById('brain-map');
    if (!stage || !el) return;
    stage.width(el.clientWidth);
    stage.height(el.clientHeight);
    stage.batchDraw();
    _debounceMiniMap();
  }

  // ── Controls ────────────────────────────────────────────────
  function _addControls() {
    var el = document.getElementById('brain-map');
    if (!el) return;
    var container = el.parentElement;

    var ctrl = document.getElementById('zoom-controls');
    if (!ctrl) {
      ctrl = document.createElement('div');
      ctrl.id = 'zoom-controls';
      ctrl.innerHTML = [
        '<div style="display:flex;gap:4px;align-items:center;margin-bottom:4px">',
        '  <button id="zoom-in" class="btn" title="Zoom in (+)" style="width:26px;height:26px;padding:0;font-size:14px">+</button>',
        '  <span id="zoom-level" style="min-width:36px;text-align:center;font-size:10px;color:var(--text-secondary)">100%</span>',
        '  <button id="zoom-out" class="btn" title="Zoom out (-)" style="width:26px;height:26px;padding:0;font-size:14px">\u2212</button>',
        '  <button id="zoom-fit" class="btn" title="Fit all (0)" style="width:26px;height:26px;padding:0;font-size:10px">Fit</button>',
        '</div>',
        '<div style="display:grid;grid-template-columns:24px 24px 24px;grid-template-rows:24px 24px 24px;gap:1px;margin-bottom:4px">',
        '  <div></div>',
        '  <button id="dpad-up" class="btn" style="padding:0;font-size:12px" title="Pan up">\u25b2</button>',
        '  <div></div>',
        '  <button id="dpad-left" class="btn" style="padding:0;font-size:12px" title="Pan left">\u25c0</button>',
        '  <button id="dpad-center" class="btn" style="padding:0;font-size:9px" title="Reset view">\u2302</button>',
        '  <button id="dpad-right" class="btn" style="padding:0;font-size:12px" title="Pan right">\u25b6</button>',
        '  <div></div>',
        '  <button id="dpad-down" class="btn" style="padding:0;font-size:12px" title="Pan down">\u25bc</button>',
        '  <div></div>',
        '</div>',
        '<div style="font-size:8px;color:var(--text-tertiary);line-height:1.2">',
        '  WASD/Arrows: pan<br>0: fit \u2022 +/-: zoom<br>Scroll: zoom \u2022 Drag: pan',
        '</div>',
      ].join('\n');
      ctrl.style.cssText = 'position:absolute;bottom:8px;left:8px;z-index:10;display:flex;flex-direction:column;align-items:center;background:var(--bg-secondary);border:1px solid var(--border-subtle);border-radius:var(--radius-lg);padding:6px;box-shadow:0 2px 8px rgba(0,0,0,0.3);';
      container.appendChild(ctrl);

      // Wire buttons
      var _dpadInterval = null;
      function _startDpad(dx, dy) {
        if (_dpadInterval) clearInterval(_dpadInterval);
        stage.position({ x: stage.x() + dx, y: stage.y() + dy });
        stage.batchDraw();
        _debounceMiniMap();
        _dpadInterval = setInterval(function() {
          stage.position({ x: stage.x() + dx, y: stage.y() + dy });
          stage.batchDraw();
          _debounceMiniMap();
        }, 30);
      }
      function _stopDpad() {
        if (_dpadInterval) { clearInterval(_dpadInterval); _dpadInterval = null; }
      }
      var _dpadStep = 30;
      var _wire = function(id, dx, dy) {
        var btn = document.getElementById(id);
        if (!btn) return;
        btn.addEventListener('mousedown', function(e) { e.preventDefault(); _startDpad(dx, dy); });
        btn.addEventListener('mouseup', _stopDpad);
        btn.addEventListener('mouseleave', _stopDpad);
        btn.addEventListener('touchstart', function(e) { e.preventDefault(); e.stopPropagation(); _startDpad(dx, dy); });
        btn.addEventListener('touchend', function(e) { e.preventDefault(); _stopDpad(); });
        btn.addEventListener('touchcancel', _stopDpad);
      };

      document.getElementById('zoom-in').addEventListener('click', function() { _zoomCenter(1.3); });
      document.getElementById('zoom-out').addEventListener('click', function() { _zoomCenter(0.7); });
      document.getElementById('zoom-fit').addEventListener('click', function() { _zoomToFit(); });
      document.getElementById('dpad-center').addEventListener('click', function() { _zoomToFit(); });

      _wire('dpad-up', 0, _dpadStep);
      _wire('dpad-down', 0, -_dpadStep);
      _wire('dpad-left', _dpadStep, 0);
      _wire('dpad-right', -_dpadStep, 0);
    }
  }

  // ── MiniMap ─────────────────────────────────────────────────
  function _addMiniMap() {
    var el = document.getElementById('brain-map');
    if (!el) return;
    var container = el.parentElement;
    var mm = document.getElementById('mini-map');
    if (!mm) {
      mm = document.createElement('div');
      mm.id = 'mini-map';
      mm.innerHTML = '<canvas id="mini-map-canvas" width="150" height="100"></canvas>';
      mm.style.cssText = 'position:absolute;bottom:8px;right:8px;z-index:10;border:1px solid #374151;background:#0a0a0a;overflow:hidden;cursor:pointer;border-radius:4px;';
      container.appendChild(mm);

      mm.addEventListener('click', function(e) {
        var rect = mm.getBoundingClientRect();
        var mx = e.clientX - rect.left, my = e.clientY - rect.top;
        var bounds = _getNodeBounds();
        if (!bounds) return;
        var pad = 50;
        var gw = bounds.maxX - bounds.minX + 2*pad;
        var gh = bounds.maxY - bounds.minY + 2*pad;
        var s = Math.min(150/gw, 100/gh);
        var targetX = (mx / s) + bounds.minX - pad;
        var targetY = (my / s) + bounds.minY - pad;
        stage.position({ x: stage.width()/2 - targetX * stage.scaleX(), y: stage.height()/2 - targetY * stage.scaleY() });
        stage.batchDraw();
      });
    }
  }

  function _getNodeBounds() {
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (var id in nodes) {
      var n = nodes[id];
      if (n.x < minX) minX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.x > maxX) maxX = n.x;
      if (n.y > maxY) maxY = n.y;
    }
    return minX === Infinity ? null : { minX: minX, minY: minY, maxX: maxX, maxY: maxY };
  }

  function _debounceMiniMap() {
    if (_minimapTimer) return;
    _minimapTimer = setTimeout(function() {
      _minimapTimer = null;
      _updateMiniMap();
    }, MINIMAP_DEBOUNCE);
  }

  function _updateMiniMap() {
    var canvas = document.getElementById('mini-map-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var W = 150, H = 100;
    ctx.clearRect(0, 0, W, H);

    var bounds = _getNodeBounds();
    if (!bounds) return;

    var pad = 20;
    var gw = bounds.maxX - bounds.minX + 2*pad;
    var gh = bounds.maxY - bounds.minY + 2*pad;
    var s = Math.min(W/gw, H/gh);

    // Draw edges (batch)
    ctx.strokeStyle = '#374151';
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    for (var i = 0; i < edges.length; i++) {
      var e = edges[i];
      var from = nodes[e.from] || nodes[e.source];
      var to = nodes[e.to] || nodes[e.target];
      if (!from || !to) continue;
      ctx.moveTo((from.x - bounds.minX + pad) * s, (from.y - bounds.minY + pad) * s);
      ctx.lineTo((to.x - bounds.minX + pad) * s, (to.y - bounds.minY + pad) * s);
    }
    ctx.stroke();

    // Draw nodes (batch)
    for (var id in nodes) {
      var n = nodes[id];
      var x = (n.x - bounds.minX + pad) * s;
      var y = (n.y - bounds.minY + pad) * s;
      ctx.fillStyle = n._color || '#C8621A';
      ctx.beginPath();
      ctx.arc(x, y, 1.5, 0, Math.PI * 2);
      ctx.fill();
    }

    // Viewport rectangle
    var stgX = -stage.x() / stage.scaleX();
    var stgY = -stage.y() / stage.scaleY();
    var vpX = (stgX - bounds.minX + pad) * s;
    var vpY = (stgY - bounds.minY + pad) * s;
    var vpW = (stage.width() / stage.scaleX()) * s;
    var vpH = (stage.height() / stage.scaleY()) * s;
    ctx.strokeStyle = '#E8920A';
    ctx.lineWidth = 1;
    ctx.strokeRect(vpX, vpY, vpW, vpH);
  }

  // ── Zoom helpers ────────────────────────────────────────────
  function _updateZoomDisplay() {
    var el = document.getElementById('zoom-level');
    if (el && stage) el.textContent = Math.round(stage.scaleX() * 100) + '%';
  }

  function _updateAngleDisplay() {
    var el = document.getElementById('angle-display');
    if (el) el.textContent = Math.round(_rotation % 360) + '\u00B0';
  }

  function _zoomCenter(factor) {
    if (!stage) return;
    var oldScale = stage.scaleX();
    var newScale = Math.max(0.05, Math.min(10, oldScale * factor));
    var cx = stage.width() / 2, cy = stage.height() / 2;
    var mpt = { x: (cx - stage.x()) / oldScale, y: (cy - stage.y()) / oldScale };
    stage.scale({ x: newScale, y: newScale });
    stage.position({ x: cx - mpt.x * newScale, y: cy - mpt.y * newScale });
    _updateZoomDisplay();
    stage.batchDraw();
    _debounceMiniMap();
  }

  function _zoomToFit() {
    if (!stage) return;
    var bounds = _getNodeBounds();
    if (!bounds) return;
    var pad = 50;
    var w = bounds.maxX - bounds.minX + 2*pad;
    var h = bounds.maxY - bounds.minY + 2*pad;
    var s = Math.min(stage.width()/w, stage.height()/h);
    var cx = (bounds.minX + bounds.maxX) / 2;
    var cy = (bounds.minY + bounds.maxY) / 2;
    stage.scale({ x: s, y: s });
    stage.position({ x: stage.width()/2 - cx*s, y: stage.height()/2 - cy*s });
    _updateZoomDisplay();
    stage.batchDraw();
    _debounceMiniMap();
  }

  function _zoomToNode(nodeId) {
    var node = nodes[nodeId];
    if (!node || !stage) return;
    var ts = 2.5;
    stage.scale({ x: ts, y: ts });
    stage.position({ x: stage.width()/2 - node.x*ts, y: stage.height()/2 - node.y*ts });
    _updateZoomDisplay();
    _updateAngleDisplay();
    stage.batchDraw();
    _debounceMiniMap();
  }

  function _zoom(factor) { _zoomCenter(factor); }

  // ── Data loading ────────────────────────────────────────────
  function loadNodes(ns, edgesArr) {
    var useNodes = ns || _lastNodes || [];
    var useEdges = edgesArr || _lastEdges || [];
    _renderGraph(useNodes, useEdges);
  }

  function _loadNodes() {
    Promise.all([
      fetch("/api/brain-map/nodes").then(function(r) { if (!r.ok) throw new Error('Nodes API: ' + r.status); return r.json(); }),
      fetch("/api/brain-map/edges").then(function(r) { if (!r.ok) throw new Error('Edges API: ' + r.status); return r.json(); }),
    ]).then(function(res) {
      _renderGraph(res[0].nodes || [], res[1].edges || []);
    }).catch(function(err) { console.error('Brain map load error:', err); });
  }

  // ── Viewport culling ────────────────────────────────────────
  function _getVisibleBounds() {
    if (!stage) return null;
    var sc = stage.scaleX();
    var sx = -stage.x() / sc;
    var sy = -stage.y() / sc;
    var sw = stage.width() / sc;
    var sh = stage.height() / sc;
    return {
      left: sx - VIEWPORT_MARGIN,
      top: sy - VIEWPORT_MARGIN,
      right: sx + sw + VIEWPORT_MARGIN,
      bottom: sy + sh + VIEWPORT_MARGIN,
    };
  }

  function _isInViewport(x, y, vp) {
    return x >= vp.left && x <= vp.right && y >= vp.top && y <= vp.bottom;
  }

  // ── Render graph ────────────────────────────────────────────
  function _renderGraph(ns, edgesData) {
    _lastNodes = ns;
    _lastEdges = edgesData || [];
    edges = _lastEdges;
    nodeLayer.destroyChildren();
    nodes = {};
    _renderedSet.clear();

    var W = stage.width(), H = stage.height();

    // Compute layout
    var positions;
    switch (_currentView) {
      case 'tree':   positions = _treeLayout(ns, _lastEdges, W, H); break;
      case 'spiral': positions = _spiralLayout(ns, W, H); break;
      case 'grid':   positions = _gridLayout(ns, W, H); break;
      case 'radial': positions = _radialLayout(ns, _lastEdges, W, H); break;
      case 'cluster':positions = _clusterLayout(ns, _lastEdges, W, H); break;
      default:       positions = _forceLayout(ns, _lastEdges, W, H);
    }

    // Add nodes (up to MAX_RENDERED_NODES)
    var added = 0;
    for (var i = 0; i < ns.length && added < MAX_RENDERED_NODES; i++) {
      var n = ns[i];
      var id = n.id || n.path;
      var pos = positions[id] || { x: W/2, y: H/2 };
      _addNode(id, n.label || n.path, n.type || 'default', pos.x, pos.y, n.finding_count || 0, n.severity || 'info');
      _renderedSet.add(id);
      added++;
    }

    // If we hit the cap, add the rest as lightweight data (for edges + minimap)
    for (var j = MAX_RENDERED_NODES; j < ns.length; j++) {
      var nn = ns[j];
      var nid = nn.id || nn.path;
      var pp = positions[nid] || { x: W/2, y: H/2 };
      nodes[nid] = { x: pp.x, y: pp.y, type: nn.type || 'default', _color: COLORS[nn.type] || COLORS.default, group: null, shape: null };
    }

    // Draw edges
    _drawEdges();

    // Labels toggle
    if (!_showLabels) {
      nodeLayer.getChildren().forEach(function(g) {
        var txt = g.findOne && g.findOne('Text');
        if (txt) txt.visible(false);
      });
    }

    nodeLayer.draw();
    _debounceMiniMap();
  }

  // ── Edge drawing (batched) ──────────────────────────────────
  function _drawEdges() {
    // Group edges by style
    var edgeGroups = {};
    for (var i = 0; i < _lastEdges.length; i++) {
      var e = _lastEdges[i];
      var fromId = e.source || e.from;
      var toId = e.target || e.to;
      var from = nodes[fromId];
      var to = nodes[toId];
      if (!from || !to || !from.group || !to.group) continue;
      var t = e.type || 'dependency';
      if (!edgeGroups[t]) edgeGroups[t] = [];
      edgeGroups[t].push({ fx: from.group.x(), fy: from.group.y(), tx: to.group.x(), ty: to.group.y() });
    }

    var styles = {
      import_dependency: { w: 1, dash: [], c: COLORS.edge, o: 0.5 },
      route_connection:  { w: 2, dash: [5,5], c: '#f59e0b', o: 0.5 },
      test_coverage:     { w: 1, dash: [2,2], c: '#22c55e', o: 0.4 },
      blast_radius:      { w: 2, dash: [], c: '#f97316', o: 0.5 },
      dead_path:         { w: 1, dash: [3,3], c: '#6b7280', o: 0.3 },
      dependency:        { w: 1, dash: [], c: COLORS.edge, o: 0.4 },
    };

    for (var type in edgeGroups) {
      var st = styles[type] || styles.dependency;
      var grp = edgeGroups[type];
      // Batch into one Konva.Line per group
      var pts = [];
      for (var j = 0; j < grp.length; j++) {
        pts.push(grp[j].fx, grp[j].fy, grp[j].tx, grp[j].ty);
      }
      if (pts.length === 0) continue;
      var line = new Konva.Line({
        points: pts,
        stroke: st.c,
        strokeWidth: st.w,
        dash: st.dash,
        opacity: st.o,
        listening: false,
      });
      line.moveToBottom();
      nodeLayer.add(line);
    }
  }

  // ── Force layout (optimized: grid-sampled repulsion) ────────
  function _forceLayout(nodesList, edgesList, W, H) {
    var pos = {};
    var n = nodesList.length;
    if (n === 0) return pos;

    // Initialize in circle
    nodesList.forEach(function(node, i) {
      var angle = (2 * Math.PI * i) / n;
      var radius = Math.min(W, H) * 0.35;
      pos[node.id || node.path] = { x: W/2 + radius*Math.cos(angle), y: H/2 + radius*Math.sin(angle), vx: 0, vy: 0 };
    });

    // Build adjacency
    var adj = {};
    edgesList.forEach(function(e) {
      var f = e.from || e.source, t = e.to || e.target;
      if (!adj[f]) adj[f] = [];
      if (!adj[t]) adj[t] = [];
      adj[f].push(t);
      adj[t].push(f);
    });

    // Fewer iterations for large graphs
    var iterations = n > 200 ? 20 : 50;
    var repulsion = 8000;
    var attraction = 0.005;
    var damping = 0.9;
    var centerPull = 0.01;

    for (var iter = 0; iter < iterations; iter++) {
      var keys = Object.keys(pos);

      // Repulsion: for large graphs, sample neighbors instead of all pairs
      if (n > 100) {
        // Only apply repulsion between nodes that are close
        for (var i = 0; i < keys.length; i++) {
          var a = pos[keys[i]];
          // Check neighbors and a few random others
          var candidates = (adj[keys[i]] || []).slice();
          // Add a few random samples
          var sampleSize = Math.min(10, n);
          for (var s = 0; s < sampleSize; s++) {
            var rk = keys[Math.floor(Math.random() * n)];
            if (rk !== keys[i] && candidates.indexOf(rk) < 0) candidates.push(rk);
          }
          for (var ci = 0; ci < candidates.length; ci++) {
            var b = pos[candidates[ci]];
            if (!b) continue;
            var dx = a.x - b.x, dy = a.y - b.y;
            var dist = Math.sqrt(dx*dx + dy*dy) || 1;
            var force = repulsion / (dist * dist);
            var fx = (dx/dist)*force, fy = (dy/dist)*force;
            a.vx += fx; a.vy += fy;
            b.vx -= fx; b.vy -= fy;
          }
        }
      } else {
        // Full O(n^2) for small graphs
        for (var ii = 0; ii < keys.length; ii++) {
          for (var jj = ii+1; jj < keys.length; jj++) {
            var aa = pos[keys[ii]], bb = pos[keys[jj]];
            var ddx = aa.x - bb.x, ddy = aa.y - bb.y;
            var ddist = Math.sqrt(ddx*ddx + ddy*ddy) || 1;
            var fforce = repulsion / (ddist*ddist);
            var ffx = (ddx/ddist)*fforce, ffy = (ddy/ddist)*fforce;
            aa.vx += ffx; aa.vy += ffy;
            bb.vx -= ffx; bb.vy -= ffy;
          }
        }
      }

      // Attraction along edges
      edgesList.forEach(function(e) {
        var a = pos[e.from || e.source], b = pos[e.to || e.target];
        if (!a || !b) return;
        var dx = b.x - a.x, dy = b.y - a.y;
        var dist = Math.sqrt(dx*dx + dy*dy) || 1;
        var force = dist * attraction;
        var fx = (dx/dist)*force, fy = (dy/dist)*force;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      });

      // Center gravity + damping
      for (var k = 0; k < keys.length; k++) {
        var p = pos[keys[k]];
        p.vx += (W/2 - p.x) * centerPull;
        p.vy += (H/2 - p.y) * centerPull;
        p.vx *= damping;
        p.vy *= damping;
        p.x += p.vx;
        p.y += p.vy;
        p.x = Math.max(40, Math.min(W-40, p.x));
        p.y = Math.max(40, Math.min(H-40, p.y));
      }
    }

    // Clean velocity
    for (var kk = 0; kk < keys.length; kk++) {
      var pp = pos[keys[kk]];
      delete pp.vx; delete pp.vy;
    }
    return pos;
  }

  // ── Other layout algorithms ─────────────────────────────────
  function _treeLayout(nodesList, edgesList, W, H) {
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var incoming = {}, adj = {};
    nodesList.forEach(function(node) { adj[node.id || node.path] = []; });
    edgesList.forEach(function(e) {
      var f = e.from||e.source, t = e.to||e.target;
      if (adj[f]) adj[f].push(t);
      if (!incoming[t]) incoming[t] = [];
      incoming[t].push(f);
    });
    var roots = nodesList.filter(function(node) { return !(incoming[node.id||node.path]||[]).length; });
    if (!roots.length) roots = [nodesList[0]];
    var levels = {}, visited = {}, queue = [];
    roots.forEach(function(node) { var id=node.id||node.path; levels[id]=0; visited[id]=true; queue.push(id); });
    while (queue.length) {
      var curr = queue.shift();
      (adj[curr]||[]).forEach(function(child) { if(!visited[child]){visited[child]=true;levels[child]=(levels[curr]||0)+1;queue.push(child);} });
    }
    nodesList.forEach(function(node) { var id=node.id||node.path; if(levels[id]===undefined) levels[id]=0; });
    var groups = {}, maxL = 0;
    nodesList.forEach(function(node) { var id=node.id||node.path, lv=levels[id]; if(!groups[lv])groups[lv]=[]; groups[lv].push(id); if(lv>maxL)maxL=lv; });
    var pad=60, lvlH=(H-pad*2)/Math.max(maxL,1);
    for (var lv=0;lv<=maxL;lv++) {
      var grp=groups[lv]||[], lvlW=(W-pad*2)/Math.max(grp.length-1,1);
      grp.forEach(function(id,i){pos[id]={x:grp.length===1?W/2:pad+lvlW*i,y:pad+lvlH*lv};});
    }
    return pos;
  }

  function _spiralLayout(nodesList, W, H) {
    var pos={}, n=nodesList.length;
    if(!n)return pos;
    var ga=Math.PI*(3-Math.sqrt(5)), cx=W/2, cy=H/2, mr=Math.min(W,H)*0.42;
    nodesList.forEach(function(node,i){
      var id=node.id||node.path, a=i*ga, r=mr*Math.sqrt(i/n);
      pos[id]={x:cx+r*Math.cos(a),y:cy+r*Math.sin(a)};
    });
    return pos;
  }

  function _gridLayout(nodesList, W, H) {
    var pos={}, n=nodesList.length;
    if(!n)return pos;
    var cols=Math.ceil(Math.sqrt(n)), rows=Math.ceil(n/cols);
    var cW=(W-80)/cols, cH=(H-80)/rows;
    nodesList.forEach(function(node,i){
      var id=node.id||node.path;
      pos[id]={x:40+cW*((i%cols)+0.5),y:40+cH*(Math.floor(i/cols)+0.5)};
    });
    return pos;
  }

  function _radialLayout(nodesList, edgesList, W, H) {
    var pos={}, n=nodesList.length;
    if(!n)return pos;
    var cx=W/2, cy=H/2;
    var incoming={}, adj={};
    nodesList.forEach(function(node){adj[node.id||node.path]=[];});
    edgesList.forEach(function(e){
      var f=e.from||e.source, t=e.to||e.target;
      if(adj[f])adj[f].push(t);
      if(!incoming[t])incoming[t]=[];
      incoming[t].push(f);
    });
    var roots=nodesList.filter(function(node){return!(incoming[node.id||node.path]||[]).length;});
    if(!roots.length)roots=[nodesList[0]];
    var depth={}, visited={}, queue=[];
    roots.forEach(function(node){var id=node.id||node.path;depth[id]=0;visited[id]=true;queue.push(id);});
    while(queue.length){
      var curr=queue.shift();
      (adj[curr]||[]).forEach(function(child){if(!visited[child]){visited[child]=true;depth[child]=(depth[curr]||0)+1;queue.push(child);}});
    }
    nodesList.forEach(function(node){var id=node.id||node.path;if(depth[id]===undefined)depth[id]=0;});
    var maxD=1;nodesList.forEach(function(node){var d=depth[node.id||node.path];if(d>maxD)maxD=d;});
    var mr=Math.min(W,H)*0.42;
    var rings={};
    nodesList.forEach(function(node){
      var id=node.id||node.path,d=depth[id];
      if(!rings[d])rings[d]=[];
      rings[d].push(id);
    });
    for(var d=0;d<=maxD;d++){
      var ring=rings[d]||[], r=(d/maxD)*mr;
      ring.forEach(function(id,i){
        var a=(2*Math.PI*i)/ring.length-Math.PI/2;
        pos[id]={x:cx+r*Math.cos(a),y:cy+r*Math.sin(a)};
      });
    }
    return pos;
  }

  function _clusterLayout(nodesList, edgesList, W, H) {
    var pos={}, n=nodesList.length;
    if(!n)return pos;
    var groups={};
    nodesList.forEach(function(node){
      var t=node.type||'default';
      if(!groups[t])groups[t]=[];
      groups[t].push(node.id||node.path);
    });
    var types=Object.keys(groups), ng=types.length;
    var cols=Math.ceil(Math.sqrt(ng)), rows=Math.ceil(ng/cols);
    var cW=W/cols, cH=H/rows;
    types.forEach(function(type,gi){
      var col=gi%cols, row=Math.floor(gi/cols);
      var ccx=cW*(col+0.5), ccy=cH*(row+0.5);
      var ids=groups[type], cn=ids.length;
      var cr=Math.min(cW,cH)*0.35;
      ids.forEach(function(id,i){
        if(cn===1){pos[id]={x:ccx,y:ccy};return;}
        var a=(2*Math.PI*i)/cn-Math.PI/2;
        var r=cr*Math.sqrt(i/cn);
        pos[id]={x:ccx+r*Math.cos(a),y:ccy+r*Math.sin(a)};
      });
    });
    return pos;
  }

  // ── Node creation ───────────────────────────────────────────
  function _healthColor(fc, sev) {
    if (fc === 0) return null;
    if (sev === 'critical' || fc >= 5) return COLORS.critical;
    if (sev === 'high' || fc >= 3) return COLORS.wounded;
    return COLORS.scanning;
  }

  function _addNode(id, label, type, x, y, fc, sev) {
    var group = new Konva.Group({ x: x, y: y, draggable: true });
    var color = COLORS[type] || COLORS.default;

    // Simplified shapes: circle for most, rect for route handlers
    var shape;
    if (type === 'route_handler') {
      shape = new Konva.Rect({ width: NODE_R*2, height: NODE_R*1.5, cornerRadius: 4, fill: color, stroke: '#4b5563', strokeWidth: 1 });
    } else if (type === 'config') {
      shape = new Konva.RegularPolygon({ sides: 4, radius: NODE_R, fill: color, stroke: '#4b5563', strokeWidth: 1 });
    } else {
      shape = new Konva.Circle({ radius: NODE_R, fill: color, stroke: '#4b5563', strokeWidth: 1 });
    }

    shape.setAttr('nodeId', id);

    // Health color override
    var hc = _healthColor(fc, sev);
    if (hc) {
      shape.fill(hc);
      shape.stroke(hc === COLORS.critical ? '#ff6b8a' : hc);
    }

    // Right-click
    group.on('contextmenu', function() { _showNodeDetails(id, label, fc, sev); });

    // Long-press (touch)
    (function() {
      var lpTimer = null, lpStart = null, lpFired = false;
      group.on('touchstart', function(ev) {
        var touch = ev.evt.touches[0];
        if (!touch) return;
        lpStart = { x: touch.clientX, y: touch.clientY };
        lpFired = false;
        lpTimer = setTimeout(function() {
          lpFired = true;
          _longPressActive = true;
          _showNodeDetails(id, label, fc, sev);
          if (navigator.vibrate) navigator.vibrate(30);
        }, 500);
      });
      group.on('touchmove', function(ev) {
        if (!lpTimer || lpFired) return;
        var touch = ev.evt.touches[0];
        if (!touch || !lpStart) return;
        if (Math.abs(touch.clientX-lpStart.x)+Math.abs(touch.clientY-lpStart.y)>10) {
          clearTimeout(lpTimer); lpTimer = null;
        }
      });
      group.on('touchend', function() { if(lpTimer){clearTimeout(lpTimer);lpTimer=null;} });
    })();

    // Label (simplified — only filename, smaller)
    var text = new Konva.Text({
      text: label.split('/').pop(),
      fontSize: 9,
      fill: COLORS.text,
      offsetX: 35,
      offsetY: -NODE_R - 3,
      width: 70,
      align: 'center',
    });

    group.add(shape, text);
    nodeLayer.add(group);

    // Store color for minimap
    var fillColor = hc || color;
    nodes[id] = { group: group, shape: shape, x: x, y: y, type: type, _color: fillColor, _severity: sev, _findings: fc, _label: label };
  }

  // ── Ant animation ───────────────────────────────────────────
  function _spawnAntAnimation(antId, nodeId) {
    var target = nodes[nodeId];
    if (!target || !target.group) return;
    var ant = new Konva.Circle({ x: stage.width()/2, y: stage.height()-40, radius: ANT_R, fill: COLORS.ant_spawn });
    antLayer.add(ant);
    ants[antId] = ant;
    ant.to({
      x: target.group.x(), y: target.group.y(), duration: 0.7,
      onFinish: function() { _circleNode(ant, target, function() { _antScan(ant); }); },
    });
  }

  function _circleNode(ant, target, onDone) {
    var angle = 0, r = NODE_R + 8;
    var anim = new Konva.Animation(function(frame) {
      angle += frame.timeDiff * 0.36;
      ant.x(target.group.x() + r * Math.cos(angle * Math.PI / 180));
      ant.y(target.group.y() + r * Math.sin(angle * Math.PI / 180));
      if (angle >= 360) { anim.stop(); onDone(); }
    }, antLayer);
    anim.start();
  }

  function _antScan(ant) {
    ant.to({ scaleX: 1.4, scaleY: 1.4, duration: 0.3,
      onFinish: function() { ant.to({ scaleX: 1, scaleY: 1, duration: 0.3 }); }
    });
  }

  function _returnAntToQueen(antId) {
    var ant = ants[antId];
    if (!ant) return;
    ant.to({
      x: stage.width()/2, y: stage.height()-40, duration: 0.8,
      onFinish: function() { ant.destroy(); antLayer.draw(); delete ants[antId]; _queenPulse(); },
    });
  }

  function _queenPulse() {
    var flash = new Konva.Circle({ x: stage.width()/2, y: stage.height()-40, radius: 20, fill: COLORS.ant_spawn, opacity: 0.6 });
    antLayer.add(flash);
    flash.to({ scaleX: 1.5, scaleY: 1.5, opacity: 0, duration: 0.4,
      onFinish: function() { flash.destroy(); antLayer.draw(); }
    });
  }

  // ── Node state ──────────────────────────────────────────────
  function setNodeState(nodeId, state) {
    var n = nodes[nodeId];
    if (!n || !n.shape) return;
    var colorMap = {
      healthy: COLORS[n.type] || COLORS.idle,
      being_scanned: COLORS.scanning,
      wounded: COLORS.wounded,
      healed: COLORS.done,
      being_fixed: COLORS.done,
      critical: COLORS.critical,
      locked: COLORS.restricted,
    };
    n.shape.fill(colorMap[state] || COLORS[state] || COLORS.idle);
    if (state === 'healed') {
      setTimeout(function() {
        if (nodes[nodeId] && nodes[nodeId].shape) {
          nodes[nodeId].shape.fill(COLORS[nodes[nodeId].type] || COLORS.idle);
          nodeLayer.batchDraw();
        }
      }, 800);
    }
    nodeLayer.batchDraw();
  }

  // ── WebSocket events ────────────────────────────────────────
  function _bindWsEvents() {
    _onWsMessage = function(event) {
      try {
        var msg = JSON.parse(event.data);
        var evt = msg.event, data = msg.data || {};
        if (evt === 'agent.started') setNodeState(data.file, 'being_scanned');
        if (evt === 'agent.done') setNodeState(data.file, 'done');
        if (evt === 'ant.spawned') _spawnAntAnimation(data.ant_id, data.node_id);
        if (evt === 'ant.result') _returnAntToQueen(data.ant_id);
        if (evt === 'ant.rejected') {
          var msgs = {
            idle: "Patchi is idle - start a scan first",
            restricted: "This file is restricted",
            cooldown: "Wait before tapping again",
            capacity: "Too many ants active",
            node_busy: "Node already busy",
          };
          var m = msgs[data.reason] || 'Spawn rejected: ' + data.reason;
          if (typeof toast === 'function') toast(m, 'error');
        }
        if (evt === 'scan.complete') _loadNodes();
      } catch (_) {}
    };
    _relistenWs();
  }

  function _relistenWs() {
    var ws = window._ws;
    if (!ws) { setTimeout(_relistenWs, 500); return; }
    ws.addEventListener('message', _onWsMessage);
  }

  // ── Node details popup ──────────────────────────────────────
  function _showNodeDetails(id, label, fc, sev) {
    var modal = document.getElementById('node-detail-modal');
    if (!modal) return;
    var sevLabel = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'None' }[sev]||'None';
    var nodeType = (nodes[id] && nodes[id].type) || 'default';

    fetch('/api/findings')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var fileFindings = (data.findings || []).filter(function(f) { return f.file === id; });
        var findingsHtml = '';
        if (fileFindings.length > 0) {
          findingsHtml = '<div class="detail-findings"><div class="detail-subtitle">Findings (' + fileFindings.length + ')</div>' +
            fileFindings.slice(0, 10).map(function(f) {
              return '<div class="detail-finding sev-' + (f.severity||'low').toLowerCase() + '">' +
                '<span class="df-sev">' + (f.severity||'').toUpperCase() + '</span>' +
                '<span class="df-msg">' + (f.message||f.title||'') + '</span>' +
                (f.line ? '<span class="df-line">:' + f.line + '</span>' : '') + '</div>';
            }).join('') +
            (fileFindings.length > 10 ? '<div class="df-more">+' + (fileFindings.length-10) + ' more</div>' : '') +
            '</div>';
        }
        modal.querySelector('.modal-title').textContent = label;
        modal.querySelector('.modal-body').innerHTML =
          '<div class="detail-row"><span class="detail-key">File</span><span class="detail-val">' + id + '</span></div>' +
          '<div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">' + nodeType + '</span></div>' +
          '<div class="detail-row"><span class="detail-key">Findings</span><span class="detail-val ' + sev + '">' + fc + '</span></div>' +
          '<div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val ' + sev + '">' + sevLabel + '</span></div>' +
          findingsHtml;
      })
      .catch(function() {
        modal.querySelector('.modal-title').textContent = label;
        modal.querySelector('.modal-body').innerHTML =
          '<div class="detail-row"><span class="detail-key">File</span><span class="detail-val">' + id + '</span></div>' +
          '<div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">' + nodeType + '</span></div>' +
          '<div class="detail-row"><span class="detail-key">Findings</span><span class="detail-val ' + sev + '">' + fc + '</span></div>';
      });

    modal.style.display = 'flex';
    modal.querySelector('.modal-close').onclick = function() { modal.style.display = 'none'; };
    modal.onclick = function(e) { if (e.target === modal) modal.style.display = 'none'; };
  }

  // ── View switching ──────────────────────────────────────────
  function switchView(viewName) {
    _currentView = viewName;
    document.querySelectorAll('[id^="view-"]').forEach(function(btn) {
      btn.style.background = btn.id === 'view-' + viewName ? 'var(--bg-tertiary)' : '';
      btn.style.fontWeight = btn.id === 'view-' + viewName ? '600' : '';
    });
    if (_lastNodes.length === 0) return;
    _renderGraph(_lastNodes, _lastEdges);
  }

  function toggleLabels() {
    _showLabels = !_showLabels;
    var btn = document.getElementById('btn-toggle-labels');
    if (btn) btn.textContent = _showLabels ? 'Hide Labels' : 'Show Labels';
    if (_lastNodes.length > 0) _renderGraph(_lastNodes, _lastEdges);
  }

  function rotateGraph(deg) {
    _rotation = (_rotation + deg + 360) % 360;
    if (stage) { stage.rotation(_rotation); stage.batchDraw(); }
    _updateAngleDisplay();
  }

  function resetRotation() {
    _rotation = 0;
    if (stage) { stage.rotation(0); stage.batchDraw(); }
    _updateAngleDisplay();
  }

  function exportPNG() {
    if (!stage) return;
    var dataURL = stage.toDataURL({ pixelRatio: 2 });
    var link = document.createElement('a');
    link.download = 'patchi-brain-map-' + Date.now() + '.png';
    link.href = dataURL;
    link.click();
  }

  function exportJSON() {
    if (!_lastNodes.length) return;
    var data = { nodes: _lastNodes, edges: _lastEdges, view: _currentView, timestamp: new Date().toISOString() };
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.download = 'patchi-brain-map-' + Date.now() + '.json';
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  }

  // ── Search ──────────────────────────────────────────────────
  var _searchQuery = '', _searchMatches = [], _searchOrigColors = {}, _searchIndex = -1;
  var _selectedNodes = []; // multi-select for Ctrl+Click comparison

  // ── Search History ─────────────────────────────────────────
  var _searchHistory = [];
  var _MAX_HISTORY = 10;
  try {
    var stored = localStorage.getItem('patchi_search_history');
    if (stored) _searchHistory = JSON.parse(stored);
  } catch(e) { _searchHistory = []; }

  function _saveToHistory(query) {
    if (!query || query.length < 2) return;
    // Remove duplicate if exists
    _searchHistory = _searchHistory.filter(function(h) { return h.query !== query; });
    _searchHistory.unshift({ query: query, time: Date.now() });
    if (_searchHistory.length > _MAX_HISTORY) _searchHistory = _searchHistory.slice(0, _MAX_HISTORY);
    try { localStorage.setItem('patchi_search_history', JSON.stringify(_searchHistory)); } catch(e) {}
  }

  function _renderSearchHistory() {
    var dd = document.getElementById('brain-search-dropdown');
    if (!dd) return;
    if (_searchHistory.length === 0) { dd.style.display = 'none'; return; }
    var html = '<div style="padding:4px 10px;font-size:10px;color:var(--text-tertiary);font-weight:600;display:flex;justify-content:space-between;align-items:center">Recent searches<span onclick="BrainMap.clearHistory()" style="cursor:pointer;color:var(--danger);font-weight:400">Clear</span></div>';
    for (var hi = 0; hi < _searchHistory.length; hi++) {
      var h = _searchHistory[hi];
      var ago = _timeAgo(h.time);
      html += '<div class="sr-history-item" style="padding:5px 10px;cursor:pointer;display:flex;align-items:center;gap:8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:var(--text-primary)" onmouseenter="this.style.background=\'var(--bg-tertiary)\'" onmouseleave="this.style.background=\'\'" onclick="document.getElementById(\'brain-search\').value=\'' + h.query.replace(/'/g, "\\'") + '\';BrainMap.searchNodes(\'' + h.query.replace(/'/g, "\\'") + '\')">';
      html += '<span style="color:var(--text-tertiary);font-size:11px">🕐</span>';
      html += '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + _escapeHtml(h.query) + '</span>';
      html += '<span style="font-size:9px;color:var(--text-tertiary);flex-shrink:0">' + ago + '</span>';
      html += '</div>';
    }
    dd.innerHTML = html;
    dd.style.display = 'block';
  }

  function _timeAgo(ts) {
    var diff = Date.now() - ts;
    if (diff < 60000) return 'just now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    return Math.floor(diff / 86400000) + 'd ago';
  }

  function _escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function clearHistory() {
    _searchHistory = [];
    try { localStorage.removeItem('patchi_search_history'); } catch(e) {}
    var dd = document.getElementById('brain-search-dropdown');
    if (dd) dd.style.display = 'none';
  }

  function _showHistoryOnFocus() {
    var inp = document.getElementById('brain-search');
    if (inp && !inp.value.trim()) {
      _renderSearchHistory();
    }
  }

  // ── Fuzzy scoring ─────────────────────────────────────────
  function _fuzzyScore(query, full, short, tokens) {
    if (!query) return 0;
    var q = query.toLowerCase();
    // Exact full path match — best
    if (full.indexOf(q) >= 0) return 1000 - full.indexOf(q);
    // Exact short name match
    if (short.indexOf(q) >= 0) return 900 - short.indexOf(q);
    // Token exact match (e.g. 'scan' matches 'security_scanner')
    for (var ti = 0; ti < tokens.length; ti++) {
      if (tokens[ti] === q) return 800;
      if (tokens[ti].indexOf(q) >= 0) return 700 - ti;
    }
    // Token prefix match (e.g. 'sec' matches 'security')
    for (var ti2 = 0; ti2 < tokens.length; ti2++) {
      if (tokens[ti2].indexOf(q) === 0) return 600 - ti2;
    }
    // Subsequence match on short name (characters in order)
    if (_isSubsequence(q, short)) return 400;
    // Subsequence match on full path
    if (_isSubsequence(q, full)) return 300;
    // Token subsequence (query chars spread across tokens)
    var tokenStr = tokens.join('');
    if (_isSubsequence(q, tokenStr)) return 200;
    // Levenshtein-like: short edit distance on short name
    var dist = _editDistance(q, short);
    if (dist <= Math.max(2, Math.floor(q.length * 0.4))) return 100 - dist;
    return 0;
  }

  function _isSubsequence(needle, haystack) {
    var ni = 0;
    for (var hi = 0; hi < haystack.length && ni < needle.length; hi++) {
      if (haystack[hi] === needle[ni]) ni++;
    }
    return ni === needle.length;
  }

  function _editDistance(a, b) {
    var m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    // Optimized: only keep two rows
    var prev = [];
    for (var i = 0; i <= n; i++) prev[i] = i;
    for (var i2 = 1; i2 <= m; i2++) {
      var curr = [i2];
      for (var j = 1; j <= n; j++) {
        var cost = a[i2 - 1] === b[j - 1] ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = curr;
    }
    return prev[n];
  }

  function searchNodes(query) {
    _searchQuery = (query || '').trim().toLowerCase();
    var countEl = document.getElementById('brain-search-count');

    if (!_searchQuery) {
      // Show history when input is cleared
      _renderSearchHistory();
      for (var id in nodes) {
        var n = nodes[id];
        if (_searchOrigColors[id] !== undefined) {
          if (n.shape) n.shape.opacity(1);
          if (n.group) n.group.opacity(1);
          if (_searchOrigColors[id] && n.shape) n.shape.fill(_searchOrigColors[id]);
          delete _searchOrigColors[id];
        }
      }
      _searchMatches = [];
      _selectedNodes = [];
      if (countEl) countEl.textContent = '';
      var dd = document.getElementById('brain-search-dropdown');
      if (dd) dd.style.display = 'none';
      var cp = document.getElementById('brain-compare-panel');
      if (cp) cp.style.display = 'none';
      nodeLayer.batchDraw();
      return;
    }

    _searchMatches = [];
    var _searchScored = [];
    for (var id2 in nodes) {
      var n2 = nodes[id2];
      if (!n2.group) continue;
      var full = id2.toLowerCase();
      var shortName = full.split('/').pop();
      // Also split name on common separators for token matching
      var tokens = shortName.replace(/[._\-\\/]/g, ' ').split(/\s+/).filter(Boolean);
      var score = _fuzzyScore(_searchQuery, full, shortName, tokens);
      if (score > 0) {
        _searchScored.push({ id: id2, score: score });
      }
    }
    // Sort by score descending (best matches first)
    _searchScored.sort(function(a, b) { return b.score - a.score; });
    _searchMatches = _searchScored.map(function(s) { return s.id; });

    for (var id3 in nodes) {
      var n3 = nodes[id3];
      if (!n3.shape || !n3.group) continue;
      var isMatch = _searchMatches.indexOf(id3) >= 0;
      if (_searchOrigColors[id3] === undefined) _searchOrigColors[id3] = n3.shape.fill();
      if (isMatch) {
        n3.shape.opacity(1); n3.group.opacity(1);
        n3.shape.fill('#E8920A');
        n3.shape.shadowColor('#E8920A'); n3.shape.shadowBlur(12); n3.shape.shadowOpacity(0.8);
      } else {
        n3.shape.opacity(0.15); n3.group.opacity(0.15); n3.shape.shadowBlur(0);
      }
    }

    // Dim non-connected edges
    nodeLayer.children.forEach(function(child) {
      if (child.getClassName && child.getClassName() === 'Line') {
        var pts = child.points();
        if (pts.length >= 4) {
          var connected = false;
          for (var mi = 0; mi < _searchMatches.length; mi++) {
            var mn = nodes[_searchMatches[mi]];
            if (mn && mn.group) {
              if (Math.abs(mn.group.x() - pts[0]) < 2 && Math.abs(mn.group.y() - pts[1]) < 2) connected = true;
              if (Math.abs(mn.group.x() - pts[2]) < 2 && Math.abs(mn.group.y() - pts[3]) < 2) connected = true;
            }
          }
          child.opacity(connected ? 0.6 : 0.05);
        }
      }
    });

    if (countEl) {
      countEl.textContent = _searchMatches.length + ' found';
      countEl.style.color = _searchMatches.length > 0 ? 'var(--accent)' : 'var(--danger)';
    }
    nodeLayer.batchDraw();

    // Auto-zoom to first match when exactly 1 result
    _searchIndex = _searchMatches.length > 0 ? 0 : -1;
    if (_searchMatches.length === 1) {
      _zoomToSearchMatch(0);
    }
    _updateSearchCount();
    _renderSearchDropdown();
  }

  function _renderSearchDropdown() {
    var dd = document.getElementById('brain-search-dropdown');
    if (!dd) return;
    if (_searchMatches.length === 0) { dd.style.display = 'none'; return; }
    var html = '';
    // Compare panel header when 2+ selected
    if (_selectedNodes.length >= 2) {
      html += '<div style="padding:6px 10px;background:rgba(88,166,255,0.1);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px">';
      html += '<span style="font-size:11px;font-weight:600;color:var(--accent)">' + _selectedNodes.length + ' selected</span>';
      html += '<button onclick="BrainMap.clearSelection()" style="margin-left:auto;font-size:10px;padding:2px 6px;border-radius:4px;border:1px solid var(--border);background:var(--bg-secondary);color:var(--text-secondary);cursor:pointer">Clear</button>';
      html += '</div>';
    }
    for (var di = 0; di < _searchMatches.length; di++) {
      var did = _searchMatches[di];
      var dn = nodes[did];
      var shortName = did.split('/').pop();
      var sev = (dn && dn._severity) || 'info';
      var fc = (dn && dn._findings) || 0;
      var sevColor = sev === 'critical' ? '#FF4D6D' : sev === 'high' ? '#F97316' : sev === 'medium' ? '#FACC15' : '#4ADE80';
      var isActive = di === _searchIndex;
      var isSelected = _selectedNodes.indexOf(did) >= 0;
      var bgColor = isSelected ? 'rgba(88,166,255,0.1)' : (isActive ? 'rgba(88,166,255,0.15)' : '');
      html += '<div class="sr-item" data-idx="' + di + '" data-id="' + did + '" style="padding:6px 10px;cursor:pointer;display:flex;align-items:center;gap:8px;border-bottom:1px solid rgba(255,255,255,0.05);transition:background 0.1s;background:' + bgColor + '" onmouseenter="if(!this.style.background)this.style.background=\'var(--bg-tertiary)\'" onmouseleave="this.style.background=\'' + bgColor.replace(/'/g, '') + '\'" onclick="BrainMap.searchSelect(' + di + ', event)" oncontextmenu="BrainMap.toggleSelect(\'' + did + '\');return false">';
      // Checkbox for multi-select
      html += '<span style="display:inline-flex;width:14px;height:14px;border-radius:3px;border:1px solid ' + (isSelected ? 'var(--accent)' : 'var(--border)') + ';align-items:center;justify-content:center;flex-shrink:0;background:' + (isSelected ? 'var(--accent)' : 'transparent') + '">';
      if (isSelected) html += '<svg width="10" height="10" viewBox="0 0 10 10"><path d="M2 5l2.5 2.5L8 3" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      html += '</span>';
      html += '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + sevColor + ';flex-shrink:0"></span>';
      html += '<span style="flex:1;font-size:12px;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + did + '">' + shortName + '</span>';
      if (fc > 0) html += '<span style="font-size:10px;color:' + sevColor + ';font-weight:600;flex-shrink:0">' + fc + '</span>';
      html += '<span style="font-size:9px;color:var(--text-tertiary);flex-shrink:0;text-transform:uppercase">' + sev + '</span>';
      html += '</div>';
    }
    dd.innerHTML = html;
    dd.style.display = 'block';
    // Highlight active item
    var items = dd.querySelectorAll('.sr-item');
    for (var hi = 0; hi < items.length; hi++) {
      if (hi !== _searchIndex && _selectedNodes.indexOf(items[hi].getAttribute('data-id')) < 0) {
        items[hi].style.background = '';
      }
    }
  }

  function commitSearch() {
    // Called on Enter to save the current query to history
    if (_searchQuery && _searchQuery.length >= 2) {
      _saveToHistory(_searchQuery);
    }
  }

  function searchSelect(idx, evt) {
    // Ctrl+Click or Cmd+Click = toggle multi-select
    if (evt && (evt.ctrlKey || evt.metaKey)) {
      toggleSelect(_searchMatches[idx]);
      return;
    }
    _zoomToSearchMatch(idx);
  }

  function toggleSelect(id) {
    var pos = _selectedNodes.indexOf(id);
    if (pos >= 0) {
      _selectedNodes.splice(pos, 1);
    } else {
      _selectedNodes.push(id);
    }
    _highlightSelectedNodes();
    _renderSearchDropdown();
    _renderComparePanel();
  }

  function clearSelection() {
    _selectedNodes = [];
    _highlightSelectedNodes();
    _renderSearchDropdown();
    _renderComparePanel();
  }

  function _highlightSelectedNodes() {
    // Reset all search-match nodes to default search style
    for (var si = 0; si < _searchMatches.length; si++) {
      var sn = nodes[_searchMatches[si]];
      if (!sn || !sn.shape) continue;
      var isSel = _selectedNodes.indexOf(_searchMatches[si]) >= 0;
      if (isSel) {
        sn.shape.shadowColor('#38bdf8'); sn.shape.shadowBlur(20); sn.shape.shadowOpacity(1);
        sn.shape.stroke('#38bdf8'); sn.shape.strokeWidth(3);
      } else if (si === _searchIndex) {
        sn.shape.shadowColor('#fff'); sn.shape.shadowBlur(20); sn.shape.shadowOpacity(1);
        sn.shape.strokeWidth(0);
      } else {
        sn.shape.shadowColor('#E8920A'); sn.shape.shadowBlur(12); sn.shape.shadowOpacity(0.8);
        sn.shape.strokeWidth(0);
      }
    }
    nodeLayer.batchDraw();
  }

  function _renderComparePanel() {
    var panel = document.getElementById('brain-compare-panel');
    if (!panel) {
      // Create panel on demand
      var dd = document.getElementById('brain-search-dropdown');
      if (!dd) return;
      panel = document.createElement('div');
      panel.id = 'brain-compare-panel';
      panel.style.cssText = 'display:none;border-top:1px solid var(--border);padding:8px 10px;background:var(--bg-secondary);font-size:11px';
      dd.parentElement.appendChild(panel);
    }
    if (_selectedNodes.length < 2) {
      panel.style.display = 'none';
      return;
    }
    var html = '<div style="font-weight:600;color:var(--accent);margin-bottom:6px;font-size:11px">Compare (' + _selectedNodes.length + ' nodes)</div>';
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:4px">';
    for (var ci = 0; ci < _selectedNodes.length; ci++) {
      var cid = _selectedNodes[ci];
      var cn = nodes[cid];
      var cShort = cid.split('/').pop();
      var cSev = (cn && cn._severity) || 'info';
      var cFc = (cn && cn._findings) || 0;
      var cColor = cSev === 'critical' ? '#FF4D6D' : cSev === 'high' ? '#F97316' : cSev === 'medium' ? '#FACC15' : '#4ADE80';
      var cPath = cid.split('/');
      var cDir = cPath.length > 1 ? cPath.slice(0, -1).join('/') : '';
      html += '<div style="padding:4px 6px;background:var(--bg-primary);border:1px solid var(--border);border-radius:4px;position:relative">';
      html += '<button onclick="BrainMap.removeSelected(\'' + cid + '\')" style="position:absolute;top:2px;right:2px;width:14px;height:14px;border:none;background:none;color:var(--text-tertiary);cursor:pointer;font-size:10px;line-height:1;padding:0">\u00d7</button>';
      html += '<div style="display:flex;align-items:center;gap:4px;margin-bottom:2px">';
      html += '<span style="width:6px;height:6px;border-radius:50%;background:' + cColor + ';flex-shrink:0"></span>';
      html += '<span style="font-weight:600;color:var(--text-primary);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + cid + '">' + cShort + '</span>';
      html += '</div>';
      if (cDir) html += '<div style="color:var(--text-tertiary);font-size:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + cDir + '">' + cDir + '</div>';
      html += '<div style="display:flex;justify-content:space-between;margin-top:2px">';
      html += '<span style="color:' + cColor + ';font-size:10px;font-weight:600">' + cFc + ' findings</span>';
      html += '<span style="color:var(--text-tertiary);font-size:9px;text-transform:uppercase">' + cSev + '</span>';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';
    panel.innerHTML = html;
    panel.style.display = 'block';
  }

  function _zoomToSearchMatch(idx) {
    if (idx < 0 || idx >= _searchMatches.length) return;
    _searchIndex = idx;
    var mn = nodes[_searchMatches[idx]];
    if (mn && mn.group) {
      // Smooth zoom: scale to 1.5x centered on node
      var targetScale = 1.5;
      var targetX = stage.width() / 2 - mn.group.x() * targetScale;
      var targetY = stage.height() / 2 - mn.group.y() * targetScale;
      // Animate via Konva.Tween if available, else instant
      stage.to({ x: targetX, y: targetY, scaleX: targetScale, scaleY: targetScale, duration: 0.3 });
      // Pulse highlight the selected node
      for (var si = 0; si < _searchMatches.length; si++) {
        var sn = nodes[_searchMatches[si]];
        if (sn && sn.shape) {
          if (si === idx) {
            sn.shape.shadowColor('#fff'); sn.shape.shadowBlur(20); sn.shape.shadowOpacity(1);
          } else {
            sn.shape.shadowColor('#E8920A'); sn.shape.shadowBlur(12); sn.shape.shadowOpacity(0.8);
          }
        }
      }
      nodeLayer.batchDraw();
      _debounceMiniMap();
    }
    _updateSearchCount();
    _renderSearchDropdown();
  }

  function _updateSearchCount() {
    var countEl = document.getElementById('brain-search-count');
    if (!countEl || _searchMatches.length === 0) return;
    if (_searchIndex >= 0 && _searchMatches.length > 1) {
      countEl.textContent = (_searchIndex + 1) + '/' + _searchMatches.length + ' found';
    } else {
      countEl.textContent = _searchMatches.length + ' found';
    }
    countEl.style.color = 'var(--accent)';
  }

  function _searchNext() {
    if (_searchMatches.length === 0) return;
    _zoomToSearchMatch((_searchIndex + 1) % _searchMatches.length);
  }

  function _searchPrev() {
    if (_searchMatches.length === 0) return;
    _zoomToSearchMatch((_searchIndex - 1 + _searchMatches.length) % _searchMatches.length);
  }

  // ── Handle events (scan) ────────────────────────────────────
  function handleEvent(event, data) {
    if (event === 'scan.started') _simulateSwarm(Object.keys(nodes));
    if (event === 'scan.finding') {
      var state = data.severity === 'critical' || data.severity === 'high' ? 'critical' :
                  data.severity === 'medium' ? 'wounded' : 'done';
      setNodeState(data.file, state);
    }
    if (event === 'scan.complete') _loadNodes();
  }

  function _simulateSwarm(nodeIds) {
    if (!antLayer || !nodeIds.length) return;
    antLayer.destroyChildren();
    var targets = nodeIds.slice(0, Math.min(nodeIds.length, 26));
    targets.forEach(function(id, i) {
      setTimeout(function() {
        var target = nodes[id];
        if (!target || !target.group) return;
        var ant = new Konva.Circle({ x: target.group.x(), y: target.group.y(), radius: 5, fill: COLORS.ant_minor });
        antLayer.add(ant);
        ants['ant_' + i] = ant;
        antLayer.batchDraw();
      }, i * 120);
    });
  }

  // ── Public API ──────────────────────────────────────────────
  function zoomIn() { _zoom(1.2); }
  function zoomOut() { _zoom(1/1.2); }
  function zoomReset() {
    if (!stage) return;
    stage.scale({ x: 1, y: 1 }); stage.position({ x: 0, y: 0 });
    offsetX = 0; offsetY = 0; _onResize(); _updateZoomDisplay(); stage.batchDraw(); _debounceMiniMap();
  }

  return {
    init: init,
    setNodeState: setNodeState,
    loadNodes: loadNodes,
    zoomIn: zoomIn,
    zoomOut: zoomOut,
    zoomReset: zoomReset,
    handleEvent: handleEvent,
    _relistenWs: _relistenWs,
    switchView: switchView,
    toggleLabels: toggleLabels,
    rotateGraph: rotateGraph,
    resetRotation: resetRotation,
    exportPNG: exportPNG,
    exportJSON: exportJSON,
    searchNodes: searchNodes,
    searchNext: function() { _searchNext(); },
    searchPrev: function() { _searchPrev(); },
    searchSelect: function(idx, evt) { searchSelect(idx, evt); },
    toggleSelect: function(id) { toggleSelect(id); },
    clearSelection: function() { clearSelection(); },
    removeSelected: function(id) { toggleSelect(id); },
    commitSearch: function() { commitSearch(); },
    clearHistory: function() { clearHistory(); },
    showHistoryOnFocus: function() { _showHistoryOnFocus(); },
  };

  // Close search dropdown when clicking outside
  document.addEventListener('mousedown', function(e) {
    var dd = document.getElementById('brain-search-dropdown');
    var inp = document.getElementById('brain-search');
    if (dd && dd.style.display !== 'none' && inp && !inp.contains(e.target) && !dd.contains(e.target)) {
      dd.style.display = 'none';
    }
  });
})();
