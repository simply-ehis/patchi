/**
 * canvas.js — Patchi Brain Map (Konva.js)
 *
 * Renders the file dependency graph as an interactive canvas.
 * Handles ant animation, node state colours, and tap-to-spawn.
 * Konva loaded from CDN in app.html.
 */

const BrainMap = (() => {
  const NODE_R = 18;
  const ANT_R = 5;
  // Colony palette — matches app.css brand identity
  // Dark = Universal Colony (amber), Light = Australian Colony (green)
  const COLORS = {
    idle:         "#1A2810",   // earth floor
    bg:           "#0A1A0D",   // deep forest
    edge:         "#1E3014",   // forest shadow
    text:         "#B8A898",   // aged silk
    // Node types
    healthy:      "#C8621A",   // worker amber — default
    scanning:     "#E8920A",   // bright amber — active scan
    done:         "#4ADE80",   // leaf green — clean
    wounded:      "#FACC15",   // warning yellow — has issues
    critical:     "#FF4D6D",   // sharp red — critical issue
    dead:         "#3D2A1A",   // dark rust — dead file
    restricted:   "#2C2010",   // darkest — restricted
    queen:        "#2C1208",   // queen node center
    entry_point:  "#8B3A0F",   // minor worker amber
    route_handler:"#7A2E08",   // soldier rust
    test:         "#4ADE80",   // leaf green
    config:       "#4A5030",   // muted forest
    sensitive:    "#FF8C42",   // high orange
    component:    "#6B8B5A",   // forest sage
    default:      "#C8621A",   // worker amber
    // Ants
    ant_minor:    "#C8621A",   // minor worker
    ant_soldier:  "#7A2E08",   // soldier
    ant_queen:    "#2C1208",   // queen
    ant_spawn:    "#E8920A",   // spawn flash
  };

  let stage, nodeLayer, antLayer, nodes = {}, ants = {}, edges = [];
  let _onWsMessage = null;
  let _initialized = false;
  
  // Zoom and pan state
  let scale = 1;
  let offsetX = 0;
  let offsetY = 0;

  function init(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    // Re-init support: destroy old stage and reset state for HTMX swaps
    if (_initialized) {
      if (stage) stage.destroy();
      stage = null; nodeLayer = null; antLayer = null;
      nodes = {}; ants = {}; edges = [];
    }
    _initialized = true;

    // Use clientWidth but fall back to parent width or a sane default
    var w = el.clientWidth || (el.parentElement && el.parentElement.clientWidth) || 800;
    var h = el.clientHeight || (el.parentElement && el.parentElement.clientHeight) || 400;
    // If dimensions are still 0, wait for layout and retry
    if (w < 10 || h < 10) {
      var pw = el.parentElement ? el.parentElement.clientWidth : 800;
      var ph = el.parentElement ? el.parentElement.clientHeight : 400;
      w = Math.max(pw - 180, 400);
      h = Math.max(ph, 300);
    }
    stage = new Konva.Stage({
      container: containerId,
      width: w,
      height: h,
    });

    nodeLayer = new Konva.Layer();
    antLayer = new Konva.Layer();
    stage.add(nodeLayer, antLayer);

    _bindWsEvents();
    // Delay node load slightly so container dimensions settle after layout
    setTimeout(function() {
      _onResize();
      _loadNodes();
    }, 100);
    
    // Add zoom controls and mini-map
    _addZoomControls();

    // Viewport resize handler
    window.addEventListener('resize', _onResize);
    // Also watch for container dimension changes (CSS transitions, etc.)
    if (typeof ResizeObserver !== 'undefined') {
      new ResizeObserver(_onResize).observe(el);
    }
    _addMiniMap();
    
    // Tap-to-spawn on node click
    nodeLayer.on("click tap", ({ target }) => {
      const nodeId = target.getAttr("nodeId");
      if (nodeId) {
        const _ws = window._ws;
        if (_ws) _ws.send(JSON.stringify({action: "spawn.ant", data: {node_id: nodeId}}));
      }
    });
    
    // ── Pan: left-click drag on background, middle-click anywhere, shift+drag ──
    var isDragging = false;
    var lastPointerPosition = null;
    var _dragTarget = null;
    var _dragStartPos = null;
    var _didDrag = false;
    
    stage.on('mousedown touchstart', function(e) {
      var btn = e.evt.button;
      var target = e.target;
      // Left-click on background OR middle-click OR shift+left = pan
      var isBackground = !target.getAttr('nodeId');
      if (btn === 0 && (isBackground || e.evt.shiftKey) || btn === 1 || btn === 2) {
        isDragging = true;
        _didDrag = false;
        _dragTarget = target;
        _dragStartPos = stage.getPointerPosition();
        lastPointerPosition = stage.getPointerPosition();
        // Set cursor to grabbing
        stage.container().style.cursor = 'grabbing';
      }
    });
    
    stage.on('mouseup touchend', function() {
      isDragging = false;
      _dragTarget = null;
      _dragStartPos = null;
      stage.container().style.cursor = 'grab';
    });
    
    stage.on('mousemove touchmove', function(e) {
      if (!isDragging) return;
      e.evt.preventDefault();
      var newPointerPosition = stage.getPointerPosition();
      if (!newPointerPosition || !lastPointerPosition) return;
      var dx = newPointerPosition.x - lastPointerPosition.x;
      var dy = newPointerPosition.y - lastPointerPosition.y;
      // Only start drag if moved >3px (avoids accidental pan on click)
      if (_dragStartPos) {
        var sdx = newPointerPosition.x - _dragStartPos.x;
        var sdy = newPointerPosition.y - _dragStartPos.y;
        if (!_didDrag && Math.abs(sdx) + Math.abs(sdy) < 3) return;
        _didDrag = true;
      }
      offsetX += dx;
      offsetY += dy;
      stage.position({ x: stage.x() + dx, y: stage.y() + dy });
      stage.batchDraw();
      _updateMiniMap();
      lastPointerPosition = newPointerPosition;
    });
    
    // Touch + cursor setup: disable browser gestures, set grab cursor
    stage.container().style.touchAction = 'none';
    stage.container().style.cursor = 'grab';
    stage.container().style.userSelect = 'none';
    
    // ── Pinch-to-zoom (two-finger touch) ──
    var _pinchState = { active: false, startDist: 0, startScale: 1, centerX: 0, centerY: 0 };
    
    function _touchDist(t1, t2) {
      var dx = t2.clientX - t1.clientX;
      var dy = t2.clientY - t1.clientY;
      return Math.sqrt(dx * dx + dy * dy);
    }
    
    stage.on('touchstart', function(e) {
      var touches = e.evt.touches;
      if (touches && touches.length === 2) {
        e.evt.preventDefault();
        _pinchState.active = true;
        _pinchState.startDist = _touchDist(touches[0], touches[1]);
        _pinchState.startScale = stage.scaleX();
        var rect = stage.container().getBoundingClientRect();
        _pinchState.centerX = (touches[0].clientX + touches[1].clientX) / 2 - rect.left;
        _pinchState.centerY = (touches[0].clientY + touches[1].clientY) / 2 - rect.top;
        isDragging = false; // disable pan during pinch
      }
    });
    
    stage.on('touchmove', function(e) {
      var touches = e.evt.touches;
      if (_pinchState.active && touches && touches.length === 2) {
        e.evt.preventDefault();
        var dist = _touchDist(touches[0], touches[1]);
        var ratio = dist / _pinchState.startDist;
        var newScale = Math.max(0.05, Math.min(10, _pinchState.startScale * ratio));
        // Zoom centered on pinch midpoint
        var cx = _pinchState.centerX;
        var cy = _pinchState.centerY;
        var oldScale = stage.scaleX();
        var mousePointTo = {
          x: (cx - stage.x()) / oldScale,
          y: (cy - stage.y()) / oldScale,
        };
        stage.scale({ x: newScale, y: newScale });
        stage.position({
          x: cx - mousePointTo.x * newScale,
          y: cy - mousePointTo.y * newScale,
        });
        _updateZoomDisplay();
        stage.batchDraw();
        _updateMiniMap();
        // Also pan with the pinch midpoint movement
        var rect = stage.container().getBoundingClientRect();
        var newCenterX = (touches[0].clientX + touches[1].clientX) / 2 - rect.left;
        var newCenterY = (touches[0].clientY + touches[1].clientY) / 2 - rect.top;
        var pdx = newCenterX - cx;
        var pdy = newCenterY - cy;
        stage.position({ x: stage.x() + pdx, y: stage.y() + pdy });
        _pinchState.centerX = newCenterX;
        _pinchState.centerY = newCenterY;
        stage.batchDraw();
      }
    });
    
    stage.on('touchend', function(e) {
      if (_pinchState.active) {
        var touches = e.evt.touches;
        if (!touches || touches.length < 2) {
          _pinchState.active = false;
        }
      }
    });
    
    // ── Zoom with mouse wheel ──
    stage.on('wheel', function(e) {
      e.evt.preventDefault();
      var oldScale = stage.scaleX();
      var pointer = stage.getPointerPosition();
      if (!pointer) return;
      var mousePointTo = {
        x: (pointer.x - stage.x()) / oldScale,
        y: (pointer.y - stage.y()) / oldScale,
      };
      var newScale = e.evt.deltaY > 0 ? oldScale * 0.9 : oldScale * 1.1;
      newScale = Math.max(0.05, Math.min(10, newScale));
      stage.scale({ x: newScale, y: newScale });
      var newPos = {
        x: pointer.x - mousePointTo.x * newScale,
        y: pointer.y - mousePointTo.y * newScale,
      };
      stage.position(newPos);
      _updateZoomDisplay();
      stage.batchDraw();
      _updateMiniMap();
    });
    
    // ── Keyboard navigation: WASD, arrows, +/-, 0 ──
    var _keyState = {};
    var _panSpeed = 40;
    var _panInterval = null;
    
    function _startPan(dx, dy) {
      if (_panInterval) clearInterval(_panInterval);
      stage.position({ x: stage.x() + dx, y: stage.y() + dy });
      stage.batchDraw();
      _updateMiniMap();
      _panInterval = setInterval(function() {
        stage.position({ x: stage.x() + dx, y: stage.y() + dy });
        stage.batchDraw();
        _updateMiniMap();
      }, 30);
    }
    function _stopPan() {
      if (_panInterval) { clearInterval(_panInterval); _panInterval = null; }
    }
    
    document.addEventListener('keydown', function(e) {
      // Don't capture if typing in an input
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
      if (_keyState[e.key]) return; // already held
      _keyState[e.key] = true;
      var dx = 0, dy = 0;
      switch(e.key) {
        case 'w': case 'W': case 'ArrowUp':    dy = _panSpeed; break;
        case 's': case 'S': case 'ArrowDown':  dy = -_panSpeed; break;
        case 'a': case 'A': case 'ArrowLeft':  dx = _panSpeed; break;
        case 'd': case 'D': case 'ArrowRight': dx = -_panSpeed; break;
        case '+': case '=': _zoomCenter(1.2); return;
        case '-': case '_': _zoomCenter(0.8); return;
        case '0': _zoomFit(); return;
        default: return;
      }
      e.preventDefault();
      _startPan(dx, dy);
    });
    document.addEventListener('keyup', function(e) {
      delete _keyState[e.key];
      if (!Object.keys(_keyState).some(function(k) { return 'wasdWASD'.indexOf(k) >= 0 || k.indexOf('Arrow') === 0; })) {
        _stopPan();
      }
    });
  }

  function _onResize() {
    const el = document.getElementById('brain-map');
    if (!stage || !el) return;
    stage.width(el.clientWidth);
    stage.height(el.clientHeight);
    stage.batchDraw();
  }

  function _addZoomControls() {
    var el = document.getElementById('brain-map');
    if (!el) return;
    var container = el.parentElement;
    
    // Create zoom + D-pad controls if they don't exist
    var zoomControls = document.getElementById('zoom-controls');
    if (!zoomControls) {
      zoomControls = document.createElement('div');
      zoomControls.id = 'zoom-controls';
      zoomControls.innerHTML = [
        '<div style="display:flex;gap:5px;align-items:center;margin-bottom:6px">',
        '  <button id="zoom-in" class="btn" title="Zoom in (+)">+</button>',
        '  <span id="zoom-level" style="min-width:40px;text-align:center;font-size:11px;color:var(--text-secondary)">100%</span>',
        '  <button id="zoom-out" class="btn" title="Zoom out (-)">−</button>',
        '  <button id="zoom-fit" class="btn" title="Fit all (0)">Fit</button>',
        '</div>',
        '<div style="display:grid;grid-template-columns:28px 28px 28px;grid-template-rows:28px 28px 28px;gap:2px;margin-bottom:4px">',
        '  <div></div>',
        '  <button id="dpad-up" class="btn" style="padding:0;font-size:14px" title="Pan up (W / ↑)">▲</button>',
        '  <div></div>',
        '  <button id="dpad-left" class="btn" style="padding:0;font-size:14px" title="Pan left (A / ←)">◀</button>',
        '  <button id="dpad-center" class="btn" style="padding:0;font-size:10px" title="Reset view (0)">⌂</button>',
        '  <button id="dpad-right" class="btn" style="padding:0;font-size:14px" title="Pan right (D / →)">▶</button>',
        '  <div></div>',
        '  <button id="dpad-down" class="btn" style="padding:0;font-size:14px" title="Pan down (S / ↓)">▼</button>',
        '  <div></div>',
        '</div>',
        '<div style="font-size:9px;color:var(--text-tertiary);line-height:1.3">',
        '  WASD / Arrows: pan<br>0: fit • +/−: zoom<br>Scroll: zoom • Drag: pan',
        '</div>',
      ].join('\n');
      zoomControls.style.cssText = [
        'position: absolute;',
        'bottom: 12px;',
        'left: 12px;',
        'z-index: 10;',
        'display: flex;',
        'flex-direction: column;',
        'align-items: center;',
        'background: var(--bg-secondary);',
        'border: 1px solid var(--border-subtle);',
        'border-radius: var(--radius-lg);',
        'padding: 8px;',
        'box-shadow: 0 2px 8px rgba(0,0,0,0.3);',
      ].join(' ');
      container.appendChild(zoomControls);
      
      document.getElementById('zoom-in').onclick = function() { _zoomCenter(1.3); };
      document.getElementById('zoom-out').onclick = function() { _zoomCenter(0.7); };
      document.getElementById('zoom-fit').onclick = function() { _zoomToFit(); };
      document.getElementById('dpad-center').onclick = function() { _zoomToFit(); };
      
      // D-pad: continuous pan while held down
      var _dpadInterval = null;
      function _startDpadPan(dx, dy) {
        if (_dpadInterval) clearInterval(_dpadInterval);
        stage.position({ x: stage.x() + dx, y: stage.y() + dy });
        stage.batchDraw();
        _updateMiniMap();
        _dpadInterval = setInterval(function() {
          stage.position({ x: stage.x() + dx, y: stage.y() + dy });
          stage.batchDraw();
          _updateMiniMap();
        }, 30);
      }
      function _stopDpadPan() {
        if (_dpadInterval) { clearInterval(_dpadInterval); _dpadInterval = null; }
      }
      var _dpadStep = 30;
      document.getElementById('dpad-up').onmousedown = function() { _startDpadPan(0, _dpadStep); };
      document.getElementById('dpad-down').onmousedown = function() { _startDpadPan(0, -_dpadStep); };
      document.getElementById('dpad-left').onmousedown = function() { _startDpadPan(_dpadStep, 0); };
      document.getElementById('dpad-right').onmousedown = function() { _startDpadPan(-_dpadStep, 0); };
      document.getElementById('dpad-up').onmouseup = _stopDpadPan;
      document.getElementById('dpad-down').onmouseup = _stopDpadPan;
      document.getElementById('dpad-left').onmouseup = _stopDpadPan;
      document.getElementById('dpad-right').onmouseup = _stopDpadPan;
      document.getElementById('dpad-up').onmouseleave = _stopDpadPan;
      document.getElementById('dpad-down').onmouseleave = _stopDpadPan;
      document.getElementById('dpad-left').onmouseleave = _stopDpadPan;
      document.getElementById('dpad-right').onmouseleave = _stopDpadPan;
      // Touch support for d-pad
      document.getElementById('dpad-up').ontouchstart = function(e) { e.preventDefault(); _startDpadPan(0, _dpadStep); };
      document.getElementById('dpad-down').ontouchstart = function(e) { e.preventDefault(); _startDpadPan(0, -_dpadStep); };
      document.getElementById('dpad-left').ontouchstart = function(e) { e.preventDefault(); _startDpadPan(_dpadStep, 0); };
      document.getElementById('dpad-right').ontouchstart = function(e) { e.preventDefault(); _startDpadPan(-_dpadStep, 0); };
      document.getElementById('dpad-up').ontouchend = _stopDpadPan;
      document.getElementById('dpad-down').ontouchend = _stopDpadPan;
      document.getElementById('dpad-left').ontouchend = _stopDpadPan;
      document.getElementById('dpad-right').ontouchend = _stopDpadPan;
    }
  }
  
  function _addMiniMap() {
    const el = document.getElementById('brain-map');
    if (!el) return;
    const container = el.parentElement;
    
    let miniMap = document.getElementById('mini-map');
    if (!miniMap) {
      miniMap = document.createElement('div');
      miniMap.id = 'mini-map';
      miniMap.innerHTML = `<canvas id="mini-map-canvas" width="150" height="100"></canvas>`;
      miniMap.style.cssText = `
        position: absolute;
        bottom: 20px;
        right: 20px;
        z-index: 10;
        border: 1px solid #374151;
        background: #0a0a0a;
        overflow: hidden;
        cursor: pointer;
      `;
      container.appendChild(miniMap);
      
      miniMap.addEventListener('click', (e) => {
        const rect = miniMap.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const canvasW = 150, canvasH = 100;
        
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        for (const id in nodes) {
          minX = Math.min(minX, nodes[id].x);
          minY = Math.min(minY, nodes[id].y);
          maxX = Math.max(maxX, nodes[id].x);
          maxY = Math.max(maxY, nodes[id].y);
        }
        if (minX === Infinity) return;
        
        const pad = 50;
        const graphW = maxX - minX + 2 * pad;
        const graphH = maxY - minY + 2 * pad;
        const sx = canvasW / graphW;
        const sy = canvasH / graphH;
        const s = Math.min(sx, sy);
        
        const targetX = (mx / s) + minX - pad;
        const targetY = (my / s) + minY - pad;
        
        stage.position({
          x: stage.width() / 2 - targetX * stage.scaleX(),
          y: stage.height() / 2 - targetY * stage.scaleY()
        });
        stage.batchDraw();
      });
    }
  }
  
  function _updateMiniMap() {
    const canvas = document.getElementById('mini-map-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = 150, H = 100;
    ctx.clearRect(0, 0, W, H);
    
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const id in nodes) {
      minX = Math.min(minX, nodes[id].x);
      minY = Math.min(minY, nodes[id].y);
      maxX = Math.max(maxX, nodes[id].x);
      maxY = Math.max(maxY, nodes[id].y);
    }
    if (minX === Infinity) return;
    
    const pad = 20;
    const graphW = maxX - minX + 2 * pad;
    const graphH = maxY - minY + 2 * pad;
    const sx = W / graphW;
    const sy = H / graphH;
    const s = Math.min(sx, sy);
    
    // Draw edges
    ctx.strokeStyle = '#374151';
    ctx.lineWidth = 0.5;
    edges.forEach(e => {
      const from = nodes[e.from] || nodes[e.source];
      const to = nodes[e.to] || nodes[e.target];
      if (!from || !to) return;
      const x1 = (from.x - minX + pad) * s;
      const y1 = (from.y - minY + pad) * s;
      const x2 = (to.x - minX + pad) * s;
      const y2 = (to.y - minY + pad) * s;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();
    });
    
    // Draw nodes
    for (const id in nodes) {
      const n = nodes[id];
      const x = (n.x - minX + pad) * s;
      const y = (n.y - minY + pad) * s;
      ctx.fillStyle = n.shape.fill() || '#C8621A';
      ctx.beginPath();
      ctx.arc(x, y, 2, 0, Math.PI * 2);
      ctx.fill();
    }
    
    // Draw viewport rectangle
    const stageW = stage.width();
    const stageH = stage.height();
    const stgX = -stage.x() / stage.scaleX();
    const stgY = -stage.y() / stage.scaleY();
    const vpX = (stgX - minX + pad) * s;
    const vpY = (stgY - minY + pad) * s;
    const vpW = (stageW / stage.scaleX()) * s;
    const vpH = (stageH / stage.scaleY()) * s;
    ctx.strokeStyle = '#E8920A';
    ctx.lineWidth = 1;
    ctx.strokeRect(vpX, vpY, vpW, vpH);
  }
  
  function _updateZoomDisplay() {
    var el = document.getElementById('zoom-level');
    if (el && stage) el.textContent = Math.round(stage.scaleX() * 100) + '%';
  }
  
  function _zoomCenter(factor) {
    if (!stage) return;
    var oldScale = stage.scaleX();
    var newScale = Math.max(0.05, Math.min(10, oldScale * factor));
    var cx = stage.width() / 2;
    var cy = stage.height() / 2;
    var mousePointTo = {
      x: (cx - stage.x()) / oldScale,
      y: (cy - stage.y()) / oldScale,
    };
    stage.scale({ x: newScale, y: newScale });
    stage.position({
      x: cx - mousePointTo.x * newScale,
      y: cy - mousePointTo.y * newScale,
    });
    _updateZoomDisplay();
    stage.batchDraw();
    _updateMiniMap();
  }
  
  function _zoomFit() { _zoomToFit(); }
  
  function _zoom(factor) {
    _zoomCenter(factor);
  }
  
  function _zoomToFit() {
    // Calculate bounding box of all nodes
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    
    for (const nodeId in nodes) {
      const node = nodes[nodeId];
      minX = Math.min(minX, node.x);
      minY = Math.min(minY, node.y);
      maxX = Math.max(maxX, node.x);
      maxY = Math.max(maxY, node.y);
    }
    
    if (minX === Infinity) return; // No nodes
    
    const stageWidth = stage.width();
    const stageHeight = stage.height();
    
    const padding = 50;
    const width = maxX - minX + 2 * padding;
    const height = maxY - minY + 2 * padding;
    
    const scaleX = stageWidth / width;
    const scaleY = stageHeight / height;
    const scale = Math.min(scaleX, scaleY);
    
    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;
    
    stage.scale({ x: scale, y: scale });
    stage.position({
      x: stageWidth / 2 - centerX * scale,
      y: stageHeight / 2 - centerY * scale
    });
    
    _updateZoomDisplay();
    stage.batchDraw();
    _updateMiniMap();
  }

  function loadNodes(ns, edges) {
    // If called without args, use stored data from last fetch
    var useNodes = ns || _lastNodes || [];
    var useEdges = edges || _lastEdges || [];
    _renderGraph(useNodes, useEdges);
  }

  function _loadNodes() {
    Promise.all([
      fetch("/api/brain-map/nodes").then(function(r) { if (!r.ok) throw new Error('Nodes API: ' + r.status); return r.json(); }),
      fetch("/api/brain-map/edges").then(function(r) { if (!r.ok) throw new Error('Edges API: ' + r.status); return r.json(); }),
    ]).then(function(res) {
      var nodesRes = res[0], edgesRes = res[1];
      _renderGraph(nodesRes.nodes || [], edgesRes.edges || []);
    }).catch(function(err) { console.error('Brain map load error:', err); });
  }

  function _renderGraph(ns, edgesData) {
    nodeLayer.destroyChildren();
    nodes = {};
    edges = edgesData || [];

    const W = stage.width(), H = stage.height();

    // Force-directed layout
    const positions = _forceLayout(ns, edgesData || [], W, H);

    ns.forEach((n, i) => {
      const pos = positions[n.id || n.path] || { x: W/2, y: H/2 };
      const fc = n.finding_count || 0;
      const sev = n.severity || 'info';
      _addNode(n.id || n.path, n.label || n.path, n.type || 'default', pos.x, pos.y, fc, sev);
    });

    (edgesData || []).forEach(e => _addEdge(e.source || e.from, e.target || e.to, e.type || 'dependency'));
    nodeLayer.draw();
    _updateMiniMap();
  }

  function _forceLayout(nodesList, edgesList, W, H) {
    // Simple force-directed simulation
    const pos = {};
    const n = nodesList.length;
    if (n === 0) return pos;

    // Initialize positions in a circle
    nodesList.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / n;
      const radius = Math.min(W, H) * 0.35;
      pos[node.id || node.path] = {
        x: W / 2 + radius * Math.cos(angle),
        y: H / 2 + radius * Math.sin(angle),
        vx: 0, vy: 0,
      };
    });

    // Build adjacency for faster lookup
    const adj = {};
    edgesList.forEach(e => {
      const f = e.from || e.source;
      const t = e.to || e.target;
      if (!adj[f]) adj[f] = [];
      if (!adj[t]) adj[t] = [];
      adj[f].push(t);
      adj[t].push(f);
    });

    // Run simulation (50 iterations)
    const repulsion = 8000;
    const attraction = 0.005;
    const damping = 0.9;
    const centerPull = 0.01;

    for (let iter = 0; iter < 50; iter++) {
      // Repulsion between all pairs
      const keys = Object.keys(pos);
      for (let i = 0; i < keys.length; i++) {
        for (let j = i + 1; j < keys.length; j++) {
          const a = pos[keys[i]], b = pos[keys[j]];
          let dx = a.x - b.x, dy = a.y - b.y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 1;
          let force = repulsion / (dist * dist);
          let fx = (dx / dist) * force;
          let fy = (dy / dist) * force;
          a.vx += fx; a.vy += fy;
          b.vx -= fx; b.vy -= fy;
        }
      }

      // Attraction along edges
      edgesList.forEach(e => {
        const a = pos[e.from || e.source], b = pos[e.to || e.target];
        if (!a || !b) return;
        let dx = b.x - a.x, dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let force = dist * attraction;
        let fx = (dx / dist) * force;
        let fy = (dy / dist) * force;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      });

      // Center gravity + damping
      Object.values(pos).forEach(p => {
        p.vx += (W / 2 - p.x) * centerPull;
        p.vy += (H / 2 - p.y) * centerPull;
        p.vx *= damping;
        p.vy *= damping;
        p.x += p.vx;
        p.y += p.vy;
        // Keep within bounds
        p.x = Math.max(40, Math.min(W - 40, p.x));
        p.y = Math.max(40, Math.min(H - 40, p.y));
      });
    }

    // Clean up velocity fields
    Object.values(pos).forEach(p => { delete p.vx; delete p.vy; });
    return pos;
  }

  function _healthColor(findingCount, severity) {
    if (findingCount === 0) return null;
    if (severity === "critical" || findingCount >= 5) return COLORS.critical;
    if (severity === "high" || findingCount >= 3) return COLORS.wounded;
    return COLORS.scanning;
  }

  function _addNode(id, label, type, x, y, findingCount, severity) {
    const group = new Konva.Group({ x, y, draggable: true });

    let shape;
    let color = COLORS.idle;
    
    switch(type) {
      case 'entry_point':
        shape = new Konva.RegularPolygon({
          sides: 6, // Hexagon
          radius: NODE_R,
          fill: COLORS.entry_point,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        color = COLORS.entry_point;
        break;
      case 'route_handler':
        shape = new Konva.Rect({
          width: NODE_R * 2,
          height: NODE_R * 1.5,
          cornerRadius: 5,
          fill: COLORS.route_handler,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        color = COLORS.route_handler;
        break;
      case 'component':
        shape = new Konva.Circle({
          radius: NODE_R,
          fill: COLORS.component,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        color = COLORS.component;
        break;
      case 'config':
        shape = new Konva.RegularPolygon({
          sides: 4, // Diamond
          radius: NODE_R,
          fill: COLORS.config,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        color = COLORS.config;
        break;
      case 'test':
        shape = new Konva.Circle({
          radius: NODE_R,
          fill: COLORS.test,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        // Add inner ring for test files
        const innerRing = new Konva.Circle({
          radius: NODE_R - 4,
          fill: 'transparent',
          stroke: "#d1fa22",
          strokeWidth: 2,
        });
        group.add(innerRing);
        color = COLORS.test;
        break;
      case 'dead':
        shape = new Konva.Circle({
          radius: NODE_R,
          fill: COLORS.dead,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        // Add X overlay for dead files
        const xLine1 = new Konva.Line({
          points: [-NODE_R, -NODE_R, NODE_R, NODE_R],
          stroke: "#ef4444",
          strokeWidth: 2,
        });
        const xLine2 = new Konva.Line({
          points: [NODE_R, -NODE_R, -NODE_R, NODE_R],
          stroke: "#ef4444",
          strokeWidth: 2,
        });
        group.add(xLine1, xLine2);
        color = COLORS.dead;
        break;
      case 'restricted':
        shape = new Konva.Circle({
          radius: NODE_R,
          fill: COLORS.idle,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        // Add lock icon
        const lockIcon = new Konva.Text({
          text: "🔒",
          fontSize: 12,
          x: -6,
          y: -6,
        });
        group.add(lockIcon);
        color = COLORS.restricted;
        break;
      case 'sensitive':
        shape = new Konva.Circle({
          radius: NODE_R,
          fill: COLORS.sensitive,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
        // Add eye-slash icon
        const eyeSlashIcon = new Konva.Text({
          text: "👁️‍🗨️",
          fontSize: 12,
          x: -6,
          y: -6,
        });
        group.add(eyeSlashIcon);
        color = COLORS.sensitive;
        break;
      default:
        shape = new Konva.Circle({
          radius: NODE_R,
          fill: color,
          stroke: "#4b5563",
          strokeWidth: 1.5,
        });
    }

    shape.setAttr("nodeId", id);

    // Override fill with health color if findings exist
    const hc = _healthColor(findingCount, severity);
    if (hc) {
      shape.fill(hc);
      // Stroke brighter for attention
      shape.stroke(hc === COLORS.critical ? "#ff6b8a" : hc);
    }

    // Right-click to show file details
    group.on("contextmenu", () => {
      _showNodeDetails(id, label, findingCount, severity);
    });

    const text = new Konva.Text({
      text: label.split("/").pop(),
      fontSize: 10,
      fill: COLORS.text,
      offsetX: 40,
      offsetY: -NODE_R - 4,
      width: 80,
      align: "center",
    });

    group.add(shape, text);
    nodeLayer.add(group);
    nodes[id] = { group, shape, x, y, type };
  }

  function _addEdge(fromId, toId, type) {
    const from = nodes[fromId], to = nodes[toId];
    if (!from || !to) return;
    
    let strokeWidth = 1;
    let dash = [];
    let color = COLORS.edge;
    
    // Different styles based on edge type
    switch(type) {
      case 'import_dependency':
        strokeWidth = 1;
        dash = [];
        color = COLORS.edge;
        break;
      case 'route_connection':
        strokeWidth = 2;
        dash = [5, 5]; // Dashed
        color = "#f59e0b"; // Amber
        break;
      case 'test_coverage':
        strokeWidth = 1;
        dash = [2, 2]; // Dotted
        color = "#22c55e"; // Green
        break;
      case 'blast_radius':
        strokeWidth = 2;
        dash = [];
        color = "#f97316"; // Orange
        break;
      case 'dead_path':
        strokeWidth = 1;
        dash = [3, 3]; // Dashed
        color = "#6b7280"; // Gray
        break;
      default:
        strokeWidth = 1;
        dash = [];
        color = COLORS.edge;
    }
    
    const line = new Konva.Line({
      points: [from.x, from.y, to.x, to.y],
      stroke: color,
      strokeWidth: strokeWidth,
      dash: dash,
      opacity: type === 'dead_path' ? 0.3 : 0.5,
    });
    
    // Add arrow for directional edges (imports)
    if (type === 'import_dependency') {
      const angle = Math.atan2(to.y - from.y, to.x - from.x);
      const arrowLength = 8;
      const arrowAngle = Math.PI / 6;
      
      const arrow1 = new Konva.Line({
        points: [
          to.x, to.y,
          to.x - arrowLength * Math.cos(angle - arrowAngle),
          to.y - arrowLength * Math.sin(angle - arrowAngle)
        ],
        stroke: color,
        strokeWidth: 1.5,
      });
      
      const arrow2 = new Konva.Line({
        points: [
          to.x, to.y,
          to.x - arrowLength * Math.cos(angle + arrowAngle),
          to.y - arrowLength * Math.sin(angle + arrowAngle)
        ],
        stroke: color,
        strokeWidth: 1.5,
      });
      
      nodeLayer.add(line, arrow1, arrow2);
    } else {
      nodeLayer.add(line);
    }
    
    line.moveToBottom();
  }

  // ── Ant animation ──────────────────────────────────────────────────────────

  function _spawnAntAnimation(antId, nodeId) {
    const target = nodes[nodeId];
    if (!target) return;

    const startX = stage.width() / 2;
    const startY = stage.height() - 40;

    const ant = new Konva.Circle({
      x: startX, y: startY,
      radius: ANT_R,
      fill: COLORS.ant_spawn,
    });
    antLayer.add(ant);
    ants[antId] = ant;

    // 0ms: appear → 700ms: move to node → circle node → scan → return
    ant.to({
      x: target.x, y: target.y,
      duration: 0.7,
      onFinish: () => {
        _circleNode(ant, target, () => _antScan(ant, antId));
      },
    });
  }

  function _circleNode(ant, target, onDone) {
    let angle = 0;
    const r = NODE_R + 8;
    const anim = new Konva.Animation(frame => {
      angle += frame.timeDiff * 0.36; // full circle in ~1000ms
      ant.x(target.x + r * Math.cos((angle * Math.PI) / 180));
      ant.y(target.y + r * Math.sin((angle * Math.PI) / 180));
      if (angle >= 360) { anim.stop(); onDone(); }
    }, antLayer);
    anim.start();
  }

  function _antScan(ant, antId) {
    // Pulse while scanning
    ant.to({ scaleX: 1.4, scaleY: 1.4, duration: 0.3,
      onFinish: () => ant.to({ scaleX: 1, scaleY: 1, duration: 0.3 }) });
  }

  function _returnAntToQueen(antId) {
    const ant = ants[antId];
    if (!ant) return;
    ant.to({
      x: stage.width() / 2, y: stage.height() - 40, duration: 0.8,
      onFinish: () => { ant.destroy(); antLayer.draw(); delete ants[antId]; _queenPulse(); },
    });
  }

  function _queenPulse() {
    const flash = new Konva.Circle({
      x: stage.width() / 2, y: stage.height() - 40,
      radius: 20, fill: COLORS.ant_spawn, opacity: 0.6,
    });
    antLayer.add(flash);
    flash.to({ scaleX: 1.5, scaleY: 1.5, opacity: 0, duration: 0.4,
      onFinish: () => { flash.destroy(); antLayer.draw(); } });
  }

  function setNodeState(nodeId, state) {
    const n = nodes[nodeId];
    if (!n) return;
    
    // Update node color based on state
    switch(state) {
      case 'healthy':
        n.shape.fill(COLORS[n.type] || COLORS.idle);
        break;
      case 'being_scanned':
        n.shape.fill(COLORS.scanning);
        break;
      case 'wounded':
        n.shape.fill(COLORS.wounded);
        break;
      case 'being_fixed':
        // Add silk strands effect (would require more complex rendering)
        n.shape.fill(COLORS.done);
        break;
      case 'healed':
        n.shape.fill(COLORS.done);
        // Transition back to healthy over time
        setTimeout(() => {
          if (nodes[nodeId]) {
            n.shape.fill(COLORS[n.type] || COLORS.idle);
            nodeLayer.batchDraw();
          }
        }, 800);
        break;
      case 'critical':
        n.shape.fill(COLORS.critical);
        break;
      case 'locked':
        n.shape.fill(COLORS.restricted);
        break;
      default:
        n.shape.fill(COLORS[state] || COLORS.idle);
    }
    
    nodeLayer.batchDraw();
  }

  function _bindWsEvents() {
    _onWsMessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        const evt = msg.event;
        const data = msg.data || {};
        if (evt === 'agent.started') setNodeState(data.file, 'being_scanned');
        if (evt === 'agent.done') setNodeState(data.file, 'done');
        if (evt === 'ant.spawned') _spawnAntAnimation(data.ant_id, data.node_id);
        if (evt === 'ant.result') _returnAntToQueen(data.ant_id);
        if (evt === 'ant.rejected') {
          const msgs = {
            idle: "Patchi is idle — start a scan first to enable ant spawning",
            restricted: "This file is restricted — no ants allowed",
            cooldown: "Wait a moment before tapping the same node again",
            capacity: "Too many ants active — wait for one to finish",
            node_busy: "This node already has enough ants working on it",
          };
          const msg = msgs[data.reason] || `Spawn rejected: ${data.reason}`;
          if (typeof toast === "function") toast(msg, "error");
        }
        if (evt === 'scan.complete') _loadNodes();
      } catch (_) {}
    };
    _relistenWs();
  }

  function _relistenWs() {
    const ws = window._ws;
    if (!ws) { setTimeout(_relistenWs, 500); return; }
    ws.addEventListener('message', _onWsMessage);
  }

  // ── Node details popup ─────────────────────────────────────────────────────

  function _showNodeDetails(id, label, findingCount, severity) {
    const _detailModal = document.getElementById("node-detail-modal");
    if (!_detailModal) { console.warn('Node detail modal not found in DOM'); return; }
    const sevLabel = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "None" }[severity] || "None";
    const nodeType = nodes[id]?.type || "default";

    // Fetch actual findings for this file
    fetch("/api/findings")
      .then(r => r.json())
      .then(data => {
        const fileFindings = (data.findings || []).filter(f => f.file === id);
        let findingsHtml = "";
        if (fileFindings.length > 0) {
          findingsHtml = `<div class="detail-findings"><div class="detail-subtitle">Findings (${fileFindings.length})</div>` +
            fileFindings.slice(0, 10).map(f => `
              <div class="detail-finding sev-${(f.severity || "low").toLowerCase()}">
                <span class="df-sev">${(f.severity || "").toUpperCase()}</span>
                <span class="df-msg">${f.message || f.title || ""}</span>
                ${f.line ? `<span class="df-line">:${f.line}</span>` : ""}
              </div>`).join("") +
            (fileFindings.length > 10 ? `<div class="df-more">+${fileFindings.length - 10} more</div>` : "") +
            `</div>`;
        }

        _detailModal.querySelector(".modal-title").textContent = label;
        _detailModal.querySelector(".modal-body").innerHTML = `
          <div class="detail-row"><span class="detail-key">File</span><span class="detail-val">${id}</span></div>
          <div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">${nodeType}</span></div>
          <div class="detail-row"><span class="detail-key">Findings</span><span class="detail-val ${severity}">${findingCount}</span></div>
          <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val ${severity}">${sevLabel}</span></div>
          ${findingsHtml}
        `;
      })
      .catch(() => {
        _detailModal.querySelector(".modal-title").textContent = label;
        _detailModal.querySelector(".modal-body").innerHTML = `
          <div class="detail-row"><span class="detail-key">File</span><span class="detail-val">${id}</span></div>
          <div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">${nodeType}</span></div>
          <div class="detail-row"><span class="detail-key">Findings</span><span class="detail-val ${severity}">${findingCount}</span></div>
          <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val ${severity}">${sevLabel}</span></div>
        `;
      });

    _detailModal.style.display = "flex";
    _detailModal.querySelector(".modal-close").onclick = () => { _detailModal.style.display = "none"; };
    _detailModal.onclick = (e) => { if (e.target === _detailModal) _detailModal.style.display = "none"; };
  }

  function zoomIn() {
    _zoom(1.2);
  }

  function zoomOut() {
    _zoom(1 / 1.2);
  }

  function zoomReset() {
    if (!stage) return;
    stage.scale({ x: 1, y: 1 });
    stage.position({ x: 0, y: 0 });
    offsetX = 0;
    offsetY = 0;
    _onResize();
    _updateZoomDisplay();
    stage.batchDraw();
    _updateMiniMap();
  }

  function handleEvent(event, data) {
    if (event === 'scan.started') {
      _simulateSwarm(Object.keys(nodes));
    }
    if (event === 'scan.finding') {
      const nodeId = data.file;
      const state = data.severity === 'critical' || data.severity === 'high' ? 'critical' :
                    data.severity === 'medium' ? 'wounded' : 'done';
      setNodeState(nodeId, state);
    }
    if (event === 'scan.complete') {
      _loadNodes();
    }
  }

  function _simulateSwarm(nodeIds) {
    if (!antLayer || nodeIds.length === 0) return;
    antLayer.destroyChildren();
    const targetIds = nodeIds.slice(0, Math.min(nodeIds.length, 26));
    targetIds.forEach((id, i) => {
      setTimeout(() => {
        const target = nodes[id];
        if (!target) return;
        const pos = target.position();
        const ant = new Konva.Circle({
          x: pos.x, y: pos.y,
          radius: 5, fill: COLORS.ant_minor,
        });
        antLayer.add(ant);
        ants['ant_' + i] = ant;
        antLayer.batchDraw();
      }, i * 120);
    });
  }

  // ── View switching ──────────────────────────────────────────
  let _currentView = 'graph';
  let _lastNodes = [];
  let _lastEdges = [];
  let _showLabels = true;
  let _rotation = 0; // degrees

  function switchView(viewName) {
    _currentView = viewName;
    document.querySelectorAll('[id^="view-"]').forEach(function(btn) {
      btn.style.background = btn.id === 'view-' + viewName ? 'var(--bg-tertiary)' : '';
      btn.style.fontWeight = btn.id === 'view-' + viewName ? '600' : '';
    });
    if (_lastNodes.length === 0) return;

    // Calculate target positions for the new layout
    var positions;
    switch (viewName) {
      case 'tree': positions = _treeLayout(_lastNodes, _lastEdges); break;
      case 'spiral': positions = _spiralLayout(_lastNodes); break;
      case 'grid': positions = _gridLayout(_lastNodes); break;
      case 'radial': positions = _radialLayout(_lastNodes, _lastEdges); break;
      case 'cluster': positions = _clusterLayout(_lastNodes, _lastEdges); break;
      case 'graph': default: positions = _graphLayout(_lastNodes, _lastEdges); break;
    }

    // Animate each node to its target position using Konva.to()
    var nodeIds = Object.keys(positions);
    nodeIds.forEach(function(id) {
      var nodeData = nodes[id];
      if (!nodeData || !nodeData.group) return;
      var target = positions[id];
      if (!target) return;
      nodeData.group.to({
        x: target.x,
        y: target.y,
        duration: 0.6,
        easing: Konva.Easings.EaseInOut,
      });
    });

    // Rebuild edges after a short delay (let positions settle)
    setTimeout(function() {
      _rebuildEdges();
    }, 650);
  }

  function _rebuildEdges() {
    // Clear and redraw all edges
    while (antLayer.children.length > 0) antLayer.remove(antLayer.children[0]);
    // Edges are stored in the edgeLayer which we don't have access to here,
    // so we redraw by calling the render pipeline
    _lastEdges.forEach(function(e) {
      var fromId = e.source || e.from;
      var toId = e.target || e.to;
      if (!nodes[fromId] || !nodes[toId]) return;
      var fromGroup = nodes[fromId].group;
      var toGroup = nodes[toId].group;
      var color = COLORS.edge;
      var line = new Konva.Line({
        points: [fromGroup.x(), fromGroup.y(), toGroup.x(), toGroup.y()],
        stroke: color,
        strokeWidth: 1,
        opacity: 0.3,
        listening: false,
      });
      antLayer.add(line);
    });
    antLayer.batchDraw();
  }

  function toggleLabels() {
    _showLabels = !_showLabels;
    var btn = document.getElementById('btn-toggle-labels');
    if (btn) btn.textContent = _showLabels ? 'Hide Labels' : 'Show Labels';
    if (_lastNodes.length > 0) _renderGraph(_lastNodes, _lastEdges);
  }

  function rotateGraph(deg) {
    _rotation = (_rotation + deg) % 360;
    if (stage) { stage.rotation(_rotation); stage.batchDraw(); }
  }

  function resetRotation() {
    _rotation = 0;
    if (stage) { stage.rotation(0); stage.batchDraw(); }
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
    if (_lastNodes.length === 0) return;
    var data = { nodes: _lastNodes, edges: _lastEdges, view: _currentView, timestamp: new Date().toISOString() };
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.download = 'patchi-brain-map-' + Date.now() + '.json';
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  }

  // ── Layout algorithms ──────────────────────────────────────

  function _treeLayout(nodesList, edgesList, W, H) {
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var incoming = {}, adj = {};
    nodesList.forEach(function(node) { adj[node.id || node.path] = []; });
    edgesList.forEach(function(e) {
      var f = e.from || e.source, t = e.to || e.target;
      if (adj[f]) adj[f].push(t);
      if (!incoming[t]) incoming[t] = [];
      incoming[t].push(f);
    });
    var roots = nodesList.filter(function(node) {
      var id = node.id || node.path;
      return !incoming[id] || incoming[id].length === 0;
    });
    if (roots.length === 0) roots = [nodesList[0]];
    var levels = {}, visited = {}, queue = [];
    roots.forEach(function(node) { var id = node.id || node.path; levels[id] = 0; visited[id] = true; queue.push(id); });
    while (queue.length > 0) {
      var curr = queue.shift();
      (adj[curr] || []).forEach(function(child) {
        if (!visited[child]) { visited[child] = true; levels[child] = (levels[curr] || 0) + 1; queue.push(child); }
      });
    }
    nodesList.forEach(function(node) { var id = node.id || node.path; if (levels[id] === undefined) levels[id] = 0; });
    var levelGroups = {}, maxLevel = 0;
    nodesList.forEach(function(node) {
      var id = node.id || node.path, lv = levels[id];
      if (!levelGroups[lv]) levelGroups[lv] = [];
      levelGroups[lv].push(id);
      if (lv > maxLevel) maxLevel = lv;
    });
    var padding = 60, levelH = (H - padding * 2) / Math.max(maxLevel, 1);
    for (var lv = 0; lv <= maxLevel; lv++) {
      var group = levelGroups[lv] || [], levelW = (W - padding * 2) / Math.max(group.length - 1, 1);
      group.forEach(function(id, i) { pos[id] = { x: group.length === 1 ? W / 2 : padding + levelW * i, y: padding + levelH * lv }; });
    }
    return pos;
  }

  function _spiralLayout(nodesList, edgesList, W, H) {
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var goldenAngle = Math.PI * (3 - Math.sqrt(5)), cx = W / 2, cy = H / 2, maxR = Math.min(W, H) * 0.42;
    nodesList.forEach(function(node, i) {
      var id = node.id || node.path, angle = i * goldenAngle, r = maxR * Math.sqrt(i / n);
      pos[id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    });
    return pos;
  }

  function _gridLayout(nodesList, edgesList, W, H) {
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var cols = Math.ceil(Math.sqrt(n)), rows = Math.ceil(n / cols);
    var cellW = (W - 80) / cols, cellH = (H - 80) / rows;
    nodesList.forEach(function(node, i) {
      var id = node.id || node.path;
      pos[id] = { x: 40 + cellW * ((i % cols) + 0.5), y: 40 + cellH * (Math.floor(i / cols) + 0.5) };
    });
    return pos;
  }

  function _radialLayout(nodesList, edgesList, W, H) {
    // Concentric rings: roots at center, dependents radiate outward by depth
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var cx = W / 2, cy = H / 2;
    var incoming = {}, adj = {};
    nodesList.forEach(function(node) { adj[node.id || node.path] = []; });
    edgesList.forEach(function(e) {
      var f = e.from || e.source, t = e.to || e.target;
      if (adj[f]) adj[f].push(t);
      if (!incoming[t]) incoming[t] = [];
      incoming[t].push(f);
    });
    var roots = nodesList.filter(function(node) { return !(incoming[node.id || node.path] || []).length; });
    if (roots.length === 0) roots = [nodesList[0]];
    var depth = {}, visited = {}, queue = [];
    roots.forEach(function(node) { var id = node.id || node.path; depth[id] = 0; visited[id] = true; queue.push(id); });
    while (queue.length > 0) {
      var curr = queue.shift();
      (adj[curr] || []).forEach(function(child) {
        if (!visited[child]) { visited[child] = true; depth[child] = (depth[curr] || 0) + 1; queue.push(child); }
      });
    }
    nodesList.forEach(function(node) { var id = node.id || node.path; if (depth[id] === undefined) depth[id] = 0; });
    var maxDepth = 1; nodesList.forEach(function(node) { var d = depth[node.id || node.path]; if (d > maxDepth) maxDepth = d; });
    var maxR = Math.min(W, H) * 0.42;
    var rings = {};
    nodesList.forEach(function(node) {
      var id = node.id || node.path, d = depth[id];
      if (!rings[d]) rings[d] = [];
      rings[d].push(id);
    });
    for (var d = 0; d <= maxDepth; d++) {
      var ring = rings[d] || [], r = (d / maxDepth) * maxR;
      ring.forEach(function(id, i) {
        var angle = (2 * Math.PI * i) / ring.length - Math.PI / 2;
        pos[id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
      });
    }
    return pos;
  }

  function _clusterLayout(nodesList, edgesList, W, H) {
    // Group nodes by type, place each cluster in a region
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var groups = {};
    nodesList.forEach(function(node) {
      var t = node.type || 'default';
      if (!groups[t]) groups[t] = [];
      groups[t].push(node.id || node.path);
    });
    var types = Object.keys(groups), numGroups = types.length;
    var cols = Math.ceil(Math.sqrt(numGroups)), rows = Math.ceil(numGroups / cols);
    var cellW = W / cols, cellH = H / rows;
    types.forEach(function(type, gi) {
      var col = gi % cols, row = Math.floor(gi / cols);
      var clusterCx = cellW * (col + 0.5), clusterCy = cellH * (row + 0.5);
      var ids = groups[type], cn = ids.length;
      var clusterR = Math.min(cellW, cellH) * 0.35;
      ids.forEach(function(id, i) {
        if (cn === 1) { pos[id] = { x: clusterCx, y: clusterCy }; return; }
        var angle = (2 * Math.PI * i) / cn - Math.PI / 2;
        var r = clusterR * Math.sqrt(i / cn);
        pos[id] = { x: clusterCx + r * Math.cos(angle), y: clusterCy + r * Math.sin(angle) };
      });
    });
    return pos;
  }

  // Override _renderGraph to store data and use current layout
  var _origRenderGraph = _renderGraph;
  _renderGraph = function(ns, edgesData) {
    _lastNodes = ns;
    _lastEdges = edgesData || [];
    nodeLayer.destroyChildren();
    nodes = {};
    edges = _lastEdges;
    var W = stage.width(), H = stage.height();
    var positions;
    switch (_currentView) {
      case 'tree': positions = _treeLayout(ns, _lastEdges, W, H); break;
      case 'spiral': positions = _spiralLayout(ns, _lastEdges, W, H); break;
      case 'grid': positions = _gridLayout(ns, _lastEdges, W, H); break;
      case 'radial': positions = _radialLayout(ns, _lastEdges, W, H); break;
      case 'cluster': positions = _clusterLayout(ns, _lastEdges, W, H); break;
      default: positions = _forceLayout(ns, _lastEdges, W, H);
    }
    ns.forEach(function(n) {
      var pos = positions[n.id || n.path] || { x: W/2, y: H/2 };
      var fc = n.finding_count || 0;
      var sev = n.severity || 'info';
      _addNode(n.id || n.path, n.label || n.path, n.type || 'default', pos.x, pos.y, fc, sev);
    });
    // Labels respect toggle
    if (!_showLabels) { nodeLayer.getChildren().forEach(function(g) { var txt = g.findOne('Text'); if (txt) txt.visible(false); }); }
    (_lastEdges || []).forEach(function(e) { _addEdge(e.source || e.from, e.target || e.to, e.type || 'dependency'); });
    nodeLayer.draw();
    _updateMiniMap();
  };

  // ── Node Search ───────────────────────────────────────────
  var _searchQuery = '';
  var _searchMatches = [];
  var _searchOrigColors = {};

  function searchNodes(query) {
    _searchQuery = (query || '').trim().toLowerCase();
    var countEl = document.getElementById('brain-search-count');
    
    // Restore all nodes to original state if query is empty
    if (!_searchQuery) {
      for (var id in nodes) {
        var n = nodes[id];
        if (_searchOrigColors[id] !== undefined) {
          n.shape.opacity(1);
          n.group.opacity(1);
          // Restore original fill if we changed it
          if (_searchOrigColors[id]) n.shape.fill(_searchOrigColors[id]);
          delete _searchOrigColors[id];
        }
      }
      _searchMatches = [];
      if (countEl) countEl.textContent = '';
      nodeLayer.batchDraw();
      return;
    }
    
    // Find matching nodes
    _searchMatches = [];
    for (var id2 in nodes) {
      var n2 = nodes[id2];
      var label = (n2.group.getAttr('label') || id2).toLowerCase();
      var shortName = label.split('/').pop();
      if (id2.toLowerCase().indexOf(_searchQuery) >= 0 ||
          label.indexOf(_searchQuery) >= 0 ||
          shortName.indexOf(_searchQuery) >= 0) {
        _searchMatches.push(id2);
      }
    }
    
    // Dim non-matches, highlight matches
    for (var id3 in nodes) {
      var n3 = nodes[id3];
      var isMatch = _searchMatches.indexOf(id3) >= 0;
      // Save original opacity if not already saved
      if (_searchOrigColors[id3] === undefined) {
        _searchOrigColors[id3] = n3.shape.fill();
      }
      if (isMatch) {
        n3.shape.opacity(1);
        n3.group.opacity(1);
        // Make matched nodes glow — bright fill + larger
        n3.shape.fill('#E8920A');
        n3.shape.shadowColor('#E8920A');
        n3.shape.shadowBlur(12);
        n3.shape.shadowOpacity(0.8);
      } else {
        n3.shape.opacity(0.15);
        n3.group.opacity(0.15);
        n3.shape.shadowBlur(0);
      }
    }
    
    // Update edges: dim edges that don't connect to matches
    nodeLayer.children.forEach(function(child) {
      if (child.getClassName() === 'Line') {
        // Edge lines — check if connected to any match
        var pts = child.points();
        if (pts.length >= 4) {
          var connected = false;
          for (var mi = 0; mi < _searchMatches.length; mi++) {
            var mn = nodes[_searchMatches[mi]];
            if (mn && Math.abs(mn.x - pts[0]) < 2 && Math.abs(mn.y - pts[1]) < 2) connected = true;
            if (mn && Math.abs(mn.x - pts[2]) < 2 && Math.abs(mn.y - pts[3]) < 2) connected = true;
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
    
    // If exactly one match, zoom to it
    if (_searchMatches.length === 1) {
      var mn = nodes[_searchMatches[0]];
      if (mn) {
        stage.position({
          x: stage.width() / 2 - mn.x * stage.scaleX(),
          y: stage.height() / 2 - mn.y * stage.scaleY(),
        });
        stage.batchDraw();
        _updateMiniMap();
      }
    }
  }

  return { init, setNodeState, loadNodes, zoomIn, zoomOut, zoomReset, handleEvent, _relistenWs, switchView, toggleLabels, rotateGraph, resetRotation, exportPNG, exportJSON, searchNodes };
})();