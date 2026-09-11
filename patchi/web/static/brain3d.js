/**
 * brain3d.js — 3D Brain Map using Three.js
 *
 * Renders the file dependency graph as an interactive 3D scene.
 * Supports orbit, zoom, pan, node click, edge rendering, and multiple layouts.
 */

var BrainMap3D = (() => {
  let scene, camera, renderer, controls, nodeGroup, edgeGroup, dotGroup;
  // Live edge lines: {a, b, line} for the currently-drawn set, so the glide
  // can stretch their endpoints in place instead of rebuilding every frame.
  let _edgeLines = [];
  let raycaster, mouse;
  let _nodes3d = {}, _edges3d = [];
  let _lastNodes = [], _lastEdges = [];
  let _currentView = 'force3d';
  let _showLabels = true;
  let _showEdges = true;
  // Same rendered-node cap as the 2D renderer: only this many nodes get real
  // meshes + label textures; the rest are lightweight position-only entries so
  // edges still route through them without paying for geometry or textures.
  const MAX_RENDERED_NODES = 300;
  // Toggleable render cap — same contract as the 2D renderer (see canvas.js).
  var _renderCap3D = !(window._PATCHI_RENDER_CAP_OFF === true);
  // Adaptive cap — same contract as the 2D renderer (see canvas.js).
  var _adaptiveCap3D = (window._PATCHI_RENDER_CAP || MAX_RENDERED_NODES);
  function _nodeLimit3D(ns) {
    return _renderCap3D ? _adaptiveCap3D : (ns ? ns.length : MAX_RENDERED_NODES);
  }
  let _nodeLabels = [];
  let _animFrame = null;
  let _initialized = false;
  // Smooth transition state
  let _animTarget = null;    // {id: {x,y,z}} target positions
  let _animProgress = 0;     // 0..1
  let _animDuration = 0;     // ms
  let _animStart = 0;        // timestamp
  let _animActive = false;
  // Momentum / inertia state
  let _momentum = { vx: 0, vy: 0, active: false };
  let _lastMouse = null;
  let _mouseDownAt = null;
  let _isMouseDown = false;
  let _selectedId = null;   // currently selected node id (highlight + edge focus)
  let _selChip = null;      // DOM chip showing the selected file
  let _lastTap = null; // {x, y, time} for double-tap detection

  // Colors matching 2D palette
  const COLORS = {
    entry_point: 0x8B3A0F,
    route_handler: 0x7A2E08,
    component: 0x6B8B5A,
    config: 0x4A5030,
    test: 0x4ADE80,
    dead: 0x3D2A1A,
    restricted: 0x2C2010,
    sensitive: 0xFF8C42,
    default: 0xC8621A,
    critical: 0xFF4D6D,
    wounded: 0xFACC15,
    scanning: 0xE8920A,
    edge: 0x1E3014,
    edgeRoute: 0xf59e0b,
    edgeTest: 0x22c55e,
    edgeBlast: 0xf97316,
    edgeDead: 0x6b7280,
    bg: 0x0A1A0D,
  };

  function _nodeColor(type, findingCount, severity) {
    if (findingCount > 0) {
      if (severity === 'critical' || findingCount >= 5) return COLORS.critical;
      if (severity === 'high' || findingCount >= 3) return COLORS.wounded;
      return COLORS.scanning;
    }
    return COLORS[type] || COLORS.default;
  }

  // ── Touch gestures ────────────────────────────────────────
  let _rotateState = null; // {startAngle, startAzimuth, startPolar}
  let _pinchState = null;  // {startDist, startZoom, center}
  let _panState = null;    // {startX, startY, startTarget}
  let _threeFingerState = null; // {startX, startY, startTime}
  let _viewPresets = ['top', 'front', 'side'];
  let _currentPreset = -1; // index into _viewPresets, -1 = custom

  const VIEW_PRESET_POSITIONS = {
    top:  { pos: [0, 900, 0.1],   up: [0, 0, -1] },   // Bird's eye
    front: { pos: [0, 0, 800],    up: [0, 1, 0] },    // Head-on
    side:  { pos: [800, 100, 0],  up: [0, 1, 0] },    // Profile
  };

  function _touchAngle(t1, t2) {
    return Math.atan2(t2.clientY - t1.clientY, t2.clientX - t1.clientX);
  }

  function _touchDist(t1, t2) {
    var dx = t2.clientX - t1.clientX;
    var dy = t2.clientY - t1.clientY;
    return Math.sqrt(dx*dx + dy*dy);
  }

  function _touchCenter(t1, t2) {
    return {
      x: (t1.clientX + t2.clientX) / 2,
      y: (t1.clientY + t2.clientY) / 2
    };
  }

  function _animateCamera(targetPos, targetUp, duration) {
    if (!camera || !controls) return;
    var startPos = camera.position.clone();
    var startUp = camera.up.clone();
    var endPos = new THREE.Vector3(targetPos[0], targetPos[1], targetPos[2]);
    var endUp = new THREE.Vector3(targetUp[0], targetUp[1], targetUp[2]);
    var startTime = performance.now();

    function _step(now) {
      var t = Math.min((now - startTime) / duration, 1);
      // Ease out cubic
      var ease = 1 - Math.pow(1 - t, 3);
      camera.position.lerpVectors(startPos, endPos, ease);
      camera.up.lerpVectors(startUp, endUp, ease);
      camera.lookAt(controls.target);
      controls.update();
      if (t < 1) requestAnimationFrame(_step);
    }
    requestAnimationFrame(_step);
  }

  function _showPresetIndicator(name) {
    // Flash a brief indicator on the 3D canvas
    var container = document.getElementById('brain-map-3d');
    if (!container) return;
    var existing = container.querySelector('.preset-indicator');
    if (existing) existing.remove();
    var el = document.createElement('div');
    el.className = 'preset-indicator brain-preset-toast';
    el.textContent = name.charAt(0).toUpperCase() + name.slice(1) + ' View';
    container.appendChild(el);
    setTimeout(function() { el.style.opacity = '0'; }, 800);
    setTimeout(function() { el.remove(); }, 1300);
  }

  // ── Momentum / inertia ───────────────────────────────────
  function _setupMomentum(el) {
    el.addEventListener('mousedown', function(e) {
      _isMouseDown = true;
      _lastMouse = { x: e.clientX, y: e.clientY, t: performance.now() };
      _mouseDownAt = { x: e.clientX, y: e.clientY };
      _momentum.active = false;
    });
    el.addEventListener('mousemove', function(e) {
      if (!_isMouseDown || !_lastMouse) return;
      var now = performance.now();
      var dt = now - _lastMouse.t;
      if (dt > 0) {
        _momentum.vx = (e.clientX - _lastMouse.x) / dt * 16; // normalize to ~60fps
        _momentum.vy = (e.clientY - _lastMouse.y) / dt * 16;
      }
      _lastMouse = { x: e.clientX, y: e.clientY, t: now };
    });
    el.addEventListener('mouseup', function(e) {
      _isMouseDown = false;
      // A click (not an orbit/pan drag) is a press+release within ~6px.
      var wasClick = false;
      if (_mouseDownAt) {
        var dx = e.clientX - _mouseDownAt.x, dy = e.clientY - _mouseDownAt.y;
        wasClick = (dx * dx + dy * dy) <= 36;
      }
      _lastMouse = null;
      _mouseDownAt = null;
      // Activate momentum if velocity is significant
      if (Math.abs(_momentum.vx) > 0.5 || Math.abs(_momentum.vy) > 0.5) {
        _momentum.active = true;
      }
      if (wasClick) _pick(e.clientX, e.clientY);
    });
    el.addEventListener('mouseleave', function() {
      _isMouseDown = false;
      _lastMouse = null;
      _mouseDownAt = null;
    });
    el.addEventListener('mouseleave', function() {
      _isMouseDown = false;
      _lastMouse = null;
    });
    // Touch momentum
    el.addEventListener('touchstart', function(e) {
      if (e.touches.length === 1) {
        _lastMouse = { x: e.touches[0].clientX, y: e.touches[0].clientY, t: performance.now() };
        _momentum.active = false;
      }
    }, { passive: true });
    el.addEventListener('touchmove', function(e) {
      if (e.touches.length !== 1 || !_lastMouse) return;
      var now = performance.now();
      var dt = now - _lastMouse.t;
      if (dt > 0) {
        _momentum.vx = (e.touches[0].clientX - _lastMouse.x) / dt * 16;
        _momentum.vy = (e.touches[0].clientY - _lastMouse.y) / dt * 16;
      }
      _lastMouse = { x: e.touches[0].clientX, y: e.touches[0].clientY, t: now };
    }, { passive: true });
    el.addEventListener('touchend', function(e) {
      if (e.touches.length === 0) {
        _lastMouse = null;
        if (Math.abs(_momentum.vx) > 0.5 || Math.abs(_momentum.vy) > 0.5) {
          _momentum.active = true;
        }
      }
    }, { passive: true });
  }

  function _applyMomentum() {
    // OrbitControls with enableDamping already provides inertia. The old
    // manual spherical-rotation here fought OrbitControls (double-rotate per
    // frame), so it is now a no-op that just decays the tracked velocity
    // used for click-vs-drag detection.
    if (!_momentum.active) return;
    _momentum.vx *= 0.9;
    _momentum.vy *= 0.9;
    if (Math.abs(_momentum.vx) < 0.01 && Math.abs(_momentum.vy) < 0.01) {
      _momentum.active = false;
    }
  }

  function _setupKeyboardNav(el) {
    // Arrows/WASD pan, +/- zoom, 0 reset — mirrors the 2D map's keyboard.
    if (!el || el._kbdWired) return;
    el._kbdWired = true;
    el.tabIndex = el.tabIndex || 0;
    el.addEventListener('keydown', function(e) {
      if (!camera || !controls) return;
      var step = camera.position.distanceTo(controls.target) * 0.08;
      var fwd = new THREE.Vector3().copy(camera.position).sub(controls.target).normalize();
      var right = new THREE.Vector3().crossVectors(fwd, camera.up).normalize();
      var up = new THREE.Vector3().crossVectors(right, fwd).normalize();
      var moved = true;
      switch (e.key) {
        case 'ArrowLeft': case 'a': case 'A':
          controls.target.addScaledVector(right, -step); break;
        case 'ArrowRight': case 'd': case 'D':
          controls.target.addScaledVector(right, step); break;
        case 'ArrowUp': case 'w': case 'W':
          controls.target.addScaledVector(up, step); break;
        case 'ArrowDown': case 's': case 'S':
          controls.target.addScaledVector(up, -step); break;
        case '+': case '=':
          camera.position.addScaledVector(fwd, -step); break;
        case '-': case '_':
          camera.position.addScaledVector(fwd, step); break;
        case '0':
          resetCamera(); break;
        default: moved = false;
      }
      if (moved) {
        e.preventDefault();
        _stopCameraFit();
        controls.update();
      }
    });
  }

  function _setupTouchRotate(el) {
    el.addEventListener('touchstart', function(e) {
      // Double-tap: reset camera
      if (e.touches.length === 1) {
        var t = e.touches[0];
        var now = Date.now();
        if (_lastTap && (now - _lastTap.time) < 300) {
          var dist = Math.hypot(t.clientX - _lastTap.x, t.clientY - _lastTap.y);
          if (dist < 30) {
            // Double-tap detected — reset camera with animation
            _lastTap = null;
            _animateCamera([0, 0, 800], [0, 1, 0], 400);
            if (controls) controls.reset();
            _showPresetIndicator('reset');
            return;
          }
        }
        _lastTap = { x: t.clientX, y: t.clientY, time: now };
      }
      // Three-finger swipe: track start position
      if (e.touches.length === 3) {
        var cx = (e.touches[0].clientX + e.touches[1].clientX + e.touches[2].clientX) / 3;
        var cy = (e.touches[0].clientY + e.touches[1].clientY + e.touches[2].clientY) / 3;
        _threeFingerState = { startX: cx, startY: cy, startTime: Date.now() };
        return;
      }
      // Two fingers: let OrbitControls handle pinch-zoom + pan natively
      // (the old manual pinch/pan/rotate here double-applied every gesture).
      if (e.touches.length === 2) {
        _pinchState = null;
        _panState = null;
        _rotateState = null;
      }
    }, { passive: false }); // Need passive: false to preventDefault for pinch

    el.addEventListener('touchmove', function(e) {
      // Two-finger gestures are handled natively by OrbitControls
      // (TWO: DOLLY_PAN). No manual handling — it used to double-zoom.
      if (e.touches.length === 3) return;
    }, { passive: true });

    el.addEventListener('touchend', function(e) {
      // Three-finger swipe: detect horizontal direction
      if (_threeFingerState && e.touches.length === 0) {
        var cx = (e.changedTouches[0].clientX);
        var dx = cx - _threeFingerState.startX;
        var dt = Date.now() - _threeFingerState.startTime;
        _threeFingerState = null;
        // Quick horizontal swipe (> 50px in < 500ms)
        if (Math.abs(dx) > 50 && dt < 500) {
          // Cycle through presets: swipe left = next, swipe right = prev
          if (dx < 0) {
            _currentPreset = (_currentPreset + 1) % _viewPresets.length;
          } else {
            _currentPreset = (_currentPreset - 1 + _viewPresets.length) % _viewPresets.length;
          }
          var presetName = _viewPresets[_currentPreset];
          var preset = VIEW_PRESET_POSITIONS[presetName];
          _animateCamera(preset.pos, preset.up, 600);
          _showPresetIndicator(presetName);
        }
      }
      // Cleanup two-finger states (OrbitControls owns the gesture now)
      if (e.touches.length < 2) {
        _pinchState = null;
        _panState = null;
        _rotateState = null;
      }
    }, { passive: true });
  }

// ── Capped-dot selection ─────────────────────────────────
  // Capped dots are tiny and dim; clicking one selects the file it represents
  // (like clicking any rendered node), highlighting its edges so its role in
  // the graph is visible even though it never got a full node sprite.

  function _selEdgesOf(id) {
    var set = {};
    var count = 0;
    _lastEdges.forEach(function(e) {
      var f = e.source || e.from, t = e.target || e.to;
      if (f === id || t === id) { set[f + '>' + t] = true; count++; }
    });
    return { set: set, count: count };
  }

  function _entry(id) { return _nodes3d[id] || null; }

  function _isCapped(id) {
    var en = _entry(id);
    return !!(en && (en.dot || (en.userData && en.userData.dot)));
  }

  function _setMeshDim(mesh, dim) {
    if (!mesh || !mesh.material) return;
    if (dim) {
      if (mesh._origOpacity === undefined) mesh._origOpacity = mesh.material.opacity;
      mesh.material.opacity = 0.10;
      mesh.material.transparent = true;
    } else {
      if (mesh._origOpacity !== undefined) mesh.material.opacity = mesh._origOpacity;
    }
  }

  function _clearChip() {
    if (_selChip && _selChip.parentNode) _selChip.parentNode.removeChild(_selChip);
    _selChip = null;
  }

  function _showChip(id, entry, edgeCount) {
    _clearChip();
    var container = document.getElementById('brain-map-3d');
    if (!container) return;
    var label = (entry && (entry.label || (entry.userData && entry.userData.label))) ||
                (id) || '';
    var short = String(label).split('/').pop();
    var chip = document.createElement('div');
    chip.className = 'brain-sel-chip';
    var dotStyle = _isCapped(id) ? 'brain-sel-chip-dot' : 'brain-sel-chip-node';
    chip.innerHTML =
      '<span class="' + dotStyle + '" aria-hidden="true"></span>' +
      '<span class="brain-sel-chip-name" title="' + (label || '').replace(/"/g, '&quot;') + '">' + short + '</span>' +
      '<span class="brain-sel-chip-meta">' + edgeCount + ' edge' + (edgeCount === 1 ? '' : 's') + '</span>' +
      '<span class="brain-sel-chip-x" title="Clear selection (Esc)" aria-label="Clear selection">✕</span>';
    container.appendChild(chip);
    _selChip = chip;
    var x = chip.querySelector('.brain-sel-chip-x');
    if (x) x.addEventListener('click', function(ev) {
      ev.stopPropagation();
      clearSelection();
    });
    chip.addEventListener('dblclick', function() { clearSelection(); });
  }

  function selectNode(id, opts) {
    opts = opts || {};
    if (!_entry(id)) { if (opts.silent) return; clearSelection(); return; }
    _selectedId = id;

    // Dim non-selected nodes/dots, restore + spotlight the selected one.
    nodeGroup.children.forEach(function(c) {
      if (c.isMesh) {
        if (c.userData && c.userData.id !== id) _setMeshDim(c, true);
        else if (c.userData && c.userData.id === id) _setMeshDim(c, false);
      }
    });
    if (dotGroup) dotGroup.children.forEach(function(c) {
      if (c.userData && c.userData.id !== id) _setMeshDim(c, true);
      else if (c.userData && c.userData.id === id) _setMeshDim(c, false);
    });
    // Dots at the far end of a highlighted edge pop so endpoints stay visible.
    _applyDotHighlight();

    // Connected edges stand out; unrelated ones are suppressed by _rebuildEdges.
    var sel = _selEdgesOf(id);
    _rebuildEdges();

    var en = _entry(id);
    _showChip(id, en, sel.count);

    if (window.hideBrainTooltip) window.hideBrainTooltip();
    // Keep the selected entry on screen when the graph shifts.
    focusNode(id);
    return sel.count;
  }

  function clearSelection() {
    _selectedId = null;
    nodeGroup.children.forEach(function(c) {
      if (c.isMesh) _setMeshDim(c, false);
    });
    if (dotGroup) dotGroup.children.forEach(function(c) {
      if (c.isMesh) _setMeshDim(c, false);
    });
    _applyDotHighlight();  // re-raise dots for an active search, if any
    _clearChip();
    if (_showEdges) _rebuildEdges();
  }

  function _pick(clientX, clientY) {
    if (!scene || !camera || !raycaster) return;
    var el = renderer && renderer.domElement;
    if (!el) return;
    var rect = el.getBoundingClientRect();
    if (rect.width === 0) return;
    mouse.x = ((clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(mouse, camera);
    var pickables = [];
    nodeGroup.children.forEach(function(c) { if (c.isMesh) pickables.push(c); });
    if (dotGroup) dotGroup.children.forEach(function(c) { pickables.push(c); });
    var hits = raycaster.intersectObjects(pickables, false);
    var picked = null;
    for (var i = 0; i < hits.length; i++) {
      var ud = hits[i].object.userData;
      if (ud && ud.id) { picked = ud.id; break; }
    }
    if (picked) {
      selectNode(picked);
    } else {
      clearSelection();
    }
  }

  function init(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    if (_initialized) destroy();
    _initialized = true;

    const W = el.clientWidth || 800;
    const H = el.clientHeight || 400;

    // Scene
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0d1117);

    // Camera
    camera = new THREE.PerspectiveCamera(60, W / H, 1, 25000);
    camera.position.set(0, 0, 800);

    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x0d1117);

    var container = document.getElementById('brain-map-3d');
    if (container) {
      container.innerHTML = '';
      container.appendChild(renderer.domElement);
    }

    // OrbitControls — full touch support with momentum
    if (typeof THREE.OrbitControls !== 'undefined') {
      controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.05; // lower = more momentum
      controls.rotateSpeed = 0.8;
      controls.zoomSpeed = 1.2;
      controls.panSpeed = 0.8;
      controls.minDistance = 50;
      controls.maxDistance = 12000;
      // Custom angular velocity tracking for extra spin
      _setupMomentum(renderer.domElement);
      // Explicit touch configuration
      controls.touches = {
        ONE: THREE.TOUCH.ROTATE,
        TWO: THREE.TOUCH.DOLLY_PAN,
      };
      controls.enableRotate = true;
      controls.enableZoom = true;
      controls.enablePan = true;
      controls.enableKeys = true;
      try {
        if (controls.listenToKeyEvents) controls.listenToKeyEvents(renderer.domElement);
      } catch (_) {}
      // User interaction cancels a pending/active zoom-to-fit so the camera
      // never fights the mouse/touch.
      controls.addEventListener('start', _stopCameraFit);
      // Prevent default touch actions on the canvas
      renderer.domElement.style.touchAction = 'none';
      // Two-finger rotate gesture
      _setupTouchRotate(renderer.domElement);
      // NOTE: wheel zoom is handled by OrbitControls itself. A custom wheel
      // handler here used to double-zoom every scroll, so it was removed.
      _setupKeyboardNav(renderer.domElement);
    }

    // Groups
    nodeGroup = new THREE.Group();
    edgeGroup = new THREE.Group();
    dotGroup = new THREE.Group();  // tiny dim dots for capped-out nodes
    scene.add(nodeGroup);
    scene.add(edgeGroup);
    scene.add(dotGroup);

    // Lights
    var ambient = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambient);
    var dir1 = new THREE.DirectionalLight(0xffffff, 0.8);
    dir1.position.set(200, 400, 300);
    scene.add(dir1);
    var dir2 = new THREE.DirectionalLight(0x58a6ff, 0.4);
    dir2.position.set(-200, -100, -200);
    scene.add(dir2);

    // Raycaster for click
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    // Hover tooltip — raycast nodes and their labels so the full filename
    // shows at the cursor (drawn labels are truncated basenames).
    var hoverLastPick = 0;
    var hoverEl = renderer.domElement;
    hoverEl.addEventListener('mousemove', function(e) {
      if (_isMouseDown) return;               // orbiting / panning
      var now = performance.now();
      if (now - hoverLastPick < 50) return;   // throttle to ~20fps
      hoverLastPick = now;
      var rect = hoverEl.getBoundingClientRect();
      if (rect.width === 0) return;
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(mouse, camera);
      // Raycast rendered nodes AND capped-out dots (both carry userData.id).
      var pickables = [];
      nodeGroup.children.forEach(function(c) { if (c.isMesh) pickables.push(c); });
      if (dotGroup) dotGroup.children.forEach(function(c) { pickables.push(c); });
      var hits = raycaster.intersectObjects(pickables, false);
      var hitLabel = null;
      for (var i = 0; i < hits.length; i++) {
        var ud = hits[i].object.userData;
        if (ud && ud.id) {
          // Dots are dim by design; prefix the tooltip so it's clear this is a
          // capped file (no label sprite) vs a rendered node. When the file
          // has findings, append the count + top severity so risk is visible
          // at a glance. Rendered nodes carry findings/severity on userData;
          // dots keep the full node record on userData.node.
          var fc = ud.dot ? (ud.node && (ud.node.finding_count || 0)) : (ud.findings || 0);
          var sev = ud.dot ? (ud.node && ud.node.severity) : ud.severity;
          hitLabel = (ud.dot ? 'capped · ' : '') + (ud.label || ud.id);
          var hitColor = null;
          if (fc > 0) {
            hitLabel += '\n\u26a0 ' + fc + ' finding' + (fc === 1 ? '' : 's') + ' · ' + (sev || 'info');
            hitColor = _healthColor(fc, sev);  // matches the node mesh's own color
          }
          break;
        }
      }
      if (hitLabel) {
        if (window.showBrainTooltip) window.showBrainTooltip(hitLabel, e.clientX, e.clientY, hitColor);
      } else if (window.hideBrainTooltip) {
        window.hideBrainTooltip();
      }
    });
    hoverEl.addEventListener('mouseleave', function() {
      if (window.hideBrainTooltip) window.hideBrainTooltip();
    });

    // Grid helper (subtle)
    var gridHelper = new THREE.GridHelper(1200, 30, 0x21262d, 0x161b22);
    gridHelper.position.y = -300;
    scene.add(gridHelper);

    // Resize handler — window resize plus container size changes (e.g. the
    // full-screen toggle, which swaps layout without resizing the window).
    window.addEventListener('resize', _onResize);
    if (typeof ResizeObserver !== 'undefined' && container) {
      try { new ResizeObserver(_onResize).observe(container); } catch (e) {}
    }

    _initialized = true;
    _animate();
  }

  function _onResize() {
    var container = document.getElementById('brain-map-3d');
    if (!container || !camera || !renderer) return;
    var w = container.clientWidth, h = container.clientHeight;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
  }

  function _animate() {
    _animFrame = requestAnimationFrame(_animate);
    _tickTransition();
    _tickCameraFit();
    _applyMomentum();
    if (controls) controls.update();
    renderer.render(scene, camera);
  }

  function _healthColor(findingCount, severity) {
    if (findingCount === 0) return null;
    if (severity === 'critical' || findingCount >= 5) return COLORS.critical;
    if (severity === 'high' || findingCount >= 3) return COLORS.wounded;
    return COLORS.scanning;
  }

  // ── Label truncation (same strategy as the 2D renderer) ────
  // Measures text at the label font size and trims with '…' so long filenames
  // fit the 240px texture budget instead of being hard-cut at 20 chars.
  var _labelProbeCtx = null;
  function _labelProbe() {
    if (!_labelProbeCtx) {
      var c = document.createElement('canvas');
      c.width = 256;
      c.height = 64;
      _labelProbeCtx = c.getContext('2d');
      _labelProbeCtx.font = '24px Inter, sans-serif';
    }
    return _labelProbeCtx;
  }
  function _measureLabelWidth3D(txt) {
    return _labelProbe().measureText(txt).width || 0;
  }
  function _truncateLabel3D(name, maxW) {
    if (!name) return name;
    if (_measureLabelWidth3D(name) <= maxW) return name;
    var ell = '…';
    var ellW = _measureLabelWidth3D(ell);
    var budget = Math.max(1, maxW - ellW);
    var lo = 1, hi = name.length, best = 1;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (_measureLabelWidth3D(name.slice(0, mid)) <= budget) { best = mid; lo = mid + 1; }
      else { hi = mid - 1; }
    }
    return name.slice(0, best) + ell;
  }

  function _addNode3D(id, label, type, x, y, z, findingCount, severity) {
    var color = COLORS[type] || COLORS.default;
    var hc = _healthColor(findingCount, severity);
    if (hc) color = hc;

    // Scale node size by finding count: more findings = bigger node.
    // Kept small on purpose — the old 5 + fc*0.65 growth made dense graphs
    // collapse into one emissive blob.
    var fc = findingCount || 0;
    var radius = 4 + Math.min(fc, 20) * 0.35;
    // Severity boosts size further
    if (severity === 'critical') radius *= 1.25;
    else if (severity === 'high') radius *= 1.12;
    // Resolution scales with size for smooth look
    var segments = radius > 10 ? 24 : 16;
    var geometry = new THREE.SphereGeometry(radius, segments, Math.max(12, segments - 4));
    // Emissive intensity scales with findings for glow effect
    var emissiveStrength = 0.12 + Math.min(fc, 15) * 0.025;
    var material = new THREE.MeshPhongMaterial({
      color: color,
      emissive: new THREE.Color(color).multiplyScalar(emissiveStrength),
      shininess: 40 + Math.min(fc, 15) * 3,
      transparent: true,
      opacity: 0.78 + Math.min(fc, 10) * 0.008,
    });
    var mesh = new THREE.Mesh(geometry, material);
    mesh.position.set(x, y, z);
    mesh.userData = { id: id, label: label, type: type, findings: findingCount, severity: severity, radius: radius };
    nodeGroup.add(mesh);
    _nodes3d[id] = mesh;

    // Label — positioned above the scaled node
    if (_showLabels) {
      var canvas = document.createElement('canvas');
      canvas.width = 256;
      canvas.height = 64;
      var ctx = canvas.getContext('2d');
      ctx.fillStyle = '#e6edf3';
      ctx.font = '24px Inter, sans-serif';
      ctx.textAlign = 'center';
      var shortLabel = label.split('/').pop();
      ctx.fillText(_truncateLabel3D(shortLabel, 240), 128, 40);
      var texture = new THREE.CanvasTexture(canvas);
      var spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true, opacity: 0.8 });
      var sprite = new THREE.Sprite(spriteMat);
      sprite.position.set(x, y + radius + 10, z);
      sprite.scale.set(80, 20, 1);
      sprite.userData = { id: id, label: label };
      nodeGroup.add(sprite);
      _nodeLabels.push(sprite);
    }
  }

  function _dotHasHighlightedEdge(id) {
    // True when the capped file's edges are highlighted: it IS the selected
    // file, it shares an edge with the selected file, or (during search) one
    // of its neighbors is a match.
    if (_selectedId) {
      if (id === _selectedId) return true;
      for (var i = 0; i < _lastEdges.length; i++) {
        var e = _lastEdges[i];
        var f = e.source || e.from, t = e.target || e.to;
        if ((f === id && t === _selectedId) || (t === id && f === _selectedId)) return true;
      }
      return false;
    }
    if (_searchActiveIds) {
      for (var j = 0; j < _lastEdges.length; j++) {
        var e2 = _lastEdges[j];
        var f2 = e2.source || e2.from, t2 = e2.target || e2.to;
        if ((f2 === id && _searchActiveIds[t2]) || (t2 === id && _searchActiveIds[f2])) return true;
      }
    }
    return false;
  }

  function _applyDotHighlight() {
    // Dots whose edges are highlighted pop to near-full opacity so the edge
    // endpoint is visible. During selection every other dot stays dimmed at
    // 0.10; otherwise (search / plain restore) dots return to their base.
    if (!dotGroup) return;
    dotGroup.children.forEach(function(c) {
      if (!c.isMesh || !c.userData || !c.userData.id) return;
      if (_dotHasHighlightedEdge(c.userData.id)) {
        if (c._origOpacity === undefined) c._origOpacity = c.material.opacity;
        c.material.opacity = 0.8;
        c.material.transparent = true;
      } else if (_selectedId) {
        if (c._origOpacity === undefined) c._origOpacity = c.material.opacity;
        c.material.opacity = 0.10;
        c.material.transparent = true;
      } else if (c._origOpacity !== undefined) {
        c.material.opacity = c._origOpacity;
      }
    });
  }

  function _isDotEntry(entry) {
    return !!(entry && entry.dot);
  }

  function _addEdge3D(from, to, type) {
    if (!_nodes3d[from] || !_nodes3d[to]) return;
    // Skip edges where BOTH endpoints are capped dots (mirrors the 2D
    // renderer's `if (!fromRendered && !toRendered) continue`) — otherwise
    // faint lines float between near-invisible dots.
    if (_isDotEntry(_nodes3d[from]) && _isDotEntry(_nodes3d[to])) return;
    // Highlight edges touching the selection/match; suppress unrelated edges
    // during selection; fade non-match edges during search.
    var highlighted = false;
    if (_selectedId) {
      highlighted = from === _selectedId || to === _selectedId;
      if (!highlighted) return;  // suppress unrelated edges
    } else if (_searchActiveIds) {
      highlighted = !!(_searchActiveIds[from] || _searchActiveIds[to]);
    }
    var fromEntry = _nodes3d[from];
    var toEntry = _nodes3d[to];
    var fromPos = fromEntry.position;
    var toPos = toEntry.position;

    var color = COLORS.edge;
    if (type === 'route_connection') color = COLORS.edgeRoute;
    else if (type === 'test_coverage') color = COLORS.edgeTest;
    else if (type === 'blast_radius') color = COLORS.edgeBlast;

    // Offset endpoints by the source/target mesh radius so lines start at the
    // sphere surface instead of piercing through the node center.
    var a = fromPos.clone ? fromPos.clone() : new THREE.Vector3(fromPos.x, fromPos.y, fromPos.z);
    var b = toPos.clone ? toPos.clone() : new THREE.Vector3(toPos.x, toPos.y, toPos.z);
    var dir = new THREE.Vector3().subVectors(b, a);
    var len = dir.length();
    if (len > 1e-6) {
      dir.normalize();
      var ra = (fromEntry.userData && fromEntry.userData.radius) || 0;
      var rb = (toEntry.userData && toEntry.userData.radius) || 0;
      if (ra > 0 && len > ra + 1) a.addScaledVector(dir, Math.min(ra * 0.9, len * 0.4));
      if (rb > 0 && len > rb + 1) b.addScaledVector(dir, -Math.min(rb * 0.9, len * 0.4));
    }

    var geometry = new THREE.BufferGeometry().setFromPoints([a, b]);
    // Highlighted edges render brighter + more opaque so the file's role pops.
    var material = new THREE.LineBasicMaterial({
      color: color,
      transparent: true,
      opacity: highlighted ? 0.9 : (_searchActiveIds ? 0.15 : 0.3),
    });
    var line = new THREE.Line(geometry, material);
    if (highlighted) {
      line.material.linewidth = 2;  // best-effort (WebGL caps at 1 on most GPUs)
      // Slight bloom-ish boost: nothing more available without postprocessing,
      // so brightness comes from opacity + color already being vivid.
    }
    edgeGroup.add(line);
    // Two-point lines: register for in-place endpoint updates during glides.
    // Culling needs the geometry's bounding sphere, which goes stale once we
    // move vertices in place — these lines span the scene anyway, so skip it.
    line.frustumCulled = false;
    _edgeLines.push({ a: from, b: to, line: line });
  }

  // ── Layout algorithms (3D-optimized) ──────────────────────

  function _forceLayout3D(nodesList, edgesList) {
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    // Scale the spawn sphere with graph size so large graphs don't start
    // as one overlapping blob.
    var r = 350 * Math.max(1, Math.cbrt(n / 120));
    // Initialize in fibonacci sphere for even distribution
    nodesList.forEach(function(node, i) {
      var phi = Math.acos(1 - 2 * (i + 0.5) / n);
      var theta = Math.PI * (1 + Math.sqrt(5)) * i;
      pos[node.id || node.path] = {
        x: r * Math.cos(theta) * Math.sin(phi),
        y: r * Math.sin(theta) * Math.sin(phi),
        z: r * Math.cos(phi),
        vx: 0, vy: 0, vz: 0,
      };
    });
    // Build adjacency
    var adj = {};
    edgesList.forEach(function(e) {
      var f = e.from || e.source, t = e.to || e.target;
      if (!adj[f]) adj[f] = []; adj[f].push(t);
      if (!adj[t]) adj[t] = []; adj[t].push(f);
    });
    // Force simulation with 3D physics
    var repulsion = 40000, attraction = 0.003, damping = 0.85, centerPull = 0.008;
    for (var iter = 0; iter < 40; iter++) {
      var keys = Object.keys(pos);
      // Repulsion between all pairs
      for (var i = 0; i < keys.length; i++) {
        for (var j = i + 1; j < keys.length; j++) {
          var a = pos[keys[i]], b = pos[keys[j]];
          var dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
          var dist = Math.sqrt(dx*dx + dy*dy + dz*dz) || 1;
          var force = repulsion / (dist * dist);
          var fx = (dx/dist)*force, fy = (dy/dist)*force, fz = (dz/dist)*force;
          a.vx += fx; a.vy += fy; a.vz += fz;
          b.vx -= fx; b.vy -= fy; b.vz -= fz;
        }
      }
      // Attraction along edges
      edgesList.forEach(function(e) {
        var a = pos[e.from||e.source], b = pos[e.to||e.target];
        if (!a||!b) return;
        var dx = b.x-a.x, dy = b.y-a.y, dz = b.z-a.z;
        var dist = Math.sqrt(dx*dx+dy*dy+dz*dz)||1;
        var force = dist * attraction;
        a.vx += (dx/dist)*force; a.vy += (dy/dist)*force; a.vz += (dz/dist)*force;
        b.vx -= (dx/dist)*force; b.vy -= (dy/dist)*force; b.vz -= (dz/dist)*force;
      });
      // Apply with damping + center pull
      Object.values(pos).forEach(function(p) {
        p.vx += (0 - p.x) * centerPull;
        p.vy += (0 - p.y) * centerPull;
        p.vz += (0 - p.z) * centerPull;
        p.vx *= damping; p.vy *= damping; p.vz *= damping;
        p.x += p.vx * 0.5; p.y += p.vy * 0.5; p.z += p.vz * 0.5;
      });
    }
    // Clean velocity fields
    Object.values(pos).forEach(function(p) { delete p.vx; delete p.vy; delete p.vz; });
    return pos;
  }

  function _treeLayout3D(nodesList, edgesList) {
    // 3D tree: root at center, branches radiate outward and upward in 3D
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
      return !(incoming[node.id || node.path] || []).length;
    });
    if (roots.length === 0) roots = [nodesList[0]];

    // BFS to assign depth
    var depth = {}, visited = {}, queue = [];
    roots.forEach(function(node) { var id = node.id || node.path; depth[id] = 0; visited[id] = true; queue.push(id); });
    while (queue.length > 0) {
      var curr = queue.shift();
      (adj[curr] || []).forEach(function(child) {
        if (!visited[child]) { visited[child] = true; depth[child] = (depth[curr] || 0) + 1; queue.push(child); }
      });
    }
    nodesList.forEach(function(node) { var id = node.id || node.path; if (depth[id] === undefined) depth[id] = 0; });
    var maxDepth = 1;
    nodesList.forEach(function(node) { var d = depth[node.id || node.path]; if (d > maxDepth) maxDepth = d; });

    // Group by depth, position in expanding 3D cone
    var rings = {};
    nodesList.forEach(function(node) {
      var id = node.id || node.path, d = depth[id];
      if (!rings[d]) rings[d] = [];
      rings[d].push(id);
    });
    for (var d = 0; d <= maxDepth; d++) {
      var ring = rings[d] || [];
      var y = (d / maxDepth) * 600 - 300; // vertical spread
      var ringR = 80 + d * 60; // expanding radius
      ring.forEach(function(id, i) {
        var angle = (2 * Math.PI * i) / ring.length;
        pos[id] = {
          x: ringR * Math.cos(angle),
          y: y,
          z: ringR * Math.sin(angle)
        };
      });
    }
    return pos;
  }

  function _spiralLayout3D(nodesList) {
    // 3D spiral: double helix (DNA-like) with alternating strands
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var turns = Math.max(3, Math.ceil(n / 30));
    var height = 700;
    var radius = 200;
    nodesList.forEach(function(node, i) {
      var id = node.id || node.path;
      var t = i / n;
      var angle = t * turns * 2 * Math.PI;
      var y = (t - 0.5) * height;
      // Alternate between two strands
      var strand = i % 2 === 0 ? 0 : Math.PI;
      var r = radius + Math.sin(t * Math.PI * 4) * 40; // slight wobble
      pos[id] = {
        x: r * Math.cos(angle + strand),
        y: y,
        z: r * Math.sin(angle + strand)
      };
    });
    return pos;
  }

  function _helixLayout3D(nodesList) {
    // Triple helix — three intertwined spirals
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var strands = 3;
    var turns = Math.max(4, Math.ceil(n / 20));
    var height = 800;
    var radius = 180;
    // Group by type into strands
    var strandGroups = {};
    nodesList.forEach(function(node, i) {
      var strand = i % strands;
      if (!strandGroups[strand]) strandGroups[strand] = [];
      strandGroups[strand].push(node);
    });
    Object.keys(strandGroups).forEach(function(si) {
      var strand = parseInt(si);
      var group = strandGroups[strand];
      var offset = (strand / strands) * 2 * Math.PI;
      group.forEach(function(node, i) {
        var id = node.id || node.path;
        var t = i / group.length;
        var angle = t * turns * 2 * Math.PI + offset;
        var y = (t - 0.5) * height;
        pos[id] = {
          x: radius * Math.cos(angle),
          y: y,
          z: radius * Math.sin(angle)
        };
      });
    });
    return pos;
  }

  function _sphereLayout3D(nodesList) {
    // Fibonacci sphere — perfectly evenly distributed on sphere surface
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var goldenRatio = (1 + Math.sqrt(5)) / 2;
    var radius = 350;
    nodesList.forEach(function(node, i) {
      var id = node.id || node.path;
      var theta = 2 * Math.PI * i / goldenRatio;
      var phi = Math.acos(1 - 2 * (i + 0.5) / n);
      pos[id] = {
        x: radius * Math.cos(theta) * Math.sin(phi),
        y: radius * Math.sin(theta) * Math.sin(phi),
        z: radius * Math.cos(phi)
      };
    });
    return pos;
  }

  function _clusterLayout3D(nodesList, edgesList) {
    // Group nodes by type, place each cluster as a sphere in 3D
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var groups = {};
    nodesList.forEach(function(node) {
      var t = node.type || 'default';
      if (!groups[t]) groups[t] = [];
      groups[t].push(node.id || node.path);
    });
    var types = Object.keys(groups);
    var numGroups = types.length;
    var goldenRatio = (1 + Math.sqrt(5)) / 2;
    var clusterR = 300;
    types.forEach(function(type, gi) {
      var phi = Math.acos(1 - 2 * (gi + 0.5) / numGroups);
      var theta = 2 * Math.PI * gi / goldenRatio;
      var cx = clusterR * Math.cos(theta) * Math.sin(phi);
      var cy = clusterR * Math.sin(theta) * Math.sin(phi);
      var cz = clusterR * Math.cos(phi);
      var ids = groups[type];
      var cn = ids.length;
      var subR = Math.min(140, 40 + cn * 2.5);
      ids.forEach(function(id, i) {
        if (cn === 1) { pos[id] = { x: cx, y: cy, z: cz }; return; }
        var p2 = Math.acos(1 - 2 * (i + 0.5) / cn);
        var t2 = 2 * Math.PI * i / goldenRatio;
        pos[id] = {
          x: cx + subR * Math.cos(t2) * Math.sin(p2),
          y: cy + subR * Math.sin(t2) * Math.sin(p2),
          z: cz + subR * Math.cos(p2)
        };
      });
    });
    return pos;
  }

  function _gridLayout3D(nodesList) {
    // 3D grid: nodes placed on a volumetric grid with depth layers
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    var cols = Math.ceil(Math.cbrt(n));
    var spacing = 45;
    var offset = (cols - 1) * spacing / 2;
    nodesList.forEach(function(node, i) {
      var id = node.id || node.path;
      var ix = i % cols;
      var iy = Math.floor(i / cols) % cols;
      var iz = Math.floor(i / (cols * cols));
      pos[id] = {
        x: ix * spacing - offset,
        y: iy * spacing - offset,
        z: iz * spacing - offset
      };
    });
    return pos;
  }

  function _radialLayout3D(nodesList, edgesList) {
    // 3D radial: root at center, dependents radiate outward in 3D hemispheres
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
      return !(incoming[node.id || node.path] || []).length;
    });
    if (roots.length === 0) roots = [nodesList[0]];

    // BFS depth
    var depth = {}, visited = {}, queue = [];
    roots.forEach(function(node) { var id = node.id || node.path; depth[id] = 0; visited[id] = true; queue.push(id); });
    while (queue.length > 0) {
      var curr = queue.shift();
      (adj[curr] || []).forEach(function(child) {
        if (!visited[child]) { visited[child] = true; depth[child] = (depth[curr] || 0) + 1; queue.push(child); }
      });
    }
    nodesList.forEach(function(node) { var id = node.id || node.path; if (depth[id] === undefined) depth[id] = 0; });
    var maxDepth = 1;
    nodesList.forEach(function(node) { var d = depth[node.id || node.path]; if (d > maxDepth) maxDepth = d; });

    // Group by depth, place in concentric 3D shells
    var rings = {};
    nodesList.forEach(function(node) {
      var id = node.id || node.path, d = depth[id];
      if (!rings[d]) rings[d] = [];
      rings[d].push(id);
    });
    var goldenRatio = (1 + Math.sqrt(5)) / 2;
    for (var d = 0; d <= maxDepth; d++) {
      var ring = rings[d] || [];
      // Single root stays at the exact center (no overlap possible); any
      // other depth-0 nodes must NOT stack there. Offset the shell radius by
      // one level so every ring (including depth 0 with 2+ nodes) gets a real
      // radius — same fix as the 2D radial layout.
      if (d === 0 && ring.length === 1) { pos[ring[0]] = { x: 0, y: 0, z: 0 }; continue; }
      var shellR = 60 + (d + 1) * 80;
      ring.forEach(function(id, i) {
        var phi = Math.acos(1 - 2 * (i + 0.5) / ring.length);
        var theta = 2 * Math.PI * i / goldenRatio + d * 0.5;
        pos[id] = {
          x: shellR * Math.cos(theta) * Math.sin(phi),
          y: shellR * Math.sin(theta) * Math.sin(phi),
          z: shellR * Math.cos(phi)
        };
      });
    }
    return pos;
  }

  // ── Camera zoom-to-fit (eased) ────────────────────────────
  // After a view glide finishes, ease the camera out (or in) so the whole
  // new layout fits the frame, instead of keeping the previous view's framing
  // (which can crop a wide layout or make a compact one look tiny).
  // Shared view-transition duration (ms) — set by the ⏱ slider in the map
  // controls (window._PATCHI_VIEW_TRANSITION_MS), clamped to 200–2000ms.
  function _viewMs() {
    var v = window._PATCHI_VIEW_TRANSITION_MS;
    return (typeof v === 'number' && v >= 200 && v <= 2000) ? v : 800;
  }

  var _pendingFit = null;
  var _fitActive = false, _fitStart = 0, _fitDuration = 700;
  var _fitFromPos = null, _fitToPos = null;
  var _fitFromTgt = null, _fitToTgt = null;

  function _boundsOf(positions) {
    var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    var minZ = Infinity, maxZ = -Infinity, n = 0;
    Object.keys(positions || {}).forEach(function(id) {
      var p = positions[id];
      if (!p) return;
      n++;
      if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
      if (p.z < minZ) minZ = p.z; if (p.z > maxZ) maxZ = p.z;
    });
    if (n === 0) return { cx: 0, cy: 0, cz: 0, r: 0 };
    var cx = (minX + maxX) / 2, cy = (minY + maxY) / 2, cz = (minZ + maxZ) / 2;
    var r = 0.5 * Math.sqrt(Math.pow(maxX - minX, 2) +
                            Math.pow(maxY - minY, 2) +
                            Math.pow(maxZ - minZ, 2));
    return { cx: cx, cy: cy, cz: cz, r: r };
  }

  function _fitDistanceFor(r) {
    var el = document.getElementById('brain-map-3d');
    var w = el ? el.clientWidth : 0, h = el ? el.clientHeight : 0;
    var aspect = (w > 0 && h > 0) ? w / h : 1.6;
    var halfV = (60 * Math.PI / 180) / 2;             // vertical half-fov
    var halfH = Math.atan(Math.tan(halfV) * aspect);  // horizontal half-fov
    var need = (r + 40) / Math.sin(Math.min(halfV, halfH)); // tighter axis
    var maxD = (controls && controls.maxDistance) ? controls.maxDistance - 10 : 11990;
    return Math.min(Math.max(need * 1.15, 150), maxD);
  }

  function _smoothFitTo(cx, cy, cz, r) {
    if (!camera || !controls) return;
    if (!(r > 0)) r = 30; // single node / degenerate bounds: frame a default radius
    var fitDist = _fitDistanceFor(r);
    var center = new THREE.Vector3(cx, cy, cz);
    var dir = new THREE.Vector3().copy(camera.position).sub(controls.target);
    if (dir.lengthSq() < 1e-8) dir.set(0, 0, 1);
    dir.normalize();
    var fromPos = camera.position.clone();
    var fromTgt = controls.target.clone();
    var toTgt = center.clone();
    // Keep the user's viewing direction — pull back / push in to frame it.
    var toPos = center.clone().addScaledVector(dir, fitDist);
    if (fromPos.distanceTo(toPos) < 3 && fromTgt.distanceTo(toTgt) < 3) return;
    _stopCameraFit();
    _fitActive = true;
    _fitStart = performance.now();
    _fitDuration = _viewMs();
    _fitFromPos = fromPos; _fitToPos = toPos;
    _fitFromTgt = fromTgt; _fitToTgt = toTgt;
  }

  function _firePendingFit() {
    if (!_pendingFit) return;
    var f = _pendingFit; _pendingFit = null;
    _smoothFitTo(f.cx, f.cy, f.cz, f.r);
  }

  function _stopCameraFit() {
    _fitActive = false;
    _pendingFit = null;
  }

  function _tickCameraFit() {
    if (!_fitActive || !camera || !controls) return;
    var t = Math.min((performance.now() - _fitStart) / _fitDuration, 1);
    var e = _easeInOutCubic(t);
    camera.position.lerpVectors(_fitFromPos, _fitToPos, e);
    controls.target.lerpVectors(_fitFromTgt, _fitToTgt, e);
    controls.update();
    if (t >= 1) _fitActive = false;
  }

  // ── Smooth Transition ─────────────────────────────────────

  function _easeInOutCubic(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  function _startTransition(targetPositions, durationMs) {
    _animTarget = targetPositions;
    _animProgress = 0;
    _animDuration = durationMs || 800;
    _animStart = performance.now();
    _animActive = true;
  }

  function _tickTransition() {
    if (!_animActive || !_animTarget) return false;
    var now = performance.now();
    var elapsed = now - _animStart;
    _animProgress = Math.min(elapsed / _animDuration, 1);
    var t = _easeInOutCubic(_animProgress);

    // Lerp each node mesh to its target
    Object.keys(_animTarget).forEach(function(id) {
      var mesh = _nodes3d[id];
      var tgt = _animTarget[id];
      if (!mesh) return;
      mesh.position.x += (tgt.x - mesh.position.x) * t;
      mesh.position.y += (tgt.y - mesh.position.y) * t;
      mesh.position.z += (tgt.z - mesh.position.z) * t;
      if (mesh.dot) mesh.dot.position.copy(mesh.position);
    });

    // Update labels to follow their nodes
    _repositionLabels();

    // Stretch live edge lines to follow the gliding nodes (no rebuild churn)
    _stretchEdges();

    if (_animProgress >= 1) {
      // Snap to exact final positions
      Object.keys(_animTarget).forEach(function(id) {
        var mesh = _nodes3d[id];
        var tgt = _animTarget[id];
        if (mesh) { mesh.position.set(tgt.x, tgt.y, tgt.z); if (mesh.dot) mesh.dot.position.copy(mesh.position); }
      });
      _repositionLabels();
      _stretchEdges();
      _animActive = false;
      _animTarget = null;
      // Nodes have arrived — now ease the camera out to frame this layout.
      _firePendingFit();
    }
    return _animActive;
  }

  function _repositionLabels() {
    nodeGroup.children.forEach(function(child) {
      if (child.isSprite) {
        // Find corresponding mesh by matching x/z and checking y offset
        var nodeId = null;
        nodeGroup.children.forEach(function(m) {
          if (m.isMesh && m.userData && m.userData.id) {
            var r = m.userData.radius || 8;
            if (Math.abs(m.position.x - child.position.x) < 1 &&
                Math.abs(m.position.z - child.position.z) < 1 &&
                Math.abs((m.position.y + r + 10) - child.position.y) < 5) {
              nodeId = m.userData.id;
            }
          }
        });
        if (nodeId && _nodes3d[nodeId]) {
          var m = _nodes3d[nodeId];
          var r = m.userData.radius || 8;
          child.position.set(m.position.x, m.position.y + r + 10, m.position.z);
        }
      }
    });
  }

  function _stretchEdges() {
    if (_edgeLines.length === 0) return;
    for (var i = 0; i < _edgeLines.length; i++) {
      var r = _edgeLines[i];
      var a = _nodes3d[r.a], b = _nodes3d[r.b];
      if (!a || !b) continue;
      var pa = a.position, pb = b.position;
      var attr = r.line.geometry.attributes.position;
      if (!attr) continue;
      var arr = attr.array;
      arr[0] = pa.x; arr[1] = pa.y; arr[2] = pa.z;
      arr[3] = pb.x; arr[4] = pb.y; arr[5] = pb.z;
      attr.needsUpdate = true;
    }
  }

  function _rebuildEdges() {
    while (edgeGroup.children.length > 0) edgeGroup.remove(edgeGroup.children[0]);
    _edgeLines = [];
    if (_showEdges) {
      _lastEdges.forEach(function(e) {
        _addEdge3D(e.source || e.from, e.target || e.to, e.type || 'dependency');
      });
    }
  }

  // ── Public API ────────────────────────────────────────────

  function loadNodes(nodesList, edgesList) {
    _lastNodes = nodesList || [];
    _lastEdges = edgesList || [];
    _render3D(_lastNodes, _lastEdges);
    if (window.updateBrainMapMeta) window.updateBrainMapMeta(_currentView);
    // First frame: ease the camera to the freshly-drawn layout's bounds.
    if (nodeGroup) {
      var posMap = {};
      Object.keys(_nodes3d).forEach(function(id) {
        var en = _nodes3d[id];
        if (en && en.position) posMap[id] = { x: en.position.x, y: en.position.y, z: en.position.z };
      });
      var bb = _boundsOf(posMap);
      if (bb.r > 0) _smoothFitTo(bb.cx, bb.cy, bb.cz, bb.r);
    }
  }

  function setRenderCap(on) {
    _renderCap3D = !!on;
    if (_lastNodes.length > 0) _render3D(_lastNodes, _lastEdges);
  }

  function _render3D(nodesList, edgesList) {
    if (!scene) return;
    // Clear previous
    while (nodeGroup.children.length > 0) nodeGroup.remove(nodeGroup.children[0]);
    while (edgeGroup.children.length > 0) edgeGroup.remove(edgeGroup.children[0]);
    _edgeLines = [];
    if (dotGroup) while (dotGroup.children.length > 0) dotGroup.remove(dotGroup.children[0]);
    _nodes3d = {};
    _nodeLabels = [];

    var positions;
    switch (_currentView) {
      case 'tree3d': positions = _treeLayout3D(nodesList, edgesList); break;
      case 'spiral3d': positions = _spiralLayout3D(nodesList); break;
      case 'helix3d': positions = _helixLayout3D(nodesList); break;
      case 'sphere3d': positions = _sphereLayout3D(nodesList); break;
      case 'grid3d': positions = _gridLayout3D(nodesList); break;
      case 'cluster3d': positions = _clusterLayout3D(nodesList, edgesList); break;
      case 'radial3d': positions = _radialLayout3D(nodesList, edgesList); break;
      case 'force3d': default: positions = _forceLayout3D(nodesList, edgesList); break;
    }

    nodesList.forEach(function(n, idx) {
      var id = n.id || n.path;
      var pos = positions[id] || { x: 0, y: 0, z: 0 };
      if (idx < _nodeLimit3D(nodesList)) {
        _addNode3D(id, n.label || n.path, n.type || 'default', pos.x, pos.y, pos.z, n.finding_count || 0, n.severity || 'info');
      } else {
        // Capped-out node: keep a position-only entry so edges route through
        // it, but ALSO render a tiny dim dot so the edge endpoint is visible
        // instead of a line floating into empty space.
        var dotGeom = new THREE.SphereGeometry(2.2, 16, 12);
        var dotMat = new THREE.MeshBasicMaterial({ color: 0x8b949e, transparent: true, opacity: 0.35, depthWrite: false });
        var dot = new THREE.Mesh(dotGeom, dotMat);
        dot.position.set(pos.x, pos.y, pos.z);
        dot.userData = { id: id, label: n.label || n.path, node: n, dot: true };
        dotGroup.add(dot);
        _nodes3d[id] = { position: dot.position, dot: dot, node: n, label: n.label || n.path };
      }
    });

    if (_showEdges) {
      edgesList.forEach(function(e) {
        _addEdge3D(e.source || e.from, e.target || e.to, e.type || 'dependency');
      });
    }

    // A rebuild creates fresh meshes/dots — re-apply an active selection
    // (dim others + edge filter) so toggling labels/edges doesn't lose it.
    if (_selectedId) _reapplySelection();
  }

  function _reapplySelection() {
    if (!_selectedId) return;
    var id = _selectedId;
    if (!_entry(id)) { clearSelection(); return; }
    nodeGroup.children.forEach(function(c) {
      if (c.isMesh && c.userData) {
        _setMeshDim(c, c.userData.id !== id);
      }
    });
    if (dotGroup) dotGroup.children.forEach(function(c) {
      if (c.userData) _setMeshDim(c, c.userData.id !== id);
    });
    _applyDotHighlight();
    _rebuildEdges();
    _clearChip();
    var en = _entry(id);
    if (en) _showChip(id, en, _selEdgesOf(id).count);
  }

  function switchView(viewName) {
    _currentView = viewName;
    if (window.updateBrainMapMeta) window.updateBrainMapMeta(viewName);
    document.querySelectorAll('[id^="view3d-"]').forEach(function(btn) {
      btn.style.background = btn.id === 'view3d-' + viewName ? 'var(--bg-tertiary)' : '';
      btn.style.fontWeight = btn.id === 'view3d-' + viewName ? '600' : '';
    });
    if (_lastNodes.length === 0) return;

    // Calculate target positions for the new layout
    var positions;
    switch (viewName) {
      case 'tree3d': positions = _treeLayout3D(_lastNodes, _lastEdges); break;
      case 'spiral3d': positions = _spiralLayout3D(_lastNodes); break;
      case 'helix3d': positions = _helixLayout3D(_lastNodes); break;
      case 'sphere3d': positions = _sphereLayout3D(_lastNodes); break;
      case 'grid3d': positions = _gridLayout3D(_lastNodes); break;
      case 'cluster3d': positions = _clusterLayout3D(_lastNodes, _lastEdges); break;
      case 'radial3d': positions = _radialLayout3D(_lastNodes, _lastEdges); break;
      case 'force3d': default: positions = _forceLayout3D(_lastNodes, _lastEdges); break;
    }

    // Start smooth transition (duration comes from the ⏱ slider)
    _startTransition(positions, _viewMs());
    // Remember the FINAL layout bounds so the camera can ease out to frame
    // the whole view once the glide completes (instead of snapping/cropping).
    var b = _boundsOf(positions);
    _pendingFit = { cx: b.cx, cy: b.cy, cz: b.cz, r: b.r };
  }

  function toggleEdges() {
    _showEdges = !_showEdges;
    var btn = document.getElementById('btn-toggle-edges-3d');
    if (btn) btn.textContent = _showEdges ? 'Hide Edges' : 'Show Edges';
    if (_lastNodes.length > 0) _render3D(_lastNodes, _lastEdges);
  }

  function toggleLabels3D() {
    _showLabels = !_showLabels;
    var btn = document.getElementById('btn-toggle-labels-3d');
    if (btn) btn.textContent = _showLabels ? 'Hide Labels' : 'Show Labels';
    if (_lastNodes.length > 0) _render3D(_lastNodes, _lastEdges);
  }

  function resetCamera() {
    if (camera) { camera.position.set(0, 0, 800); camera.lookAt(0, 0, 0); }
    if (controls) controls.reset();
  }

  function exportPNG3D() {
    if (!renderer) return;
    renderer.render(scene, camera);
    var dataURL = renderer.domElement.toDataURL('image/png');
    var link = document.createElement('a');
    link.download = 'patchi-brain-3d-' + Date.now() + '.png';
    link.href = dataURL;
    link.click();
  }

  function toggleFullscreen() {
    var container = document.getElementById('brain-map-3d');
    if (!container) return;
    var btn = document.getElementById('btn-toggle-fullscreen-3d');

    if (!document.fullscreenElement) {
      container.requestFullscreen().catch(function(err) {
        console.warn('Fullscreen request failed:', err);
      });
      if (btn) btn.textContent = '⛶ Exit Fullscreen';
      container.classList.add('brain-fullscreen');
    } else {
      document.exitFullscreen();
      if (btn) btn.textContent = '⛶ Fullscreen';
      container.classList.remove('brain-fullscreen');
    }
    // Trigger resize to fit the new dimensions
    setTimeout(function() {
      if (typeof BrainMap3D !== 'undefined' && BrainMap3D.resize) {
        BrainMap3D.resize();
      }
    }, 100);
  }

  function focusNode(nodeId) {
    var mesh = _nodes3d[nodeId];
    if (!mesh || !camera || !controls) return;
    var target = mesh.position.clone();
    camera.position.set(target.x + 200, target.y + 100, target.z + 200);
    controls.target.copy(target);
    controls.update();
  }

  function getStats() {
    // Audit hook: rendered = nodes with real meshes (the cap), labels = sprites.
    var meshes = 0;
    // Groups exist only after init() — guard so the hook is safe pre-init
    // (e.g. when toggle3D refreshes page meta before the engine is ready).
    if (nodeGroup) nodeGroup.children.forEach(function(ch) {
      if (ch.isMesh) meshes++;
    });
    return {
      nodes: Object.keys(_nodes3d).length,
      rendered: meshes,
      labels: _nodeLabels ? _nodeLabels.length : 0,
      capped: dotGroup ? dotGroup.children.length : 0,
      edges: _lastEdges.length,
      view: _currentView,
    };
  }

  function destroy() {
    if (_animFrame) cancelAnimationFrame(_animFrame);
    if (renderer) renderer.dispose();
    if (controls) controls.dispose();
    _initialized = false;
  }

  // ── Node Search ───────────────────────────────────────────
  var _searchOrigColors = {};
  var _searchActiveIds = null;  // matched node ids during an active search
  var _searchMatchList = [];
  var _searchIdx = -1;

  function _focusSearchIdx() {
    if (!_searchMatchList.length) return;
    _searchIdx = ((_searchIdx % _searchMatchList.length) + _searchMatchList.length) % _searchMatchList.length;
    var id = _searchMatchList[_searchIdx];
    if (id) focusNode(id);
    var countEl = document.getElementById('brain-search-count');
    if (countEl) countEl.textContent = (_searchIdx + 1) + ' / ' + _searchMatchList.length + ' found';
  }

  function searchNext() {
    if (!_searchMatchList.length) return;
    _searchIdx++;
    _focusSearchIdx();
  }

  function searchPrev() {
    if (!_searchMatchList.length) return;
    _searchIdx--;
    _focusSearchIdx();
  }

  function searchNodes(query) {
    var q = (query || '').trim().toLowerCase();
    var countEl = document.getElementById('brain-search-count');
    var matchCount = 0;
    // Search and selection both dim the graph — a fresh search dismisses the
    // current selection so the match highlight reads cleanly.
    if (q && _selectedId) clearSelection();

    // Restore all nodes if query is empty
    if (!q) {
      _searchMatchList = [];
      _searchIdx = -1;
      nodeGroup.children.forEach(function(child) {
        if (child.isMesh && child.userData && child.userData.id) {
          var id = child.userData.id;
          if (_searchOrigColors[id] !== undefined) {
            child.material.color.set(_searchOrigColors[id]);
            child.material.emissive.set(new THREE.Color(_searchOrigColors[id]).multiplyScalar(0.2));
            child.material.opacity = 0.85;
            delete _searchOrigColors[id];
          }
        }
        if (child.isSprite) {
          child.material.opacity = 0.8;
        }
      });
      _searchActiveIds = null;
      _rebuildEdges();
      _applyDotHighlight();
      if (countEl) countEl.textContent = '';
      return;
    }

    // Find and highlight matches
    var matchIds = {};
    nodeGroup.children.forEach(function(child) {
      if (child.isMesh && child.userData && child.userData.id) {
        var id = child.userData.id;
        var label = (child.userData.label || id).toLowerCase();
        var shortName = label.split('/').pop();
        var isMatch = id.toLowerCase().indexOf(q) >= 0 ||
                      label.indexOf(q) >= 0 ||
                      shortName.indexOf(q) >= 0;
        if (_searchOrigColors[id] === undefined) {
          _searchOrigColors[id] = child.material.color.getHex();
        }
        if (isMatch) {
          matchCount++;
          matchIds[id] = true;
          child.material.color.set(0xE8920A);
          child.material.emissive.set(new THREE.Color(0xE8920A).multiplyScalar(0.6));
          child.material.opacity = 1.0;
        } else {
          child.material.color.set(_searchOrigColors[id]);
          child.material.emissive.set(new THREE.Color(_searchOrigColors[id]).multiplyScalar(0.05));
          child.material.opacity = 0.12;
        }
      }
      if (child.isSprite) {
        child.material.opacity = 0.15;
      }
    });

    _searchActiveIds = matchIds;
    _searchMatchList = Object.keys(matchIds);
    _searchIdx = _searchMatchList.length ? 0 : -1;
    _rebuildEdges();
    _applyDotHighlight();
    if (countEl) {
      countEl.textContent = matchCount + ' found';
      countEl.style.color = matchCount > 0 ? 'var(--accent)' : 'var(--danger)';
    }
  }

  function getPositions() {
    // Test/audit hook: id -> [x, y, z] for every rendered 3D node.
    var out = {};
    Object.keys(_nodes3d).forEach(function(id) {
      var p = _nodes3d[id].position;
      out[id] = [p.x, p.y, p.z];
    });
    return out;
  }

  return {
    init: init,
    loadNodes: loadNodes,
    setRenderCap: setRenderCap,
    switchView: switchView,
    getPositions: getPositions,
    truncateLabel: _truncateLabel3D,
    toggleEdges: toggleEdges,
    toggleLabels: toggleLabels3D,
    resetCamera: resetCamera,
    resize: _onResize,
    exportPNG: exportPNG3D,
    toggleFullscreen: toggleFullscreen,
    focusNode: focusNode,
    getStats: getStats,
    destroy: destroy,
    searchNodes: searchNodes,
    searchNext: searchNext,
    searchPrev: searchPrev,
    selectNode: selectNode,
    clearSelection: clearSelection,
    // Audit/test hook: camera + fit state for visual verification.
    _camera: function() {
      if (!camera || !controls) return null;
      var el = document.getElementById('brain-map-3d');
      var aspect = (el && el.clientWidth > 0 && el.clientHeight > 0) ? el.clientWidth / el.clientHeight : 1.6;
      return {
        px: camera.position.x, py: camera.position.y, pz: camera.position.z,
        tx: controls.target.x, ty: controls.target.y, tz: controls.target.z,
        ux: camera.up.x, uy: camera.up.y, uz: camera.up.z,
        aspect: aspect,
        fitting: _fitActive,
      };
    },
    // Audit/test hook: live edge lines — geometry identity (proves the same
    // line object is stretched in place during a glide) + endpoint sample.
    _edges: function() {
      var out = { count: _edgeLines.length, geoms: [], sample: null };
      for (var i = 0; i < _edgeLines.length && i < 3; i++) {
        var r = _edgeLines[i];
        out.geoms.push(r.line.geometry.uuid);
        if (i === 0) {
          out.first = { a: r.a, b: r.b };
          if (r.line.geometry.attributes.position) {
            var arr = r.line.geometry.attributes.position.array;
            out.sample = [arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]];
          }
        }
      }
      return out;
    },
    // Audit/test hook: capped-dot opacity map (id -> opacity).
    _dotStates: function() {
      var out = {};
      if (dotGroup) dotGroup.children.forEach(function(c) {
        if (c.isMesh && c.userData && c.userData.id) out[c.userData.id] = c.material.opacity;
      });
      return out;
    },
    // Audit/test hook: edge line material opacities.
    _edgeOpacities: function() {
      var out = [];
      if (edgeGroup) edgeGroup.children.forEach(function(c) {
        if (c.isLine && c.material) out.push(c.material.opacity);
      });
      return out;
    },
    // Audit/test hook: project a node's world position to screen coordinates.
    _project: function(id) {
      if (!camera || !renderer || !_entry(id)) return null;
      var v = _entry(id).position.clone().project(camera);
      var w = renderer.domElement.clientWidth || 800;
      var h = renderer.domElement.clientHeight || 400;
      return { x: (v.x + 1) / 2 * w, y: (-v.y + 1) / 2 * h, z: v.z };
    },
  };
})();
