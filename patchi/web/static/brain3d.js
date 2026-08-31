/**
 * brain3d.js — 3D Brain Map using Three.js
 *
 * Renders the file dependency graph as an interactive 3D scene.
 * Supports orbit, zoom, pan, node click, edge rendering, and multiple layouts.
 */

var BrainMap3D = (() => {
  let scene, camera, renderer, controls, nodeGroup, edgeGroup;
  let raycaster, mouse;
  let _nodes3d = {}, _edges3d = [];
  let _lastNodes = [], _lastEdges = [];
  let _currentView = 'force3d';
  let _showLabels = true;
  let _showEdges = true;
  let _nodeLabels = [];
  let _animFrame = null;
  let _initialized = false;
  // Smooth transition state
  let _animTarget = null;    // {id: {x,y,z}} target positions
  let _animProgress = 0;     // 0..1
  let _animDuration = 0;     // ms
  let _animStart = 0;        // timestamp
  let _animActive = false;

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
    camera = new THREE.PerspectiveCamera(60, W / H, 1, 10000);
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

    // OrbitControls
    if (typeof THREE.OrbitControls !== 'undefined') {
      controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.08;
      controls.rotateSpeed = 0.8;
      controls.zoomSpeed = 1.2;
      controls.panSpeed = 0.8;
      controls.minDistance = 50;
      controls.maxDistance = 3000;
    }

    // Groups
    nodeGroup = new THREE.Group();
    edgeGroup = new THREE.Group();
    scene.add(nodeGroup);
    scene.add(edgeGroup);

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

    // Grid helper (subtle)
    var gridHelper = new THREE.GridHelper(1200, 30, 0x21262d, 0x161b22);
    gridHelper.position.y = -300;
    scene.add(gridHelper);

    // Resize handler
    window.addEventListener('resize', _onResize);

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
    if (controls) controls.update();
    renderer.render(scene, camera);
  }

  function _healthColor(findingCount, severity) {
    if (findingCount === 0) return null;
    if (severity === 'critical' || findingCount >= 5) return COLORS.critical;
    if (severity === 'high' || findingCount >= 3) return COLORS.wounded;
    return COLORS.scanning;
  }

  function _addNode3D(id, label, type, x, y, z, findingCount, severity) {
    var color = COLORS[type] || COLORS.default;
    var hc = _healthColor(findingCount, severity);
    if (hc) color = hc;

    // Scale node size by finding count: more findings = bigger node
    // Base radius 5, max ~18 for nodes with many findings
    var fc = findingCount || 0;
    var radius = 5 + Math.min(fc, 20) * 0.65;
    // Severity boosts size further
    if (severity === 'critical') radius *= 1.4;
    else if (severity === 'high') radius *= 1.2;
    // Resolution scales with size for smooth look
    var segments = radius > 12 ? 24 : 16;
    var geometry = new THREE.SphereGeometry(radius, segments, segments);
    // Emissive intensity scales with findings for glow effect
    var emissiveStrength = 0.2 + Math.min(fc, 15) * 0.04;
    var material = new THREE.MeshPhongMaterial({
      color: color,
      emissive: new THREE.Color(color).multiplyScalar(emissiveStrength),
      shininess: 40 + Math.min(fc, 15) * 3,
      transparent: true,
      opacity: 0.85 + Math.min(fc, 10) * 0.01,
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
      ctx.fillText(shortLabel.substring(0, 20), 128, 40);
      var texture = new THREE.CanvasTexture(canvas);
      var spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true, opacity: 0.8 });
      var sprite = new THREE.Sprite(spriteMat);
      sprite.position.set(x, y + radius + 10, z);
      sprite.scale.set(80, 20, 1);
      nodeGroup.add(sprite);
      _nodeLabels.push(sprite);
    }
  }

  function _addEdge3D(from, to, type) {
    if (!_nodes3d[from] || !_nodes3d[to]) return;
    var fromPos = _nodes3d[from].position;
    var toPos = _nodes3d[to].position;

    var color = COLORS.edge;
    if (type === 'route_connection') color = COLORS.edgeRoute;
    else if (type === 'test_coverage') color = COLORS.edgeTest;
    else if (type === 'blast_radius') color = COLORS.edgeBlast;

    var geometry = new THREE.BufferGeometry().setFromPoints([fromPos, toPos]);
    var material = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.3 });
    var line = new THREE.Line(geometry, material);
    edgeGroup.add(line);
  }

  // ── Layout algorithms (3D-optimized) ──────────────────────

  function _forceLayout3D(nodesList, edgesList) {
    var pos = {}, n = nodesList.length;
    if (n === 0) return pos;
    // Initialize in fibonacci sphere for even distribution
    nodesList.forEach(function(node, i) {
      var phi = Math.acos(1 - 2 * (i + 0.5) / n);
      var theta = Math.PI * (1 + Math.sqrt(5)) * i;
      var r = 350;
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
      var shellR = 60 + d * 80;
      ring.forEach(function(id, i) {
        if (d === 0) { pos[id] = { x: 0, y: 0, z: 0 }; return; }
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
    });

    // Update labels to follow their nodes
    _repositionLabels();

    // Update edges to follow nodes
    _rebuildEdges();

    if (_animProgress >= 1) {
      // Snap to exact final positions
      Object.keys(_animTarget).forEach(function(id) {
        var mesh = _nodes3d[id];
        var tgt = _animTarget[id];
        if (mesh) mesh.position.set(tgt.x, tgt.y, tgt.z);
      });
      _repositionLabels();
      _rebuildEdges();
      _animActive = false;
      _animTarget = null;
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

  function _rebuildEdges() {
    while (edgeGroup.children.length > 0) edgeGroup.remove(edgeGroup.children[0]);
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
  }

  function _render3D(nodesList, edgesList) {
    if (!scene) return;
    // Clear previous
    while (nodeGroup.children.length > 0) nodeGroup.remove(nodeGroup.children[0]);
    while (edgeGroup.children.length > 0) edgeGroup.remove(edgeGroup.children[0]);
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

    nodesList.forEach(function(n) {
      var pos = positions[n.id || n.path] || { x: 0, y: 0, z: 0 };
      _addNode3D(n.id || n.path, n.label || n.path, n.type || 'default', pos.x, pos.y, pos.z, n.finding_count || 0, n.severity || 'info');
    });

    if (_showEdges) {
      edgesList.forEach(function(e) {
        _addEdge3D(e.source || e.from, e.target || e.to, e.type || 'dependency');
      });
    }
  }

  function switchView(viewName) {
    _currentView = viewName;
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

    // Start smooth transition
    _startTransition(positions, 800);
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

  function focusNode(nodeId) {
    var mesh = _nodes3d[nodeId];
    if (!mesh || !camera || !controls) return;
    var target = mesh.position.clone();
    camera.position.set(target.x + 200, target.y + 100, target.z + 200);
    controls.target.copy(target);
    controls.update();
  }

  function getStats() {
    return { nodes: Object.keys(_nodes3d).length, edges: _lastEdges.length, view: _currentView };
  }

  function destroy() {
    if (_animFrame) cancelAnimationFrame(_animFrame);
    if (renderer) renderer.dispose();
    if (controls) controls.dispose();
    _initialized = false;
  }

  // ── Node Search ───────────────────────────────────────────
  var _searchOrigColors = {};

  function searchNodes(query) {
    var q = (query || '').trim().toLowerCase();
    var countEl = document.getElementById('brain-search-count');
    var matchCount = 0;

    // Restore all nodes if query is empty
    if (!q) {
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
      _rebuildEdges();
      if (countEl) countEl.textContent = '';
      return;
    }

    // Find and highlight matches
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

    _rebuildEdges();
    if (countEl) {
      countEl.textContent = matchCount + ' found';
      countEl.style.color = matchCount > 0 ? 'var(--accent)' : 'var(--danger)';
    }
  }

  return {
    init: init,
    loadNodes: loadNodes,
    switchView: switchView,
    toggleEdges: toggleEdges,
    toggleLabels: toggleLabels3D,
    resetCamera: resetCamera,
    exportPNG: exportPNG3D,
    focusNode: focusNode,
    getStats: getStats,
    destroy: destroy,
    searchNodes: searchNodes,
  };
})();
