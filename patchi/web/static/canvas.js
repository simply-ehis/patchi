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

    stage = new Konva.Stage({
      container: containerId,
      width: el.clientWidth,
      height: el.clientHeight,
    });

    nodeLayer = new Konva.Layer();
    antLayer = new Konva.Layer();
    stage.add(nodeLayer, antLayer);

    _bindWsEvents();
    _loadNodes();
    
    // Add zoom controls and mini-map
    _addZoomControls();

    // Viewport resize handler
    window.addEventListener('resize', _onResize);
    _addMiniMap();
    
    // Tap-to-spawn on node click
    nodeLayer.on("click tap", ({ target }) => {
      const nodeId = target.getAttr("nodeId");
      if (nodeId) {
        const _ws = window._ws;
        if (_ws) _ws.send(JSON.stringify({action: "spawn.ant", data: {node_id: nodeId}}));
      }
    });
    
    // Pan with middle mouse button or space + drag
    let isDragging = false;
    let lastPointerPosition;
    
    stage.on('mousedown touchstart', (e) => {
      if (e.evt.button === 1 || e.evt.shiftKey) { // Middle mouse or shift
        isDragging = true;
        lastPointerPosition = stage.getPointerPosition();
      }
    });
    
    stage.on('mouseup touchend', () => {
      isDragging = false;
    });
    
    stage.on('mousemove touchmove', (e) => {
      if (!isDragging) return;
      e.evt.preventDefault();
      
      const newPointerPosition = stage.getPointerPosition();
      const dx = newPointerPosition.x - lastPointerPosition.x;
      const dy = newPointerPosition.y - lastPointerPosition.y;
      
      offsetX += dx;
      offsetY += dy;
      
      stage.position({
        x: stage.x() + dx,
        y: stage.y() + dy
      });
      stage.batchDraw();
      _updateMiniMap();
      
      lastPointerPosition = newPointerPosition;
    });
    
    // Zoom with mouse wheel
    stage.on('wheel', (e) => {
      e.evt.preventDefault();
      
      const oldScale = stage.scaleX();
      const pointer = stage.getPointerPosition();
      
      const mousePointTo = {
        x: (pointer.x - stage.x()) / oldScale,
        y: (pointer.y - stage.y()) / oldScale,
      };
      
      const newScale = e.evt.deltaY > 0 ? oldScale * 0.9 : oldScale * 1.1;
      
      stage.scale({ x: newScale, y: newScale });
      
      const newPos = {
        x: pointer.x - mousePointTo.x * newScale,
        y: pointer.y - mousePointTo.y * newScale,
      };
      
      stage.position(newPos);
      stage.batchDraw();
      _updateMiniMap();
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
    const el = document.getElementById('brain-map');
    if (!el) return;
    const container = el.parentElement;
    
    // Create zoom controls div if it doesn't exist
    let zoomControls = document.getElementById('zoom-controls');
    if (!zoomControls) {
      zoomControls = document.createElement('div');
      zoomControls.id = 'zoom-controls';
      zoomControls.innerHTML = `
        <button id="zoom-in" class="btn">+</button>
        <span id="zoom-level">100%</span>
        <button id="zoom-out" class="btn">-</button>
        <button id="zoom-fit" class="btn">Fit</button>
      `;
      zoomControls.style.cssText = `
        position: absolute;
        bottom: 20px;
        left: 20px;
        z-index: 10;
        display: flex;
        gap: 5px;
        align-items: center;
      `;
      container.appendChild(zoomControls);
      
      document.getElementById('zoom-in').onclick = () => _zoom(1.2);
      document.getElementById('zoom-out').onclick = () => _zoom(0.8);
      document.getElementById('zoom-fit').onclick = () => _zoomToFit();
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
  
  function _zoom(factor) {
    const oldScale = stage.scaleX();
    const newScale = Math.max(0.1, Math.min(4, oldScale * factor));
    
    stage.scale({ x: newScale, y: newScale });
    document.getElementById('zoom-level').textContent = `${Math.round(newScale * 100)}%`;
    stage.batchDraw();
    _updateMiniMap();
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
    
    document.getElementById('zoom-level').textContent = `${Math.round(scale * 100)}%`;
    stage.batchDraw();
    _updateMiniMap();
  }

  function loadNodes(ns, edges) {
    _renderGraph(ns || [], edges || []);
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
    scale = 1;
    offsetX = 0;
    offsetY = 0;
    const el = document.getElementById('brain-map');
    if (stage && el) {
      stage.width(el.clientWidth);
      stage.height(el.clientHeight);
      const layer = stage.findOne('Layer');
      if (layer) {
        layer.position({ x: 0, y: 0 });
        layer.scale({ x: 1, y: 1 });
        layer.batchDraw();
      }
    }
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
    if (_lastNodes.length > 0) _renderGraph(_lastNodes, _lastEdges);
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

  return { init, setNodeState, loadNodes, zoomIn, zoomOut, zoomReset, handleEvent, _relistenWs, switchView, toggleLabels, rotateGraph, resetRotation, exportPNG, exportJSON };
})();