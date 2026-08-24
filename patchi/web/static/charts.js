/**
 * charts.js — SVG chart helpers for Patchi dashboard.
 *
 * Health score ring, language donut, findings timeline.
 */

const Charts = (() => {

  function healthRing(containerId, score, components) {
    const el = document.getElementById(containerId);
    if (!el) return;

    const size = 180;
    const r = 72;
    const circumference = 2 * Math.PI * r;
    const offset = circumference - (score / 100) * circumference;

    const color = score >= 90 ? '#4ADE80' :
                  score >= 70 ? '#4ADE80' :
                  score >= 50 ? '#FACC15' :
                  score >= 30 ? '#FF8C42' : '#FF4D6D';

    const grade = score >= 90 ? 'A' :
                  score >= 70 ? 'B' :
                  score >= 50 ? 'C' :
                  score >= 30 ? 'D' : 'F';

    let html = `
      <div class="health-ring-container">
        <div class="health-ring">
          <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            <circle class="health-ring-bg" cx="${size/2}" cy="${size/2}" r="${r}" />
            <circle class="health-ring-fill" cx="${size/2}" cy="${size/2}" r="${r}"
              stroke="${color}"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${offset}" />
          </svg>
          <div class="health-ring-text">
            <div class="health-score" style="color:${color}">${score}</div>
            <div class="health-grade">Grade ${grade}</div>
          </div>
        </div>`;

    if (components) {
      html += '<div class="health-components">';
      for (const [key, val] of Object.entries(components)) {
        const name = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        const barColor = val >= 70 ? '#4ADE80' : val >= 50 ? '#FACC15' : '#FF4D6D';
        html += `
          <div class="component-bar">
            <span class="component-name">${name}</span>
            <div class="component-track">
              <div class="component-fill" style="width:${val}%;background:${barColor}"></div>
            </div>
            <span class="component-value">${Math.round(val)}</span>
          </div>`;
      }
      html += '</div>';
    }

    html += '</div>';
    el.innerHTML = html;
  }

  function languageDonut(containerId, languages) {
    const el = document.getElementById(containerId);
    if (!el) return;

    const size = 160;
    const r = 60;
    const strokeWidth = 20;
    const circumference = 2 * Math.PI * r;
    const total = Object.values(languages).reduce((a, b) => a + b, 0);

    const langColors = {
      python: '#3B82F6',
      javascript: '#FACC15',
      typescript: '#3B82F6',
      html: '#FF8C42',
      css: '#A855F7',
      bash: '#6B7280',
    };

    let html = `<div class="chart-container">
      <div class="chart-title">Languages</div>
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">`;

    let offset = 0;
    for (const [lang, count] of Object.entries(languages)) {
      const pct = count / total;
      const dash = pct * circumference;
      const gap = circumference - dash;
      const color = langColors[lang.toLowerCase()] || '#6B7280';

      html += `<circle cx="${size/2}" cy="${size/2}" r="${r}"
        fill="none" stroke="${color}" stroke-width="${strokeWidth}"
        stroke-dasharray="${dash} ${gap}"
        stroke-dashoffset="${-offset}"
        style="transform: rotate(-90deg); transform-origin: center;" />`;

      offset += dash;
    }

    html += `<text x="${size/2}" y="${size/2}" text-anchor="middle" dy="0.35em"
      fill="#F2EDD6" font-size="18" font-weight="700" font-family="JetBrains Mono, monospace">${total}</text>
      <text x="${size/2}" y="${size/2 + 16}" text-anchor="middle"
      fill="#8B8B8B" font-size="10" font-family="Inter, sans-serif">files</text>
    </svg>`;

    // Legend
    html += '<div style="margin-top:8px">';
    for (const [lang, count] of Object.entries(languages)) {
      const color = langColors[lang.toLowerCase()] || '#6B7280';
      const pct = Math.round((count / total) * 100);
      html += `<span style="display:inline-block;margin-right:12px;font-size:11px">
        <span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${color};margin-right:4px"></span>
        ${lang} (${pct}%)
      </span>`;
    }
    html += '</div></div>';

    el.innerHTML = html;
  }

  function findingsTimeline(containerId, scanHistory) {
    const el = document.getElementById(containerId);
    if (!el) return;

    const width = 400;
    const height = 120;
    const padding = { top: 10, right: 10, bottom: 20, left: 30 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    if (scanHistory.length === 0) { el.innerHTML = '<div class="chart-container"><div class="chart-title">Findings Over Time</div><div style="color:var(--text-dim);font-size:12px;padding:20px;text-align:center">No scan history yet.</div></div>'; return; }
    const maxFindings = Math.max(1, ...scanHistory.map(s => s.total || 0));
    const barWidth = Math.max(4, (chartW / scanHistory.length) - 2);

    let html = `<div class="chart-container">
      <div class="chart-title">Findings Over Time</div>
      <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;

    // Grid lines
    for (let i = 0; i <= 4; i++) {
      const y = padding.top + (chartH / 4) * i;
      html += `<line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"
        stroke="#2A2A2A" stroke-width="1" />`;
      html += `<text x="${padding.left - 4}" y="${y + 3}" text-anchor="end"
        fill="#555" font-size="9" font-family="JetBrains Mono, monospace">
        ${Math.round(maxFindings * (1 - i / 4))}</text>`;
    }

    // Bars
    scanHistory.forEach((scan, i) => {
      const x = padding.left + (chartW / scanHistory.length) * i;
      const total = scan.total || 0;
      const h = (total / maxFindings) * chartH;
      const y = padding.top + chartH - h;

      const critH = (scan.critical || 0) / maxFindings * chartH;
      const highH = (scan.high || 0) / maxFindings * chartH;
      const medH = (scan.medium || 0) / maxFindings * chartH;

      const safeH = h - critH - highH - medH;
      if (safeH > 0) {
        html += `<rect x="${x}" y="${y}" width="${barWidth}" height="${safeH}"
          fill="#4ADE80" rx="2" opacity="0.8" />`;
      }
      if (critH > 0) {
        html += `<rect x="${x}" y="${y + safeH}" width="${barWidth}" height="${critH}"
          fill="#FF4D6D" rx="2" />`;
      }
      if (highH > 0) {
        html += `<rect x="${x}" y="${y + safeH + critH}" width="${barWidth}" height="${highH}"
          fill="#FF8C42" rx="2" />`;
      }
      if (medH > 0) {
        html += `<rect x="${x}" y="${y + safeH + critH + highH}" width="${barWidth}" height="${medH}"
          fill="#FACC15" rx="2" />`;
      }
    });

    html += '</svg></div>';
    el.innerHTML = html;
  }

  return { healthRing, languageDonut, findingsTimeline };
})();
