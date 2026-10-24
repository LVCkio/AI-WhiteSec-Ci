// Biểu đồ SVG nhỏ gọn, không thư viện ngoài. Mỗi mark có data-tip -> tooltip khi rê chuột / focus.
import { esc, num, pct } from './ui.js';

const tipRow = (color, name, value) =>
  `<div class="tt-row"><span>${color?`<i style="width:9px;height:9px;border-radius:2px;display:inline-block;background:${color}"></i>`:''}${esc(name)}</span><b>${esc(value)}</b></div>`;
export const tip = (title, rows) => esc(`<div class="tt-title">${esc(title)}</div>${rows.map(r => tipRow(...r)).join('')}`);
export const legend = items => `<div class="legend">${items.map(([c, n]) => `<span><i style="background:${c}"></i>${esc(n)}</span>`).join('')}</div>`;

// Thanh ngang nhóm: mỗi hạng mục 1–3 thanh (vd. cảnh báo trên code có lỗ hổng vs sau vá).
export function groupedHBar(cats, series, {max=1, fmt=v => pct(v), labelWidth=190, barH=11, gap=3, groupGap=16, ci=null, width=640} = {}) {
  const inner = width - labelWidth - 64;
  const groupH = series.length * barH + (series.length - 1) * gap;
  const height = cats.length * (groupH + groupGap) + 8;
  const x = v => labelWidth + Math.max(0, Math.min(1, (v ?? 0) / max)) * inner;
  const ticks = [0, .25, .5, .75, 1].map(t => t * max);
  let out = `<svg class="chart" viewBox="0 0 ${width} ${height + 18}" role="img" aria-label="Biểu đồ thanh ngang">`;
  out += `<g class="grid">${ticks.map(t => `<line x1="${x(t)}" x2="${x(t)}" y1="0" y2="${height}"/>`).join('')}</g>`;
  out += ticks.map(t => `<text x="${x(t)}" y="${height + 14}" text-anchor="middle">${esc(fmt(t))}</text>`).join('');
  cats.forEach((cat, i) => {
    const y0 = 4 + i * (groupH + groupGap);
    out += `<text class="lbl" x="${labelWidth - 10}" y="${y0 + groupH / 2 + 4}" text-anchor="end">${esc(cat)}</text>`;
    const rows = series.map(s => [s.color, s.name, fmt(s.values[i])]);
    series.forEach((s, j) => {
      const v = s.values[i];
      const y = y0 + j * (barH + gap);
      const w = Math.max(v ? 3 : 0, x(v) - labelWidth);
      out += `<rect x="${labelWidth}" y="${y}" width="${w}" height="${barH}" rx="4" fill="${s.color}"/>`;
      if (ci && ci[j] && ci[j][i]) {
        const [lo, hi] = ci[j][i];
        out += `<line x1="${x(lo)}" x2="${x(hi)}" y1="${y + barH / 2}" y2="${y + barH / 2}" stroke="#e3e9f6" stroke-width="1.5"/>`;
        out += `<line x1="${x(lo)}" x2="${x(lo)}" y1="${y + 2}" y2="${y + barH - 2}" stroke="#e3e9f6" stroke-width="1.5"/><line x1="${x(hi)}" x2="${x(hi)}" y1="${y + 2}" y2="${y + barH - 2}" stroke="#e3e9f6" stroke-width="1.5"/>`;
      }
      out += `<text class="val" x="${Math.max(x(v), ci && ci[j] && ci[j][i] ? x(ci[j][i][1]) : 0) + 6}" y="${y + barH - 1}">${esc(fmt(v))}</text>`;
    });
    out += `<rect class="hit" x="0" y="${y0 - groupGap / 2}" width="${width}" height="${groupH + groupGap}" data-tip="${tip(cat, rows)}" tabindex="-1"/>`;
  });
  return out + '</svg>';
}

// Đường: x số (ngưỡng / epoch), nhiều chuỗi cùng một trục y; marker dọc (ngưỡng đã chọn).
export function lineChart(xs, series, {width=640, height=250, yMax=1, yFmt=v => pct(v, 0), xFmt=v => num(v, 2), xLabel='', marker=null, valueFmt=v => pct(v)} = {}) {
  const L = 44, R = 16, T = 12, B = 34;
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const X = v => L + (x1 === x0 ? 0 : (v - x0) / (x1 - x0)) * (width - L - R);
  const Y = v => T + (1 - Math.max(0, Math.min(1, v / yMax))) * (height - T - B);
  const ticks = [0, .25, .5, .75, 1].map(t => t * yMax);
  let out = `<svg class="chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Biểu đồ đường">`;
  out += `<g class="grid">${ticks.map(t => `<line x1="${L}" x2="${width - R}" y1="${Y(t)}" y2="${Y(t)}"/>`).join('')}</g>`;
  out += ticks.map(t => `<text x="${L - 8}" y="${Y(t) + 4}" text-anchor="end">${esc(yFmt(t))}</text>`).join('');
  const xt = xs.length > 8 ? [x0, x0 + (x1 - x0) / 4, x0 + (x1 - x0) / 2, x0 + 3 * (x1 - x0) / 4, x1] : xs;
  out += xt.map(v => `<text x="${X(v)}" y="${height - 16}" text-anchor="middle">${esc(xFmt(v))}</text>`).join('');
  if (xLabel) out += `<text x="${(L + width - R) / 2}" y="${height - 2}" text-anchor="middle">${esc(xLabel)}</text>`;
  if (marker) {
    out += `<line class="mark-line" x1="${X(marker.x)}" x2="${X(marker.x)}" y1="${T}" y2="${height - B}"/>`;
    out += `<text x="${X(marker.x) + 5}" y="${T + 10}" style="fill:#c7bdff">${esc(marker.label)}</text>`;
  }
  series.forEach(s => {
    const pts = xs.map((v, i) => s.values[i] == null ? null : `${X(v).toFixed(1)},${Y(s.values[i]).toFixed(1)}`).filter(Boolean);
    out += `<polyline fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="${pts.join(' ')}"/>`;
    const last = xs.length - 1;
    if (s.values[last] != null && s.endLabel === true) out += `<text x="${X(xs[last]) - 4}" y="${Y(s.values[last]) - 7}" text-anchor="end" style="fill:${s.color};font-weight:600">${esc(s.name)}</text>`;
  });
  xs.forEach((v, i) => {
    const left = i ? (X(xs[i - 1]) + X(v)) / 2 : L;
    const right = i < xs.length - 1 ? (X(xs[i + 1]) + X(v)) / 2 : width - R;
    const rows = series.map(s => [s.color, s.name, s.values[i] == null ? '—' : (s.fmt || valueFmt)(s.values[i])]);
    out += `<rect class="hit" x="${left}" y="${T}" width="${Math.max(1, right - left)}" height="${height - T - B}" data-tip="${tip(`${xLabel ? xLabel + ' ' : ''}${xFmt(v)}`, rows)}"/>`;
  });
  return out + '</svg>';
}

// Thang tuần tự một màu (xanh) cho heatmap trên nền tối: giá trị lớn = sáng hơn.
const RAMP = ['#0f1b38', '#104281', '#184f95', '#1c5cab', '#256abf', '#2a78d6', '#3987e5', '#5598e7', '#6da7ec', '#86b6ef', '#9ec5f4'];
export function heatColor(t) {
  if (t == null || Number.isNaN(t)) return null;
  const i = Math.round(Math.max(0, Math.min(1, t)) * (RAMP.length - 1));
  return {bg: RAMP[i], fg: i >= 7 ? '#071230' : '#e3e9f6'};
}
export function heatmap(rows, cols, cell, {rowW='150px', corner=''} = {}) {
  let out = `<div class="table-wrap"><div class="heat" style="grid-template-columns:${rowW} repeat(${cols.length},minmax(48px,1fr))"><div class="hh">${esc(corner)}</div>`;
  out += cols.map(c => `<div class="hh">${esc(c.label)}</div>`).join('');
  rows.forEach(r => {
    out += `<div class="hr">${esc(r.label)}</div>`;
    cols.forEach(c => {
      const v = cell(r, c);
      if (!v) { out += '<div class="hc na">—</div>'; return; }
      const col = heatColor(v.t);
      out += `<div class="hc" style="background:${col.bg};color:${col.fg}" data-tip="${v.tip || ''}">${esc(v.text)}${v.sub ? `<small>${esc(v.sub)}</small>` : ''}</div>`;
    });
  });
  return out + '</div></div>';
}

// Thanh xếp chồng tỉ lệ (vd. BLOCK/REVIEW/PASS) kèm tooltip.
export function stackBar(parts, total, title='') {
  if (!total) return '<div class="stack"><span style="width:100%;background:#1a2442"></span></div>';
  return `<div class="stack" role="img" aria-label="${esc(title)}">${parts.filter(p => p.value > 0).map(p =>
    `<span style="width:${100 * p.value / total}%;background:${p.color}" data-tip="${tip(title || p.name, [[p.color, p.name, `${p.value} (${pct(p.value / total)})`]])}"></span>`).join('')}</div>`;
}
