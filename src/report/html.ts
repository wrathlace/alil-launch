import type { ScanResult } from '../types.js';

const escape = (value: unknown): string =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** A single self-contained file with no external requests, so it can be shared offline. */
export function renderHtml(result: ScanResult): string {
  const rows = result.findings.map((f) => `
    <article class="finding ${f.severity}">
      <header><span class="tag">${f.severity}</span><h3>${escape(f.title)}</h3></header>
      ${f.file ? `<code>${escape(f.file)}${f.line ? `:${f.line}` : ''}</code>` : ''}
      <p>${escape(f.message)}</p>
      <p class="fix"><strong>Fix:</strong> ${escape(f.fix)}</p>
    </article>`).join('');
  const bars = result.categories.map((c) => `
    <div class="bar"><span>${escape(c.category)}</span><div class="track"><div style="width:${c.score}%"></div></div><b>${c.score}</b></div>`).join('');
  const tone = result.verdict === 'READY' ? 'good' : result.verdict === 'NOT READY' ? 'bad' : 'warn';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alil Launch report</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--text:#1c1c1a;--muted:#6b6b66;--line:#e4e4df;--good:#2e7d32;--warn:#b26a00;--bad:#c62828;--accent:#2f5bea}
@media(prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--text:#ececea;--muted:#a0a09a;--line:#2e2e2b;--good:#66bb6a;--warn:#ffb74d;--bad:#ef5350;--accent:#8ea8ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px}h1{font-size:20px;margin:0 0 4px}.muted{color:var(--muted);margin:0 0 24px;font-size:14px}
.hero{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:24px}
.verdict{font-size:36px;font-weight:700;margin:0}.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.bar{display:grid;grid-template-columns:110px 1fr 36px;gap:12px;align-items:center;font-size:14px;margin-top:8px}.track{height:8px;background:var(--line);border-radius:4px;overflow:hidden}.track div{height:100%;background:var(--accent)}
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--muted);border-radius:8px;padding:14px 16px;margin-bottom:10px}
.finding.critical,.finding.high{border-left-color:var(--bad)}.finding.medium{border-left-color:var(--warn)}
.finding header{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.finding h3{font-size:16px;margin:0}.finding p{margin:6px 0 0;overflow-wrap:anywhere}
.tag{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}code{font-size:13px;color:var(--muted);overflow-wrap:anywhere}
</style></head><body><main>
<h1>Alil Launch report</h1>
<p class="muted">${escape(result.scannedAt)} · ${result.url && !result.filesScanned ? escape(result.url) : `${result.filesScanned} files`} · v${escape(result.tool.version)}</p>
<section class="hero"><p class="verdict ${tone}">${escape(result.verdict)}</p><p><strong>${result.score}/100</strong> (grade ${escape(result.grade)})</p>${bars}</section>
${result.incomplete.map((gap) => `<p class="finding medium"><strong>Not checked:</strong> ${escape(gap)}</p>`).join('')}
<section>${rows || '<p>No issues found.</p>'}</section>
</main></body></html>
`;
}
