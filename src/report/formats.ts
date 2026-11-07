import type { ScanResult, Severity } from '../types.js';

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

const SARIF_LEVEL: Record<Severity, string> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

export function renderSarif(result: ScanResult): string {
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'alil-launch',
          version: result.tool.version,
          informationUri: 'https://www.npmjs.com/package/alil-launch',
          rules: result.rules.map((rule) => ({
            id: rule.id,
            name: rule.title,
            shortDescription: { text: rule.title },
            fullDescription: { text: rule.description },
            help: { text: rule.fix },
            defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
          })),
        },
      },
      results: result.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: SARIF_LEVEL[finding.severity],
        message: { text: `${finding.message} Fix: ${finding.fix}` },
        partialFingerprints: { 'alil-launch': finding.fingerprint },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.file ?? 'package.json' },
            ...(finding.line ? { region: { startLine: finding.line } } : {}),
          },
        }],
      })),
    }],
  }, null, 2);
}

function where(file?: string, line?: number): string {
  if (!file) return 'project';
  return `\`${file}${line ? `:${line}` : ''}\``;
}

export function renderMarkdown(result: ScanResult): string {
  const lines = [
    `## Alil Launch: ${result.verdict} (${result.score}/100, grade ${result.grade})`,
    '',
    `${result.counts.critical} critical, ${result.counts.high} high, ${result.counts.medium} medium, ${result.counts.low} low. ${result.url && !result.filesScanned ? `Checked ${result.url}.` : `Scanned ${result.filesScanned} files.`}`,
    '',
    '| Category | Score | Findings |',
    '|---|---:|---:|',
    ...result.categories.map((c) => `| ${c.category} | ${c.score} | ${c.findings} |`),
    '',
    ...result.incomplete.flatMap((gap) => [`> **Not checked:** ${gap}`, '']),
  ];
  if (result.findings.length) {
    lines.push('| Severity | Issue | Where | Fix |', '|---|---|---|---|');
    for (const f of result.findings.slice(0, 100)) {
      const text = `${f.title}: ${f.message}`.replace(/\|/g, '\\|');
      lines.push(`| ${f.severity} | ${text} | ${where(f.file, f.line)} | ${f.fix.replace(/\|/g, '\\|')} |`);
    }
  }
  return `${lines.join('\n')}\n`;
}

/** A task list an AI coding agent can work through. Contains no secret values. */
export function renderPrompt(result: ScanResult): string {
  const lines = [
    `Alil Launch scored this project ${result.score}/100 (${result.verdict}). Fix the issues below in order, most severe first.`,
    'Rules for you, the coding agent:',
    '- Never print, log or commit a secret value. Replace it with an environment variable.',
    '- A leaked credential must be rotated by the owner. List these for them, because editing code does not revoke the key.',
    '- Do not delete user data or rewrite git history without asking.',
    '- After fixing, run `npx alil-launch` again and repeat until no critical or high issues remain.',
    ...result.incomplete.map((gap) => `- This scan is incomplete, so do not call the project safe. Not checked: ${gap}`),
    '',
  ];
  result.findings.filter((f) => f.severity !== 'info').slice(0, 60).forEach((f, i) => {
    lines.push(`${i + 1}. [${f.severity}] ${f.title} (${f.ruleId}) at ${where(f.file, f.line)}`);
    lines.push(`   Problem: ${f.message}`);
    lines.push(`   Fix: ${f.fix}`);
  });
  return `${lines.join('\n')}\n`;
}

export function renderBadge(result: ScanResult): string {
  const color = result.score >= 80 ? '#2e7d32' : result.score >= 50 ? '#b26a00' : '#c62828';
  const label = 'alil-launch';
  const value = `${result.score}/100`;
  const left = 82;
  const right = 52;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${left + right}" height="20" role="img" aria-label="${label}: ${value}"><rect width="${left}" height="20" fill="#444"/><rect x="${left}" width="${right}" height="20" fill="${color}"/><g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle"><text x="${left / 2}" y="14">${label}</text><text x="${left + right / 2}" y="14">${value}</text></g></svg>\n`;
}
