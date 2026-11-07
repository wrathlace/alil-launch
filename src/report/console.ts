import type { Finding, ScanResult, Severity } from '../types.js';

const enabled = (): boolean => !process.env.NO_COLOR && (Boolean(process.stdout.isTTY) || Boolean(process.env.FORCE_COLOR));
const code = (open: number, close: number) => (text: string): string => (enabled() ? `\x1b[${open}m${text}\x1b[${close}m` : text);

const bold = code(1, 22);
const dim = code(2, 22);
const red = code(31, 39);
const green = code(32, 39);
const yellow = code(33, 39);
const blue = code(34, 39);
const magenta = code(35, 39);

const SEVERITY_STYLE: Record<Severity, (s: string) => string> = {
  critical: (s) => bold(red(s)), high: red, medium: yellow, low: blue, info: dim,
};

const scoreColor = (score: number): ((s: string) => string) => (score >= 80 ? green : score >= 50 ? yellow : red);

function bar(score: number, width = 20): string {
  const filled = Math.round((score / 100) * width);
  return scoreColor(score)('█'.repeat(filled)) + dim('░'.repeat(width - filled));
}

function location(finding: Finding): string {
  if (!finding.file) return '';
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

export function renderConsole(result: ScanResult, { verbose = false }: { verbose?: boolean } = {}): string {
  const out: string[] = [''];
  const verdictStyle = result.verdict === 'READY' ? green : result.verdict === 'NOT READY' ? red : yellow;
  out.push(`  ${bold('Alil Launch')} ${dim(`v${result.tool.version}`)}`);
  const stack = [...result.stack.languages, ...result.stack.frameworks, ...result.stack.databases];
  const seconds = (result.durationMs / 1000).toFixed(1);
  const siteOnly = Boolean(result.url) && !result.filesScanned;
  out.push(`  ${dim(siteOnly ? `${result.url} checked in ${seconds}s` : `${result.filesScanned} files scanned in ${seconds}s${stack.length ? ` · ${stack.join(', ')}` : ''}`)}`);
  out.push('');
  out.push(`  ${bold(verdictStyle(result.verdict))}   ${bold(`${result.score}/100`)}  ${dim(`grade ${result.grade}`)}`);
  out.push('');
  for (const { category, score, findings } of result.categories) {
    out.push(`  ${category.padEnd(13)} ${bar(score)} ${String(score).padStart(3)}${findings ? dim(`  ${findings} found`) : ''}`);
  }
  out.push('');

  for (const gap of result.incomplete) out.push(`  ${yellow('NOT CHECKED')} ${gap}`);
  if (result.incomplete.length) out.push('');

  const limit = verbose ? Infinity : 25;
  const visible = result.findings.filter((f) => verbose || f.severity !== 'info').slice(0, limit);
  for (const finding of visible) {
    const tag = SEVERITY_STYLE[finding.severity](finding.severity.toUpperCase().padEnd(8));
    out.push(`  ${tag} ${bold(finding.title)} ${dim(finding.ruleId)}`);
    if (finding.file) out.push(`           ${magenta(location(finding))}`);
    if (finding.message && finding.message !== finding.title) out.push(`           ${finding.message}`);
    if (finding.evidence) out.push(`           ${dim(finding.evidence)}`);
    out.push(`           ${green('Fix:')} ${finding.fix}`);
    out.push('');
  }
  const hidden = result.findings.length - visible.length;
  if (hidden > 0) out.push(`  ${dim(`${hidden} more not shown. Use --verbose to see them all.`)}`, '');

  const { critical, high, medium, low } = result.counts;
  out.push(`  ${red(`${critical} critical`)}  ${red(`${high} high`)}  ${yellow(`${medium} medium`)}  ${blue(`${low} low`)}${result.suppressed ? dim(`  ${result.suppressed} suppressed`) : ''}`);
  if (result.findings.length && !siteOnly) out.push(`  ${dim('Run `alil-launch fix` for safe automatic fixes.')}`);
  if (result.packagesChecked !== null) out.push(`  ${dim(`${result.packagesChecked} packages checked for known vulnerabilities.`)}`);
  else if (!siteOnly) out.push(`  ${dim('Known vulnerabilities were not checked. Add --online to look up CVEs.')}`);
  out.push('');
  return out.join('\n');
}
