import { scan } from './core/scanner.js';
import { severityRank } from './types.js';
import type { ScanOptions, ScanResult, Severity } from './types.js';

export { scan, VERSION } from './core/scanner.js';
export { allRules } from './rules/index.js';
export { applyFixes } from './fix.js';
export { renderConsole } from './report/console.js';
export { renderBadge, renderJson, renderMarkdown, renderPrompt, renderSarif } from './report/formats.js';
export { renderHtml } from './report/html.js';
export { monitor } from './monitor.js';
export type { MonitorOptions, MonitorRun } from './monitor.js';
export * from './types.js';

/**
 * Throws if a project has findings at or above a severity, for use inside any test runner.
 *
 *   test('safe to launch', () => assertLaunchReady('.'));
 */
export async function assertLaunchReady(root = '.', options: ScanOptions & { failOn?: Severity } = {}): Promise<ScanResult> {
  const failOn = options.failOn ?? 'high';
  const result = await scan(root, options);
  const blocking = result.findings.filter((f) => severityRank(f.severity) <= severityRank(failOn));
  if (result.incomplete.length) throw new Error(`alil-launch could not finish:\n${result.incomplete.map((gap) => `  ${gap}`).join('\n')}`);
  if (blocking.length) {
    const list = blocking.slice(0, 10).map((f) => `  [${f.severity}] ${f.title}${f.file ? ` (${f.file})` : ''}`).join('\n');
    throw new Error(`alil-launch found ${blocking.length} blocking issue(s):\n${list}`);
  }
  return result;
}
