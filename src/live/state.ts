import type { FindingInput, Reporter, ScanContext } from '../types.js';
import { severityRank } from '../types.js';
import { scanText } from '../rules/secrets.js';
import type { Pkg } from '../rules/manifests.js';
import type { Platforms } from '../rules/platforms.js';
import type { Detector, Library } from './libraries.js';
import { RULES } from './rules.js';

export interface WordPress {
  core?: string;
  plugins: Map<string, Set<string>>;
  themes: Set<string>;
  /** Versions named in generator tags, by lowercased name, which many plugins add. */
  generators: Map<string, string>;
}

export interface Tech {
  name: string;
  version?: string;
  source: string;
}

/** Everything learned about one site while it is checked, shared by the live check modules. */
export interface LiveState {
  site: URL;
  ctx: ScanContext;
  report: Reporter;
  /** So each issue is reported once, at the first place it was seen. */
  seen: Set<string>;
  assetDirs: Set<string>;
  /** Script URL to the page it was first seen on. */
  scripts: Map<string, string>;
  wordpress: WordPress | null;
  detector: Detector;
  libraries: Map<string, Library & { where: string }>;
  endpoints: Map<string, string>;
  tech: Map<string, Tech>;
  /** Exact package versions learned from exposed lockfiles and page markup, for OSV. */
  packages: Pkg[];
  /** Server software and platforms to look up in the NVD. */
  components: Platforms['components'];
  sourceMaps: Array<{ url: string; files: number; own: string[]; packages: Set<string>; content: boolean }>;
}

export function once(state: LiveState, key: string): boolean {
  if (state.seen.has(key)) return false;
  state.seen.add(key);
  return true;
}

export function addTech(state: LiveState, name: string, version: string | undefined, source: string): void {
  const existing = state.tech.get(name.toLowerCase());
  if (existing && (existing.version || !version)) return;
  state.tech.set(name.toLowerCase(), { name, version, source });
}

export function addLibraries(state: LiveState, libs: Library[], where: string): void {
  for (const lib of libs) {
    const key = `${lib.name}@${lib.version}`;
    if (!state.libraries.has(key)) state.libraries.set(key, { ...lib, where });
  }
}

/**
 * Runs the project secret patterns over public code. The generic "name = value" rule only runs on
 * original sources from source maps: in bundles and pages it mostly matches labels and placeholders.
 */
export function scanForSecrets(state: LiveState, text: string, where: string, { generic = false } = {}): void {
  scanText(where, text, (ruleId: string, input: FindingInput = {}) => {
    if (ruleId === 'secret/public-env-var' || (ruleId === 'secret/generic' && !generic)) return;
    let severity = input.severity;
    let message = input.message ?? '';
    const at = `${where}${input.line && input.line > 1 ? ` line ${input.line}` : ''}`;
    if (ruleId === 'secret/google-api-key') {
      severity = 'low';
      message = `Google API key in ${at}. Browser keys are public by design, so confirm it is restricted to your domains and APIs.`;
    } else if (message.endsWith('found in source.')) {
      message = message.replace(/found in source\.$/, `found in ${at}.`);
    } else {
      message = `${message} In ${at}.`;
    }
    if (ruleId === 'secret/generic' && severity && severityRank(severity) < severityRank('medium')) severity = 'medium';
    if (!once(state, `secret:${input.key}`)) return;
    state.report(RULES.secret.id, { ...input, file: undefined, line: undefined, key: `${ruleId}:${input.key}`, severity, message });
  });
}
