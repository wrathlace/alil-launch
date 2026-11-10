export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
  | 'secrets'
  | 'config'
  | 'dependencies'
  | 'backups'
  | 'deployment'
  | 'launch'
  | 'live'
  | 'checks';

export interface RuleMeta {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  fix: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  message: string;
  fix: string;
  file?: string;
  line?: number;
  /** Always redacted. Never contains a full secret. */
  evidence?: string;
  /** CVE or advisory ids behind a vulnerability finding. Monitoring uses these to spot new disclosures. */
  advisories?: string[];
  /** True when an advisory is listed in CISA's Known Exploited Vulnerabilities catalog. */
  exploited?: boolean;
  /** Stable hash used by baselines and SARIF. Survives line moves. */
  fingerprint: string;
}

export interface FindingInput {
  message?: string;
  file?: string;
  line?: number;
  evidence?: string;
  advisories?: string[];
  exploited?: boolean;
  severity?: Severity;
  /** Extra identity for the fingerprint, such as a hash of the secret. */
  key?: string;
}

export type Reporter = (ruleId: string, input?: FindingInput) => void;

export interface Stack {
  languages: string[];
  frameworks: string[];
  databases: string[];
  packageManagers: string[];
  isWebServer: boolean;
  isFrontend: boolean;
  isLibrary: boolean;
}

export interface GitInfo {
  isRepo: boolean;
  tracked: Set<string>;
}

export interface ScanContext {
  root: string;
  /** Project-relative paths, forward slashes, after ignores. */
  files: string[];
  /** Every path seen before default ignores, used for "was this committed" rules. */
  allPaths: string[];
  git: GitInfo;
  stack: Stack;
  options: ScanOptions;
  /** Requested checks that could not finish. Any entry stops a READY verdict. */
  gaps: string[];
  /** Packages looked up for known vulnerabilities, or null when that check did not run. */
  packagesChecked: number | null;
  /** Pages of the live site that were fetched, or null when no site was checked. */
  pagesChecked: number | null;
  read(path: string): string | null;
  exists(path: string): boolean;
  /** Text of every scanned file whose path matches. */
  matching(pattern: RegExp, maxBytes?: number): Array<{ path: string; text: string }>;
}

export interface Checker {
  name: string;
  rules: RuleMeta[];
  run(ctx: ScanContext, report: Reporter): void | Promise<void>;
}

export interface CustomRule {
  id: string;
  title?: string;
  pattern: string;
  flags?: string;
  files?: string;
  severity?: Severity;
  category?: Category;
  message?: string;
  fix?: string;
}

export interface Config {
  ignore?: string[];
  rules?: Record<string, 'off' | Severity>;
  customRules?: CustomRule[];
  failOn?: Severity;
}

export interface ScanOptions {
  url?: string;
  online?: boolean;
  history?: boolean;
  run?: boolean;
  staged?: boolean;
  only?: Category[];
  baseline?: string;
  config?: Config;
  /** Reads no project files, for a check of the live site alone. */
  skipFiles?: boolean;
  /** Internal pages the live check may fetch after the home page. */
  maxPages?: number;
}

export interface CategoryScore {
  category: Category;
  score: number;
  findings: number;
}

export type Verdict = 'READY' | 'INCOMPLETE' | 'RISKY' | 'NOT READY';

export interface ScanResult {
  tool: { name: string; version: string };
  root: string;
  url?: string;
  scannedAt: string;
  durationMs: number;
  filesScanned: number;
  stack: Stack;
  score: number;
  grade: string;
  verdict: Verdict;
  categories: CategoryScore[];
  counts: Record<Severity, number>;
  findings: Finding[];
  suppressed: number;
  /** Requested checks that could not finish, so a clean result here proves nothing. */
  incomplete: string[];
  packagesChecked: number | null;
  pagesChecked: number | null;
  rules: RuleMeta[];
}

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}
