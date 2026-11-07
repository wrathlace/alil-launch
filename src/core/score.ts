import type { Category, CategoryScore, Finding, Severity, Verdict } from '../types.js';

const WEIGHT: Record<Severity, number> = { critical: 30, high: 12, medium: 5, low: 1.5, info: 0 };

/** Repeats of one rule count for less, so a single noisy issue cannot sink a project alone. */
function penalty(findings: Finding[]): number {
  const seen = new Map<string, number>();
  let total = 0;
  for (const finding of findings) {
    const n = seen.get(finding.ruleId) ?? 0;
    seen.set(finding.ruleId, n + 1);
    total += WEIGHT[finding.severity] / (1 + n);
  }
  return total;
}

export function scoreOf(findings: Finding[]): number {
  let score = Math.round(100 * Math.exp(-penalty(findings) / 60));
  if (findings.some((f) => f.severity === 'critical')) score = Math.min(score, 49);
  else if (findings.some((f) => f.severity === 'high')) score = Math.min(score, 79);
  return score;
}

export function gradeOf(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

export function verdictOf(findings: Finding[], gaps: string[] = []): Verdict {
  if (findings.some((f) => f.severity === 'critical')) return 'NOT READY';
  if (findings.some((f) => f.severity === 'high')) return 'RISKY';
  return gaps.length ? 'INCOMPLETE' : 'READY';
}

export function categoryScores(findings: Finding[], categories: Category[]): CategoryScore[] {
  return categories.map((category) => {
    const own = findings.filter((f) => f.category === category);
    return { category, score: scoreOf(own), findings: own.length };
  });
}
