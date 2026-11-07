import type { Checker, Config, CustomRule, RuleMeta } from '../types.js';

function toMeta(rule: CustomRule): RuleMeta {
  return {
    id: rule.id.startsWith('custom/') ? rule.id : `custom/${rule.id}`,
    title: rule.title ?? rule.id,
    category: rule.category ?? 'config',
    severity: rule.severity ?? 'medium',
    description: rule.message ?? `Matches ${rule.pattern}`,
    fix: rule.fix ?? 'See your team guidelines.',
  };
}

/** Rules a project defines in .alil-launch.json. */
export function customChecker(config: Config): Checker {
  const defined = (config.customRules ?? []).map((rule) => ({
    rule,
    meta: toMeta(rule),
    pattern: new RegExp(rule.pattern, rule.flags?.replace(/[gy]/g, '') ?? ''),
    files: rule.files ? new RegExp(rule.files) : /./,
  }));
  return {
    name: 'custom',
    rules: defined.map((d) => d.meta),
    run(ctx, report) {
      for (const { meta, pattern, files, rule } of defined) {
        for (const { path, text } of ctx.matching(files)) {
          text.split('\n').forEach((line, i) => {
            if (pattern.test(line)) report(meta.id, { file: path, line: i + 1, message: rule.message });
          });
        }
      }
    },
  };
}
