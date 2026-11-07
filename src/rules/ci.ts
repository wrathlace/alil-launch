import type { Checker, RuleMeta } from '../types.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'config',
});

const RULES = {
  prTarget: rule('ci/pull-request-target-checkout', 'Untrusted PR code runs with secrets', 'critical', '`pull_request_target` has repository secrets, so checking out PR code lets anyone steal them.', 'Use `pull_request`, or never check out the PR head in this workflow.'),
  injection: rule('ci/script-injection', 'Untrusted input inside a run step', 'high', 'Titles and branch names are attacker-controlled and run as shell code here.', 'Pass the value through `env:` and quote it in the script.'),
  unpinned: rule('ci/unpinned-third-party-action', 'Third-party action not pinned to a commit', 'medium', 'A moved tag could run new code with your secrets.', 'Pin the action to a full commit SHA.'),
  permissions: rule('ci/no-token-permissions', 'Workflow has default token permissions', 'low', 'The job token may have more write access than it needs.', 'Add a top-level `permissions: contents: read` block.'),
  echoSecret: rule('ci/secret-printed', 'Secret printed in a workflow', 'high', 'Masking is easily bypassed, so build logs may expose it.', 'Do not echo secrets.'),
};

const UNTRUSTED = /\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|discussion)\.[\w.]*(title|body|ref|label)|event\.head_commit\.message|head_ref)[^}]*\}\}/;

export const ciChecker: Checker = {
  name: 'ci',
  rules: Object.values(RULES),
  run(ctx, report) {
    for (const { path, text } of ctx.matching(/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/)) {
      const hasPrTarget = /pull_request_target/.test(text);
      const lines = text.split('\n');
      let inRun = false;
      let runIndent = 0;
      lines.forEach((line, i) => {
        const indent = line.length - line.trimStart().length;
        if (/^\s*(-\s*)?run:/.test(line)) {
          inRun = true;
          runIndent = indent;
        } else if (inRun && line.trim() && indent <= runIndent) {
          inRun = false;
        }
        const isRunLine = inRun || /^\s*(-\s*)?run:/.test(line);
        if (isRunLine && UNTRUSTED.test(line)) report(RULES.injection.id, { file: path, line: i + 1 });
        if (isRunLine && /\becho\b.*\$\{\{\s*secrets\./.test(line)) report(RULES.echoSecret.id, { file: path, line: i + 1 });
        const uses = /^\s*(?:-\s*)?uses:\s*["']?([^@\s"']+)@([^\s"'#]+)/.exec(line);
        if (uses && !/^(actions|github)\//.test(uses[1]) && !uses[1].startsWith('.') && !/^[0-9a-f]{40}$/.test(uses[2])) {
          report(RULES.unpinned.id, { file: path, line: i + 1, evidence: `${uses[1]}@${uses[2]}` });
        }
        if (hasPrTarget && /ref:\s*.*github\.(event\.pull_request\.head|head_ref)/.test(line)) {
          report(RULES.prTarget.id, { file: path, line: i + 1 });
        }
      });
      if (!/^permissions:/m.test(text) && !/^\s+permissions:/m.test(text)) report(RULES.permissions.id, { file: path });
    }
  },
};
