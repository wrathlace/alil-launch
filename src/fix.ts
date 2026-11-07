import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { usedEnvVars } from './core/env.js';
import { buildContext } from './core/scanner.js';

export interface FixChange {
  file: string;
  description: string;
}

const DOCKERIGNORE = `.git
.env
.env.*
!.env.example
node_modules
dist
build
coverage
*.log
*.pem
*.sql
*.dump
`;

/** Only adds safe project files. It never edits source code and never touches existing values. */
export function applyFixes(rootInput: string, dryRun = false): FixChange[] {
  const ctx = buildContext(rootInput, {});
  const changes: FixChange[] = [];
  const path = (file: string): string => join(ctx.root, file);

  const gitignorePath = path('.gitignore');
  const gitignore = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf8') : '';
  if (!/^\s*\/?(\*\*\/)?\.env(\*|\.\*)?\s*$/m.test(gitignore)) {
    changes.push({ file: '.gitignore', description: 'Ignore .env files, keeping .env.example' });
    if (!dryRun) {
      const prefix = gitignore && !gitignore.endsWith('\n') ? '\n' : '';
      writeFileSync(gitignorePath, `${gitignore}${prefix}.env\n.env.*\n!.env.example\n`);
    }
  }

  const hasExample = ctx.files.some((f) => /(^|\/)\.env\.(example|sample|template)$/i.test(f));
  const used = [...usedEnvVars(ctx).keys()].sort();
  if (!hasExample && used.length) {
    changes.push({ file: '.env.example', description: `List ${used.length} environment variable(s) with empty values` });
    if (!dryRun) writeFileSync(path('.env.example'), `${used.map((name) => `${name}=`).join('\n')}\n`);
  }

  const usesDocker = ctx.files.some((f) => /(^|\/)Dockerfile/.test(f));
  if (usesDocker && !existsSync(path('.dockerignore'))) {
    changes.push({ file: '.dockerignore', description: 'Keep secrets and git history out of images' });
    if (!dryRun) writeFileSync(path('.dockerignore'), DOCKERIGNORE);
  }
  return changes;
}
