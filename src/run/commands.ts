import { spawn } from 'node:child_process';
import { delimiter, dirname } from 'node:path';
import type { Checker, RuleMeta, ScanContext } from '../types.js';
import { parseJson } from '../core/util.js';

const rule = (id: string, title: string, description: string, fix: string): RuleMeta => ({
  id, title, description, fix, category: 'checks', severity: 'critical',
});

const RULES = {
  failed: rule('run/command-failed', 'Project command failed', 'Your own build, test, lint or type check failed.', 'Run the command locally and fix the first error.'),
  timeout: rule('run/command-timed-out', 'Project command timed out', 'A build or test did not finish in 10 minutes.', 'Find the hang, or run the command in CI with a longer limit.'),
  unavailable: { ...rule('run/command-unavailable', 'Project command could not run', 'A tool the command needs is missing, so this check says nothing about your code.', 'Install the tool, or run this check in CI.'), severity: 'low' as const },
};

const TIMEOUT_MS = 10 * 60 * 1000;
const TOOL_MISSING = /is not recognized as an internal or external command|: command not found/;

export interface ProjectCommand {
  label: string;
  command: string;
  severity: 'critical' | 'high' | 'medium';
}

export function detectCommands(ctx: Pick<ScanContext, 'read' | 'exists'>): ProjectCommand[] {
  const commands: ProjectCommand[] = [];
  const pkg = parseJson<any>(ctx.read('package.json'));
  if (pkg?.scripts) {
    const runner = ctx.exists('pnpm-lock.yaml') ? 'pnpm' : ctx.exists('yarn.lock') ? 'yarn' : ctx.exists('bun.lockb') || ctx.exists('bun.lock') ? 'bun' : 'npm';
    const add = (script: string, severity: ProjectCommand['severity']): void => {
      const body = pkg.scripts[script];
      if (body && !/no test specified/.test(body)) commands.push({ label: script, command: `${runner} run ${script}`, severity });
    };
    add('typecheck', 'high');
    add('lint', 'medium');
    add('test', 'high');
    add('build', 'critical');
  }
  if (ctx.exists('go.mod')) commands.push({ label: 'go test', command: 'go test ./...', severity: 'high' });
  if (ctx.exists('Cargo.toml')) commands.push({ label: 'cargo test', command: 'cargo test', severity: 'high' });
  if (ctx.exists('pytest.ini') || ctx.exists('conftest.py') || /pytest/.test(ctx.read('pyproject.toml') ?? '') || /pytest/.test(ctx.read('requirements.txt') ?? '')) {
    commands.push({ label: 'pytest', command: 'python -m pytest -q', severity: 'high' });
  }
  return commands;
}

/** Package managers usually sit next to node, even when the shell PATH omits them. */
function commandEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, CI: '1' };
  const keys = Object.keys(env).filter((key) => key.toUpperCase() === 'PATH');
  for (const key of keys.length ? keys : ['PATH']) env[key] = `${dirname(process.execPath)}${delimiter}${env[key] ?? ''}`;
  return env;
}

function execute(command: string, cwd: string): Promise<{ code: number | null; output: string; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(command, { cwd, shell: true, env: commandEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let timedOut = false;
    const keep = (chunk: Buffer): void => {
      output = (output + chunk.toString()).slice(-4000);
    };
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, TIMEOUT_MS);
    child.on('error', () => undefined);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, output, timedOut });
    });
  });
}

export const runChecker: Checker = {
  name: 'run',
  rules: Object.values(RULES),
  async run(ctx, report) {
    if (!ctx.options.run) return;
    for (const { label, command, severity } of detectCommands(ctx)) {
      const result = await execute(command, ctx.root);
      if (result.timedOut) {
        report(RULES.timeout.id, { key: label, severity, message: `\`${command}\` timed out.` });
      } else if (result.code === 127 || result.code === 9009 || TOOL_MISSING.test(result.output)) {
        report(RULES.unavailable.id, { key: label, message: `\`${command}\` could not start because a tool is not installed here.` });
      } else if (result.code !== 0) {
        const tail = result.output.trim().split('\n').slice(-6).join(' | ').slice(0, 400);
        report(RULES.failed.id, { key: label, severity, message: `\`${command}\` exited with code ${result.code}. ${tail}` });
      }
    }
  },
};
