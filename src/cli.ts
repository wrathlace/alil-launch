#!/usr/bin/env node
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { DEFAULT_BASELINE, writeBaseline } from "./core/baseline.js";
import { CONFIG_FILE } from "./core/config.js";
import { CATEGORY_ORDER, scan, VERSION } from "./core/scanner.js";
import { createDemoProject } from "./demo.js";
import { applyFixes } from "./fix.js";
import { startMcpServer } from "./mcp.js";
import {
  monitor,
  renderMonitorJson,
  renderMonitorMarkdown,
  renderMonitorText,
  withoutCredentials,
  type MonitorRun,
} from "./monitor.js";
import { renderConsole } from "./report/console.js";
import {
  renderBadge,
  renderJson,
  renderMarkdown,
  renderPrompt,
  renderSarif,
} from "./report/formats.js";
import { renderHtml } from "./report/html.js";
import { allRules } from "./rules/index.js";
import type { Category, ScanResult, Severity } from "./types.js";
import { SEVERITIES, severityRank } from "./types.js";

const HELP = `alil-launch ${VERSION}
A lil check before you launch.

Usage
  npx alil-launch [path] [options]    Scan a project (default: current folder)
  npx alil-launch demo                Scan a deliberately broken sample project
  npx alil-launch fix [path]          Apply safe fixes (--dry-run to preview)
  npx alil-launch init [path]         Add a config file and GitHub workflows
  npx alil-launch monitor [targets]   Report what is new since the last check.
                                      Targets are folders or git URLs
  npx alil-launch rules               List every rule
  npx alil-launch explain <rule-id>   Explain one rule
  npx alil-launch mcp                 Start the MCP server for AI coding agents

Deeper checks (all off by default)
  --url <url>        Check your live site: TLS, headers, exposed files. With no
                     path, only the site is checked. Add a path to scan both
  --online           Look up CVEs and advisories for your dependencies and
                     platforms, and find packages that do not exist.
                     Sends package names and versions only
  --history          Search git history for secrets
  --run              Run the project's own build, lint and test commands

Output
  --format <name>    pretty, json, sarif, markdown or prompt (default: pretty)
  --output <file>    Write the report to a file
  --html <file>      Write a shareable HTML report
  --badge <file>     Write an SVG score badge
  --verbose          Show every finding

Control
  --fail-on <level>  Exit 1 at this severity or above (default: high)
  --only <list>      Comma list: secrets,config,dependencies,backups,deployment,launch
  --staged           Scan only staged files, for pre-commit hooks
  --baseline [file]  Ignore findings recorded in a baseline file
  --update-baseline  Record current findings in the baseline file
  --version, --help

Monitoring
  --every <hours>    Keep running and check again at this interval
  --webhook <url>    Post new issues to Slack, Discord or Teams. Also read from
                     ALIL_LAUNCH_WEBHOOK
  --state <file>     Where to remember what was seen (one target only)

Environment
  NVD_API_KEY        Optional. Makes WordPress, Joomla and Nextcloud lookups
                     about ten times faster
`;

const WORKFLOW = `name: alil-launch
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx -y alil-launch@latest --online --fail-on high
`;

const MONITOR_WORKFLOW = `name: alil-launch monitor
on:
  schedule:
    - cron: '17 6 * * *'
  workflow_dispatch:
permissions:
  contents: read
  issues: write
jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: actions/cache/restore@v4
        with:
          path: .alil-launch-monitor.json
          key: alil-launch-monitor-\${{ github.run_id }}
          restore-keys: alil-launch-monitor-
      - id: monitor
        env:
          ALIL_LAUNCH_WEBHOOK: \${{ secrets.ALIL_LAUNCH_WEBHOOK }}
          NVD_API_KEY: \${{ secrets.NVD_API_KEY }}
        run: |
          status=0
          npx -y alil-launch@latest monitor --format markdown --output alil-launch-monitor.md || status=$?
          echo "status=$status" >> "$GITHUB_OUTPUT"
      - uses: actions/cache/save@v4
        if: hashFiles('.alil-launch-monitor.json') != ''
        with:
          path: .alil-launch-monitor.json
          key: alil-launch-monitor-\${{ github.run_id }}
      - env:
          GH_TOKEN: \${{ github.token }}
          STATUS: \${{ steps.monitor.outputs.status }}
        run: |
          label=alil-launch-monitor
          [ -f alil-launch-monitor.md ] || exit 0
          cat alil-launch-monitor.md >> "$GITHUB_STEP_SUMMARY"
          number=$(gh issue list --label "$label" --state open --limit 1 --json number --jq '.[0].number // empty')
          if grep -q 'No open issues' alil-launch-monitor.md; then
            [ -z "$number" ] || gh issue close "$number" --comment 'All clear. No open issues remain.'
          elif [ -z "$number" ]; then
            gh label create "$label" --force --color B60205
            gh issue create --label "$label" --title 'Security issues found by Alil Launch' --body-file alil-launch-monitor.md
          else
            gh issue edit "$number" --body-file alil-launch-monitor.md
            [ "$STATUS" != 1 ] || gh issue comment "$number" --body 'New issues were found. See the updated description.'
          fi
      - run: exit \${{ steps.monitor.outputs.status == '1' && '0' || steps.monitor.outputs.status }}
`;

function parse() {
  return parseArgs({
    allowPositionals: true,
    options: {
      url: { type: "string" },
      online: { type: "boolean" },
      history: { type: "boolean" },
      run: { type: "boolean" },
      format: { type: "string", short: "f", default: "pretty" },
      output: { type: "string", short: "o" },
      html: { type: "string" },
      badge: { type: "string" },
      verbose: { type: "boolean", short: "v" },
      "fail-on": { type: "string" },
      only: { type: "string" },
      staged: { type: "boolean" },
      baseline: { type: "string" },
      "update-baseline": { type: "boolean" },
      "dry-run": { type: "boolean" },
      every: { type: "string" },
      webhook: { type: "string" },
      state: { type: "string" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean" },
    },
  });
}

type Values = ReturnType<typeof parse>["values"];

function render(result: ScanResult, values: Values): string {
  switch (values.format) {
    case "json":
      return renderJson(result);
    case "sarif":
      return renderSarif(result);
    case "markdown":
      return renderMarkdown(result);
    case "prompt":
      return renderPrompt(result);
    case "pretty":
      return renderConsole(result, { verbose: values.verbose });
    default:
      throw new Error(`Unknown format: ${values.format}`);
  }
}

/** A mistyped category would otherwise scan nothing and look clean. */
function parseOnly(values: Values): Category[] | undefined {
  const only = values.only?.split(",").map((s) => s.trim()) as
    | Category[]
    | undefined;
  const unknown = only?.filter((c) => !CATEGORY_ORDER.includes(c)) ?? [];
  if (unknown.length)
    throw new Error(
      `Unknown --only category: ${unknown.join(", ")}. Choose from: ${CATEGORY_ORDER.join(", ")}`,
    );
  return only;
}

function writeFile(path: string, content: string): void {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, content);
}

/** A URL with nothing that points at a folder means the site alone, not the current directory. */
function isSiteOnly(path: string | undefined, values: Values): boolean {
  return Boolean(
    values.url &&
      !path &&
      !values.online &&
      !values.history &&
      !values.run &&
      !values.staged &&
      !values.only &&
      !values["update-baseline"],
  );
}

async function runScan(
  root: string,
  values: Values,
  siteOnly = false,
): Promise<number> {
  const failOn = (values["fail-on"] ?? "high") as Severity;
  if (!SEVERITIES.includes(failOn))
    throw new Error(`--fail-on must be one of: ${SEVERITIES.join(", ")}`);
  const baselinePath =
    values.baseline ??
    (existsSync(join(root, DEFAULT_BASELINE))
      ? join(root, DEFAULT_BASELINE)
      : undefined);
  const result = await scan(root, {
    url: values.url,
    online: values.online,
    history: values.history,
    run: values.run,
    staged: values.staged,
    only: parseOnly(values),
    baseline: values["update-baseline"] ? undefined : baselinePath,
  });

  if (values["update-baseline"]) {
    const path = values.baseline ?? join(root, DEFAULT_BASELINE);
    writeBaseline(path, result.findings);
    process.stdout.write(
      `Recorded ${result.findings.length} finding(s) in ${path}\n`,
    );
    return 0;
  }

  const report = render(result, values);
  if (values.output) writeFile(values.output, report);
  else process.stdout.write(`${report}\n`);
  if (values.html) writeFile(values.html, renderHtml(result));
  if (values.badge) writeFile(values.badge, renderBadge(result));
  if (
    result.findings.some(
      (f) => severityRank(f.severity) <= severityRank(failOn),
    )
  )
    return 1;
  return result.incomplete.length ? 2 : 0;
}

const MONITOR_RENDERERS: Record<string, (run: MonitorRun) => string> = {
  json: renderMonitorJson,
  markdown: renderMonitorMarkdown,
  pretty: renderMonitorText,
};

async function runMonitorOnce(
  targets: string[],
  values: Values,
): Promise<number> {
  const failOn = (values["fail-on"] ?? "high") as Severity;
  if (!SEVERITIES.includes(failOn))
    throw new Error(`--fail-on must be one of: ${SEVERITIES.join(", ")}`);
  // Checked before any run, because a run saves its state and only alerts once.
  const renderRun = MONITOR_RENDERERS[values.format ?? "pretty"];
  if (!renderRun)
    throw new Error("monitor supports these formats: pretty, json, markdown");
  const only = parseOnly(values);
  const reports: string[] = [];
  let code = 0;
  for (const target of targets) {
    try {
      const run = await monitor(target, {
        state: values.state,
        failOn,
        url: values.url,
        only,
        baseline: values.baseline,
        webhook: values.webhook ?? process.env.ALIL_LAUNCH_WEBHOOK,
      });
      reports.push(renderRun(run));
      code = Math.max(code, run.exitCode);
    } catch (error) {
      process.stderr.write(
        `alil-launch: ${withoutCredentials(target)}: ${(error as Error).message}\n`,
      );
      code = 2;
    }
  }
  const report = reports.join("\n");
  if (values.output) writeFile(values.output, report);
  else process.stdout.write(report);
  return code;
}

const MAX_EVERY_HOURS = 24 * 24;

async function runMonitor(targets: string[], values: Values): Promise<number> {
  if (values.state && targets.length > 1)
    throw new Error("--state works with one target at a time");
  if (values.every === undefined) return runMonitorOnce(targets, values);
  const hours = Number(values.every);
  // Past this, setTimeout overflows and fires at once, which would hammer the APIs.
  if (!(hours >= 1 && hours <= MAX_EVERY_HOURS))
    throw new Error(`--every must be from 1 to ${MAX_EVERY_HOURS} hours`);
  for (;;) {
    await runMonitorOnce(targets, values);
    await new Promise((done) => setTimeout(done, hours * 3_600_000));
  }
}

function runInit(root: string): void {
  const created: string[] = [];
  const create = (file: string, content: string): void => {
    const path = join(root, file);
    if (existsSync(path)) return;
    writeFile(path, content);
    created.push(file);
  };
  create(
    CONFIG_FILE,
    `${JSON.stringify({ ignore: [], rules: {}, customRules: [] }, null, 2)}\n`,
  );
  create(".github/workflows/alil-launch.yml", WORKFLOW);
  create(".github/workflows/alil-launch-monitor.yml", MONITOR_WORKFLOW);
  process.stdout.write(
    created.length
      ? `Created: ${created.join(", ")}\n`
      : "Nothing to do. Files already exist.\n",
  );
}

async function main(): Promise<number> {
  const { values, positionals } = parse();
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  const [command, argument] = positionals;
  switch (command) {
    case "demo": {
      const root = createDemoProject();
      process.stdout.write(
        "Scanning a deliberately broken sample project. All of its secrets are fake.\n",
      );
      try {
        await runScan(root, values);
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
      return 0;
    }
    case "fix": {
      const changes = applyFixes(argument ?? ".", values["dry-run"]);
      if (!changes.length) process.stdout.write("No safe fixes to apply.\n");
      for (const change of changes)
        process.stdout.write(
          `${values["dry-run"] ? "Would change" : "Changed"} ${change.file}: ${change.description}\n`,
        );
      return 0;
    }
    case "init":
      runInit(argument ?? ".");
      return 0;
    case "rules":
      for (const rule of allRules())
        process.stdout.write(
          `${rule.severity.padEnd(9)}${rule.id.padEnd(40)}${rule.title}\n`,
        );
      process.stdout.write(`\n${allRules().length} rules\n`);
      return 0;
    case "explain": {
      if (!argument) throw new Error("Usage: alil-launch explain <rule-id>");
      const rule = allRules().find((r) => r.id === argument);
      if (!rule)
        throw new Error(
          `No rule named ${argument}. Run \`alil-launch rules\` to list them.`,
        );
      process.stdout.write(
        `${rule.title} (${rule.id})\nSeverity: ${rule.severity}\n\n${rule.description}\n\nFix: ${rule.fix}\n`,
      );
      return 0;
    }
    case "monitor":
      return runMonitor(
        positionals.length > 1 ? positionals.slice(1) : ["."],
        values,
      );
    case "mcp":
      startMcpServer();
      return -1;
    default:
      return runScan(command ?? ".", values, isSiteOnly(command, values));
  }
}

main()
  .then((code) => {
    if (code >= 0) process.exitCode = code;
  })
  .catch((error: Error) => {
    process.stderr.write(`alil-launch: ${error.message}\n`);
    process.exitCode = 2;
  });
