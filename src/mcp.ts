import { createInterface } from 'node:readline';
import { allRules } from './rules/index.js';
import { scan, VERSION } from './core/scanner.js';
import { renderPrompt } from './report/formats.js';
import type { Category } from './types.js';

const TOOLS = [
  {
    name: 'scan_project',
    description: 'Check whether a project is safe to launch. Finds secrets, unsafe settings, missing backups and deployment mistakes. Results never contain secret values.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path of the project folder' },
        categories: { type: 'array', items: { type: 'string' }, description: 'Optional filter, such as ["secrets","backups"]' },
        online: { type: 'boolean', description: 'Also look up known vulnerabilities (CVEs). Sends package names and versions to public vulnerability databases' },
      },
      required: ['path'],
    },
  },
  {
    name: 'explain_rule',
    description: 'Explain an Alil Launch rule and how to fix it.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
  },
];

async function callTool(name: string, args: any): Promise<string> {
  if (name === 'scan_project') {
    const result = await scan(args.path, { only: args.categories as Category[] | undefined, online: args.online === true });
    return renderPrompt(result);
  }
  if (name === 'explain_rule') {
    const rule = allRules().find((r) => r.id === args.id);
    return rule ? JSON.stringify(rule, null, 2) : `No rule named ${args.id}.`;
  }
  throw new Error(`Unknown tool: ${name}`);
}

async function handle(message: any): Promise<unknown> {
  switch (message.method) {
    case 'initialize':
      return {
        protocolVersion: message.params?.protocolVersion ?? '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'alil-launch', version: VERSION },
      };
    case 'ping':
      return {};
    case 'tools/list':
      return { tools: TOOLS };
    case 'tools/call':
      try {
        const text = await callTool(message.params.name, message.params.arguments ?? {});
        return { content: [{ type: 'text', text }] };
      } catch (error) {
        return { isError: true, content: [{ type: 'text', text: (error as Error).message }] };
      }
    default:
      throw Object.assign(new Error(`Method not found: ${message.method}`), { code: -32601 });
  }
}

/** Minimal Model Context Protocol server over stdio, so AI coding agents can run scans. */
export function startMcpServer(): void {
  const lines = createInterface({ input: process.stdin });
  lines.on('line', async (line) => {
    if (!line.trim()) return;
    let message: any;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (message.id === undefined) return;
    try {
      const result = await handle(message);
      process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result })}\n`);
    } catch (error) {
      const { code = -32603, message: text } = error as Error & { code?: number };
      process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code, message: text } })}\n`);
    }
  });
}
