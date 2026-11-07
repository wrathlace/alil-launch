import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Config } from '../types.js';

export const CONFIG_FILE = '.alil-launch.json';

export function loadConfig(root: string): Config {
  try {
    const parsed = JSON.parse(readFileSync(join(root, CONFIG_FILE), 'utf8')) as Config;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw new Error(`${CONFIG_FILE} is not valid JSON: ${(error as Error).message}`);
  }
}
