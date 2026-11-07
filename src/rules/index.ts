import type { Checker, RuleMeta } from '../types.js';
import { liveChecker } from '../live/url.js';
import { runChecker } from '../run/commands.js';
import { backupsChecker } from './backups.js';
import { ciChecker } from './ci.js';
import { configChecker } from './config.js';
import { containersChecker } from './containers.js';
import { dependenciesChecker } from './dependencies.js';
import { deploymentChecker } from './deployment.js';
import { launchChecker } from './launch.js';
import { secretsChecker } from './secrets.js';

export const CHECKERS: Checker[] = [
  secretsChecker, configChecker, containersChecker, ciChecker, dependenciesChecker,
  backupsChecker, deploymentChecker, launchChecker, runChecker, liveChecker,
];

export function allRules(): RuleMeta[] {
  return CHECKERS.flatMap((c) => c.rules);
}
