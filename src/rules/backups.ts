import type { Checker, RuleMeta } from '../types.js';
import { isTestPath } from '../core/util.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'backups',
});

const RULES = {
  missing: rule('backup/none-found', 'No backup setup found', 'high', 'The project uses a database, but nothing in it shows how data is backed up.', 'Schedule automated backups (pg_dump, mysqldump, restic, Litestream or your provider), then record the setup in the repo.'),
  restore: rule('backup/no-restore-plan', 'No restore procedure documented', 'medium', 'A backup you have never restored may not work.', 'Write down the restore steps in a runbook and test them on a schedule.'),
  dump: rule('backup/dump-committed', 'Database dump committed to the repo', 'high', 'Dumps often contain real user data and password hashes.', 'Remove it from git and history, then treat the data as exposed.'),
  sqlite: rule('backup/sqlite-in-repo', 'SQLite database committed to the repo', 'high', 'Production data can leak, and deploys can overwrite it.', 'Remove it from git and keep it on a persistent volume.'),
  ephemeral: rule('backup/sqlite-on-serverless', 'SQLite on an ephemeral host', 'high', 'Vercel, Netlify and similar hosts wipe the disk, so data is lost on deploy.', 'Use a hosted database, or a persistent volume with Litestream.'),
};

const EVIDENCE = /\b(pg_dump|pg_basebackup|pgbackrest|wal-g|barman|mysqldump|mariabackup|xtrabackup|mongodump|restic|borgbackup|borg create|duplicity|litestream|velero|aws backup|backup_retention_period|point_in_time_recovery|pitr|automated_backups|rclone sync|kopia)\b/i;
const BACKUP_FILE = /(^|\/)[^/]*(backup|restic|litestream)[^/]*$/i;
const RESTORE = /\b(pg_restore|mongorestore|restic restore|litestream restore|restore (the |a |from )?(database|backup|db))\b/i;
const DUMP_FILE = /\.(sql|dump|bak|sql\.gz|dump\.gz|bson)$/i;
const MIGRATION_PATH = /(^|\/)(migrations?|schema|seeds?|sql|db\/(migrate|init)|supabase|init)(\/|$)/i;
const SQLITE_FILE = /\.(sqlite3?|db)$/i;

export const backupsChecker: Checker = {
  name: 'backups',
  rules: Object.values(RULES),
  run(ctx, report) {
    for (const path of ctx.allPaths) {
      if (isTestPath(path)) continue;
      const tracked = !ctx.git.isRepo || ctx.git.tracked.has(path);
      if (!tracked || /(^|\/)(node_modules|vendor)\//.test(path)) continue;
      if (SQLITE_FILE.test(path)) {
        report(RULES.sqlite.id, { file: path });
      } else if (DUMP_FILE.test(path)) {
        const text = ctx.read(path);
        const looksLikeData = text === null || /^\s*INSERT INTO\b/im.test(text) || /^COPY .* FROM stdin/im.test(text);
        const plainMigration = MIGRATION_PATH.test(path) && !/dump|backup/i.test(path) && (text?.match(/^\s*INSERT INTO\b/gim)?.length ?? 0) < 20;
        if (looksLikeData && !plainMigration) report(RULES.dump.id, { file: path });
      }
    }

    if (ctx.stack.databases.length === 0) return;
    const usesSqlite = ctx.stack.databases.includes('sqlite');
    const serverless = ctx.exists('vercel.json') || ctx.exists('netlify.toml') || ctx.stack.frameworks.includes('next');
    if (usesSqlite && serverless) report(RULES.ephemeral.id, { message: 'SQLite is in use and this project looks serverless.' });

    const managed = ctx.stack.databases.some((db) => db === 'supabase' || db === 'firebase');
    let found = ctx.files.some((f) => BACKUP_FILE.test(f));
    let restorable = false;
    const docs = ctx.matching(/\.(sh|ya?ml|tf|md|toml|json|conf|cron|txt)$|(^|\/)(crontab|Makefile|Procfile)$/i);
    for (const { text } of docs) {
      if (EVIDENCE.test(text)) found = true;
      if (RESTORE.test(text)) restorable = true;
    }
    if (!found) {
      report(RULES.missing.id, {
        severity: managed ? 'medium' : 'high',
        message: `Uses ${ctx.stack.databases.join(', ')}, but no backup tooling or schedule was found.${managed ? ' Your provider may offer backups, so confirm they are on for your plan.' : ''}`,
      });
    } else if (!restorable) {
      report(RULES.restore.id);
    }
  },
};
