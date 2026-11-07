import type { Checker, RuleMeta, Reporter } from '../types.js';

const rule = (id: string, title: string, severity: RuleMeta['severity'], description: string, fix: string): RuleMeta => ({
  id, title, severity, description, fix, category: 'config',
});

const RULES = {
  root: rule('docker/runs-as-root', 'Container runs as root', 'medium', 'A compromised app gets root inside the container.', 'Add a non-root `USER` before the final CMD.'),
  latest: rule('docker/unpinned-base-image', 'Base image is not pinned', 'medium', 'Builds change without warning when `latest` moves.', 'Pin an exact version, such as `node:22.11-alpine`.'),
  secretEnv: rule('docker/secret-in-image', 'Secret baked into the image', 'critical', 'ENV and ARG values stay readable in image layers.', 'Pass secrets at runtime or use BuildKit secrets.'),
  curlPipe: rule('docker/curl-pipe-shell', 'Remote script piped into a shell', 'high', 'The build runs whatever that URL serves that day.', 'Download a pinned version and verify its checksum.'),
  ignore: rule('docker/no-dockerignore', 'No .dockerignore', 'high', '`COPY .` can bake .env files and git history into the image.', 'Add a .dockerignore. `alil-launch fix` can create one.'),
  healthcheck: rule('docker/no-healthcheck', 'No container health check', 'low', 'Orchestrators cannot tell whether the app is working.', 'Add a HEALTHCHECK instruction.'),
  sock: rule('compose/docker-socket-mounted', 'Docker socket mounted into a container', 'critical', 'Access to the socket is root access on the host.', 'Remove the mount, or put a restricted socket proxy in front of it.'),
  privileged: rule('compose/privileged', 'Privileged container', 'high', 'A privileged container can take over the host.', 'Remove `privileged: true`.'),
  hostNet: rule('compose/host-network', 'Host networking enabled', 'medium', 'The container shares the host network with no isolation.', 'Use bridge networks and publish only what you need.'),
  dbPort: rule('compose/database-port-exposed', 'Database port published to all interfaces', 'high', 'Docker port rules can bypass host firewalls, leaving the database on the internet.', 'Remove the port mapping or bind it to `127.0.0.1`.'),
  weakPass: rule('compose/weak-default-password', 'Weak or hardcoded service password', 'high', 'A guessable password is committed in the compose file.', 'Use `${VAR}` substitution with a strong value from an uncommitted env file.'),
  latestImage: rule('compose/unpinned-image', 'Service image is not pinned', 'low', 'Restarting can silently upgrade a service.', 'Pin a version tag.'),
  noVolume: rule('compose/database-without-volume', 'Database has no persistent volume', 'critical', 'Recreating this container deletes all data.', 'Mount a named volume at the data directory.'),
  restart: rule('compose/no-restart-policy', 'No restart policy', 'low', 'The service stays down after a crash or reboot.', 'Add `restart: unless-stopped`.'),
};

const DB_IMAGE = /(?:^|\/)(postgres|postgis|mysql|mariadb|mongo|redis|elasticsearch|clickhouse|timescaledb)(?::|$)/i;
const DB_PORTS = /(^|[:"'\s-])(5432|3306|27017|6379|9200|8123)\s*:\s*\d+/;
const DATA_DIR = /\/var\/lib\/(postgresql|mysql)|\/data\b|\/bitnami|\/usr\/share\/elasticsearch\/data/;
const SECRET_ENV = /^\s*(?:ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*[= ]\s*["']?[^\s"'$]+/i;

function checkDockerfile(path: string, text: string, ctxHasIgnore: boolean, report: Reporter): void {
  const lines = text.split('\n');
  let lastUser = '';
  let hasHealthcheck = false;
  let copiesAll = false;
  const stages = new Set<string>();
  lines.forEach((raw, i) => {
    const line = raw.trim();
    const from = /^FROM\s+(?:--\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (from) {
      lastUser = '';
      const image = from[1];
      if (from[2]) stages.add(from[2].toLowerCase());
      const tagged = /:[^/]+$/.test(image) || image.includes('@sha256:');
      if (!stages.has(image.toLowerCase()) && image !== 'scratch' && !image.includes('$') && (!tagged || /:latest$/.test(image))) {
        report(RULES.latest.id, { file: path, line: i + 1, evidence: image });
      }
    }
    if (/^USER\s+/i.test(line)) lastUser = line.split(/\s+/)[1];
    if (/^HEALTHCHECK\s+/i.test(line)) hasHealthcheck = true;
    if (/^(COPY|ADD)\s+(--\S+\s+)*\.\s/i.test(line)) copiesAll = true;
    if (SECRET_ENV.test(line) && !/\s[A-Z_]+$|=[A-Z_]+$|placeholder|dummy|blank/i.test(line)) report(RULES.secretEnv.id, { file: path, line: i + 1, evidence: line.split(/[= ]/).slice(0, 2).join(' ') });
    if (/\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(line)) report(RULES.curlPipe.id, { file: path, line: i + 1 });
  });
  if (!/^\s*FROM/im.test(text)) return;
  if (!lastUser || /^(root|0)(:|$)/.test(lastUser)) report(RULES.root.id, { file: path });
  if (!hasHealthcheck) report(RULES.healthcheck.id, { file: path });
  if (copiesAll && !ctxHasIgnore) report(RULES.ignore.id, { file: path });
}

interface Block {
  name: string;
  line: number;
  lines: Array<{ text: string; number: number }>;
}

/** Splits a compose file into services by indentation, which avoids needing a YAML dependency. */
function serviceBlocks(text: string): Block[] {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => /^services:\s*(#.*)?$/.test(l));
  if (start < 0) return [];
  const blocks: Block[] = [];
  let indent = -1;
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const width = line.length - line.trimStart().length;
    if (width === 0) break;
    if (indent < 0) indent = width;
    if (width === indent && /^\s*[\w.-]+:\s*$/.test(line)) {
      blocks.push({ name: line.trim().slice(0, -1), line: i + 1, lines: [] });
    } else if (blocks.length) {
      blocks[blocks.length - 1].lines.push({ text: line, number: i + 1 });
    }
  }
  return blocks;
}

const WEAK = /^(admin|root|password\d*|pass|secret|123456\d*|changeme|example|test|postgres|mysql|wordpress|default|qwerty)$/i;

function checkCompose(path: string, text: string, report: Reporter): void {
  for (const service of serviceBlocks(text)) {
    const find = (re: RegExp) => service.lines.find((l) => re.test(l.text) && !/^\s*#/.test(l.text));
    const image = find(/^\s*image:/)?.text.split('image:')[1].trim().replace(/["']/g, '') ?? '';
    const isDb = DB_IMAGE.test(image);
    if (image && !image.includes('$') && (!/:[^/]+$/.test(image) || image.endsWith(':latest'))) {
      report(RULES.latestImage.id, { file: path, line: service.line, evidence: `${service.name}: ${image}` });
    }
    const sock = find(/docker\.sock/);
    if (sock) report(RULES.sock.id, { file: path, line: sock.number, key: service.name, message: `Service \`${service.name}\` can control the Docker host.` });
    const privileged = find(/^\s*privileged:\s*true/);
    if (privileged) report(RULES.privileged.id, { file: path, line: privileged.number, key: service.name });
    const net = find(/^\s*network_mode:\s*["']?host/);
    if (net) report(RULES.hostNet.id, { file: path, line: net.number, key: service.name });
    if (isDb) {
      for (const l of service.lines) {
        if (DB_PORTS.test(l.text) && /^\s*-/.test(l.text) && !/127\.0\.0\.1|localhost/.test(l.text)) {
          report(RULES.dbPort.id, { file: path, line: l.number, key: service.name, message: `Service \`${service.name}\` publishes its database port.` });
        }
      }
      if (!/redis/i.test(image) && !service.lines.some((l) => /^\s*-/.test(l.text) && DATA_DIR.test(l.text))) {
        report(RULES.noVolume.id, { file: path, line: service.line, key: service.name, message: `Service \`${service.name}\` loses its data when recreated.` });
      }
    }
    for (const l of service.lines) {
      const env = /^\s*-?\s*["']?([A-Z_]*(?:PASSWORD|PASS|PASSWD))["']?\s*[:=]\s*["']?([^"'\s$]{1,40})["']?\s*$/.exec(l.text);
      if (env && WEAK.test(env[2]) || (env && env[2].toLowerCase() === service.name.toLowerCase())) {
        report(RULES.weakPass.id, { file: path, line: l.number, key: `${service.name}:${env![1]}`, message: `\`${env![1]}\` in \`${service.name}\` uses a guessable value.` });
      }
    }
    if (!find(/^\s*restart:/) && !find(/^\s*deploy:/) && /(^|\/)(docker-)?compose(\.prod(uction)?)?\.ya?ml$/.test(path) && /prod/.test(path)) {
      report(RULES.restart.id, { file: path, line: service.line, key: service.name });
    }
  }
}

export const containersChecker: Checker = {
  name: 'containers',
  rules: Object.values(RULES),
  run(ctx, report) {
    const hasIgnore = ctx.exists('.dockerignore');
    for (const { path, text } of ctx.matching(/(^|\/)Dockerfile(\.[\w-]+)?$|\.dockerfile$/i)) checkDockerfile(path, text, hasIgnore, report);
    for (const { path, text } of ctx.matching(/(^|\/)(docker-)?compose[^/]*\.ya?ml$/i)) checkCompose(path, text, report);
  },
};
