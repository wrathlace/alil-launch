import type { ScanContext, Severity } from '../types.js';
import { parseJson } from '../core/util.js';

export interface Pkg {
  name: string;
  version: string;
  ecosystem: string;
  file: string;
}

/** Dependencies a manifest names but whose installed version cannot be known from the repo. */
export interface Unchecked {
  file: string;
  severity: Severity;
  message: string;
}

interface Parsed {
  packages: Pkg[];
  unresolved: string[];
}

type Dep = [name: string, version: string | undefined];

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'];
const PYTHON_LOCKS = ['poetry.lock', 'uv.lock', 'Pipfile.lock'];
const EXACT = /^[=v]*(\d+\.\d+\.\d+[\w.+-]*)$/;
const TOML_SECTION_END = '(?=^\\[|$(?![\\s\\S]))';

function section(text: string, header: string): string[] {
  const re = new RegExp(`^\\[${header}\\]\\n([\\s\\S]*?)${TOML_SECTION_END}`, 'gm');
  return [...text.matchAll(re)].map((m) => m[1]);
}

const tomlKeys = (block: string): string[] => [...block.matchAll(/^([A-Za-z][\w.-]*)\s*=/gm)].map((m) => m[1]);

function requirementLines(lines: string[]): Dep[] {
  const out: Dep[] = [];
  for (const line of lines) {
    if (line.includes('://')) continue;
    const m = /^\s*([A-Za-z][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==\s*([^\s;#,*]+)\s*(?:[;#].*)?$)?/.exec(line);
    if (m) out.push([m[1], m[2]]);
  }
  return out;
}

function pyprojectDeps(text: string): Dep[] {
  const pep621 = [...text.matchAll(/^(?:dev-)?dependencies\s*=\s*\[([\s\S]*?)^\]/gm)]
    .flatMap((m) => [...m[1].matchAll(/["']([^"']+)["']/g)].map((q) => q[1]));
  const poetry = section(text, 'tool\\.poetry\\.(?:[\\w.-]*\\.)?dependencies').flatMap(tomlKeys)
    .filter((name) => name.toLowerCase() !== 'python');
  return [...requirementLines(pep621), ...poetry.map((name): Dep => [name, undefined])];
}

const MANIFESTS: Array<{ pattern: RegExp; ecosystem: string; locks: string[]; deps(text: string): Dep[] }> = [
  {
    pattern: /(^|\/)package\.json$/,
    ecosystem: 'npm',
    locks: NPM_LOCKS,
    deps(text) {
      const pkg = parseJson<any>(text);
      return Object.entries<any>({ ...pkg?.dependencies, ...pkg?.devDependencies })
        .filter(([, spec]) => !/^(file:|link:|workspace:|portal:|git|https?:)/.test(String(spec)))
        .map(([name, spec]) => [name, EXACT.exec(String(spec))?.[1]]);
    },
  },
  {
    pattern: /(^|\/)composer\.json$/,
    ecosystem: 'Packagist',
    locks: ['composer.lock'],
    deps(text) {
      const pkg = parseJson<any>(text);
      return Object.entries<any>({ ...pkg?.require, ...pkg?.['require-dev'] })
        .filter(([name]) => name.includes('/'))
        .map(([name, spec]) => [name, EXACT.exec(String(spec))?.[1]]);
    },
  },
  { pattern: /(^|\/)requirements[^/]*\.txt$/, ecosystem: 'PyPI', locks: PYTHON_LOCKS, deps: (text) => requirementLines(text.split('\n')) },
  { pattern: /(^|\/)pyproject\.toml$/, ecosystem: 'PyPI', locks: PYTHON_LOCKS, deps: pyprojectDeps },
  {
    pattern: /(^|\/)Gemfile$/,
    ecosystem: 'RubyGems',
    locks: ['Gemfile.lock'],
    deps: (text) => [...text.matchAll(/^\s*gem\s+['"]([^'"]+)['"]/gm)].map((m): Dep => [m[1], undefined]),
  },
  {
    pattern: /(^|\/)Cargo\.toml$/,
    ecosystem: 'crates.io',
    locks: ['Cargo.lock'],
    deps: (text) => section(text, '(?:dev-|build-)?dependencies').flatMap(tomlKeys).map((name): Dep => [name, undefined]),
  },
];

const element = (text: string, name: string): string | undefined =>
  new RegExp(`<${name}>\\s*([\\s\\S]*?)\\s*</${name}>`).exec(text)?.[1];

function fromPom(text: string, file: string): Parsed {
  const body = text.replace(/<!--[\s\S]*?-->/g, '');
  const properties = new Map([...(element(body, 'properties') ?? '').matchAll(/<([\w.-]+)>\s*([^<]+?)\s*<\/\1>/g)].map((m) => [m[1], m[2]]));
  const resolve = (version?: string): string | undefined => {
    const value = version?.replace(/\$\{([^}]+)\}/g, (all, key) => properties.get(key) ?? all);
    return value && /^\d/.test(value) && !value.includes('${') ? value : undefined;
  };
  const blocks = [...body.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].map((m) => m[1]);
  const parent = element(body, 'parent');
  if (parent) blocks.push(parent);
  const coordinates = (block: string): string => `${element(block, 'groupId')}:${element(block, 'artifactId')}`;
  // A version in dependencyManagement also applies to the same package listed without one.
  const managed = new Map<string, string>();
  for (const block of blocks) {
    const version = resolve(element(block, 'version'));
    if (version) managed.set(coordinates(block), version);
  }
  const parsed: Parsed = { packages: [], unresolved: [] };
  for (const name of new Set(blocks.map(coordinates))) {
    const version = managed.get(name);
    if (version) parsed.packages.push({ name, version, ecosystem: 'Maven', file });
    else parsed.unresolved.push(name);
  }
  return parsed;
}

const GRADLE_DEPENDENCY = /\b(?:implementation|api|compile|runtime|compileOnly|runtimeOnly|annotationProcessor|kapt|ksp|testImplementation|testCompile|testRuntimeOnly|developmentOnly|classpath)\b\s*\(?\s*(?:platform\(\s*)?['"]([\w.-]+:[\w.-]+)(?::([^'"]+))?['"]/g;

function fromGradle(text: string, file: string): Parsed {
  const parsed: Parsed = { packages: [], unresolved: [] };
  for (const m of text.matchAll(GRADLE_DEPENDENCY)) {
    if (m[2] && /^\d/.test(m[2])) parsed.packages.push({ name: m[1], version: m[2], ecosystem: 'Maven', file });
    else parsed.unresolved.push(m[1]);
  }
  return parsed;
}

function fromVersionCatalog(text: string, file: string): Parsed {
  const versions = new Map((section(text, 'versions')[0] ?? '').split('\n').flatMap((line) => {
    const m = /^([\w.-]+)\s*=\s*"([^"]+)"/.exec(line);
    return m ? [[m[1], m[2]] as const] : [];
  }));
  const parsed: Parsed = { packages: [], unresolved: [] };
  for (const line of (section(text, 'libraries')[0] ?? '').split('\n')) {
    const short = /=\s*"([\w.-]+:[\w.-]+):([^"]+)"/.exec(line);
    const long = /module\s*=\s*"([\w.-]+:[\w.-]+)"/.exec(line);
    const split = /group\s*=\s*"([\w.-]+)".*name\s*=\s*"([\w.-]+)"/.exec(line);
    const name = short?.[1] ?? long?.[1] ?? (split ? `${split[1]}:${split[2]}` : undefined);
    if (!name) continue;
    const ref = /version\.ref\s*=\s*"([^"]+)"/.exec(line)?.[1];
    const version = short?.[2] ?? /version\s*=\s*"([^"]+)"/.exec(line)?.[1] ?? (ref ? versions.get(ref) : undefined);
    if (version) parsed.packages.push({ name, version, ecosystem: 'Maven', file });
    else parsed.unresolved.push(name);
  }
  return parsed;
}

function fromDotnetProject(text: string, file: string): Parsed {
  const parsed: Parsed = { packages: [], unresolved: [] };
  const re = /<(PackageReference|PackageVersion|package)\b([^>]*?)(?:\/>|>([\s\S]*?)<\/\1>)/gi;
  for (const m of text.matchAll(re)) {
    const name = /\b(?:Include|id)="([^"]+)"/i.exec(m[2])?.[1];
    const version = /\bVersion="([^"]+)"/i.exec(m[2])?.[1] ?? /<Version>\s*([^<\s]+)/i.exec(m[3] ?? '')?.[1];
    if (!name) continue;
    if (version && /^\d/.test(version)) parsed.packages.push({ name, version, ecosystem: 'NuGet', file });
    else parsed.unresolved.push(name);
  }
  return parsed;
}

const GRADLE_ADVICE = 'Enable Gradle dependency locking and commit gradle.lockfile.';
const BUILD_FILES: Array<{ pattern: RegExp; locks: string[]; parse(text: string, file: string): Parsed; advice: string }> = [
  { pattern: /(^|\/)pom\.xml$/, locks: [], parse: fromPom, advice: 'Run `mvn dependency:tree` to see the full list.' },
  { pattern: /(^|\/)build\.gradle(\.kts)?$/, locks: ['gradle.lockfile'], parse: fromGradle, advice: GRADLE_ADVICE },
  { pattern: /(^|\/)libs\.versions\.toml$/, locks: ['gradle.lockfile'], parse: fromVersionCatalog, advice: GRADLE_ADVICE },
  {
    pattern: /(\.(cs|fs|vb)proj|(^|\/)Directory\.Packages\.props|(^|\/)packages\.config)$/,
    locks: ['packages.lock.json'],
    parse: fromDotnetProject,
    advice: 'Set RestorePackagesWithLockFile and commit packages.lock.json.',
  },
];

function sample(names: string[]): string {
  const unique = [...new Set(names)];
  return `${unique.slice(0, 5).join(', ')}${unique.length > 5 ? ` and ${unique.length - 5} more` : ''}`;
}

/** Reads what it can from manifests, and reports the rest, so a missing lockfile is never read as clean. */
export function readManifests(ctx: Pick<ScanContext, 'matching' | 'exists'>): { packages: Pkg[]; unchecked: Unchecked[] } {
  const packages: Pkg[] = [];
  const unchecked: Unchecked[] = [];
  const hasLock = (file: string, locks: string[]): boolean => {
    const dir = file.slice(0, file.lastIndexOf('/') + 1);
    return locks.some((lock) => ctx.exists(dir + lock) || ctx.exists(lock));
  };

  for (const manifest of MANIFESTS) {
    for (const { path, text } of ctx.matching(manifest.pattern)) {
      if (hasLock(path, manifest.locks)) continue;
      const deps = manifest.deps(text.replace(/\r\n/g, '\n'));
      if (!deps.length) continue;
      for (const [name, version] of deps) if (version) packages.push({ name, version, ecosystem: manifest.ecosystem, file: path });
      const loose = deps.filter(([, version]) => !version).map(([name]) => name);
      unchecked.push(loose.length
        ? { file: path, severity: 'high', message: `There is no lockfile, so the installed versions of ${loose.length} of ${deps.length} direct dependencies are unknown and were not checked: ${sample(loose)}. Their own dependencies were not checked either.` }
        : { file: path, severity: 'low', message: `There is no lockfile, so only direct dependencies can be looked up (${deps.length} found), not their own dependencies.` });
    }
  }

  for (const { pattern, locks, parse, advice } of BUILD_FILES) {
    for (const { path, text } of ctx.matching(pattern)) {
      if (hasLock(path, locks)) continue;
      const parsed = parse(text.replace(/\r\n/g, '\n'), path);
      const total = parsed.packages.length + parsed.unresolved.length;
      if (!total) continue;
      packages.push(...parsed.packages);
      unchecked.push(parsed.unresolved.length
        ? { file: path, severity: 'medium', message: `${parsed.unresolved.length} of ${total} dependencies get their version from elsewhere, such as a parent or BOM, and were not checked: ${sample(parsed.unresolved)}. Their own dependencies were not checked either. ${advice}` }
        : { file: path, severity: 'low', message: `Only direct dependencies can be looked up (${total} found), not their own dependencies. ${advice}` });
    }
  }
  return { packages, unchecked };
}
