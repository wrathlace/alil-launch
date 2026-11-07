/** Small .gitignore matcher, used only when the project is not a git repository. */
export interface IgnoreRule {
  negate: boolean;
  regex: RegExp;
  dirOnly: boolean;
}

function toRegex(pattern: string): RegExp {
  const trimmed = pattern.replace(/\/$/, '');
  const anchored = trimmed.includes('/');
  const glob = trimmed.replace(/^\//, '');
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          out += '(?:.*/)?';
        } else {
          out += '.*';
        }
      } else {
        out += '[^/]*';
      }
    } else if (ch === '?') {
      out += '[^/]';
    } else {
      out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`${anchored ? '^' : '(?:^|/)'}${out}(?:/|$)`);
}

export function parseIgnore(text: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const negate = line.startsWith('!');
    const pattern = negate ? line.slice(1) : line;
    rules.push({ negate, regex: toRegex(pattern), dirOnly: pattern.endsWith('/') });
  }
  return rules;
}

export function isIgnored(path: string, isDir: boolean, rules: IgnoreRule[]): boolean {
  let ignored = false;
  for (const rule of rules) {
    if (rule.dirOnly && !isDir && !rule.regex.test(path)) continue;
    if (rule.regex.test(isDir ? `${path}/` : path)) ignored = !rule.negate;
  }
  return ignored;
}
