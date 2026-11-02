import { readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join, relative } from 'node:path';
import type { Sighting } from '../types.js';

/** Parse a dotenv file into name/value pairs. Supports `export`, quotes, comments and multi-line quoted values. */
export function parseEnv(text: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const name = m[1]!;
    let raw = m[2]!;
    const quote = raw[0];
    let value: string;
    if (quote === '"' || quote === "'" || quote === '`') {
      // Collect lines until the closing quote (PEM keys are often multi-line).
      let body = raw.slice(1);
      while (!body.includes(quote) && i + 1 < lines.length) body += '\n' + lines[++i];
      const end = body.indexOf(quote);
      value = end === -1 ? body : body.slice(0, end);
      if (quote === '"') value = value.replace(/\\n/g, '\n');
    } else {
      raw = raw.replace(/\s+#.*$/, '');
      value = raw.trim();
    }
    out.push({ name, value });
  }
  return out;
}

const ENV_FILE = /^\.env(\..+)?$/;
const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'out', '.vercel', '.turbo', 'coverage']);

/** Find `.env*` files under `root` (max depth 3, skips node_modules and build output). */
export function findEnvFiles(root: string, depth = 3): string[] {
  const found: string[] = [];
  const walk = (dir: string, level: number) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (level < depth && !SKIP_DIRS.has(entry)) walk(full, level + 1);
      } else if (ENV_FILE.test(entry)) {
        found.push(full);
      }
    }
  };
  walk(root, 0);
  return found.sort();
}

/** Template files list names, but their values are placeholders. */
export function isTemplateFile(path: string): boolean {
  return /\.(example|sample|template|dist)$/.test(basename(path));
}

export function scanEnvFile(path: string, root = process.cwd()): Sighting[] {
  const template = isTemplateFile(path);
  const location = (relative(root, path) || basename(path)) + (template ? ' (template)' : '');
  return parseEnv(readFileSync(path, 'utf8')).map(({ name, value }) => ({
    name,
    platform: 'env' as const,
    location,
    ...(template || !value ? {} : { value }),
  }));
}
