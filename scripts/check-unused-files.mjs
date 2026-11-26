/**
 * Verifies that every non-test file under `src/` is transitively imported from
 * `src/main.tsx` (zero dead source files left behind).
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import ts from 'typescript';

const REPO_ROOT = process.cwd();
const SRC_DIR = resolve(REPO_ROOT, 'src');
const ENTRY_FILE = resolve(SRC_DIR, 'main.tsx');

function collectAllSourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectAllSourceFiles(full));
    } else if (
      entry.isFile() &&
      !entry.name.endsWith('.test.ts') &&
      !entry.name.endsWith('.test.tsx')
    ) {
      out.push(full);
    }
  }
  return out;
}

function resolveImport(fromFile, specifier) {
  if (!specifier.startsWith('.')) return null;
  const base = resolve(dirname(fromFile), specifier);
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.css`,
    join(base, 'index.ts'),
    join(base, 'index.tsx'),
  ];
  for (const c of candidates) {
    if (existsSync(c) && statSync(c).isFile()) {
      return c;
    }
  }
  return null;
}

function collectSpecifiers(filePath) {
  if (filePath.endsWith('.css')) return [];
  const text = readFileSync(filePath, 'utf8');
  const sf = ts.createSourceFile(filePath, text, ts.ScriptTarget.Latest, true);
  const specs = [];
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specs.push(node.moduleSpecifier.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return specs;
}

const visited = new Set();
const queue = [ENTRY_FILE];

while (queue.length > 0) {
  const current = queue.pop();
  if (visited.has(current)) continue;
  visited.add(current);

  for (const spec of collectSpecifiers(current)) {
    const resolved = resolveImport(current, spec);
    if (resolved && !visited.has(resolved)) {
      queue.push(resolved);
    }
  }
}

const allSourceFiles = collectAllSourceFiles(SRC_DIR);
const unused = allSourceFiles.filter((f) => !visited.has(f));

if (unused.length > 0) {
  console.error('Unused source files found under src/:');
  for (const f of unused) {
    console.error(`  - ${relative(REPO_ROOT, f)}`);
  }
  process.exit(1);
}

console.log(
  `Dead-code check passed: all ${allSourceFiles.length} non-test source files under src/ are reachable from src/main.tsx.`,
);
