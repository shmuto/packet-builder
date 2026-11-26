import { execFileSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const LEGACY_COMMIT = 'ffbcf65';
const REPO_ROOT = process.cwd();
const DIST_LEGACY = join(REPO_ROOT, 'dist', 'legacy');
const CI_LEGACY_DIST = join(REPO_ROOT, 'legacy-src', 'dist');

function main() {
  if (existsSync(join(CI_LEGACY_DIST, 'index.html'))) {
    rmSync(DIST_LEGACY, { recursive: true, force: true });
    cpSync(CI_LEGACY_DIST, DIST_LEGACY, { recursive: true });
    console.log(`Copied pre-built legacy dist from ${CI_LEGACY_DIST} to ${DIST_LEGACY}`);
    return;
  }

  // Fallback for local dev / E2E: build commit ffbcf65 in a temporary git worktree
  const tempBase = mkdtempSync(join(tmpdir(), 'tsumiki-legacy-'));
  const worktreeDir = join(tempBase, 'wt');
  try {
    execFileSync('git', ['worktree', 'add', '--detach', worktreeDir, LEGACY_COMMIT], {
      cwd: REPO_ROOT,
      stdio: 'pipe',
    });
    const nodeModulesSrc = resolve(REPO_ROOT, 'node_modules');
    if (existsSync(nodeModulesSrc)) {
      symlinkSync(nodeModulesSrc, join(worktreeDir, 'node_modules'), 'dir');
    } else {
      execFileSync('npm', ['ci'], { cwd: worktreeDir, stdio: 'inherit' });
    }
    execFileSync('npm', ['run', 'build'], { cwd: worktreeDir, stdio: 'inherit' });
    rmSync(DIST_LEGACY, { recursive: true, force: true });
    cpSync(join(worktreeDir, 'dist'), DIST_LEGACY, { recursive: true });
    console.log(`Built legacy commit ${LEGACY_COMMIT} into ${DIST_LEGACY}`);
  } finally {
    try {
      execFileSync('git', ['worktree', 'remove', '--force', worktreeDir], {
        cwd: REPO_ROOT,
        stdio: 'pipe',
      });
    } catch {
      // Ignore if worktree was never created
    }
    rmSync(tempBase, { recursive: true, force: true });
  }
}

main();
