import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { loadInventory } from '../dist/inventory.js';
import { Store } from '../dist/store.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-cli-operations-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return {
    dir,
    run(args) {
      return spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8', timeout: 15000 });
    },
  };
}
test('plain library lists normalize without configuration, models or invented versions', (t) => {
  const { dir, run } = setup(t),
    input = join(dir, 'libraries.txt'),
    output = join(dir, 'normalized.json');
  writeFileSync(
    input,
    '# Application dependencies\nphp:symfony/http-foundation@7.1.0\npython:Requests\nnpm:@scope/pkg@1.2.3\n',
  );
  const result = run(['normalize-libraries', '--input', input, '--output', output]);
  assert.equal(result.status, 0, result.stderr);
  const list = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(
    list.map(({ ecosystem, name, version }) => ({ ecosystem, name, version })),
    [
      { ecosystem: 'Packagist', name: 'symfony/http-foundation', version: '7.1.0' },
      { ecosystem: 'PyPI', name: 'requests', version: undefined },
      { ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3' },
    ],
  );
  assert.equal(statSync(output).mode & 0o777, 0o600);
  assert.equal(run(['normalize-libraries', '--input', input, '--output', output]).status, 1);
  assert.equal(JSON.parse(run(['ecosystems']).stdout).length, 12);
});
test('library setup enables OSV and makes vendor and heartbeat settings visible', (t) => {
  const { dir, run } = setup(t),
    input = join(dir, 'libraries.txt'),
    target = join(dir, 'watch');
  writeFileSync(input, 'symfony/http-foundation\nguzzlehttp/guzzle 7.9.2\n');
  const result = run([
    'init',
    '--yes',
    '--directory',
    target,
    '--libraries',
    input,
    '--ecosystem',
    'php',
    '--vendor-feeds',
    'php,python',
    '--heartbeat',
  ]);
  assert.equal(result.status, 0, result.stderr);
  const config = join(target, 'security-watch.yaml');
  const inventory = loadInventory(join(target, 'systems.yaml'));
  assert.equal(inventory.systems[0].components.length, 2);
  assert.equal(inventory.systems[0].components[0].version, undefined);
  assert.equal(inventory.systems[0].environment, 'unknown');
  const doctor = run(['doctor', '--config', config]);
  assert.equal(doctor.status, 2);
  const report = JSON.parse(doctor.stdout);
  assert.equal(report.sources.osv, true);
  assert.deepEqual(report.sources.vendor_feeds, ['php', 'python']);
  assert.deepEqual(report.ecosystems, ['Packagist']);
  assert.equal(report.external_heartbeat.configured, true);
  assert(report.missing_environment_variables.includes('HEARTBEAT_URL'));
  assert.match(readFileSync(join(target, '.env.example'), 'utf8'), /^HEARTBEAT_URL=$/m);
});
test('ambiguous library input fails before creating setup files', (t) => {
  const { dir, run } = setup(t),
    input = join(dir, 'libraries.txt'),
    target = join(dir, 'watch');
  writeFileSync(input, 'requests\n');
  const result = run(['init', '--yes', '--directory', target, '--libraries', input]);
  assert.equal(result.status, 1);
  assert(!existsSync(join(target, 'security-watch.yaml')));
  assert.equal(run(['init', '--yes', '--directory', target, '--ecosystem', 'php']).status, 1);
});
test('pruning defaults to a read-only plan and backup verification needs no monitor config', async (t) => {
  const { dir, run } = setup(t),
    db = join(dir, 'watch.db'),
    config = join(dir, 'config.json'),
    backup = join(dir, 'backup.db');
  const store = new Store(db);
  store.setMeta('last_scan', JSON.stringify({ at: new Date().toISOString(), degraded: false }));
  await store.backup(backup);
  store.close();
  writeFileSync(
    config,
    JSON.stringify({ version: 1, database: db, maintenance: { retention: { analysis_cache_days: 1 } } }),
  );
  const plan = run(['prune', '--config', config]);
  assert.equal(plan.status, 0, plan.stderr);
  assert.equal(JSON.parse(plan.stdout).applied, false);
  const apply = run(['prune', '--config', config, '--apply']);
  assert.equal(apply.status, 0, apply.stderr);
  assert.equal(JSON.parse(apply.stdout).applied, true);
  const verify = run(['verify-backup', '--input', backup]);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).ok, true);
});
