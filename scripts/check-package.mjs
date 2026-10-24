import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'security-watch-pack-'));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run through npm run check.');
function run(args, cwd = temp) {
  const result = spawnSync(process.execPath, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'Package check failed');
  return result.stdout;
}
try {
  const [packed] = JSON.parse(
    run([npmCli, 'pack', '--ignore-scripts', '--json', '--pack-destination', temp], root),
  );
  for (const file of packed.files)
    if (
      !/^(dist\/|examples\/|docs\/|package.json$|README.md$|LICENSE$|SECURITY.md$|CONTRIBUTING.md$)/.test(
        file.path,
      )
    )
      throw new Error(`Unexpected packed file: ${file.path}`);
  for (const required of [
    'dist/cli.js',
    'dist/index.js',
    'dist/index.d.ts',
    'README.md',
    'SECURITY.md',
    'docs/configuration.md',
    'LICENSE',
    'examples/advisories.json',
  ])
    if (!packed.files.some((file) => file.path === required))
      throw new Error(`Missing packed file: ${required}`);
  const consumer = join(temp, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run(
    [npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund', join(temp, packed.filename)],
    consumer,
  );
  const cli = join(consumer, 'node_modules/@shieldaai/security-watch/dist/cli.js');
  if (run([cli, '--version'], consumer).trim() !== packed.version)
    throw new Error('CLI version does not match the packed package');
  const providers = JSON.parse(run([cli, 'providers'], consumer));
  if (providers.length !== 22 || !providers.some((provider) => provider.id === 'anthropic'))
    throw new Error('Packed CLI provider catalog is incomplete');
  const templates = JSON.parse(run([cli, 'templates'], consumer));
  if (templates.length !== 24 || !templates.some((template) => template.id === 'python'))
    throw new Error('Packed CLI system templates are incomplete');
  const libraries = join(consumer, 'libraries.txt');
  writeFileSync(libraries, 'php:symfony/http-foundation@7.1.0\npython:Requests\n');
  const normalized = JSON.parse(run([cli, 'normalize-libraries', '--input', libraries], consumer));
  if (
    normalized.length !== 2 ||
    normalized[0].ecosystem !== 'Packagist' ||
    normalized[1].name !== 'requests' ||
    normalized[1].version !== undefined
  )
    throw new Error('Packed library normalization failed');
  const configured = join(consumer, 'configured');
  run(
    [
      cli,
      'init',
      '--yes',
      '--directory',
      configured,
      '--systems',
      'nodejs,python',
      '--notifications',
      'slack',
    ],
    consumer,
  );
  const credentials = join(configured, '.env');
  writeFileSync(credentials, 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/PACKAGE_TEST_ONLY\n', {
    mode: 0o600,
  });
  const doctor = JSON.parse(
    run(
      [cli, 'doctor', '--config', join(configured, 'security-watch.yaml'), '--credentials-file', credentials],
      consumer,
    ),
  );
  if (
    !doctor.ok ||
    doctor.systems !== 2 ||
    doctor.notification_channels.join(',') !== 'slack' ||
    doctor.poll_interval_minutes !== 30 ||
    doctor.news_lookback_minutes !== 40
  )
    throw new Error('Packed setup and credential loading failed');
  run([cli, 'init', '--yes'], consumer);
  const report = JSON.parse(
    run(
      [
        cli,
        'scan',
        '--dry-run',
        '--fixture',
        join(consumer, 'node_modules/@shieldaai/security-watch/examples/advisories.json'),
      ],
      consumer,
    ),
  );
  if (!report.findings.some((f) => f.applicability === 'affected'))
    throw new Error('Packed CLI did not match the fixture');
  writeFileSync(
    join(consumer, 'consumer.mts'),
    `import { parseConfig, Store, PROVIDERS, providerDefinition, parseLibraryList, type Ecosystem, type Assessment, type ModelProvider } from '@shieldaai/security-watch';
const ecosystem: Ecosystem = 'Packagist';
if (parseLibraryList('symfony/http-foundation', ecosystem)[0]?.ecosystem !== ecosystem) throw new Error('Unexpected ecosystem exports');
const provider: ModelProvider = 'anthropic';
const config = parseConfig({version: 1, poll_interval_minutes: 30, news_lookback_minutes: 40});
const store = new Store(':memory:');
const findings: Assessment[] = store.findings();
if (config.version !== 1 || findings.length) throw new Error('Unexpected exports');
if (config.news_lookback_minutes !== 40 || config.poll_interval_minutes !== 30) throw new Error('Unexpected timing configuration');
if (PROVIDERS.length !== 22 || providerDefinition(provider).apiKeyEnv !== 'ANTHROPIC_API_KEY') throw new Error('Unexpected provider exports');
store.close();
`,
  );
  run(
    [
      join(root, 'node_modules/typescript/bin/tsc'),
      'consumer.mts',
      '--module',
      'NodeNext',
      '--moduleResolution',
      'NodeNext',
      '--target',
      'ES2023',
      '--strict',
      '--skipLibCheck',
      'false',
      '--types',
      'node',
      '--typeRoots',
      join(root, 'node_modules/@types'),
      '--outDir',
      'compiled',
    ],
    consumer,
  );
  run([join(consumer, 'compiled/consumer.mjs')], consumer);
  console.log('Clean packed CLI, offline matching, public types and exports passed.');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
