import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  cachingHttp,
  checkAdvisory,
  checkChange,
  checkPackages,
  checkProject,
  dependencyFilesAt,
  failsAt,
  isCommitId,
  upgradeSummary,
  fixesAbove,
  formatAdvisoryReport,
  formatChangeReport,
  formatCheckReport,
} from '../dist/check.js';
import { SecurityWatchMcpServer, TOOLS, usableRoot } from '../dist/mcp-server.js';
import { isDependencyFilePath } from '../dist/manifests.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
// The Docker test stage has no git; the change checks need it.
const noGit = spawnSync('git', ['--version']).status === 0 ? false : 'git is not installed';
const now = Date.parse('2026-11-24T12:00:00Z');

// A small, synthetic OSV: records keyed by ID, each naming one package and its affected range.
function osvRecord(id, ecosystem, name, introduced, fixed, extra = {}) {
  return {
    id,
    modified: '2026-01-01T00:00:00Z',
    published: '2025-01-01T00:00:00Z',
    aliases: extra.aliases ?? [],
    summary: extra.summary ?? `Problem in ${name}`,
    details: extra.details ?? `${name} before ${fixed ?? 'any fix'} has a problem.`,
    affected: [
      {
        package: { ecosystem, name },
        ranges: [
          {
            type: ecosystem === 'npm' ? 'SEMVER' : 'ECOSYSTEM',
            events: [{ introduced }, ...(fixed ? [{ fixed }] : [])],
          },
        ],
      },
    ],
    database_specific: extra.severity === null ? {} : { severity: extra.severity ?? 'HIGH' },
  };
}
const RECORDS = {
  'GHSA-aaaa-aaaa-aaaa': osvRecord('GHSA-aaaa-aaaa-aaaa', 'npm', 'minimist', '1.0.0', '1.2.6', {
    aliases: ['CVE-2021-44906'],
    severity: 'CRITICAL',
    summary: 'Prototype pollution in minimist',
  }),
  'GHSA-bbbb-bbbb-bbbb': osvRecord('GHSA-bbbb-bbbb-bbbb', 'npm', 'lodash', '0', '4.17.21', {
    aliases: ['CVE-2021-23337'],
  }),
  'GHSA-cccc-cccc-cccc': osvRecord('GHSA-cccc-cccc-cccc', 'PyPI', 'requests', '0', '2.32.0', {
    severity: 'MODERATE',
  }),
  // No severity at all, as many GO- records.
  'GO-2026-1': osvRecord('GO-2026-1', 'npm', 'nosev', '0', '2.0.0', {
    severity: null,
    summary: 'Infinite loop in nosev',
  }),
  // A GitHub advisory that says the package is malware, without a MAL- record.
  'GHSA-mmmm-mmmm-mmmm': osvRecord('GHSA-mmmm-mmmm-mmmm', 'npm', 'crossenv', '0', undefined, {
    summary: 'Malicious Package in crossenv',
    severity: 'CRITICAL',
  }),
  // Two findings for one package, fixed in different versions; one alias in GitHub's mixed case.
  'GHSA-mult-aaaa-1111': osvRecord('GHSA-mult-aaaa-1111', 'npm', 'multi', '0', '1.1.0', {
    aliases: ['GHSA-Xy12-ab34-cd56'],
  }),
  'GHSA-mult-bbbb-2222': osvRecord('GHSA-mult-bbbb-2222', 'npm', 'multi', '0', '1.3.0'),
  // A Python-style record whose GIT range lists a commit as its fix, beside a real version.
  'PYSEC-2026-1': {
    ...osvRecord('PYSEC-2026-1', 'npm', 'gitfix', '0', '9.3.0'),
    affected: [
      {
        package: { ecosystem: 'npm', name: 'gitfix' },
        ranges: [
          {
            type: 'GIT',
            repo: 'https://github.com/x/gitfix',
            events: [{ introduced: '0' }, { fixed: '2444cddab2f8aa' }],
          },
          { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.3.0' }] },
        ],
      },
    ],
  },
  // Date-style versions, as org.json and pdfminer.six use.
  'GHSA-date-aaaa-bbbb': osvRecord('GHSA-date-aaaa-bbbb', 'PyPI', 'datever', '0', '20230227'),
  // One package, one entry per release line, as urllib3 and log4j-core.
  'GHSA-line-aaaa-bbbb': {
    ...osvRecord('GHSA-line-aaaa-bbbb', 'PyPI', 'twoline', '0', '2.0.6', { severity: 'HIGH' }),
    affected: [
      {
        package: { ecosystem: 'PyPI', name: 'twoline' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0.0' }, { fixed: '2.0.6' }] }],
      },
      {
        package: { ecosystem: 'PyPI', name: 'twoline' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.26.17' }] }],
      },
    ],
  },
  // Many mirror IDs beside the CVE, as GitHub's Rapid Reset advisory.
  'GHSA-mirr-aaaa-bbbb': osvRecord('GHSA-mirr-aaaa-bbbb', 'npm', 'mirrored', '0', '2.0.0', {
    aliases: ['BIT-aaa-2023-1', 'BIT-bbb-2023-1', 'BIT-ccc-2023-1', 'CVE-2023-44487'],
  }),
  'GHSA-loww-aaaa-bbbb': osvRecord('GHSA-loww-aaaa-bbbb', 'npm', 'lowpkg', '0', '2.0.0', { severity: 'LOW' }),
  'MAL-2026-1': osvRecord('MAL-2026-1', 'npm', 'evil-pkg', '0', undefined, {
    summary: 'Malicious code in evil-pkg (npm)',
    severity: 'CRITICAL',
  }),
  // A CVE record converted from NVD: no package ecosystem, only an alias that names one.
  'CVE-2021-44906': {
    id: 'CVE-2021-44906',
    modified: '2026-01-01T00:00:00Z',
    details: 'Minimist <=1.2.5 is vulnerable to Prototype Pollution.',
    aliases: ['GHSA-aaaa-aaaa-aaaa'],
    affected: [{ ranges: [{ type: 'GIT', repo: 'https://github.com/x/y', events: [{ introduced: '0' }] }] }],
  },
};

function affects(record, query) {
  record = {
    ...record,
    affected: [
      { ...record.affected[0], ranges: record.affected[0].ranges.filter((range) => range.type !== 'GIT') },
    ],
  };
  const affected = record.affected[0];
  if (!affected.package || affected.package.ecosystem !== query.package.ecosystem) return false;
  if (affected.package.name.toLowerCase() !== query.package.name.toLowerCase()) return false;
  if (!query.version) return true;
  const events = affected.ranges[0].events;
  const fixed = events.find((event) => event.fixed)?.fixed;
  const cmp = (a, b) => {
    const x = a.split('.').map(Number);
    const y = b.split('.').map(Number);
    for (let i = 0; i < Math.max(x.length, y.length); i++)
      if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
    return 0;
  };
  const introduced = events.find((event) => event.introduced)?.introduced ?? '0';
  return (
    (introduced === '0' || cmp(query.version, introduced) >= 0) && (!fixed || cmp(query.version, fixed) < 0)
  );
}

function fakeHttp({ kev = ['CVE-2021-23337'], fail = false, log = [] } = {}) {
  return async (url, options = {}) => {
    log.push(`${options.method ?? 'GET'} ${url}`);
    if (fail && url.includes('osv.dev')) return { status: 503, headers: {}, body: 'down' };
    if (url === 'https://api.osv.dev/v1/querybatch') {
      const { queries } = JSON.parse(options.body);
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: queries.map((query) => ({
            vulns: Object.values(RECORDS)
              .filter((record) => record.affected[0].package && affects(record, query))
              .map((record) => ({ id: record.id, modified: record.modified })),
          })),
        }),
      };
    }
    const match = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
    if (match) {
      const record = RECORDS[decodeURIComponent(match[1])];
      return record
        ? { status: 200, headers: {}, body: JSON.stringify(record) }
        : { status: 404, headers: {}, body: '{}' };
    }
    if (url.includes('known_exploited_vulnerabilities.json'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          dateReleased: '2026-11-01T00:00:00Z',
          count: kev.length,
          vulnerabilities: kev.map((cveID) => ({
            cveID,
            vendorProject: 'v',
            product: 'p',
            vulnerabilityName: 'n',
            shortDescription: 'd',
            requiredAction: 'a',
            dateAdded: '2026-10-01',
          })),
        }),
      };
    return { status: 404, headers: {}, body: '' };
  };
}

function lockfile(dependencies) {
  const packages = { '': { name: 'demo', version: '1.0.0', dependencies } };
  for (const [name, version] of Object.entries(dependencies)) packages[`node_modules/${name}`] = { version };
  return JSON.stringify({ name: 'demo', version: '1.0.0', lockfileVersion: 3, requires: true, packages });
}

function project(dependencies = { lodash: '4.17.20', minimist: '1.2.5' }, extra = {}) {
  const root = mkdtempSync(join(tmpdir(), 'sw-check-'));
  writeFileSync(join(root, 'package-lock.json'), lockfile(dependencies));
  for (const [path, content] of Object.entries(extra)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

function git(root, ...args) {
  return execFileSync('git', ['-C', root, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], {
    encoding: 'utf8',
  });
}

test('a project check lists affected packages, most urgent first, with the fix and the file', async () => {
  const root = project();
  try {
    const report = await checkProject({ project: root, http: fakeHttp(), now });
    assert.equal(report.packages, 2);
    assert.equal(report.degraded, false);
    assert.deepEqual(
      report.findings.map((finding) => [finding.id, finding.package.name, finding.exploited, finding.fixed]),
      [
        // Known exploited outranks the higher advisory severity.
        ['GHSA-bbbb-bbbb-bbbb', 'lodash', true, '4.17.21'],
        ['GHSA-aaaa-aaaa-aaaa', 'minimist', false, '1.2.6'],
      ],
    );
    assert.deepEqual(report.findings[1].aliases, ['CVE-2021-44906']);
    assert.deepEqual(report.findings[0].files, ['package-lock.json']);
    const text = formatCheckReport(report);
    assert.match(text, /2 known vulnerabilities in installed versions/);
    assert.match(text, /known exploited \(CISA KEV\)/);
    assert.match(text, /Fix: upgrade to 1\.2\.6\. In: package-lock\.json/);
    // minSeverity hides lower findings but never a known-exploited one.
    assert.match(formatCheckReport(report, 'critical'), /lodash/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a clean project, an empty folder and a failing source each say so', async () => {
  const clean = project({ lodash: '4.17.21' });
  const empty = mkdtempSync(join(tmpdir(), 'sw-empty-'));
  try {
    const report = await checkProject({ project: clean, http: fakeHttp(), now });
    assert.equal(report.findings.length, 0);
    assert.match(formatCheckReport(report), /No known vulnerabilities in these versions/);
    const none = await checkProject({ project: empty, http: fakeHttp(), now });
    assert.equal(none.packages, 0);
    assert.match(formatCheckReport(none), /No dependencies found/);
    const down = await checkProject({ project: clean, http: fakeHttp({ fail: true }), now });
    assert.equal(down.degraded, true);
    assert.match(formatCheckReport(down), /^INCOMPLETE: findings may be missing./m);
  } finally {
    rmSync(clean, { recursive: true, force: true });
    rmSync(empty, { recursive: true, force: true });
  }
});

test('package checks flag malware and accept ecosystem aliases; bad input is refused', async () => {
  const report = await checkPackages(
    [
      { ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' },
      { ecosystem: 'python', name: 'Requests', version: '2.31.0' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
    ],
    { http: fakeHttp(), now },
  );
  assert.equal(report.findings[0].package.name, 'evil-pkg');
  assert.equal(report.findings[0].malware, true);
  assert.match(formatCheckReport(report), /MALWARE[\s\S]*remove this package and rotate any credentials/);
  assert.ok(report.findings.some((finding) => finding.package.name === 'requests'));
  assert.ok(!report.findings.some((finding) => finding.package.name === 'lodash'));
  await assert.rejects(checkPackages([], { http: fakeHttp() }), /at least one/);
  await assert.rejects(
    checkPackages([{ ecosystem: 'cobol', name: 'x' }], { http: fakeHttp() }),
    /Unsupported library ecosystem/,
  );
  // Without a version, every advisory is listed for checking by hand.
  const any = await checkPackages([{ ecosystem: 'npm', name: 'minimist' }], { http: fakeHttp(), now });
  assert.equal(any.findings[0]?.applicability, 'unknown');
});

test('an advisory check follows a CVE record to the package record and answers for the project', async () => {
  const root = project();
  try {
    const hit = await checkAdvisory('cve-2021-44906', { project: root, http: fakeHttp(), now });
    assert.equal(hit.found, true);
    assert.deepEqual(
      hit.findings.map((finding) => finding.package.name),
      ['minimist'],
    );
    assert.ok(hit.packages.some((item) => item.name === 'minimist' && item.fixed === '1.2.6'));
    assert.match(formatAdvisoryReport(hit), /This project IS affected/);
    const safe = project({ minimist: '1.2.6' });
    try {
      const miss = await checkAdvisory('GHSA-AAAA-aaaa-aaaa', { project: safe, http: fakeHttp(), now });
      assert.equal(miss.findings.length, 0);
      assert.deepEqual(miss.present_not_affected, ['npm:minimist@1.2.6']);
      assert.match(formatAdvisoryReport(miss), /at versions the advisory does not list as affected/);
    } finally {
      rmSync(safe, { recursive: true, force: true });
    }
    const unknown = await checkAdvisory('CVE-2099-0001', { project: root, http: fakeHttp(), now });
    assert.equal(unknown.found, false);
    assert.match(formatAdvisoryReport(unknown), /OSV has no record/);
    await assert.rejects(checkAdvisory('not an id', { project: root, http: fakeHttp() }), /advisory ID/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a change check reports only what the change added and what it fixed', { skip: noGit }, async () => {
  const root = project(
    { lodash: '4.17.20', express: '4.17.1' },
    { 'api/requirements.txt': 'requests==2.31.0\n', 'README.md': 'x' },
  );
  try {
    git(root, 'init', '-q');
    git(root, 'add', '-A');
    git(root, 'commit', '-qm', 'base');
    writeFileSync(
      join(root, 'package-lock.json'),
      lockfile({ lodash: '4.17.21', express: '4.17.1', minimist: '1.2.5' }),
    );
    const change = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
    assert.deepEqual(
      change.added.map((finding) => finding.package.name),
      ['minimist'],
    );
    assert.deepEqual(
      change.resolved.map((finding) => finding.package.name),
      ['lodash'],
    );
    assert.equal(change.unchanged, 1); // requests, untouched
    assert.deepEqual(change.packages.added, ['npm:minimist@1.2.5']);
    assert.deepEqual(change.packages.changed, ['npm:lodash 4.17.20 -> 4.17.21']);
    const text = formatChangeReport(change);
    assert.match(text, /brings in 1 known vulnerability/);
    assert.match(text, /It fixes 1/);
    // Only dependency files are taken from git, at the paths the project reader uses.
    const { folder } = dependencyFilesAt(root, 'HEAD');
    try {
      const copied = execFileSync('find', [folder, '-type', 'f'], { encoding: 'utf8' })
        .trim()
        .split('\n')
        .map((line) =>
          line
            .slice(folder.length + 1)
            .split('/')
            .slice(1)
            .join('/'),
        )
        .sort();
      assert.deepEqual(copied, ['api/requirements.txt', 'package-lock.json']);
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
    await assert.rejects(
      checkChange({ project: root, base: '--upload-pack=x', http: fakeHttp() }),
      /must be a git ref/,
    );
    await assert.rejects(
      checkChange({ project: root, base: 'no-such-branch', http: fakeHttp() }),
      /does not know no-such-branch/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a change check of a subfolder and of a repository with no commits', { skip: noGit }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'sw-mono-'));
  try {
    mkdirSync(join(root, 'svc'));
    writeFileSync(join(root, 'svc', 'package-lock.json'), lockfile({ lodash: '4.17.21' }));
    writeFileSync(join(root, 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
    git(root, 'init', '-q');
    await assert.rejects(
      checkChange({ project: join(root, 'svc'), base: 'HEAD', http: fakeHttp() }),
      /does not know HEAD/,
    );
    git(root, 'add', '-A');
    git(root, 'commit', '-qm', 'base');
    writeFileSync(join(root, 'svc', 'package-lock.json'), lockfile({ lodash: '4.17.20' }));
    const change = await checkChange({ project: join(root, 'svc'), base: 'HEAD', http: fakeHttp(), now });
    // The root lockfile's minimist is outside the folder checked.
    assert.deepEqual(
      change.added.map((finding) => finding.package.name),
      ['lodash'],
    );
    assert.deepEqual(change.added[0].files, ['package-lock.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('dependency file paths follow the project reader', () => {
  assert.equal(isDependencyFilePath('package-lock.json'), true);
  assert.equal(isDependencyFilePath('svc/requirements-dev.txt'), true);
  assert.equal(isDependencyFilePath('node_modules/x/package.json'), false);
  assert.equal(isDependencyFilePath('.github/package.json'), false);
  assert.equal(isDependencyFilePath('test/fixtures/package-lock.json'), false);
  assert.equal(isDependencyFilePath('../package-lock.json'), false);
  assert.equal(isDependencyFilePath('README.md'), false);
});

test('fixed versions below the installed one are left out', () => {
  assert.equal(fixesAbove('0.2.4; 1.2.6', '1.2.5'), '1.2.6');
  assert.equal(fixesAbove('1.2.6', undefined), '1.2.6');
  assert.equal(fixesAbove('abc; 2.0', '1.0.0'), '2.0; abc');
});

test('the GET cache serves static files once and passes POSTs through', async () => {
  const log = [];
  const http = cachingHttp(fakeHttp({ log }));
  await http('https://api.osv.dev/v1/vulns/MAL-2026-1');
  await http('https://api.osv.dev/v1/vulns/MAL-2026-1');
  await http('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"queries":[]}' });
  await http('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"queries":[]}' });
  assert.equal(log.filter((line) => line.startsWith('GET')).length, 1);
  assert.equal(log.filter((line) => line.startsWith('POST')).length, 2);
});

// MCP server.

function server(options = {}) {
  const sent = [];
  const instance = new SecurityWatchMcpServer({ http: fakeHttp(), now: () => now, ...options }, (message) =>
    sent.push(message),
  );
  const call = async (name, args = {}) => {
    const id = sent.length + 1000;
    await instance.handle({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
    return sent.find((message) => message.id === id);
  };
  return { instance, sent, call };
}

test('the MCP server describes itself and its tools within directory limits', async () => {
  const root = project();
  try {
    const { instance, sent } = server({ root });
    await instance.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {} },
    });
    assert.equal(sent[0].result.protocolVersion, '2025-06-18');
    assert.equal(sent[0].result.serverInfo.name, 'security-watch');
    await instance.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const tools = sent[1].result.tools;
    assert.deepEqual(
      tools.map((tool) => tool.name),
      [
        'check_project_vulnerabilities',
        'check_dependency_change',
        'check_package',
        'check_advisory',
        'list_dependencies',
        'write_sbom',
      ],
    );
    for (const tool of tools) {
      assert.match(tool.name, /^[a-z_]{1,64}$/);
      assert.ok(tool.description.length <= 1024, tool.name);
      assert.equal(tool.inputSchema.type, 'object');
      assert.equal(typeof tool.annotations.readOnlyHint, 'boolean');
      assert.equal(tool.title.length > 0, true);
    }
    // Only write_sbom writes; only the network tools say they reach outside.
    assert.deepEqual(
      tools.filter((tool) => !tool.annotations.readOnlyHint).map((tool) => tool.name),
      ['write_sbom'],
    );
    assert.deepEqual(
      tools.filter((tool) => !tool.annotations.openWorldHint).map((tool) => tool.name),
      ['list_dependencies', 'write_sbom'],
    );
    await instance.handle({ jsonrpc: '2.0', id: 3, method: 'nope' });
    assert.equal(sent[2].error.code, -32601);
    await instance.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
    assert.equal(sent.length, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('MCP tools answer, and refuse paths outside the project', async () => {
  const root = project({ lodash: '4.17.20' }, { 'svc/package-lock.json': lockfile({ minimist: '1.2.5' }) });
  const outside = mkdtempSync(join(tmpdir(), 'sw-outside-'));
  try {
    symlinkSync(outside, join(root, 'link'));
    const { call } = server({ root });
    const all = await call('check_project_vulnerabilities');
    assert.equal(all.result.isError, false);
    assert.match(all.result.content[0].text, /lodash[\s\S]*minimist|minimist[\s\S]*lodash/);
    const svc = await call('check_project_vulnerabilities', { path: 'svc' });
    assert.doesNotMatch(svc.result.content[0].text, /lodash/);
    for (const path of ['..', '../x', outside, 'link', 'missing'])
      assert.equal((await call('check_project_vulnerabilities', { path })).result.isError, true, path);
    const deps = await call('list_dependencies', { includePackages: true });
    assert.match(deps.result.content[0].text, /2 packages \(npm\) from 2 files/);
    assert.match(deps.result.content[0].text, /pkg:npm\/minimist@1\.2\.5/);
    const pkg = await call('check_package', {
      packages: [{ ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' }],
    });
    assert.match(pkg.result.content[0].text, /MALWARE/);
    assert.equal((await call('check_package', { packages: [] })).result.isError, true);
    assert.equal((await call('check_package', { packages: [{ name: 'x' }] })).result.isError, true);
    const advisory = await call('check_advisory', { id: 'CVE-2021-44906' });
    assert.match(advisory.result.content[0].text, /IS affected/);
    assert.equal((await call('check_dependency_change', {})).result.isError, true);
    const notGit = await call('check_dependency_change', { base: 'HEAD' });
    assert.match(notGit.result.content[0].text, /Not a git repository/);
    const unknown = await call('list_watch_findings');
    assert.equal(unknown.error.code, -32602);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('write_sbom writes inside the project only and does not replace a file unasked', async () => {
  const root = project();
  const outside = mkdtempSync(join(tmpdir(), 'sw-outside-'));
  try {
    symlinkSync(outside, join(root, 'out'));
    const { call } = server({ root });
    const first = await call('write_sbom', {
      output: 'sbom/app.cdx.json',
      owner: 'Dana, platform team',
      exposure: 'internet',
    });
    assert.equal(first.result.isError, false, first.result.content[0].text);
    const bom = JSON.parse(readFileSync(join(root, 'sbom', 'app.cdx.json'), 'utf8'));
    assert.equal(bom.bomFormat, 'CycloneDX');
    assert.ok(bom.metadata.properties.some((item) => item.value === 'Dana, platform team'));
    assert.match(
      (await call('write_sbom', { output: 'sbom/app.cdx.json' })).result.content[0].text,
      /overwrite: true/,
    );
    assert.equal(
      (await call('write_sbom', { output: 'sbom/app.cdx.json', overwrite: true })).result.isError,
      false,
    );
    for (const output of ['../x.json', join(outside, 'x.json'), 'out/x.json', 'sbom.xml'])
      assert.equal((await call('write_sbom', { output })).result.isError, true, output);
    assert.equal(existsSync(join(outside, 'x.json')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('a server started outside a project takes the client root, and refuses the home folder', async () => {
  const home = mkdtempSync(join(tmpdir(), 'sw-home-'));
  const root = project();
  try {
    assert.equal(usableRoot('/', home), false);
    assert.equal(usableRoot(home, home), false);
    assert.equal(usableRoot(join(home, '..'), home), false);
    assert.equal(usableRoot(root, home), true);
    const { instance, sent, call } = server({ root: home, home });
    assert.equal(instance.root, undefined);
    const refused = await call('list_dependencies');
    assert.match(refused.result.content[0].text, /No project folder is open/);
    await instance.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { capabilities: { roots: {} } },
    });
    await instance.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const ask = sent.find((message) => message.method === 'roots/list');
    assert.ok(ask);
    await instance.handle({
      jsonrpc: '2.0',
      id: ask.id,
      result: { roots: [{ uri: 'file:///' }, { uri: pathToFileURL(root).href }] },
    });
    await new Promise((done) => setImmediate(done));
    assert.ok(instance.root.endsWith(root.split('/').at(-1)));
    assert.equal((await call('list_dependencies')).result.isError, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('list_watch_findings is offered only with a monitor configuration and reads its database', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-watch-'));
  try {
    writeFileSync(join(dir, 'systems.yaml'), 'systems: []\n');
    writeFileSync(
      join(dir, 'security-watch.yaml'),
      'version: 1\ninventory: ./systems.yaml\ndatabase: ./data/watch.db\n',
    );
    const { instance, sent, call } = server({ root: dir, config: join(dir, 'security-watch.yaml') });
    await instance.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.ok(sent[0].result.tools.some((tool) => tool.name === 'list_watch_findings'));
    assert.match((await call('list_watch_findings')).result.content[0].text, /no database yet/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the MCP server runs over stdio from the CLI and answers concurrently', async () => {
  const root = project({ lodash: '4.17.21' });
  try {
    const child = spawn(process.execPath, [cli, 'mcp', root], { stdio: ['pipe', 'pipe', 'pipe'] });
    const lines = createInterface({ input: child.stdout });
    const replies = new Map();
    const waiters = new Map();
    lines.on('line', (line) => {
      const message = JSON.parse(line);
      if (waiters.has(message.id)) waiters.get(message.id)(message);
      else replies.set(message.id, message);
    });
    const request = (id, method, params) =>
      new Promise((done) => {
        waiters.set(id, done);
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    const init = await request(1, 'initialize', { protocolVersion: '2099-01-01', capabilities: {} });
    assert.equal(init.result.protocolVersion, '2025-11-25');
    child.stdin.write('not json\n');
    const listing = await request(2, 'tools/call', { name: 'list_dependencies', arguments: {} });
    assert.match(listing.result.content[0].text, /1 package \(npm\)/);
    child.kill();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('check on the command line: exit codes, JSON and argument checks', () => {
  const run = (...args) =>
    spawnSync(process.execPath, [cli, 'check', ...args], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
  assert.equal(run('--fail-on', 'severe').status, 2);
  assert.match(run('--package', 'lodash').stderr, /ecosystem:name@version/);
  assert.match(run('.', '--package', 'npm:x@1').stderr, /leave out the project/);
  assert.match(run('--base', 'HEAD', '--sbom', 'x.json').stderr, /cannot be combined/);
  assert.notEqual(run('--unknown-flag').status, 0);
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.match(help.stdout, /security-watch check \[PROJECT\]/);
  assert.match(help.stdout, /security-watch mcp \[PROJECT\]/);
});

test('every MCP tool is documented in the agent guide', () => {
  const guide = readFileSync(new URL('../docs/agents.md', import.meta.url), 'utf8');
  for (const tool of [...TOOLS.map((item) => item.name), 'list_watch_findings'])
    assert.match(guide, new RegExp(`\`${tool}\``));
});

// Regressions from the independent review of 1.4.0.

test('R1: a finding without a severity is shown by default, counted, and gated as medium', async () => {
  const root = project({ nosev: '1.0.0' });
  try {
    const report = await checkProject({ project: root, http: fakeHttp(), now });
    assert.equal(report.findings[0].priority, 'unknown');
    const text = formatCheckReport(report);
    assert.match(text, /Infinite loop in nosev/);
    assert.match(text, /1 without a severity in the advisory/);
    assert.match(text, /the advisory gives no severity/);
    assert.doesNotMatch(formatCheckReport(report, 'high'), /Infinite loop/);
    assert.match(formatCheckReport(report, 'high'), /1 below high not shown/);
    assert.equal(failsAt(report.findings[0], 'medium'), true);
    assert.equal(failsAt(report.findings[0], 'high'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test(
  'R2: submodules, nested repositories and ignored folders are not part of a change',
  { skip: noGit },
  async () => {
    const root = project({ lodash: '4.17.21' }, { '.gitignore': 'vendored/\n' });
    const sub = mkdtempSync(join(tmpdir(), 'sw-sub-'));
    try {
      git(root, 'init', '-q');
      git(root, 'add', '-A');
      git(root, 'commit', '-qm', 'base');
      // An ignored folder and a nested repository, each with a vulnerable lockfile.
      mkdirSync(join(root, 'vendored'));
      writeFileSync(join(root, 'vendored', 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
      mkdirSync(join(root, 'nested'));
      writeFileSync(join(root, 'nested', 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
      git(join(root, 'nested'), 'init', '-q');
      // A submodule with a vulnerable lockfile.
      writeFileSync(join(sub, 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
      git(sub, 'init', '-q');
      git(sub, 'add', '-A');
      git(sub, 'commit', '-qm', 'sub');
      git(root, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', sub, 'libs/sub');
      git(root, 'commit', '-qm', 'submodule');
      const change = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
      assert.deepEqual(change.packages, { added: [], removed: [], changed: [] });
      assert.equal(change.added.length, 0);
      // An untracked file that is not ignored is part of the change.
      mkdirSync(join(root, 'svc'));
      writeFileSync(join(root, 'svc', 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
      const untracked = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
      assert.deepEqual(
        untracked.added.map((finding) => finding.files),
        [['svc/package-lock.json']],
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(sub, { recursive: true, force: true });
    }
  },
);

test('R3: a dependency file that cannot be read makes the check incomplete', { skip: noGit }, async () => {
  const root = project({ lodash: '4.17.20' });
  try {
    git(root, 'init', '-q');
    git(root, 'add', '-A');
    git(root, 'commit', '-qm', 'base');
    writeFileSync(join(root, 'package-lock.json'), '<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> other\n');
    const plain = await checkProject({ project: root, http: fakeHttp(), now });
    assert.equal(plain.degraded, true);
    assert.match(
      formatCheckReport(plain),
      /^INCOMPLETE[\s\S]*not read: package-lock\.json: could not be read/m,
    );
    assert.doesNotMatch(formatCheckReport(plain), /No known vulnerabilities in these versions/);
    const change = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
    assert.equal(change.head.degraded, true);
    assert.match(formatChangeReport(change).split('\n')[1], /^INCOMPLETE/);
    // The command line exits 2 and needs no network to say so.
    const run = spawnSync(process.execPath, [cli, 'check', root], { encoding: 'utf8' });
    assert.equal(run.status, 2, run.stdout + run.stderr);
    assert.match(run.stdout, /INCOMPLETE/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R4/R5: write_sbom replaces only an SBOM, stays out of hidden folders and never creates folders outside', async () => {
  const root = project(
    { lodash: '4.17.20' },
    { 'tsconfig.json': '{"compilerOptions":{}}', '.claude/settings.json': '{}' },
  );
  const outside = mkdtempSync(join(tmpdir(), 'sw-outside-'));
  try {
    symlinkSync(outside, join(root, 'link'));
    symlinkSync(join(root, 'missing-target.json'), join(root, 'dangling.json'));
    const { call } = server({ root });
    for (const output of ['package-lock.json', 'tsconfig.json']) {
      const before = readFileSync(join(root, output), 'utf8');
      const result = await call('write_sbom', { output, overwrite: true });
      assert.equal(result.result.isError, true, output);
      assert.match(result.result.content[0].text, /not a CycloneDX or SPDX SBOM/);
      assert.equal(readFileSync(join(root, output), 'utf8'), before);
    }
    for (const output of ['.claude/settings.json', '.github/sbom.json', 'sub/.hidden.json'])
      assert.match(
        (await call('write_sbom', { output, overwrite: true })).result.content[0].text,
        /hidden/,
        output,
      );
    assert.equal((await call('write_sbom', { output: 'link/sub/sbom.json' })).result.isError, true);
    assert.equal(existsSync(join(outside, 'sub')), false, 'no folder created outside the project');
    assert.equal((await call('write_sbom', { output: 'dangling.json' })).result.isError, true);
    assert.equal(existsSync(join(root, 'missing-target.json')), false);
    assert.equal((await call('write_sbom', { output: 'sbom.cdx.json' })).result.isError, false);
    assert.equal(
      (await call('write_sbom', { output: 'sbom.cdx.json', overwrite: true })).result.isError,
      false,
    );
    const tool = TOOLS.find((item) => item.name === 'write_sbom');
    assert.equal(tool.annotations.destructiveHint, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('R6: a package without an exact version MAY be affected, and does not fail the check', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sw-manifest-'));
  try {
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ name: 'm', dependencies: { minimist: '^1.2.8' } }),
    );
    const report = await checkAdvisory('CVE-2021-44906', { project: root, http: fakeHttp(), now });
    const text = formatAdvisoryReport(report);
    assert.doesNotMatch(text, /IS affected/);
    assert.match(text, /MAY be affected/);
    assert.equal(
      report.findings.every((finding) => !failsAt(finding, 'low')),
      true,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R7: a tool call made before the client names its roots waits for them', async () => {
  const home = mkdtempSync(join(tmpdir(), 'sw-home-'));
  const root = project();
  try {
    const { instance, sent } = server({ root: home, home });
    await instance.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { capabilities: { roots: {} } },
    });
    await instance.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const call = instance.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'list_dependencies', arguments: {} },
    });
    const ask = sent.find((message) => message.method === 'roots/list');
    await instance.handle({
      jsonrpc: '2.0',
      id: ask.id,
      result: { roots: [{ uri: pathToFileURL(root).href }] },
    });
    await call;
    const reply = sent.find((message) => message.id === 2);
    assert.equal(reply.result.isError, false, reply.result.content[0].text);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test(
  'R8/R9: a path in another letter case, and REF... compares with the branch point',
  { skip: noGit },
  async () => {
    const root = project({ lodash: '4.17.20' });
    try {
      git(root, 'init', '-q', '-b', 'main');
      git(root, 'add', '-A');
      git(root, 'commit', '-qm', 'base');
      git(root, 'checkout', '-qb', 'feature');
      writeFileSync(join(root, 'package-lock.json'), lockfile({ lodash: '4.17.20', minimist: '1.2.5' }));
      git(root, 'commit', '-qam', 'feature adds minimist');
      git(root, 'checkout', '-q', 'main');
      writeFileSync(join(root, 'package-lock.json'), lockfile({ lodash: '4.17.21' }));
      git(root, 'commit', '-qam', 'main upgrades lodash');
      git(root, 'checkout', '-q', 'feature');
      const tip = await checkChange({ project: root, base: 'main', http: fakeHttp(), now });
      // Against main's tip, main's lodash upgrade shows up in reverse.
      assert.ok(tip.added.some((finding) => finding.package.name === 'lodash'));
      const point = await checkChange({ project: root, base: 'main...', http: fakeHttp(), now });
      assert.deepEqual(
        point.added.map((finding) => finding.package.name),
        ['minimist'],
      );
      const upper = root.replace(/sw-check-/, 'SW-CHECK-');
      if (existsSync(upper)) {
        const cased = await checkChange({ project: upper, base: 'HEAD~1', http: fakeHttp(), now });
        assert.deepEqual(
          cased.added.map((finding) => finding.package.name),
          ['minimist'],
        );
      }
      await assert.rejects(
        checkChange({ project: root, base: '-x...', http: fakeHttp() }),
        /must be a git ref/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test('R10: identifiers keep their case, GitHub malware is malware, one upgrade fixes several', async () => {
  const report = await checkPackages(
    [
      { ecosystem: 'npm', name: 'multi', version: '1.0.0' },
      { ecosystem: 'npm', name: 'crossenv', version: '1.0.0' },
    ],
    { http: fakeHttp(), now },
  );
  const crossenv = report.findings.find((finding) => finding.package.name === 'crossenv');
  assert.equal(crossenv.malware, true);
  assert.equal(crossenv.priority, 'critical');
  const multi = report.findings.filter((finding) => finding.package.name === 'multi');
  assert.ok(multi.some((finding) => finding.aliases.includes('GHSA-xy12-ab34-cd56')));
  assert.deepEqual(upgradeSummary(report.findings), [
    '- npm multi 1.0.0: upgrading to 1.3.0 (or a later 1.3.x release) fixes all 2. A newer release line is not checked here: check it before moving to one.',
  ]);
  assert.match(formatCheckReport(report), /Upgrades that fix several at once/);
  // Checking packages by name says nothing about lockfiles.
  const unversioned = await checkPackages([{ ecosystem: 'npm', name: 'multi' }], { http: fakeHttp(), now });
  assert.doesNotMatch(formatCheckReport(unversioned), /lockfile/);
  const ghsa = await checkAdvisory('GHSA-aaaa-aaaa-aaaa', {
    project: mkdtempSync(join(tmpdir(), 'sw-e-')),
    http: fakeHttp(),
    now,
  });
  assert.ok(
    !ghsa.aliases.some((alias) => alias.toUpperCase() === 'GHSA-AAAA-AAAA-AAAA'),
    'not its own alias',
  );
});

test('R12: the report names the project it read, and notes are not "not read"', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sw-range-'));
  try {
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ name: 'm', dependencies: { lodash: '^4.17.21' } }),
    );
    const report = await checkProject({ project: root, http: fakeHttp(), now });
    const text = formatCheckReport(report);
    assert.match(text.split('\n')[0], new RegExp(`in ${root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.equal(report.degraded, false);
    assert.doesNotMatch(text, /INCOMPLETE|not read/i);
    assert.match(text, /Notes:\n- package\.json: 1 of 1 dependencies have a version range/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// Regressions from the second review of 1.4.0.

test('S1/S6: commit IDs are never fixed versions, and one upgrade is judged per release line', async () => {
  const report = await checkPackages([{ ecosystem: 'npm', name: 'gitfix', version: '1.0.0' }], {
    http: fakeHttp(),
    now,
  });
  assert.equal(report.findings[0].fixed, '9.3.0');
  assert.equal(
    fixesAbove('2444cddab2f8, 9.3.0; 1.11.28, 2.2.10; 1.11.28', '1.11.0'),
    '1.11.28; 2.2.10; 9.3.0',
  );
  assert.equal(fixesAbove('eb31d845, 0.2.4; 1.2.6', undefined), '0.2.4; 1.2.6');
  const finding = (id, fixed) => ({
    id,
    aliases: [],
    title: id,
    severity: 'high',
    priority: 'high',
    applicability: 'affected',
    exploited: false,
    malware: false,
    package: { ecosystem: 'npm', name: 'lib', version: '5.0.0' },
    files: [],
    fixed,
    reasons: [],
  });
  // 5.1.0 fixes B but not A, whose fix on the 5.1 line is 5.1.14.
  assert.deepEqual(upgradeSummary([finding('A', '4.2.26; 5.1.14; 5.2.8'), finding('B', '5.1.0')]), [
    '- npm lib 5.0.0: upgrading to 5.1.14 (or a later 5.1.x release) fixes all 2. A newer release line is not checked here: check it before moving to one.',
  ]);
  // A commit ID never becomes a version to upgrade to.
  assert.deepEqual(upgradeSummary([finding('A', '2444cddab2f8'), finding('B', '5.1.0')]), [
    '- npm lib 5.0.0: upgrading to 5.1.0 (or a later 5.1.x release) fixes 1 of 2; 1 name no fixed version. A newer release line is not checked here: check it before moving to one.',
  ]);
});

test('S2: the project’s git configuration runs nothing', { skip: noGit }, async () => {
  const root = project({ lodash: '4.17.20' });
  const marker = join(tmpdir(), `sw-fsmonitor-${process.pid}-${Date.now()}`);
  try {
    git(root, 'init', '-q');
    git(root, 'add', '-A');
    git(root, 'commit', '-qm', 'base');
    git(root, 'config', 'core.fsmonitor', `touch ${marker}`);
    await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
    assert.equal(existsSync(marker), false, 'core.fsmonitor ran');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(marker, { force: true });
  }
});

test(
  'S3/S7: a linked folder that leads out is not read, and an unreadable file is skipped, not fatal',
  { skip: noGit },
  async () => {
    const root = project(
      { lodash: '4.17.21' },
      {
        'sub/package-lock.json': lockfile({ lodash: '4.17.21' }),
        'svc/package-lock.json': lockfile({ lodash: '4.17.21' }),
      },
    );
    const outside = mkdtempSync(join(tmpdir(), 'sw-outside-'));
    try {
      git(root, 'init', '-q');
      git(root, 'add', '-A');
      git(root, 'commit', '-qm', 'base');
      writeFileSync(join(outside, 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
      rmSync(join(root, 'sub'), { recursive: true });
      symlinkSync(outside, join(root, 'sub'));
      const linked = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
      assert.ok(!linked.added.some((item) => item.package.name === 'minimist'), 'read through a link');
      if (process.getuid?.() !== 0) {
        chmodSync(join(root, 'svc', 'package-lock.json'), 0o000);
        const change = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
        assert.equal(change.head.degraded, true);
        assert.match(formatChangeReport(change), /not read: svc\/package-lock\.json: could not be read/);
        chmodSync(join(root, 'svc', 'package-lock.json'), 0o644);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  },
);

test('S4/S5/S9: CVE first among IDs, no severity sorts as medium, package checks speak of versions', async () => {
  const report = await checkPackages(
    [
      { ecosystem: 'npm', name: 'mirrored', version: '1.0.0' },
      { ecosystem: 'npm', name: 'lowpkg', version: '1.0.0' },
      { ecosystem: 'npm', name: 'nosev', version: '1.0.0' },
    ],
    { http: fakeHttp(), now },
  );
  const mirrored = report.findings.find((finding) => finding.package.name === 'mirrored');
  assert.equal(mirrored.aliases[0], 'CVE-2023-44487');
  assert.match(formatCheckReport(report), /GHSA-mirr-aaaa-bbbb, CVE-2023-44487/);
  const order = report.findings.map((finding) => finding.package.name);
  assert.ok(order.indexOf('nosev') < order.indexOf('lowpkg'), order.join());
  const text = formatCheckReport(report);
  assert.match(text, /in these versions/);
  assert.doesNotMatch(text, /installed versions|lockfile/);
});

test('S8: an advisory lookup stops when the call is cancelled', async () => {
  const controller = new AbortController();
  controller.abort();
  const root = project();
  try {
    await assert.rejects(
      checkAdvisory('CVE-2021-44906', { project: root, http: fakeHttp(), now, signal: controller.signal }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// Regressions from the final review of 1.4.0.

test('B1: date-style versions are versions, not commit IDs', async () => {
  assert.equal(isCommitId('20230227'), false);
  assert.equal(isCommitId('2444cddab2f8'), true);
  assert.equal(isCommitId('1234567890123456789012345678901234567890'), true);
  assert.equal(fixesAbove('20231013; 20230227', '20220320'), '20230227; 20231013');
  const report = await checkPackages([{ ecosystem: 'pypi', name: 'datever', version: '20220320' }], {
    http: fakeHttp(),
    now,
  });
  assert.equal(report.findings[0].fixed, '20230227');
  assert.match(formatCheckReport(report), /Fix: upgrade to 20230227\./);
});

test('B2: the advisory header keeps every release line’s fix', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sw-twoline-'));
  writeFileSync(join(root, 'requirements.txt'), 'twoline==1.26.0\n');
  try {
    const report = await checkAdvisory('GHSA-line-aaaa-bbbb', { project: root, http: fakeHttp(), now });
    const header = formatAdvisoryReport(report)
      .split('\n')
      .find((text) => text.startsWith('Packages it concerns'));
    assert.match(header, /fixed in 1\.26\.17; 2\.0\.6/);
    assert.equal(report.severity, 'high');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test(
  'B5: a file skipped in the working tree is left out at the base too, and said',
  { skip: noGit },
  async () => {
    const root = project({ lodash: '4.17.21' }, { 'sub/package-lock.json': lockfile({ lodash: '4.17.20' }) });
    const outside = mkdtempSync(join(tmpdir(), 'sw-outside-'));
    try {
      git(root, 'init', '-q');
      git(root, 'add', '-A');
      git(root, 'commit', '-qm', 'base');
      writeFileSync(join(outside, 'package-lock.json'), lockfile({ minimist: '1.2.5' }));
      rmSync(join(root, 'sub'), { recursive: true });
      symlinkSync(outside, join(root, 'sub'));
      const change = await checkChange({ project: root, base: 'HEAD', http: fakeHttp(), now });
      assert.deepEqual(change.packages.removed, [], 'sub/package-lock.json is not read as removed');
      assert.equal(change.resolved.length, 0, 'its advisories are not read as fixed');
      assert.equal(change.head.degraded, true);
      assert.match(
        formatChangeReport(change),
        /sub\/package-lock\.json: reached through a link that leads outside/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  },
);
