import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const image = process.argv[2] ?? 'shielda-security-watch:0.1.0-alpha.0';
const name = `security-watch-check-${process.pid}`;
const evidence = JSON.parse(
  readFileSync(fileURLToPath(new URL('../examples/advisories.json', import.meta.url)), 'utf8'),
);
// Run on native Linux volumes: SQLite should not rely on desktop VM file sharing.
const script = `
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {writeFileSync,statSync} from 'node:fs';
assert.equal(process.getuid(),1000);
const inventory={systems:[{id:'demo',name:'Demo',environment:'test',exposure:'internal',criticality:'high',updated_at:new Date().toISOString(),components:[{id:'parser',ecosystem:'npm',name:'example-parser',version:'1.2.0'}]}]};
writeFileSync('/config/systems.json',JSON.stringify(inventory),{mode:0o600});
writeFileSync('/config/security-watch.yaml',JSON.stringify({version:1,inventory:'/config/systems.json',database:'/data/watch.db',sources:{cve_now:false,hacker_news:false,osv:false,github:false,kev:false}}),{mode:0o600});
writeFileSync('/config/advisories.json',JSON.stringify(${JSON.stringify(evidence)}),{mode:0o600});
const run=args=>execFileSync(process.execPath,['/app/dist/cli.js',...args,'--config','/config/security-watch.yaml'],{encoding:'utf8',timeout:15000});
const report=JSON.parse(run(['scan','--fixture','/config/advisories.json']));
const finding=report.findings.find(f=>f.category==='library');assert.equal(finding.applicability,'affected');
run(['scan','--fixture','/config/advisories.json']);
assert.equal(JSON.parse(run(['history',finding.id])).length,1);
assert.equal(JSON.parse(run(['status'])).worker_lock,false);
assert.equal(JSON.parse(run(['health','--scan-only'])).ok,true);
assert.equal(statSync('/data/watch.db').mode&0o777,0o600);
run(['backup','--output','/data/backup.db']);assert(statSync('/data/backup.db').size>0);
console.log('Docker passed: non-root, private config, read-only root, network disabled, persisted matching, deduplication and backup.');
`;
try {
  assert.equal(
    execFileSync('docker', ['image', 'inspect', '--format', '{{.Config.User}}', image], {
      encoding: 'utf8',
    }).trim(),
    'node',
  );
  const result = execFileSync(
    'docker',
    [
      'run',
      '--rm',
      '-i',
      '--name',
      name,
      '--network',
      'none',
      '--read-only',
      '--cap-drop',
      'ALL',
      '--security-opt',
      'no-new-privileges',
      '--tmpfs',
      '/config:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700',
      '--tmpfs',
      '/tmp:rw,noexec,nosuid,mode=1777',
      '--entrypoint',
      'node',
      image,
      '--input-type=module',
    ],
    { input: script, encoding: 'utf8', timeout: 60000 },
  );
  process.stdout.write(result);
} finally {
  spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore', timeout: 10000 });
}
