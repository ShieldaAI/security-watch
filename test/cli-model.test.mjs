import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

test('CLI dry-run performs source matching but never invokes a configured paid model or resets persistent budgets', t => {
  const dir = mkdtempSync(join(tmpdir(), 'security-watch-cli-model-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'requests.json'); const hook = join(dir, 'mock-transport.mjs');
  const now = new Date().toISOString();
  writeFileSync(join(dir, 'systems.json'), JSON.stringify({ systems: [{ id: 'prod', name: 'Production', updated_at: now, components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }] }] }));
  writeFileSync(join(dir, 'security-watch.yaml'), JSON.stringify({ version: 1, inventory: './systems.json', database: './data/watch.db', sources: { osv: true, github: false, kev: false, feeds: [] }, models: { enabled: true, analysis: { provider: 'openai', model: 'fixture-model', api_key_env: 'WATCH_CLI_DRY_MODEL_KEY' }, daily_request_limit: 1, daily_token_limit: 100000 } }));
  // Simulate the real source/model HTTP protocols in the child. Any model invocation is observable.
  writeFileSync(hook, `import https from 'node:https';
import http from 'node:http';
import {EventEmitter} from 'node:events';
import {syncBuiltinESMExports} from 'node:module';
import {writeFileSync} from 'node:fs';
const requests=[];
https.request=(url,options,callback)=>{
  const req=new EventEmitter();let body='';
  req.write=chunk=>{body+=String(chunk);return true;};
  req.destroy=error=>{if(error)queueMicrotask(()=>req.emit('error',error));return req;};
  req.end=()=>{queueMicrotask(()=>{
    requests.push({hostname:url.hostname,path:url.pathname});writeFileSync(${JSON.stringify(log)},JSON.stringify(requests));
    let data;
    if(url.hostname==='api.osv.dev'&&url.pathname==='/v1/querybatch')data={results:JSON.parse(body).queries.map(()=>({vulns:[{id:'GHSA-abcd-2345-efgh'}]}))};
    else if(url.hostname==='api.osv.dev'&&url.pathname.startsWith('/v1/vulns/'))data={id:'GHSA-abcd-2345-efgh',modified:${JSON.stringify(now)},summary:'Alpha critical vulnerability',details:'The alpha package is affected in version 1.0.0.',database_specific:{severity:'CRITICAL'},affected:[{package:{ecosystem:'npm',name:'alpha'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'1.0.1'}]}]}]};
    else {req.emit('error',new Error('TEST_MODEL_REQUEST_FORBIDDEN'));return;}
    const res=new EventEmitter();res.statusCode=200;res.headers={};res.destroy=()=>{};callback(res);res.emit('data',Buffer.from(JSON.stringify(data)));res.emit('end');
  });return req;};
  return req;
};
http.request=()=>{throw new Error('TEST_UNEXPECTED_NETWORK');};globalThis.fetch=()=>{throw new Error('TEST_UNEXPECTED_NETWORK');};syncBuiltinESMExports();
`);
  for (let run = 0; run < 2; run++) {
    const result = spawnSync(process.execPath, ['--import', hook, cli, 'scan', '--dry-run'], { cwd: dir, env: { ...process.env, WATCH_CLI_DRY_MODEL_KEY: 'fixture-key-only' }, encoding: 'utf8', timeout: 8000 });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    const finding = report.findings.find(item => item.category === 'library');
    assert.equal(finding.applicability, 'affected');
    assert.equal(finding.source_severity, 'critical');
    assert.equal(finding.ai, undefined);
    assert(!report.errors.some(error => error.source === 'models'));
    const requests = JSON.parse(readFileSync(log, 'utf8'));
    assert.equal(requests.length, 2);
    assert(requests.every(request => request.hostname === 'api.osv.dev'));
    assert.equal(existsSync(join(dir, 'data/watch.db')), false);
    assert.equal(existsSync(join(dir, 'data/watch.db.lock')), false);
    assert.equal(result.stdout.includes('fixture-key-only'), false);
  }
});
