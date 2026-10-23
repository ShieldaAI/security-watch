import {fileURLToPath} from 'node:url';
import {parseConfig,loadInventory,readFixture,Store,runScan} from '../dist/index.js';
const inventory=loadInventory(fileURLToPath(new URL('../examples/systems.example.yaml',import.meta.url)));
for(const system of inventory.systems)system.updated_at=new Date().toISOString();
const config=parseConfig({version:1});const store=new Store(':memory:');
try {
  const report=await runScan({config,inventory,store,fixture:readFixture(fileURLToPath(new URL('../examples/advisories.json',import.meta.url)))});
  console.log(JSON.stringify({notice:'Offline synthetic demonstration: no network, models or notifications.',findings:report.findings.map(f=>({system:f.system_id,applicability:f.applicability,source_severity:f.source_severity,fix:f.fix}))},null,2));
}finally{store.close();}
