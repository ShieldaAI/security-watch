import { readFileSync, statSync } from 'node:fs';
import { z } from 'zod';
import { assess, decide } from './assessment.js';
import { collectSources } from './sources.js';
import { ModelAnalyzer } from './models.js';
import { Store } from './store.js';
import { safeHttp } from './http.js';
import { missingCredentials } from './config.js';
import { hash, severityRank, timestamp } from './util.js';
import type { Assessment, Config, Decision, Evidence, HttpClient, Inventory } from './types.js';

export interface ScanReport { at:string; findings:Assessment[]; decisions:Record<string,Decision>; degraded:boolean; errors:{source:string;message:string}[]; evidence_count:number }
const evidenceSchema=z.object({
  id:z.string().min(1),source:z.string().min(1),kind:z.enum(['advisory','news','kev','health']),title:z.string(),
  url:z.string(),description:z.string(),aliases:z.array(z.string()),severity:z.enum(['unknown','low','medium','high','critical']),
  modified_at:z.iso.datetime(),fetched_at:z.iso.datetime(),published_at:z.iso.datetime().optional(),
  packages:z.array(z.object({ecosystem:z.string(),name:z.string(),range:z.string().optional(),versions:z.array(z.string()).optional(),matched_versions:z.array(z.string()).optional(),fixed:z.string().optional()}).strict()),
  withdrawn:z.boolean().optional(),exploited:z.boolean().optional(),malware:z.boolean().optional(),
}).strict();
export function readFixture(path:string):Evidence[] {
  if(statSync(path).size>8_388_608) throw new Error('Fixture exceeds 8 MiB');
  return z.array(evidenceSchema).max(5000).parse(JSON.parse(readFileSync(path,'utf8')));
}
export function healthFinding(source:string,message:string,now=Date.now()):Assessment {
  return {id:`health-${hash(source).slice(0,20)}`,event_id:`health:${source}`,system_id:'monitor',category:'health',
    applicability:'unknown',source_severity:'high',priority:'high',title:`Monitoring needs attention: ${source}`,
    summary:message,reasons:['Monitoring is incomplete; this is not a clean security result.'],evidence_ids:[],urls:[],exploited:false,updated_at:timestamp(now)};
}

export async function runScan(options:{config:Config;inventory:Inventory;store:Store;http?:HttpClient;fixture?:Evidence[];now?:number;onUrgent?:()=>Promise<void>}):Promise<ScanReport> {
  const {config,inventory,store}=options;
  const now=options.now ?? Date.now(); const http=options.http ?? safeHttp;
  const result=options.fixture ? {evidence:options.fixture,errors:[],checkpoints:{}} : await collectSources(inventory,config,store.checkpoints(),http,now,store.evidence());
  store.saveEvidence(result.evidence,result.checkpoints);
  const evidence=store.evidence();
  const findings=assess(inventory,evidence,config,now);
  const errors=[...result.errors];
  if(!options.fixture && missingCredentials(config).length) errors.push({source:'credentials',message:'Configured model or delivery credentials are missing. Structured advisory matching continues; run doctor to see required variable names.'});
  if(!inventory.systems.length) errors.push({source:'inventory',message:'Inventory is empty; add systems before enabling monitoring.'});
  if(!config.sources.osv&&!config.sources.github&&!config.sources.kev&&!config.sources.feeds.length&&!options.fixture) errors.push({source:'sources',message:'All sources are disabled.'});
  if(config.sources.feeds.length&&!config.models.enabled) errors.push({source:'models',message:'AI is disabled. News receives keyword candidate matching only; contextual news severity is incomplete.'});
  for(const system of inventory.systems) {
    const updated=Date.parse(system.updated_at);
    if(!Number.isFinite(updated)||updated>now+300_000||now-updated>config.inventory_stale_days*86_400_000) errors.push({source:`inventory:${system.id}`,message:'Inventory timestamp is stale or in the future; verify installed versions and deployment context.'});
  }
  const decisions:Record<string,Decision>={};
  const persist=(a:Assessment)=>{
    const decision=decide(a,config); decisions[a.id]=decision;
    store.saveAssessment(a,decision,now,config.digest_interval_hours*3_600_000);
  };
  // Urgent deterministic results enter the outbox before any optional model request.
  const urgent=findings.filter(a=>a.category!=='news' && decide(a,config).action==='notify');
  const previousById=new Map(store.findings().map(a=>[a.id,a]));
  urgent.forEach(finding=>{
    const previous=previousById.get(finding.id);
    // Do not oscillate between a prior AI escalation and its unchanged deterministic baseline.
    persist(previous && previous.active!==false && severityRank[previous.priority]>severityRank[finding.priority] ? {...finding,priority:previous.priority} : finding);
  });
  if(options.onUrgent) await options.onUrgent();
  const analyzer=new ModelAnalyzer(config,store,http,options.now===undefined?Date.now:()=>now);
  const analyzed:Assessment[]=[];
  for(const finding of findings.sort((a,b)=>severityRank[b.priority]-severityRank[a.priority])) {
    const system=inventory.systems.find(s=>s.id===finding.system_id);
    let enriched=system && !options.fixture ? await analyzer.analyze(finding,system,evidence) : finding;
    const previous=previousById.get(finding.id);
    if((enriched.ai?.status==='unavailable'||enriched.ai?.status==='conflicting') && previous && previous.active!==false &&
      (previous.applicability===enriched.applicability||enriched.applicability==='unknown'||enriched.applicability==='conflicting') && enriched.applicability!=='not_affected' && !enriched.withdrawn &&
      severityRank[previous.priority]>severityRank[enriched.priority]) {
      enriched={...enriched,priority:previous.priority,reasons:[...enriched.reasons,'Previous priority retained pending valid AI reassessment.']};
    }
    if(enriched.ai?.status==='unavailable'||enriched.ai?.status==='conflicting') {
      const code=enriched.reasons.find(r=>r.startsWith('MODEL_'))?.split(';')[0] ?? 'Analysis disagreement';
      if(!errors.some(e=>e.source==='models'&&e.message===code)) errors.push({source:'models',message:code});
    }
    analyzed.push(enriched);persist(enriched);
  }
  const healthFindings=errors.map(e=>healthFinding(e.source,e.message,now));
  healthFindings.forEach(persist);
  const active=new Set([...analyzed,...healthFindings].map(a=>a.id));
  for(const previous of store.findings()) if(!active.has(previous.id)&&previous.active!==false) {
    store.saveAssessment({...previous,active:false,updated_at:timestamp(now),reasons:[...previous.reasons,'No longer in the current assessment. This does not establish remediation.']},
      {action:'record',channels:[],reason:'No current inventory/evidence match or monitoring issue recovered'},now);
  }
  const report={at:timestamp(now),findings:[...analyzed,...healthFindings],decisions,degraded:errors.length>0,errors,evidence_count:evidence.length};
  store.setMeta('last_scan',JSON.stringify({at:report.at,degraded:report.degraded,errors:report.errors,findings:report.findings.length}));
  return report;
}
