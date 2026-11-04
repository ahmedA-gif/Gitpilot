import {RepositoryOverview} from './RepositoryOverview';
import {useState} from 'react';
import {ArrowRight, Check, CheckCircle2, ChevronDown, Github, LoaderCircle, AlertTriangle, ShieldCheck, ScanLine, Download, MessageSquare} from 'lucide-react';

type Props = {
 repo:string; setRepo:(value:string)=>void; modules:string[]; setModules:(value:string[])=>void;
 scan:any; running:boolean; locked:boolean; startScan:(event:React.FormEvent)=>void; goto:(tab:number)=>void; onDownload:(format:'html'|'json')=>void;
};
const options=[{id:'repository',label:'Repository overview'},{id:'dependencies',label:'Python packages'},{id:'security',label:'Security checks'},{id:'ci',label:'Build checks'}];

function ShieldScene(){return <div className="shield-scene" aria-hidden="true"><div className="shield-floor"/><div className="shield-orbit orbit-one"/><div className="shield-orbit orbit-two"/><div className="shield-object"><div className="shield-layer back"/><div className="shield-layer middle"/><div className="shield-face"><svg viewBox="0 0 120 140" fill="none"><path d="M60 7 108 26v40c0 34-48 65-48 65S12 100 12 66V26L60 7Z" fill="url(#shield-face)" stroke="#d1ffae" strokeWidth="2"/><path d="m38 66 16 16 30-35" stroke="#e6ffd3" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round"/><defs><linearGradient id="shield-face" x1="10" y1="0" x2="100" y2="140" gradientUnits="userSpaceOnUse"><stop stopColor="#8bcb62" stopOpacity=".5"/><stop offset="1" stopColor="#172b22"/></linearGradient></defs></svg></div></div><span className="scene-dot dot-one"/><span className="scene-dot dot-two"/></div>}

export function Analyzer({repo,setRepo,modules,setModules,scan,running,locked,startScan,goto,onDownload}:Props){
 const [effects,setEffects]=useState(()=>{try{return sessionStorage.getItem('repoguard.visuals')!=='paused';}catch{return true;}});
 const toggleEffects=()=>{setEffects(!effects);try{sessionStorage.setItem('repoguard.visuals',effects?'paused':'on');}catch{}};
 const done=scan&&!running;
 const evidence=(tool:string)=>scan?.executions?.find((e:any)=>e.tool===tool&&e.status==='completed')?.result;
 const security=evidence('scan_known_vulnerabilities');
 const dependency=evidence('parse_python_dependencies');
 const coverage=security?.scanned>0;
 const count=scan?.findings?.length??0;
 const unavailable=scan?.checks?.filter((c:any)=>c.status==='unavailable').length??0;
 const title=scan?.status==='failed'?'We couldn’t finish this scan':scan?.readiness?.status==='blocked'?'Some issues need your attention':unavailable?'Your report is ready, with a few gaps':'Your report is ready';
 const summary=scan?.status==='failed'?(scan.errors?.[0]??'Please try again.'):count?`${count} known security ${count===1?'advisory was':'advisories were'} found in declared Python package versions.`:coverage?'No known advisories were returned for the exact package versions checked.':'Repository checks are available. Python security results could not be confirmed.';
 return <div className={`simple-analyzer ${effects?'effects-on':'effects-off'}`}>
  <section className="start-card">
   <div className="start-intro"><span className="simple-eyebrow"><span/> LIVE REPOSITORY CHECK</span><h2>Understand your repo.<br/><span>Know what to fix next.</span></h2><p>Paste a public GitHub link. Get a clear summary<br className="desktop-br"/> of your code, packages, and release checks.</p></div>
   <ShieldScene/>
   <button type="button" className="effects-toggle" aria-pressed={effects} onClick={toggleEffects}>{effects?'Pause visuals':'Play visuals'}</button>
   <form onSubmit={startScan} className="simple-scan-form">
    <label htmlFor="repo-url">Your GitHub repository</label>
    <div className="simple-input-row"><div className="simple-repo-input"><Github size={21}/><input id="repo-url" value={repo} onChange={e=>setRepo(e.target.value)} placeholder="https://github.com/owner/repository" required disabled={locked} autoComplete="off" spellCheck={false} aria-describedby="repo-help"/></div><button className="primary" disabled={locked||!repo.trim()||modules.length===0}>{running?<LoaderCircle size={18} className="spin"/>:<ScanLine size={18}/>} {running?'Scanning…':'Scan repository'}{!running&&<ArrowRight size={17}/>}</button></div>
    <p id="repo-help" className="simple-help">Repository, file, or branch links work. We check the default branch. No sign-in needed.</p>
    <details className="scan-settings"><summary>Scan options <span>{modules.length===4?'All checks enabled':`${modules.length} selected`}</span><ChevronDown size={16}/></summary><div className="simple-options">{options.map(option=><label key={option.id}><input type="checkbox" disabled={locked} checked={modules.includes(option.id)} onChange={()=>setModules(modules.includes(option.id)?modules.filter(id=>id!==option.id):[...modules,option.id])}/>{option.label}</label>)}</div>{modules.length===0&&<p className="simple-help">Choose at least one check to start.</p>}<p className="simple-help">Security checks also read Python package files. Unpinned versions and other languages are not covered.</p></details>
   </form>
  </section>
  {running&&<section className="scan-live" role="status" aria-live="polite"><div className="scan-radar"><ScanLine size={24}/></div><div><h3>{scan?.progress===0?'Connecting to GitHub…':'Checking your repository…'}</h3><p>{scan?.checks?.length?`${scan.checks.length} checks returned. We’ll show your summary here.`:'This can take a few minutes. You can keep this page open.'}</p></div><strong>{scan?.progress??0}%</strong><div className="progress-bar"><i style={{width:`${scan?.progress??0}%`}}/></div></section>}
  {done&&<section className="scan-summary" aria-live="polite"><div className="summary-title"><div className="summary-icon">{scan.status==='failed'||count||unavailable?<AlertTriangle size={24}/>:<ShieldCheck size={24}/>}</div><div><span className="simple-eyebrow">{scan.repository_info?.full_name??scan.repository}</span><h2>{title}</h2></div></div><p className="summary-copy">{summary}</p>{scan.repository_info&&<p className="repository-caption">{scan.repository_info.language??'Language not reported'} · {scan.repository_info.default_branch??'Default branch'}{scan.repository_info.html_url&&<> · <a href={scan.repository_info.html_url} target="_blank" rel="noreferrer">Open on GitHub ↗</a></>}</p>}{scan.status!=='failed'&&<><div className="summary-metrics"><div><strong>{dependency?scan.dependencies.length:'—'}</strong><span>Package declarations</span></div><div><strong>{coverage?count:'—'}</strong><span>Known advisories</span></div><div><strong>{unavailable}</strong><span>Incomplete checks</span></div></div>{(!coverage||security?.coverage!=='complete')&&<p className="summary-note">{!dependency?.manifests?.length?'No supported Python package files were available. Other languages can still get repository and build checks.':'Security coverage is limited to exact Python versions. Missing results do not mean the repository is safe.'}</p>}<div className="summary-actions"><button className="primary" onClick={()=>goto(1)}>See findings <ArrowRight size={16}/></button><button className="secondary" onClick={()=>goto(2)}><MessageSquare size={16}/>Explain my results</button><a className="secondary" href={`/api/scans/${scan.id}/export?format=html`} onClick={event=>{event.preventDefault();onDownload('html');}} download><Download size={16}/>Download report</a></div></>}
   <details className="check-details"><summary>Check-by-check details <ChevronDown size={16}/></summary><div>{scan.checks.map((check:any,index:number)=><div className="simple-check" key={index}>{check.status==='passed'?<CheckCircle2 size={18}/>:<AlertTriangle size={18}/>}<div><strong>{check.name}</strong><p>{check.detail}</p></div><span>{check.status==='passed'?'Done':check.status==='failed'?'Needs attention':'Not confirmed'}</span></div>)}</div></details><button className="text-button" onClick={()=>goto(4)}>Open full report <ArrowRight size={15}/></button>
  </section>}
  {done&&<RepositoryOverview key={scan.id} scan={scan}/>}
  {!scan&&!running&&<div className="quick-guide"><div><span>1</span><strong>Paste a link</strong><p>Any public GitHub repository.</p></div><div><span>2</span><strong>Run the checks</strong><p>Read-only. Your code stays unchanged.</p></div><div><span>3</span><strong>See what matters</strong><p>Plain-language findings and next steps.</p></div></div>}
  <p className="scope-note"><Check size={15}/>Real provider data, briefly cached. Python package security · GitHub activity & builds.</p>
 </div>;
}
