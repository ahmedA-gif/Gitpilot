import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from 'typescript';
const source=fs.readFileSync(new URL('../src/session.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {mergeActivity,loadReportHistory}=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
const report={id:'scan',repository:'owner/repo',created_at:'2026-11-06',status:'completed',dependencies:[],findings:[],checks:[],executions:[],errors:[],modules:[]};
test('manual and assistant calls remain visible alongside scan activity',()=>{
 const manual={id:'manual',timestamp:'2026-11-06T01:00:00Z',tool:'get_repository_info'};
 const assistant={id:'assistant',timestamp:'2026-11-06T02:00:00Z',tool:'inspect_ci_status'};
 const scan={id:'scan',timestamp:'2026-11-06T03:00:00Z',tool:'parse_python_dependencies'};
 assert.deepEqual(mergeActivity([manual,assistant],[manual,scan]).map(item=>item.id),['scan','assistant','manual']);
});
test('corrupt or unfinished stored reports do not crash the saved reports screen',()=>{
 for(const value of ['null','{}','"wrong"','[null,{}]','invalid',JSON.stringify([{...report,status:'running'}]),JSON.stringify([{...report,dependencies:[null]}])])assert.deepEqual(loadReportHistory({getItem:()=>value}),[]);
 assert.equal(loadReportHistory({getItem:()=>JSON.stringify([report])})[0].repository,'owner/repo');
});
test('reports saved before the Gitpilot rename remain available',()=>{
 const storage={getItem:key=>key==='repopilot.reports.v1'?JSON.stringify([report]):null};
 assert.equal(loadReportHistory(storage)[0].id,'scan');
});
