export function mergeActivity<T extends {id:string;timestamp?:string}>(...groups:T[][]):T[]{
 const entries=new Map<string,T>();
 for(const group of groups)for(const item of group)if(item&&typeof item.id==='string')entries.set(item.id,item);
 return [...entries.values()].sort((a,b)=>(b.timestamp??'').localeCompare(a.timestamp??'')).slice(0,100);
}
export function loadReportHistory(storage:Pick<Storage,'getItem'>):Record<string,any>[] {
 try{
  const value=JSON.parse(storage.getItem('gitpilot.reports.v1')??storage.getItem('repopilot.reports.v1')??'[]');
  if(!Array.isArray(value))return [];
  return value.filter(item=>item&&typeof item==='object'&&typeof item.id==='string'&&typeof item.repository==='string'&&typeof item.created_at==='string'&&['completed','partial','failed'].includes(item.status)&&['dependencies','findings','checks','executions','errors','modules'].every(key=>Array.isArray(item[key]))&&item.dependencies.every((dependency:any)=>dependency&&typeof dependency.name==='string')&&item.findings.every((finding:any)=>finding&&typeof finding.id==='string'&&typeof finding.package==='string')&&item.executions.every((execution:any)=>execution&&typeof execution.id==='string'&&typeof execution.tool==='string')&&item.checks.every((check:any)=>check&&typeof check.name==='string')).slice(0,4);
 }catch{return [];}
}
