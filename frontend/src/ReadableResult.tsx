import React from 'react';

type RecordValue = Record<string, unknown>;
const hidden = new Set(['type', 'mimeType', 'mime_type', 'role', 'annotations', 'meta', '_meta', 'node_id']);
const friendly: Record<string, string> = {full_name:'Repository', html_url:'Repository link', stargazers_count:'Stars', forks_count:'Forks', open_issues_count:'Open issues', pushed_at:'Last push', updated_at:'Last updated', size:'Repository size (KB)', uri:'Address', text:'Details', messages:'Prompt', content:'Details'};
export const label = (name: string) => friendly[name] ?? name.replace(/[_-]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase());

function decoded(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try { return JSON.parse(trimmed); } catch { return value; }
  }
  return value;
}

/** Presents real protocol data as readable, expandable evidence without exposing wire-format JSON. */
export function ReadableResult({value, depth = 0}: {value: unknown; depth?: number}): React.ReactNode {
  value = decoded(value);
  if (value == null || value === '') return <span className="evidence-muted">Not available</span>;
  if (typeof value === 'boolean') return <span>{value ? 'Yes' : 'No'}</span>;
  if (typeof value === 'string' || typeof value === 'number') {
    const display = String(value);
    return /^https:\/\//.test(display) ? <a className="evidence-link" href={display} target="_blank" rel="noreferrer">{display}</a> : <span className="evidence-text">{display}</span>;
  }
  if (Array.isArray(value)) {
    if (!value.length) return <span className="evidence-muted">None returned</span>;
    const entries = value.map((item, index) => <li key={index}><ReadableResult value={item} depth={depth + 1}/></li>);
    return <><ul className="evidence-list">{entries.slice(0, 4)}</ul>{entries.length > 4 && <details className="evidence-more"><summary>Show {entries.length - 4} more</summary><ul className="evidence-list">{entries.slice(4)}</ul></details>}</>;
  }
  if (typeof value === 'object') {
    const object = value as RecordValue;
    if ('text' in object && Object.keys(object).every(key => ['type', 'text', 'annotations', 'meta', '_meta'].includes(key))) return <ReadableResult value={object.text} depth={depth + 1}/>;
    const entries = Object.entries(object).filter(([key, item]) => !hidden.has(key) && item != null && item !== '');
    if (!entries.length) return <span className="evidence-muted">No additional details</span>;
    const fields = entries.map(([key, item]) => <div className="evidence-field" key={key}><dt>{label(key)}</dt><dd><ReadableResult value={item} depth={depth + 1}/></dd></div>);
    return <div className={`evidence-grid ${depth ? 'nested' : ''}`}><dl className="evidence-grid">{fields.slice(0, 6)}</dl>{fields.length > 6 && <details className="evidence-more"><summary>Show {fields.length - 6} more details</summary><dl className="evidence-grid">{fields.slice(6)}</dl></details>}</div>;
  }
  return <span className="evidence-muted">Not available</span>;
}

export function plainAssistantText(text: string): string {
  return text.replace(/^```(?:json)?\s*/gim, '').replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '$1 ($2)').replace(/^\s{0,3}#{1,6}\s+/gm, '').replace(/\*\*([^*]+)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1');
}
