import React from 'react';
import {label} from './ReadableResult';
type Values = Record<string, any>;
type Props = {name: string; fields: Record<string, any>; required: string[]; values: Values; setValues: (value: Values) => void; hasScan: boolean};

export function ToolInputs({name, fields, required, values, setValues, hasScan}: Props) {
  const set = (key: string, value: unknown) => setValues({...values, [key]: value});
  const entries = Object.entries(fields);
  if (!entries.length) return <p className="input-help">This request does not need any details.</p>;
  return <div className="tool-fields">{entries.map(([key, schema]) => {
    if (name === 'evaluate_release_readiness' && key === 'evidence') {
      return <div className="input-note" key={key}><strong>Release evidence</strong><p>{hasScan ? 'Uses evidence from your selected report.' : 'Select a completed report first to assess its evidence.'}</p></div>;
    }
    if (key === 'dependencies' && name === 'scan_known_vulnerabilities') {
      return <div key={key}><label className="field-label" htmlFor={`field-${key}`}>PACKAGES AND EXACT VERSIONS</label><textarea id={`field-${key}`} className="standard-input multiline" value={values._packageLines ?? ''} onChange={e => set('_packageLines', e.target.value)} placeholder={'One per line, for example:\npackage-name==1.2.3'}/><p className="input-help">{hasScan ? 'Leave blank to use declared packages from your selected report.' : 'Enter an exact version for each package.'}</p></div>;
    }
    if (key === 'findings' && name === 'check_known_exploitation') {
      return <div key={key}><label className="field-label" htmlFor={`field-${key}`}>CVE IDENTIFIERS</label><textarea id={`field-${key}`} className="standard-input multiline" value={values._cveLines ?? ''} onChange={e => set('_cveLines', e.target.value)} placeholder="One CVE identifier per line"/><p className="input-help">{hasScan ? 'Leave blank to check findings from your selected report.' : 'Enter one or more CVE identifiers.'}</p></div>;
    }
    return <div key={key}><label className="field-label" htmlFor={`field-${key}`}>{label(key).toUpperCase()}{required.includes(key) ? ' · REQUIRED' : ''}</label><input id={`field-${key}`} className="standard-input" value={String(values[key] ?? '')} onChange={e => set(key, e.target.value)} placeholder={key === 'repository' ? 'owner/repository' : key === 'package' ? 'Python package name' : label(key)} />{schema.description && <p className="input-help">{schema.description}</p>}</div>;
  })}</div>;
}
