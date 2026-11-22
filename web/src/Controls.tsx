import { useEffect, useState } from 'react';

type Rule = { enabled: boolean; expression: string };
type Rules = Record<string, Rule>;
async function request(path: string, init?: RequestInit) {
  const response = await fetch('/api/v1/' + path, init);
  const value = await response.json();
  if (!response.ok) throw new Error(value.message || response.statusText);
  return value;
}
export function Controls({ inventory }: { inventory: boolean }) {
  const [rules, setRules] = useState<Rules>({});
  const [sources, setSources] = useState<Array<{name:string;updated:string;rows:number}>>([]);
  const [message, setMessage] = useState('');
  useEffect(() => {
    if (inventory) request('inventories').then(setSources).catch(e => setMessage(e.message));
    else request('settings/schedules').then(setRules).catch(e => setMessage(e.message));
  }, [inventory]);
  return <section className="panel assessment-form"><h2>{inventory ? 'Excel inventories' : 'Feed schedules'}</h2>
    {inventory ? <><p>Use hostname, vendor, product and version as first-sheet headers. Upload under the same name to replace a snapshot.</p>
      <form onSubmit={async event => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        try {
          const result = await request('inventories/' + encodeURIComponent(String(data.get('name'))), {method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:data.get('file') as File});
          setSources(await request('inventories'));
          setMessage('Imported ' + result.count + ' rows.');
        } catch(e) { setMessage((e as Error).message); }
      }}><label>Source name <input name="name" required pattern="[a-zA-Z0-9_\-]{1,48}" /></label>
      <label>Workbook <input type="file" name="file" accept=".xlsx" required /></label><button className="button primary">Import workbook</button></form>
      {sources.map(s => <p key={s.name}><strong>{s.name}</strong> · {s.rows} installations · {new Date(s.updated).toLocaleString()}</p>)}</> :
      <form onSubmit={async event => {event.preventDefault(); try {setRules(await request('settings/schedules',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(rules)}));setMessage('Schedules saved.');} catch(e){setMessage((e as Error).message);} }}>
        <p>Schedules use the server time zone. For example, */15 * * * * runs every 15 minutes.</p>
        {Object.entries(rules).map(([key,rule]) => <fieldset key={key}><legend>{key.toUpperCase()}</legend>
        <label><input type="checkbox" checked={rule.enabled} onChange={e=>setRules({...rules,[key]:{...rule,enabled:e.target.checked}})} /> Enabled</label>
        <label>Cron expression <input required value={rule.expression} onChange={e=>setRules({...rules,[key]:{...rule,expression:e.target.value}})} /></label></fieldset>)}
        <button disabled={!Object.keys(rules).length} className="button primary">Save schedules</button></form>}
      <p role="status">{message}</p></section>;
}
