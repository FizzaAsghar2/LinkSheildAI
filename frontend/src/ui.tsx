import { useEffect, useState } from 'react';
import { Shield, Globe, ScanLine, Trash2 } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
type Scan = { id: number; url: string; status: string; risk_score: number | null; classification: string | null; created_at: string; result: any };

export default function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [url, setUrl] = useState('');
  const [current, setCurrent] = useState<Scan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);

  async function refresh() {
    try {
      const [items, health] = await Promise.all([
        fetch(`${API}/api/v1/scans`).then(r => r.json()),
        fetch(`${API}/health`).then(r => r.ok),
      ]);
      setScans(items);
      setConnected(health);
    } catch { setConnected(false); }
  }

  useEffect(() => { refresh(); }, []);

  async function submit(e: any) {
    e.preventDefault(); setError(''); setBusy(true); setCurrent(null);
    try {
      const response = await fetch(`${API}/api/v1/scans`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      if (!response.ok) throw new Error((await response.json()).detail || 'Could not start scan');
      let scan = await response.json(); setCurrent(scan);
      for (let i = 0; i < 40; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        scan = await fetch(`${API}/api/v1/scans/${scan.id}`).then(r => r.json());
        setCurrent(scan);
        if (['completed', 'failed'].includes(scan.status)) break;
      }
      await refresh();
    } catch (err: any) { setError(err.message || 'Backend unavailable'); }
    finally { setBusy(false); }
  }

  async function remove(id: number) {
    await fetch(`${API}/api/v1/scans/${id}`, { method: 'DELETE' });
    if (current?.id === id) setCurrent(null);
    await refresh();
  }

  const result = current?.result;
  const seriousFinding = result?.findings?.find((finding: any) => ['high', 'critical'].includes(finding.severity));
  const suspicious = current?.status === 'completed' && (!!seriousFinding || (current.risk_score ?? 0) >= 40);
  const safe = current?.status === 'completed' && !suspicious && current.risk_score !== null;
  const verdict = suspicious ? 'Suspicious' : safe ? 'Safe' : current?.status === 'failed' ? 'Could not scan' : 'Scanning…';
  const explanation = seriousFinding?.title || (suspicious
    ? result?.findings?.[0]?.title || 'The scan found patterns that need a closer look.'
    : safe
      ? 'No major risky behavior was found in the code we inspected. A scan cannot guarantee that every part of a site is safe.'
      : 'The page could not be fully checked. Try again later.');

  return <main className="simple-app">
    <header className="simple-top"><div className="brand"><div className="logo"><Shield size={21}/></div><span>LINKSHIELD <b>AI</b></span></div><span className={'connection ' + (connected ? 'connected' : '')}>{connected ? 'Connected' : 'Offline'}</span></header>
    <section className="simple-hero"><div className="eyebrow">LINK SAFETY CHECK</div><h1>Check a link<br/><em>before you open it.</em></h1><p>We inspect the page and its code for signs of risky behavior.</p>
      <form className="scanbox" onSubmit={submit}><Globe size={19}/><input value={url} onChange={e => setUrl(e.target.value)} placeholder="Paste a website link" type="url" required/><button disabled={busy}><ScanLine size={17}/>{busy ? 'Checking…' : 'Check link'}</button></form>
      {error && <div className="error">{error}</div>}
      <div className="simple-hint">The scan does not open or run the page’s scripts.</div>
    </section>

    {current && <section className={'verdict-card ' + (suspicious ? 'is-suspicious' : safe ? 'is-safe' : '')}>
      <div className="verdict-label">{verdict}</div>
      <div className="verdict-url">{result?.domain || current.url}</div>
      <p>{explanation}</p>
    </section>}

    <section className="recent"><div className="recent-heading"><h2>Recent checks</h2><span>{scans.length}</span></div>
      {scans.length ? scans.slice(0, 6).map(scan => {
        const finding = scan.result?.findings?.find((item: any) => ['high', 'critical'].includes(item.severity));
        const isRisky = !!finding || (scan.risk_score ?? 0) >= 40;
        const label = scan.status !== 'completed' ? scan.status : !scan.result?.scanner_version ? 'Rescan' : isRisky ? 'Suspicious' : 'Safe';
        return <div className="recent-row" key={scan.id} onClick={() => setCurrent(scan)}>
          <span className="recent-url">{scan.url}</span><span className={'recent-verdict ' + (isRisky ? 'risky' : 'okay')}>{label}</span>
          <button className="icon" title="Delete check" onClick={e => { e.stopPropagation(); remove(scan.id); }}><Trash2 size={15}/></button>
        </div>;
      }) : <p className="no-checks">Your checked links will appear here.</p>}
    </section>
    <footer className="simple-footer"><Shield size={14}/> LINKSHIELD AI</footer>
  </main>;
}
