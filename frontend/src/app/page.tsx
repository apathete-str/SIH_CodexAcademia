'use client';

import { useState } from 'react';
import { ShieldCheck, Upload, Search, MapPin, Activity, ArrowUpRight, FileText, Globe2, Fingerprint, CheckCircle2 } from 'lucide-react';

type Result = { email: { subject: string; from_addr?: string; body_text: string; urls: string[] }; threat: { threat_score: number; verdict: string; category?: string; confidence: number; explanation: string; signals: { name: string; score: number; description: string }[] }; geo: { origin_country?: string; sender_ip?: string; geo_risk: number }; iocs?: { type: string; value: string; source: string }[]; timeline?: { stage: string; action: string; status: string }[] };

const configuredApi = process.env.NEXT_PUBLIC_API_URL || (process.env.NODE_ENV === 'development' ? 'http://localhost:8000' : '');
const API = configuredApi && /^https?:\/\//.test(configuredApi) ? configuredApi : configuredApi ? `https://${configuredApi}` : '';

export default function Home() {
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState('');

  async function analyze(file: File) {
    setFileName(file.name);
    setLoading(true); setError('');
    try {
      if (!API) throw new Error('Analysis service is not configured. Set NEXT_PUBLIC_API_URL in Vercel.');
      const body = new FormData();
      body.append('file', file);
      const response = await fetch(`${API.replace(/\/$/, '')}/api/v1/ingest/analyze`, { method: 'POST', body });
      if (!response.ok) {
        let detail = `Analysis failed (${response.status})`;
        try {
          const payload = await response.json() as { detail?: string };
          if (payload.detail) detail = payload.detail;
        } catch {
          // Keep the status-based message when the API does not return JSON.
        }
        throw new Error(detail);
      }
      setResult(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to reach analysis service');
    } finally { setLoading(false); }
  }

  const verdict = result?.threat.verdict || 'awaiting input';
  function handleDrop(event: React.DragEvent<HTMLLabelElement>) {
    event.preventDefault(); setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) analyze(file);
  }

  return <main className="shell">
    <nav><div className="brand"><span className="brand-mark"><ShieldCheck size={20} /></span><span>Sentinel</span><small>THREAT INTELLIGENCE</small></div><div className="nav-status"><span className="pulse" /> SYSTEMS OPERATIONAL <span className="nav-divider" /> SIH / 2026</div></nav>
    <section className="hero"><div><p className="eyebrow">EMAIL THREAT INTELLIGENCE PLATFORM</p><h1>Clarity in every<br /><em>digital message.</em></h1><p className="lede">Inspect suspicious emails with explainable detection, infrastructure context, and a court-ready evidence trail.</p></div><div className="metric-rail"><div><b>03</b><span>analysis layers</span></div><div><b>360°</b><span>evidence context</span></div></div></section>
    <div className="workflow"><span className="active"><i>01</i> Upload</span><span><i>02</i> Assess</span><span><i>03</i> Trace</span></div>
    <section className="workspace"><div className="upload-panel"><div className="section-label"><span>01</span> INGEST EVIDENCE</div><label onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={handleDrop} className={`dropzone ${loading ? 'loading' : ''} ${dragging ? 'dragging' : ''}`}><input type="file" accept=".eml,.msg,.txt" onChange={event => event.target.files?.[0] && analyze(event.target.files[0])} /><span className="upload-icon"><Upload size={22} /></span><strong>{loading ? 'Analyzing message...' : dragging ? 'Release to inspect' : 'Drop an email file here'}</strong><span>or click to browse · EML, MSG, TXT</span>{fileName && !loading && <small><FileText size={13} /> {fileName}</small>}</label>{error && <p className="error">{error}</p>}<div className="mini-log"><span><Activity size={14} /> PIPELINE READY</span><span>PARSE → ENRICH → SCORE → TRACE</span></div></div>
      <div className="result-panel"><div className="section-label"><span>02</span> THREAT ASSESSMENT <span className="live-tag">LIVE</span></div>{result ? <><div className={`verdict ${verdict}`}><div><span className="verdict-kicker">COMPOSITE VERDICT</span><strong>{verdict.toUpperCase()}</strong><span>{result.threat.category?.replace('_', ' ') || 'unclassified'} · {Math.round(result.threat.confidence * 100)}% confidence</span></div><b>{Math.round(result.threat.threat_score)}<small>/100</small></b></div><div className="email-meta"><span>SUBJECT</span><strong>{result.email.subject}</strong><span>FROM</span><strong>{result.email.from_addr || 'unknown sender'}</strong></div><p className="explanation">{result.threat.explanation}</p><div className="signals">{result.threat.signals.slice(0, 4).map(signal => <div className="signal" key={signal.name}><span>{signal.name.replaceAll('_', ' ')}</span><b>{Math.round(signal.score * 100)}%</b><div className="bar"><i style={{ width: `${signal.score * 100}%` }} /></div></div>)}</div></> : <div className="empty"><span className="empty-icon"><Search size={22} /></span><strong>Ready when you are</strong><span>Upload a message to see its risk profile and reasoning.</span></div>}</div></section>
    <section className="lower"><div className="lower-heading"><div><p className="eyebrow">03 / INFRASTRUCTURE TRACE</p><h2>Origin intelligence</h2><p>Context that helps you understand where a message came from.</p></div><ArrowUpRight size={20} /></div><div className="intel-grid"><div className="intel-card"><MapPin size={19} /><span>ORIGIN COUNTRY</span><strong>{result?.geo.origin_country || '—'}</strong><small>{result?.geo.sender_ip || 'No sender IP resolved'}</small></div><div className="intel-card"><Globe2 size={19} /><span>GEO RISK INDEX</span><strong>{result ? `${Math.round(result.geo.geo_risk * 100)} / 100` : '—'}</strong><small>IP reputation and route context</small></div><div className="intel-card"><Fingerprint size={19} /><span>FORENSIC STATE</span><strong>{result ? 'CAPTURED' : 'READY'}</strong><small>{result ? `${result.timeline?.length ?? 0} stages · ${result.iocs?.length ?? 0} IOCs` : 'Hash chain prepared on ingest'}</small></div></div>{result && <div className="evidence-grid"><div className="evidence-block"><div className="section-label"><span>04</span> IOC INVENTORY</div><div className="ioc-list">{(result.iocs ?? []).map(ioc => <div className="ioc" key={`${ioc.type}-${ioc.value}`}><b>{ioc.type}</b><span>{ioc.value}</span></div>)}</div></div><div className="evidence-block"><div className="section-label"><span>05</span> ANALYSIS TIMELINE</div><div className="timeline">{(result.timeline ?? []).map(event => <div className="timeline-event" key={event.stage}><i /><div><b>{event.stage}</b><span>{event.action.replaceAll('_', ' ')}</span></div></div>)}</div></div></div>}</section>
    <footer><span><CheckCircle2 size={14} /> Evidence stays in your workspace</span><span>Sentinel analysis core · v1.0</span></footer>
  </main>;
}
