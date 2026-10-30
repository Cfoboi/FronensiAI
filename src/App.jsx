import { useEffect, useRef, useState } from 'react';
import {
  addCustodyEvent,
  downloadEvidence,
  getCaseRecords,
  getCases,
  openVault,
  saveEvidence,
  verifyCustody,
} from './vault';
import { supabase, supabaseConfigured } from './supabase/client';
import './App.css';

const formatBytes = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const formatDate = (value) => new Date(value).toLocaleString(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
});

function Icon({ name, size = 18 }) {
  const paths = {
    lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /><path d="M12 14v3" /></>,
    plus: <><path d="M12 5v14M5 12h14" /></>,
    upload: <><path d="M12 16V4m0 0L7 9m5-5 5 5" /><path d="M5 15v4a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-4" /></>,
    file: <><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z" /><path d="M13 3v7h7" /></>,
    download: <><path d="M12 4v12m0 0 5-5m-5 5-5-5" /><path d="M5 20h14" /></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z" /><path d="m9 12 2 2 4-4" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 4 4" /></>,
    arrow: <><path d="M5 12h14m-6-6 6 6-6 6" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    close: <><path d="m18 6-12 12M6 6l12 12" /></>,
  };

  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
}

function App() {
  const [db, setDb] = useState(null);
  const [caseId, setCaseId] = useState('');
  const [caseInput, setCaseInput] = useState('');
  const [cases, setCases] = useState([]);
  const [records, setRecords] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [custodian, setCustodian] = useState('');
  const [custodyAction, setCustodyAction] = useState('Evidence reviewed');
  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [integrityValid, setIntegrityValid] = useState(true);
  const [authSession, setAuthSession] = useState(null);
  const [authPanelOpen, setAuthPanelOpen] = useState(false);
  const [authMode, setAuthMode] = useState('signIn');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authBusy, setAuthBusy] = useState(false);
  const [authMessage, setAuthMessage] = useState('');
  const [authError, setAuthError] = useState('');
  const fileInput = useRef(null);

  useEffect(() => {
    if (!supabase) return undefined;
    let active = true;
    supabase.auth.getSession().then(({ data, error: sessionError }) => {
      if (!active) return;
      if (sessionError) setAuthError(sessionError.message);
      setAuthSession(data.session);
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setAuthSession(session);
      if (session) setAuthPanelOpen(false);
    });
    return () => {
      active = false;
      subscription.unsubscribe();
    };
  }, []);

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      try {
        if (!window.crypto?.subtle) {
          throw new Error('Secure browser cryptography is unavailable. Open this app over HTTPS or localhost.');
        }
        if (!window.indexedDB) throw new Error('This browser does not support private local evidence storage.');
        const vault = await openVault();
        const storedCases = await getCases(vault);
        if (active) {
          setDb(vault);
          setCases(storedCases);
        }
      } catch (vaultError) {
        if (active) setError(vaultError.message || 'The private vault could not be opened.');
      }
    };
    initialize();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    if (!db || !caseId) {
      setRecords([]);
      setSelectedId(null);
      return () => { active = false; };
    }
    getCaseRecords(db, caseId)
      .then((items) => {
        if (active) {
          setRecords(items);
          setSelectedId(items[0]?.id ?? null);
        }
      })
      .catch((vaultError) => {
        if (active) setError(vaultError.message || 'Could not read this case from the vault.');
      });
    return () => { active = false; };
  }, [db, caseId]);

  const selectedRecord = records.find((record) => record.id === selectedId);
  const filteredRecords = records.filter((record) => (
    record.name.toLowerCase().includes(query.toLowerCase())
    || record.sha256.toLowerCase().includes(query.toLowerCase())
  ));

  useEffect(() => {
    let active = true;
    if (!selectedRecord) {
      setIntegrityValid(true);
      return () => { active = false; };
    }
    verifyCustody(selectedRecord.custody)
      .then((valid) => { if (active) setIntegrityValid(valid); })
      .catch(() => { if (active) setIntegrityValid(false); });
    return () => { active = false; };
  }, [selectedRecord]);

  const openCase = (event) => {
    event.preventDefault();
    const normalized = caseInput.trim();
    if (!normalized) return;
    setError('');
    setNotice('');
    setCaseId(normalized);
    setCaseInput(normalized);
  };

  const submitAuth = async (event) => {
    event.preventDefault();
    if (!supabase) return;
    setAuthBusy(true);
    setAuthError('');
    setAuthMessage('');
    try {
      const result = authMode === 'signUp'
        ? await supabase.auth.signUp({ email: authEmail.trim(), password: authPassword })
        : await supabase.auth.signInWithPassword({ email: authEmail.trim(), password: authPassword });
      if (result.error) throw result.error;
      if (authMode === 'signUp' && !result.data.session) {
        setAuthMessage('Check your email to confirm the new account, then sign in.');
        setAuthMode('signIn');
        setAuthPassword('');
      } else {
        setAuthPanelOpen(false);
        setAuthPassword('');
      }
    } catch (authIssue) {
      setAuthError(authIssue.message || 'Authentication failed.');
    } finally {
      setAuthBusy(false);
    }
  };

  const signOut = async () => {
    if (!supabase) return;
    const { error: signOutError } = await supabase.auth.signOut();
    if (signOutError) setAuthError(signOutError.message);
  };

  const handleFiles = async (fileList) => {
    const files = Array.from(fileList || []);
    if (!files.length || !db || !caseId) return;
    if (!custodian.trim()) {
      setError('Enter the custodian name before adding evidence.');
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    try {
      for (const file of files) {
        await saveEvidence(db, { file, caseId, custodian: custodian.trim() });
      }
      const updatedRecords = await getCaseRecords(db, caseId);
      setRecords(updatedRecords);
      setSelectedId(updatedRecords[0]?.id ?? null);
      setCases(await getCases(db));
      setNotice(`${files.length} ${files.length === 1 ? 'file' : 'files'} encrypted and added to ${caseId}.`);
    } catch (vaultError) {
      setError(vaultError.message || 'The evidence could not be secured.');
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = '';
    }
  };

  const logCustodyEvent = async (event) => {
    event.preventDefault();
    if (!selectedRecord || !custodian.trim()) {
      setError('Enter the custodian name to record a custody event.');
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await addCustodyEvent(db, selectedRecord.id, custodian.trim(), custodyAction);
      setRecords(await getCaseRecords(db, caseId));
      setNotice('Custody event recorded.');
    } catch (vaultError) {
      setError(vaultError.message || 'The custody event could not be recorded.');
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async () => {
    if (!selectedRecord) return;
    try {
      const blob = await downloadEvidence(db, selectedRecord.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = selectedRecord.name;
      link.click();
      URL.revokeObjectURL(url);
    } catch (vaultError) {
      setError(vaultError.message || 'The evidence could not be decrypted.');
    }
  };

  return (
    <div className="locker-app">
      <header className="topbar">
        <a className="brand" href="#home" aria-label="Evidence Locker home">
          <span className="brand-mark"><Icon name="lock" size={20} /></span>
          <span>Evidence<span className="brand-light">Locker</span></span>
        </a>
        <div className="topbar-right">
          <span className="privacy-indicator"><span className="privacy-dot" /> {supabaseConfigured ? 'TEAM SIGN-IN CONFIGURED' : 'PRIVATE LOCAL VAULT'}</span>
          {supabaseConfigured && (authSession ? (
            <div className="auth-user"><span title={authSession.user.email}>{authSession.user.email}</span><button type="button" className="auth-link" onClick={signOut}>Sign out</button></div>
          ) : (
            <button type="button" className="auth-link auth-trigger" onClick={() => { setAuthError(''); setAuthMessage(''); setAuthPanelOpen((open) => !open); }}>
              {authPanelOpen ? 'Close sign in' : 'Team sign in'}
            </button>
          ))}
          <span className="topbar-divider" />
          <label className="custodian-field">
            <span>Custodian</span>
            <input value={custodian} onChange={(event) => setCustodian(event.target.value)} placeholder="Your name" aria-label="Custodian name" />
          </label>
        </div>
      </header>

      {supabaseConfigured && authPanelOpen && (
        <section className="auth-panel" aria-label="Team account">
          <form onSubmit={submitAuth}>
            <div className="auth-panel-heading">
              <div><p className="eyebrow">FORENSIAI TEAM ACCESS</p><h2>{authMode === 'signUp' ? 'Create investigator account' : 'Sign in to your account'}</h2></div>
              <button type="button" className="auth-link" onClick={() => { setAuthMode(authMode === 'signUp' ? 'signIn' : 'signUp'); setAuthError(''); setAuthMessage(''); }}>
                {authMode === 'signUp' ? 'Use existing account' : 'Create account'}
              </button>
            </div>
            <div className="auth-fields">
              <label>Email<input type="email" autoComplete="email" required value={authEmail} onChange={(event) => setAuthEmail(event.target.value)} /></label>
              <label>Password<input type="password" autoComplete={authMode === 'signUp' ? 'new-password' : 'current-password'} minLength={8} required value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} /></label>
              <button type="submit" className="button button-dark" disabled={authBusy}>{authBusy ? 'Please wait…' : authMode === 'signUp' ? 'Create account' : 'Sign in'}</button>
            </div>
            {authError && <p className="auth-feedback auth-feedback-error" role="alert">{authError}</p>}
            {authMessage && <p className="auth-feedback" role="status">{authMessage}</p>}
            <p className="auth-disclaimer">Your Supabase password is used only for sign-in. The separate vault passphrase is never sent to Supabase.</p>
          </form>
        </section>
      )}

      <main className="workspace">
        <section className="page-heading">
          <div>
            <p className="eyebrow">DIGITAL EVIDENCE MANAGEMENT</p>
            <h1>Evidence locker</h1>
            <p className="heading-copy">Securely catalog files and maintain a clear record of custody.</p>
          </div>
          <div className="encryption-note"><Icon name="shield" size={17} /><span>AES-256 encrypted at rest</span></div>
        </section>

        <section className="case-toolbar" aria-label="Case selection">
          <form className="case-form" onSubmit={openCase}>
            <label htmlFor="case-id">CASE ID</label>
            <div className="case-input-wrap">
              <input id="case-id" value={caseInput} onChange={(event) => setCaseInput(event.target.value)} placeholder="Enter a case ID" list="saved-cases" />
              <datalist id="saved-cases">{cases.map((savedCase) => <option key={savedCase} value={savedCase} />)}</datalist>
            </div>
            <button type="submit" className="button button-dark" disabled={!db || !caseInput.trim()}>
              Open case <Icon name="arrow" size={16} />
            </button>
          </form>
          <div className="case-context">
            <span className="case-context-label">CURRENT CASE</span>
            <strong>{caseId || 'No case selected'}</strong>
          </div>
        </section>

        {(error || notice) && (
          <div className={`feedback ${error ? 'feedback-error' : 'feedback-success'}`} role={error ? 'alert' : 'status'}>
            <span>{error || notice}</span>
            <button type="button" className="icon-button feedback-dismiss" aria-label="Dismiss message" onClick={() => { setError(''); setNotice(''); }}><Icon name="close" size={16} /></button>
          </div>
        )}

        <div className="dashboard-grid">
          <section className="evidence-column" aria-label="Case evidence">
            <div className="section-header">
              <div>
                <h2>Evidence files <span className="count-badge">{records.length}</span></h2>
                <p>{caseId ? `Items filed under ${caseId}` : 'Open a case to view or add evidence'}</p>
              </div>
              {caseId && (
                <button type="button" className="button button-accent" disabled={busy || !db} onClick={() => fileInput.current?.click()}>
                  <Icon name="plus" size={17} /> Add evidence
                </button>
              )}
              <input ref={fileInput} className="visually-hidden" type="file" multiple disabled={!caseId || busy} onChange={(event) => handleFiles(event.target.files)} aria-label="Choose evidence files" />
            </div>

            {caseId && (
              <div
                className={`drop-zone ${dragging ? 'drop-zone-active' : ''} ${busy ? 'drop-zone-busy' : ''}`}
                onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => { event.preventDefault(); setDragging(false); handleFiles(event.dataTransfer.files); }}
              >
                <span className="drop-icon"><Icon name={busy ? 'lock' : 'upload'} size={19} /></span>
                <span className="drop-copy"><strong>{busy ? 'Encrypting and cataloging…' : 'Drop evidence files here'}</strong><span>Files are encrypted in this browser before being stored.</span></span>
                <button type="button" className="text-button" disabled={busy || !db} onClick={() => fileInput.current?.click()}>{busy ? 'Please wait' : 'Browse files'}</button>
              </div>
            )}

            <div className="list-toolbar">
              <span className="list-label">CASE CONTENTS</span>
              <label className="search-box">
                <Icon name="search" size={16} />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search files or hash" aria-label="Search evidence" />
              </label>
            </div>

            {records.length > 0 ? (
              filteredRecords.length > 0 ? (
                <div className="evidence-list">
                  <div className="list-head"><span>FILE</span><span>ADDED</span><span>SHA-256</span><span>STATUS</span></div>
                  {filteredRecords.map((record) => (
                    <button type="button" className={`evidence-row ${selectedId === record.id ? 'evidence-row-selected' : ''}`} key={record.id} onClick={() => setSelectedId(record.id)}>
                      <span className="file-cell"><span className="file-icon"><Icon name="file" size={17} /></span><span className="file-name-wrap"><strong>{record.name}</strong><small>{formatBytes(record.size)} <span className="file-type">{record.type || 'Unknown type'}</span></small></span></span>
                      <span className="date-cell">{formatDate(record.createdAt)}</span>
                      <span className="hash-cell">{record.sha256.slice(0, 12)}…</span>
                      <span className="status-cell"><span className="status-mark"><Icon name="check" size={12} /></span> Secured</span>
                    </button>
                  ))}
                </div>
              ) : <div className="empty-search">No evidence matches “{query}”.</div>
            ) : (
              <div className="empty-state">
                <div className="empty-art"><span><Icon name="file" size={23} /></span><i /><i /></div>
                <h3>{caseId ? 'This case is ready for evidence' : 'Start with a case ID'}</h3>
                <p>{caseId ? 'Add files to create encrypted records with a SHA-256 fingerprint and custody event.' : 'Enter a case ID above to open an existing case or begin a new one.'}</p>
                {caseId && <button type="button" className="button button-accent" disabled={busy || !db} onClick={() => fileInput.current?.click()}><Icon name="upload" size={17} /> Select evidence</button>}
              </div>
            )}
          </section>

          <aside className="detail-column" aria-label="Evidence details">
            {selectedRecord ? (
              <>
                <div className="detail-heading">
                  <div className="detail-title-wrap"><span className="detail-file-icon"><Icon name="file" size={19} /></span><div><p className="eyebrow">EVIDENCE RECORD</p><h2 title={selectedRecord.name}>{selectedRecord.name}</h2></div></div>
                  <button type="button" className="icon-button download-button" onClick={handleDownload} aria-label="Decrypt and download evidence" title="Decrypt and download"><Icon name="download" size={18} /></button>
                </div>

                <div className="integrity-banner">
                  <span className="integrity-icon"><Icon name={integrityValid ? 'shield' : 'close'} size={16} /></span>
                  <span><strong>{integrityValid ? 'Custody chain verified' : 'Custody chain check failed'}</strong><small>{integrityValid ? 'Event links match the stored record' : 'One or more event links do not match'}</small></span>
                </div>

                <div className="metadata-section">
                  <div className="detail-section-title"><h3>File metadata</h3><span>EXTRACTED</span></div>
                  <dl className="metadata-list">
                    <div><dt>File type</dt><dd>{selectedRecord.type || 'Unknown'}</dd></div>
                    {selectedRecord.pdfVersion && <div><dt>PDF version</dt><dd>{selectedRecord.pdfVersion}</dd></div>}
                    {selectedRecord.dimensions && <div><dt>Dimensions</dt><dd>{selectedRecord.dimensions}</dd></div>}
                    {selectedRecord.duration && <div><dt>Duration</dt><dd>{selectedRecord.duration}</dd></div>}
                    <div><dt>File size</dt><dd>{formatBytes(selectedRecord.size)}</dd></div>
                    <div><dt>Modified</dt><dd>{formatDate(selectedRecord.lastModified)}</dd></div>
                    <div className="metadata-hash"><dt>SHA-256</dt><dd>{selectedRecord.sha256}</dd></div>
                  </dl>
                </div>

                <div className="custody-section">
                  <div className="detail-section-title"><h3>Chain of custody</h3><span>{selectedRecord.custody.length} EVENTS</span></div>
                  <ol className="custody-list">
                    {selectedRecord.custody.slice().reverse().map((entry) => (
                      <li key={entry.eventHash}>
                        <span className="timeline-dot"><Icon name="clock" size={13} /></span>
                        <div className="event-copy"><strong>{entry.action}</strong><span>{entry.actor}</span><time dateTime={entry.timestamp}>{formatDate(entry.timestamp)}</time><code>{entry.eventHash.slice(0, 16)}…</code></div>
                      </li>
                    ))}
                  </ol>
                  <form className="custody-form" onSubmit={logCustodyEvent}>
                    <label htmlFor="custody-action">Record an event</label>
                    <div className="custody-controls">
                      <select id="custody-action" value={custodyAction} onChange={(event) => setCustodyAction(event.target.value)}>
                        <option>Evidence reviewed</option>
                        <option>Evidence transferred</option>
                        <option>Evidence accessed</option>
                        <option>Evidence returned to storage</option>
                      </select>
                      <button type="submit" className="icon-button record-event-button" disabled={busy || !custodian.trim()} aria-label="Record custody event" title="Record custody event"><Icon name="plus" size={17} /></button>
                    </div>
                  </form>
                </div>
              </>
            ) : (
              <div className="detail-placeholder">
                <span className="placeholder-lock"><Icon name="lock" size={21} /></span>
                <h3>Evidence details</h3>
                <p>{records.length ? 'Select a file to inspect its metadata and custody record.' : 'File metadata, cryptographic fingerprints, and custody events will appear here.'}</p>
              </div>
            )}
          </aside>
        </div>

        <footer className="workspace-footer">
          <span><Icon name="lock" size={14} /> Files and metadata stay in this browser</span>
          <span>Local browser storage is not a tamper-proof or court-certified evidence system.</span>
        </footer>
      </main>
    </div>
  );
}

export default App;