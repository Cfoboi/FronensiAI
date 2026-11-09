import React, { useState } from 'react';
import {
  ForensicCase,
  EvidenceItem,
  HumanCheckpoint,
  AISummaryResult,
  AIWorkflowResult,
} from '../types/forensics';
import {
  Bot,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  FileText,
  Workflow,
  Terminal,
  Send,
  AlertCircle,
  Plus,
  HelpCircle,
  ChevronRight,
  ShieldAlert,
  ArrowRight,
  Layers,
  GitCommit,
  Link2,
  Check,
  Scale,
  ListChecks,
  CheckSquare,
  Square,
  X,
  SlidersHorizontal,
  ArrowUpRight
} from 'lucide-react';

interface AICopilotDeskProps {
  currentCase: ForensicCase;
  evidenceItems: EvidenceItem[];
  onUpdateCheckpoints: (checkpoints: HumanCheckpoint[]) => void;
  onNavigateToReport: (reportType?: 'concurrent_correlation' | 'comprehensive') => void;
}

export const AICopilotDesk: React.FC<AICopilotDeskProps> = ({
  currentCase,
  evidenceItems,
  onUpdateCheckpoints,
  onNavigateToReport,
}) => {
  const [activeTab, setActiveTab] = useState<'checkpoints' | 'summarize' | 'workflow' | 'terminal'>('checkpoints');
  const [isSummarizing, setIsSummarizing] = useState(false);
  const [isSuggestingWorkflow, setIsSuggestingWorkflow] = useState(false);

  // Concurrent Evidence Analysis State
  const [summaryMode, setSummaryMode] = useState<'concurrent' | 'standard'>('concurrent');
  const [selectedArtifactIds, setSelectedArtifactIds] = useState<string[]>(() =>
    evidenceItems.map((e) => e.id)
  );
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  // Results from AI
  const [summaryResult, setSummaryResult] = useState<AISummaryResult | null>(null);
  const [workflowResult, setWorkflowResult] = useState<AIWorkflowResult | null>(null);

  // Sync selected artifacts when evidenceItems change
  React.useEffect(() => {
    setSelectedArtifactIds(evidenceItems.map((e) => e.id));
  }, [evidenceItems]);

  // Terminal chat state

  // Terminal chat state
  const [chatQuery, setChatQuery] = useState('');
  const [chatMessages, setChatMessages] = useState<
    Array<{ sender: 'user' | 'copilot'; text: string; timestamp: string }>
  >([
    {
      sender: 'copilot',
      text: `DFIR Co-Pilot initialized for Case ${currentCase.caseNumber} ("${currentCase.title}").\n\nOperating Protocol:\n• Objective observations only\n• No definitive culpability or legal accusations\n• Human confirmation checkpoints enforced for every analytical finding\n\nHow can I assist your investigation? (e.g. summarize artifacts, generate Volatility commands, analyze regex).`,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [isQuerying, setIsQuerying] = useState(false);

  // Add custom checkpoint modal state
  const [showAddCheckpointModal, setShowAddCheckpointModal] = useState(false);
  const [newCheckpointText, setNewCheckpointText] = useState('');
  const [newCheckpointAction, setNewCheckpointAction] = useState('');

  // Annotation modal state
  const [annotatingCheckpoint, setAnnotatingCheckpoint] = useState<HumanCheckpoint | null>(null);
  const [annotationNote, setAnnotationNote] = useState('');

  const checkpoints = currentCase.checkpoints || [];
  const confirmedCount = checkpoints.filter((c) => c.status === 'confirmed').length;
  const pendingCount = checkpoints.filter((c) => c.status === 'pending').length;
  const rejectedCount = checkpoints.filter((c) => c.status === 'rejected').length;

  // Checkpoint actions
  const handleConfirmCheckpoint = (id: string) => {
    const updated = checkpoints.map((c) => {
      if (c.id === id) {
        return {
          ...c,
          status: 'confirmed' as const,
          confirmedAt: new Date().toISOString(),
          confirmedBy: currentCase.leadInvestigator,
        };
      }
      return c;
    });
    onUpdateCheckpoints(updated);
  };

  const handleRejectCheckpoint = (id: string) => {
    const updated = checkpoints.map((c) => {
      if (c.id === id) {
        return {
          ...c,
          status: 'rejected' as const,
          confirmedAt: new Date().toISOString(),
          confirmedBy: currentCase.leadInvestigator,
          examinerNote: 'Excluded by examiner after manual inspection.',
        };
      }
      return c;
    });
    onUpdateCheckpoints(updated);
  };

  const handleSaveAnnotation = () => {
    if (!annotatingCheckpoint) return;
    const updated = checkpoints.map((c) => {
      if (c.id === annotatingCheckpoint.id) {
        return {
          ...c,
          examinerNote: annotationNote,
          status: 'confirmed' as const,
          confirmedAt: new Date().toISOString(),
          confirmedBy: currentCase.leadInvestigator,
        };
      }
      return c;
    });
    onUpdateCheckpoints(updated);
    setAnnotatingCheckpoint(null);
    setAnnotationNote('');
  };

  const handleAddCustomCheckpoint = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCheckpointText) return;
    const newChk: HumanCheckpoint = {
      id: `chk-${Date.now().toString().slice(-4)}`,
      checkpoint: newCheckpointText,
      suggestedVerificationAction: newCheckpointAction || 'Independently inspect primary evidence artifact.',
      status: 'pending',
    };
    onUpdateCheckpoints([...checkpoints, newChk]);
    setNewCheckpointText('');
    setNewCheckpointAction('');
    setShowAddCheckpointModal(false);
  };

  // Call Server-Side AI Endpoints
  const handleRunSummarize = async () => {
    setIsSummarizing(true);
    setErrorBanner(null);
    try {
      const filteredItems = evidenceItems.filter((e) =>
        selectedArtifactIds.includes(e.id)
      );
      const itemsToUse = filteredItems.length > 0 ? filteredItems : evidenceItems;

      const res = await fetch('/api/copilot/summarize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caseDetails: currentCase,
          mode: summaryMode,
          selectedEvidenceIds: itemsToUse.map((e) => e.id),
          evidenceItems: itemsToUse.map((e) => ({
            id: e.id,
            title: e.title,
            type: e.type,
            fileName: e.fileName,
            sha256: e.sha256,
            hashStatus: e.hashStatus,
            acquiredBy: e.acquiredBy,
            acquisitionDate: e.acquisitionDate,
            acquisitionMethod: e.acquisitionMethod,
            custodian: e.custodian,
            location: e.location,
            tags: e.tags,
            metadata: { fileSize: e.fileSize, entropy: e.entropy },
            content: e.rawContent || e.hexSample || '',
          })),
        }),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status} error`);
      }

      const data = await res.json();
      setSummaryResult(data);
      setActiveTab('summarize');

      // Auto-import newly extracted checkpoints into the Case Checkpoint list if not already present
      if (data.humanConfirmationCheckpoints && Array.isArray(data.humanConfirmationCheckpoints)) {
        const existingTexts = new Set(checkpoints.map((c) => c.checkpoint.toLowerCase()));
        const newOnes: HumanCheckpoint[] = [];

        data.humanConfirmationCheckpoints.forEach((item: any, idx: number) => {
          if (!existingTexts.has(item.checkpoint.toLowerCase())) {
            newOnes.push({
              id: `chk-ai-${Date.now().toString().slice(-4)}-${idx}`,
              checkpoint: item.checkpoint,
              suggestedVerificationAction: item.suggestedVerificationAction,
              status: 'pending',
            });
          }
        });

        if (newOnes.length > 0) {
          onUpdateCheckpoints([...checkpoints, ...newOnes]);
        }
      }
    } catch (err: any) {
      console.error('Summarize error:', err);
      setErrorBanner('Failed to synthesize concurrent evidence: ' + (err.message || 'Server error'));
    } finally {
      setIsSummarizing(false);
    }
  };

  const handleRunWorkflow = async () => {
    setIsSuggestingWorkflow(true);
    setErrorBanner(null);
    try {
      const res = await fetch('/api/copilot/suggest-workflow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caseDetails: currentCase,
          evidenceItems: evidenceItems.map((e) => ({
            id: e.id,
            title: e.title,
            type: e.type,
            sha256: e.sha256,
          })),
          currentFocus: 'Forensic artifact analysis and timeline reconstruction',
        }),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status} error`);
      }

      const data = await res.json();
      setWorkflowResult(data);
      setActiveTab('workflow');
    } catch (err: any) {
      console.error('Workflow error:', err);
      setErrorBanner('Failed to suggest workflow: ' + (err.message || 'Server error'));
    } finally {
      setIsSuggestingWorkflow(false);
    }
  };

  const handleSendChatQuery = async (queryText?: string) => {
    const textToSend = queryText || chatQuery;
    if (!textToSend.trim() || isQuerying) return;

    const userMsg = {
      sender: 'user' as const,
      text: textToSend,
      timestamp: new Date().toLocaleTimeString(),
    };
    setChatMessages((prev) => [...prev, userMsg]);
    if (!queryText) setChatQuery('');
    setIsQuerying(true);

    try {
      const res = await fetch('/api/copilot/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: textToSend,
          caseContext: currentCase,
          activeEvidence: evidenceItems[0] || null,
        }),
      });

      const data = await res.json();
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: data.answer || 'Query completed.',
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } catch (err: any) {
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: 'Error contacting AI Co-Pilot server: ' + (err.message || 'Check connection.'),
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setIsQuerying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Strict Ethical & Forensic Guardrails Banner */}
      <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-900/60 border border-cyan-500/40 flex items-center justify-center text-cyan-300 shrink-0">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-zinc-100 flex items-center gap-2">
                <span>DFIR Co-Pilot Operating Guardrails Active</span>
                <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                  Human-in-the-Loop Protocol
                </span>
              </div>
              <p className="text-[11px] text-zinc-300 mt-0.5">
                The Co-Pilot strictly states <strong>objective observations</strong>, identifies anomalies, and proposes workflows.
                It <strong>never draws definitive culpability conclusions</strong>. Every finding requires human investigator confirmation.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleRunSummarize}
              disabled={isSummarizing}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-100 rounded-lg text-xs font-medium transition-colors"
            >
              {isSummarizing ? (
                <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              ) : (
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              )}
              <span>Summarize Evidence</span>
            </button>

            <button
              onClick={handleRunWorkflow}
              disabled={isSuggestingWorkflow}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-100 rounded-lg text-xs font-medium transition-colors"
            >
              {isSuggestingWorkflow ? (
                <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              ) : (
                <Workflow className="w-3.5 h-3.5 text-cyan-400" />
              )}
              <span>Suggest Workflow</span>
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-1.5 bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="flex items-center gap-1 overflow-x-auto text-xs">
          <button
            onClick={() => setActiveTab('checkpoints')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'checkpoints'
                ? 'bg-zinc-800 text-cyan-300 font-semibold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Human Confirmation Desk ({confirmedCount}/{checkpoints.length} Confirmed)</span>
          </button>

          <button
            onClick={() => setActiveTab('summarize')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'summarize'
                ? 'bg-zinc-800 text-cyan-300 font-semibold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Evidence Summary &amp; Timeline</span>
          </button>

          <button
            onClick={() => setActiveTab('workflow')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'workflow'
                ? 'bg-zinc-800 text-cyan-300 font-semibold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Workflow className="w-3.5 h-3.5" />
            <span>Analytical Workflow Plan</span>
          </button>

          <button
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'terminal'
                ? 'bg-zinc-800 text-cyan-300 font-semibold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Investigator Copilot Terminal</span>
          </button>
        </div>

        <button
          onClick={() => onNavigateToReport()}
          className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium px-3 py-1"
        >
          <span>Draft Final DFIR Report</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* --- TAB 1: HUMAN CONFIRMATION CHECKPOINT MATRIX --- */}
      {activeTab === 'checkpoints' && (
        <div className="space-y-5">
          {/* Status Metric Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800 flex items-center justify-between">
              <div>
                <div className="text-xs text-zinc-500 font-medium">Confirmed by Examiner</div>
                <div className="text-lg font-bold text-emerald-400 font-mono tabular-nums">{confirmedCount}</div>
              </div>
              <CheckCircle2 className="w-5 h-5 text-emerald-500/80" />
            </div>

            <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800 flex items-center justify-between">
              <div>
                <div className="text-xs text-zinc-500 font-medium">Pending Human Validation</div>
                <div className="text-lg font-bold text-amber-400 font-mono tabular-nums">{pendingCount}</div>
              </div>
              <Clock className="w-5 h-5 text-amber-500/80" />
            </div>

            <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800 flex items-center justify-between">
              <div>
                <div className="text-xs text-zinc-500 font-medium">Rejected / Excluded</div>
                <div className="text-lg font-bold text-zinc-400 font-mono tabular-nums">{rejectedCount}</div>
              </div>
              <XCircle className="w-5 h-5 text-zinc-500" />
            </div>
          </div>

          {/* Action Header */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-zinc-100">
                Independent Human Examiner Checkpoints
              </h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Every AI observation must be independently tested and ratified before incorporation into official reports.
              </p>
            </div>
            <button
              onClick={() => setShowAddCheckpointModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-xs font-medium transition-colors shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Define Custom Checkpoint</span>
            </button>
          </div>

          {/* Checkpoints List */}
          <div className="space-y-3">
            {checkpoints.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 bg-zinc-900/40 border border-zinc-800 rounded-xl text-xs">
                No checkpoints currently registered. Click &quot;Summarize Evidence&quot; to auto-extract checkpoints from artifacts.
              </div>
            ) : (
              checkpoints.map((chk, idx) => (
                <div
                  key={chk.id || idx}
                  className={`p-4 rounded-xl border transition-colors ${
                    chk.status === 'confirmed'
                      ? 'bg-zinc-900/60 border-emerald-900/60'
                      : chk.status === 'rejected'
                      ? 'bg-zinc-950/40 border-zinc-800 opacity-60'
                      : 'bg-zinc-900/80 border-amber-500/30'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                    <div className="space-y-1.5 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] text-zinc-500">Checkpoint #{idx + 1}</span>
                        <span>·</span>
                        {chk.status === 'confirmed' ? (
                          <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3" />
                            Confirmed by {chk.confirmedBy || currentCase.leadInvestigator}
                          </span>
                        ) : chk.status === 'rejected' ? (
                          <span className="text-[11px] font-semibold text-zinc-500 flex items-center gap-1">
                            <XCircle className="w-3 h-3" />
                            Rejected / False Positive
                          </span>
                        ) : (
                          <span className="text-[11px] font-semibold text-amber-400 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            Requires Verification
                          </span>
                        )}
                      </div>

                      <div className="text-xs font-semibold text-zinc-100 leading-relaxed">
                        {chk.checkpoint}
                      </div>

                      <div className="text-[11px] text-zinc-400 bg-zinc-950/60 p-2 rounded border border-zinc-800/80">
                        <span className="text-zinc-500 font-medium">Recommended Verification Action: </span>
                        <span>{chk.suggestedVerificationAction}</span>
                      </div>

                      {chk.examinerNote && (
                        <div className="text-[11px] text-cyan-300 bg-cyan-950/30 p-2 rounded border border-cyan-800/40 mt-1">
                          <strong className="text-cyan-400">Examiner Verification Note: </strong>
                          <span>{chk.examinerNote}</span>
                        </div>
                      )}
                    </div>

                    {/* Checkpoint Action Controls */}
                    <div className="flex items-center gap-2 shrink-0 pt-1">
                      <button
                        onClick={() => handleConfirmCheckpoint(chk.id)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors ${
                          chk.status === 'confirmed'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-zinc-800 hover:bg-emerald-950 text-zinc-300 hover:text-emerald-300 border border-zinc-700'
                        }`}
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Confirm &amp; Ratify</span>
                      </button>

                      <button
                        onClick={() => {
                          setAnnotatingCheckpoint(chk);
                          setAnnotationNote(chk.examinerNote || '');
                        }}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
                      >
                        Add Note
                      </button>

                      <button
                        onClick={() => handleRejectCheckpoint(chk.id)}
                        className="p-1.5 rounded-lg text-zinc-500 hover:text-rose-400 hover:bg-zinc-800 transition-colors"
                        title="Reject checkpoint"
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Error banner if any */}
      {errorBanner && (
        <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-xl text-xs text-rose-300 flex items-start justify-between gap-3">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{errorBanner}</span>
          </div>
          <button
            onClick={() => setErrorBanner(null)}
            className="text-rose-400 hover:text-rose-200 text-xs shrink-0 font-mono"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* --- TAB 2: EVIDENCE SUMMARY & CONCURRENT CORRELATION --- */}
      {activeTab === 'summarize' && (
        <div className="space-y-6">
          {/* Concurrent Evidence Configuration & Scope Selector */}
          <div className="p-5 bg-zinc-900/80 rounded-xl border border-zinc-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>Concurrent Evidence Scope &amp; Correlation Engine</span>
                </h3>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Analyze concurrent artifacts to detect temporal overlaps, cross-source corroborations, and timeline discrepancies.
                </p>
              </div>

              {/* Mode Toggle */}
              <div className="flex items-center gap-1 p-0.5 bg-zinc-950 rounded-lg border border-zinc-800 text-xs shrink-0">
                <button
                  onClick={() => setSummaryMode('concurrent')}
                  className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
                    summaryMode === 'concurrent'
                      ? 'bg-zinc-800 text-cyan-300 shadow-sm'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <Link2 className="w-3.5 h-3.5" />
                  <span>Concurrent Multi-Evidence</span>
                </button>
                <button
                  onClick={() => setSummaryMode('standard')}
                  className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
                    summaryMode === 'standard'
                      ? 'bg-zinc-800 text-cyan-300 shadow-sm'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Single-Artifact Breakdown</span>
                </button>
              </div>
            </div>

            {/* Artifact Checkbox Selector */}
            <div className="space-y-2 pt-2 border-t border-zinc-800/80">
              <div className="flex items-center justify-between text-xs">
                <span className="text-zinc-400 font-medium">
                  Select Concurrent Artifacts to Cross-Examine ({selectedArtifactIds.length}/{evidenceItems.length} selected):
                </span>
                <div className="flex items-center gap-2 text-[11px]">
                  <button
                    onClick={() => setSelectedArtifactIds(evidenceItems.map((e) => e.id))}
                    className="text-cyan-400 hover:text-cyan-300 underline"
                  >
                    Select All
                  </button>
                  <span>·</span>
                  <button
                    onClick={() => setSelectedArtifactIds([])}
                    className="text-zinc-500 hover:text-zinc-300"
                  >
                    Clear Selection
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {evidenceItems.map((item) => {
                  const isChecked = selectedArtifactIds.includes(item.id);
                  return (
                    <label
                      key={item.id}
                      onClick={(e) => {
                        e.preventDefault();
                        if (isChecked) {
                          setSelectedArtifactIds((prev) => prev.filter((id) => id !== item.id));
                        } else {
                          setSelectedArtifactIds((prev) => [...prev, item.id]);
                        }
                      }}
                      className={`flex items-start gap-2.5 p-2.5 rounded-lg border text-xs cursor-pointer transition-colors ${
                        isChecked
                          ? 'bg-cyan-950/20 border-cyan-800/70 text-zinc-200'
                          : 'bg-zinc-950/40 border-zinc-800/80 text-zinc-500 hover:border-zinc-700'
                      }`}
                    >
                      <div className="mt-0.5 text-cyan-400">
                        {isChecked ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4 text-zinc-600" />}
                      </div>
                      <div className="min-w-0 flex-1 space-y-0.5">
                        <div className="font-semibold truncate">{item.title}</div>
                        <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-400">
                          <span className="text-cyan-300">{item.id}</span>
                          <span>·</span>
                          <span>{item.type}</span>
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Execute Synthesis Button */}
            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-zinc-500 font-mono">
                Adhering to ISO/IEC 27037 &amp; Zero-Speculation Rules
              </span>
              <button
                onClick={handleRunSummarize}
                disabled={isSummarizing || selectedArtifactIds.length === 0}
                className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-zinc-950 font-semibold rounded-lg text-xs transition-colors flex items-center gap-2 shadow-sm"
              >
                {isSummarizing ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-zinc-950 border-t-transparent rounded-full animate-spin" />
                    <span>Synthesizing Concurrent Artifacts...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Execute Concurrent Synthesis ({selectedArtifactIds.length} Items)</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {!summaryResult ? (
            <div className="p-8 text-center bg-zinc-900/40 rounded-xl border border-zinc-800 space-y-3">
              <Layers className="w-8 h-8 text-cyan-400 mx-auto" />
              <div className="text-sm font-semibold text-zinc-200">
                Ready for Multi-Source Concurrent Correlation
              </div>
              <p className="text-xs text-zinc-400 max-w-md mx-auto">
                Click &quot;Execute Concurrent Synthesis&quot; above to cross-reference timestamps, detect overlapping activity windows, identify corroborating indicators, and formulate human verification checkpoints.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Executive Overview */}
              <div className="p-5 rounded-xl bg-zinc-900/80 border border-zinc-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span>Objective Factual Synthesis</span>
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    Mode: {summaryResult.summaryMode === 'concurrent' ? 'Concurrent Correlation' : 'Standard Summary'}
                  </span>
                </div>
                <p className="text-xs text-zinc-300 leading-relaxed whitespace-pre-line">
                  {summaryResult.executiveSummary}
                </p>
              </div>

              {/* Concurrent Metrics KPI Bar */}
              {summaryResult.concurrentMetrics && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3.5 bg-zinc-900/80 border border-zinc-800 rounded-xl">
                    <div className="text-[11px] text-zinc-400">Analyzed Artifacts</div>
                    <div className="text-xl font-bold font-mono text-zinc-100 mt-1">
                      {summaryResult.concurrentMetrics.totalAnalyzedArtifacts}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">Multi-source inputs</div>
                  </div>

                  <div className="p-3.5 bg-zinc-900/80 border border-cyan-900/50 rounded-xl">
                    <div className="text-[11px] text-zinc-400">Concurrency Windows</div>
                    <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                      {summaryResult.concurrentTimeWindows?.length || summaryResult.concurrentMetrics.temporalConcurrencyClusters}
                    </div>
                    <div className="text-[10px] text-cyan-500/80 mt-0.5">Synchronized clusters</div>
                  </div>

                  <div className="p-3.5 bg-zinc-900/80 border border-emerald-900/50 rounded-xl">
                    <div className="text-[11px] text-zinc-400">Corroborated Points</div>
                    <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                      {summaryResult.concurrentMetrics.corroboratedPoints}
                    </div>
                    <div className="text-[10px] text-emerald-500/80 mt-0.5">2+ concurrent sources</div>
                  </div>

                  <div className="p-3.5 bg-zinc-900/80 border border-amber-900/50 rounded-xl">
                    <div className="text-[11px] text-zinc-400">Discrepancies / Offsets</div>
                    <div className="text-xl font-bold font-mono text-amber-400 mt-1">
                      {summaryResult.concurrentMetrics.discrepanciesIdentified}
                    </div>
                    <div className="text-[10px] text-amber-500/80 mt-0.5">Requires clock calibration</div>
                  </div>
                </div>
              )}

              {/* Temporal Concurrency Windows */}
              {summaryResult.concurrentTimeWindows && summaryResult.concurrentTimeWindows.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Synchronized Temporal Concurrency Windows</span>
                    </h3>
                    <span className="text-[11px] text-zinc-400">
                      {summaryResult.concurrentTimeWindows.length} Overlapping Activity Windows
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {summaryResult.concurrentTimeWindows.map((tw, idx) => (
                      <div
                        key={tw.id || idx}
                        className="p-4 bg-zinc-900/70 border border-zinc-800 rounded-xl space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] text-cyan-400 bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800">
                            Window #{idx + 1}
                          </span>
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                            tw.concurrencyLevel === 'High'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : 'bg-zinc-800 text-zinc-300'
                          }`}>
                            {tw.concurrencyLevel} Concurrency
                          </span>
                        </div>

                        <div className="font-mono text-[11px] text-zinc-200 font-semibold">
                          {tw.timeWindowUTC}
                        </div>

                        <p className="text-[11px] text-zinc-300 leading-relaxed">
                          {tw.eventSummary}
                        </p>

                        <div className="pt-2 border-t border-zinc-800/80 space-y-1">
                          <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Active Concurrent Sources:</div>
                          <div className="flex flex-wrap gap-1">
                            {tw.activeEvidenceTitles.map((t, i) => (
                              <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 bg-zinc-950 text-zinc-300 rounded border border-zinc-800">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Cross-Evidence Corroboration Matrix */}
              {summaryResult.crossEvidenceCorrelations && summaryResult.crossEvidenceCorrelations.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider flex items-center gap-2">
                      <Scale className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Cross-Evidence Corroboration Matrix</span>
                    </h3>
                    <span className="text-[11px] text-zinc-400">
                      Source A ↔ Source B Validation
                    </span>
                  </div>

                  <div className="border border-zinc-800 rounded-xl overflow-hidden bg-zinc-900/60 text-xs">
                    <div className="divide-y divide-zinc-800">
                      {summaryResult.crossEvidenceCorrelations.map((corr, idx) => (
                        <div key={corr.id || idx} className="p-4 space-y-2 hover:bg-zinc-900/40 transition-colors">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-cyan-400 font-semibold">{corr.primaryEvidenceTitle}</span>
                              <span className="text-zinc-500">↔</span>
                              <span className="font-mono text-cyan-300 font-semibold">{corr.concurrentEvidenceTitle}</span>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <span className="font-mono text-[10px] text-zinc-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
                                {corr.timestampCorrelation}
                              </span>
                              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                                corr.corroborationStatus === 'Strongly Corroborated'
                                  ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                  : corr.corroborationStatus === 'Discrepancy / Offset'
                                  ? 'bg-amber-950 text-amber-300 border-amber-800'
                                  : 'bg-zinc-800 text-zinc-300 border-zinc-700'
                              }`}>
                                {corr.corroborationStatus}
                              </span>
                            </div>
                          </div>

                          <p className="text-zinc-300 text-[11px] leading-relaxed">
                            {corr.observation}
                          </p>

                          <div className="text-[11px] text-zinc-400 bg-zinc-950/70 p-2 rounded border border-zinc-800/80 flex items-start gap-2">
                            <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                            <div>
                              <strong className="text-zinc-300">Examiner Verification Check: </strong>
                              <span>{corr.examinerVerificationCheck}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Clock Drift & Discrepancy Notice */}
              {summaryResult.concurrentMetrics?.clockDriftCaveats && summaryResult.concurrentMetrics.clockDriftCaveats.length > 0 && (
                <div className="p-4 bg-amber-950/30 border border-amber-800/60 rounded-xl space-y-1.5 text-xs">
                  <div className="font-semibold text-amber-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5" />
                    <span>Temporal Clock Drift &amp; Concurrency Caveats</span>
                  </div>
                  <ul className="text-zinc-300 text-[11px] space-y-1 list-disc pl-4">
                    {summaryResult.concurrentMetrics.clockDriftCaveats.map((c, i) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Extracted Artifacts Grid */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">
                  Extracted Indicators &amp; Technical Artifacts
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {summaryResult.extractedArtifacts.map((art, idx) => (
                    <div key={idx} className="p-3.5 bg-zinc-900/60 rounded-xl border border-zinc-800 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-zinc-100">{art.name}</span>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                            art.corroborationStatus === 'Corroborated'
                              ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                              : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                          }`}>
                            {art.corroborationStatus}
                          </span>
                          <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800">
                            {art.category}
                          </span>
                        </div>
                      </div>
                      <p className="text-zinc-300 text-[11px] leading-relaxed">{art.observation}</p>
                      <div className="text-[11px] text-zinc-500 pt-1 border-t border-zinc-800/80">
                        Significance: {art.significance}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Forensic Master Timeline */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">
                  Chronological Multi-Track Master Timeline (Normalized to UTC)
                </h3>
                <div className="border border-zinc-800 rounded-xl overflow-hidden bg-zinc-900/60 text-xs">
                  <table className="w-full text-left">
                    <thead className="bg-zinc-900 border-b border-zinc-800 text-zinc-400">
                      <tr>
                        <th className="py-2.5 px-4 font-mono">Timestamp (UTC)</th>
                        <th className="py-2.5 px-4">Artifact Source</th>
                        <th className="py-2.5 px-4">Observed Activity</th>
                        <th className="py-2.5 px-4">Forensic Note</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800">
                      {summaryResult.timelineEvents.map((evt, idx) => (
                        <tr key={idx} className="hover:bg-zinc-800/40">
                          <td className="py-2.5 px-4 font-mono text-cyan-300 whitespace-nowrap text-[11px]">
                            {evt.timestampUTC}
                          </td>
                          <td className="py-2.5 px-4 font-mono text-zinc-400 text-[11px]">
                            <span className="px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-cyan-400">
                              {evt.sourceItem}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-zinc-200">
                            {evt.activity}
                          </td>
                          <td className="py-2.5 px-4 text-zinc-400 text-[11px]">
                            {evt.forensicNote}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Unverified Hypotheses */}
              <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 space-y-2">
                <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Unverified Hypotheses (Requires Independent Corroboration)</span>
                </h3>
                <ul className="space-y-1.5 text-xs text-zinc-300 list-disc pl-4">
                  {summaryResult.unverifiedHypotheses.map((h, idx) => (
                    <li key={idx}>{h}</li>
                  ))}
                </ul>
              </div>

              {/* Action Callout: Route into Case Report Generator */}
              <div className="p-5 bg-gradient-to-r from-cyan-950/40 to-zinc-900/80 border border-cyan-800/60 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-bold text-zinc-100 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <span>Generate Court-Ready Report from Concurrent Evidence</span>
                  </div>
                  <p className="text-xs text-zinc-400 mt-1">
                    Compile this multi-source correlation matrix, verified timelines, and ratified checkpoints into a formal technical dossier.
                  </p>
                </div>

                <button
                  onClick={() => onNavigateToReport('concurrent_correlation')}
                  className="px-4 py-2.5 bg-cyan-400 hover:bg-cyan-300 text-zinc-950 font-semibold rounded-lg text-xs transition-colors flex items-center gap-2 shrink-0 shadow-lg"
                >
                  <span>Draft Concurrent Evidence Dossier</span>
                  <ArrowUpRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* --- TAB 3: WORKFLOW SUGGESTION --- */}
      {activeTab === 'workflow' && (
        <div className="space-y-6">
          {!workflowResult ? (
            <div className="p-8 text-center bg-zinc-900/60 rounded-xl border border-zinc-800 space-y-3">
              <Workflow className="w-8 h-8 text-cyan-400 mx-auto" />
              <div className="text-sm font-semibold text-zinc-200">
                Propose Standard Forensic Analytical Workflow
              </div>
              <p className="text-xs text-zinc-400 max-w-md mx-auto">
                Generate an ISO/IEC 27037 &amp; NIST SP 800-86 standard workflow tailored to the active evidence artifacts with precise CLI commands and verification deliverables.
              </p>
              <button
                onClick={handleRunWorkflow}
                disabled={isSuggestingWorkflow}
                className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-zinc-950 font-semibold rounded-lg text-xs transition-colors"
              >
                {isSuggestingWorkflow ? 'Formulating Methodology...' : 'Generate Analytical Plan'}
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-zinc-100">{workflowResult.workflowTitle}</h3>
                  <p className="text-xs text-zinc-400 mt-0.5">
                    Adhering to ISO/IEC 27037 (Digital Evidence Handling) and NIST SP 800-86
                  </p>
                </div>
              </div>

              {/* Safeguards Card */}
              <div className="p-3.5 bg-zinc-900/70 rounded-xl border border-zinc-800 space-y-1.5 text-xs">
                <span className="font-semibold text-zinc-200">Mandatory Handling Safeguards:</span>
                <ul className="space-y-1 text-zinc-400 list-disc pl-4 text-[11px]">
                  {workflowResult.evidenceHandlingSafeguards.map((s, idx) => (
                    <li key={idx}>{s}</li>
                  ))}
                </ul>
              </div>

              {/* Phases */}
              <div className="space-y-4">
                {workflowResult.recommendedPhases.map((phase, pIdx) => (
                  <div key={pIdx} className="p-4 bg-zinc-900/60 rounded-xl border border-zinc-800 space-y-3">
                    <div>
                      <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider">
                        Phase {pIdx + 1}
                      </span>
                      <h4 className="text-xs font-bold text-zinc-100">{phase.phaseName}</h4>
                      <p className="text-[11px] text-zinc-400 mt-0.5">{phase.objective}</p>
                    </div>

                    <div className="space-y-3 pt-2">
                      {phase.steps.map((step) => (
                        <div key={step.stepNumber} className="p-3 bg-zinc-950/80 rounded-lg border border-zinc-800 space-y-2 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-zinc-200">
                              Step {step.stepNumber}: {step.title}
                            </span>
                            <span className="text-[10px] text-zinc-500 font-mono">
                              Deliverable: {step.expectedDeliverable}
                            </span>
                          </div>

                          <p className="text-zinc-300 text-[11px] leading-relaxed">{step.description}</p>

                          {step.recommendedToolCommand && (
                            <div className="p-2 bg-zinc-900 rounded font-mono text-[11px] text-cyan-300 overflow-x-auto border border-zinc-800">
                              <code>{step.recommendedToolCommand}</code>
                            </div>
                          )}

                          <div className="text-[11px] text-amber-300 bg-amber-950/20 p-2 rounded border border-amber-800/30 flex items-start gap-1.5">
                            <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
                            <span><strong>Required Checkpoint:</strong> {step.humanConfirmationCheckpoint}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* --- TAB 4: INVESTIGATOR TERMINAL --- */}
      {activeTab === 'terminal' && (
        <div className="space-y-4">
          {/* Quick Prompt Chips */}
          <div className="flex items-center gap-1.5 overflow-x-auto text-[11px]">
            <span className="text-zinc-500 shrink-0">Quick Queries:</span>
            <button
              onClick={() => handleSendChatQuery('Provide Volatility 3 command line to inspect process tree and open sockets')}
              className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 rounded-md border border-zinc-800 whitespace-nowrap shrink-0"
            >
              Volatility 3 commands
            </button>
            <button
              onClick={() => handleSendChatQuery('Explain regex pattern to identify SQL injection and directory traversal in web access logs')}
              className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 rounded-md border border-zinc-800 whitespace-nowrap shrink-0"
            >
              SQLi / Traversal Regex
            </button>
            <button
              onClick={() => handleSendChatQuery('How can we rule out NTP clock skew between host and perimeter proxy logs?')}
              className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 rounded-md border border-zinc-800 whitespace-nowrap shrink-0"
            >
              Clock Skew Analysis
            </button>
          </div>

          {/* Chat Window */}
          <div className="rounded-xl bg-zinc-950 border border-zinc-800 overflow-hidden flex flex-col h-[460px]">
            <div className="p-3 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between text-xs text-zinc-400">
              <span className="flex items-center gap-1.5 text-zinc-200 font-semibold font-mono">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>DFIR Co-Pilot Console</span>
              </span>
              <span className="text-[11px] font-mono text-zinc-500">
                Gemini 3.8 Flash · ISO/IEC 27037 Safe Mode
              </span>
            </div>

            <div className="flex-1 p-4 overflow-y-auto space-y-3 font-mono text-xs">
              {chatMessages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
                >
                  <div
                    className={`max-w-[85%] p-3 rounded-lg leading-relaxed whitespace-pre-wrap select-text ${
                      msg.sender === 'user'
                        ? 'bg-cyan-950 text-cyan-100 border border-cyan-800/80 font-sans'
                        : 'bg-zinc-900 text-zinc-200 border border-zinc-800'
                    }`}
                  >
                    {msg.text}
                  </div>
                  <span className="text-[10px] text-zinc-500 mt-1 px-1">{msg.timestamp}</span>
                </div>
              ))}
              {isQuerying && (
                <div className="flex items-center gap-2 text-zinc-500 text-xs py-2">
                  <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  <span>DFIR Co-Pilot analyzing inquiry against evidentiary guidelines...</span>
                </div>
              )}
            </div>

            <div className="p-3 bg-zinc-900 border-t border-zinc-800 flex items-center gap-2">
              <input
                type="text"
                value={chatQuery}
                onChange={(e) => setChatQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendChatQuery()}
                placeholder="Ask technical question, command line syntax, or regex parsing..."
                className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-cyan-500/50"
              />
              <button
                onClick={() => handleSendChatQuery()}
                disabled={isQuerying || !chatQuery.trim()}
                className="px-3.5 py-2 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-zinc-950 font-semibold rounded-lg text-xs transition-colors flex items-center gap-1.5 shrink-0"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Submit</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Define Custom Checkpoint */}
      {showAddCheckpointModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl w-full max-w-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100">Define Custom Human Checkpoint</h3>
            <p className="text-xs text-zinc-400">
              Establish a mandatory human verification criterion before technical findings can be approved.
            </p>

            <form onSubmit={handleAddCustomCheckpoint} className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-300 mb-1 font-medium">Checkpoint Factual Assertion:</label>
                <textarea
                  rows={3}
                  value={newCheckpointText}
                  onChange={(e) => setNewCheckpointText(e.target.value)}
                  placeholder="e.g. Verify that the SQL injection payload caused actual database record extraction rather than application error 500."
                  className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-zinc-100"
                  required
                />
              </div>

              <div>
                <label className="block text-zinc-300 mb-1 font-medium">Verification Action Required:</label>
                <input
                  type="text"
                  value={newCheckpointAction}
                  onChange={(e) => setNewCheckpointAction(e.target.value)}
                  placeholder="e.g. Reconstruct packet stream in Wireshark offset 0x4A2100"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-zinc-100"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddCheckpointModal(false)}
                  className="px-3 py-1.5 text-zinc-400 hover:text-zinc-200 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-zinc-950 font-semibold rounded"
                >
                  Add Checkpoint
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Annotate Checkpoint */}
      {annotatingCheckpoint && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl w-full max-w-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100">Examiner Verification Note</h3>
            <p className="text-xs text-zinc-300 italic">
              &quot;{annotatingCheckpoint.checkpoint}&quot;
            </p>

            <div className="space-y-3 text-xs">
              <label className="block text-zinc-400">Record your independent laboratory findings:</label>
              <textarea
                rows={4}
                value={annotationNote}
                onChange={(e) => setAnnotationNote(e.target.value)}
                placeholder="e.g. Inspected packet stream at offset 0x4A2100; payload returned 500 Internal Error without database leakage."
                className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-zinc-100"
                required
              />

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setAnnotatingCheckpoint(null)}
                  className="px-3 py-1.5 text-zinc-400 hover:text-zinc-200 rounded"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveAnnotation}
                  className="px-4 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-zinc-950 font-semibold rounded"
                >
                  Save &amp; Ratify Checkpoint
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
