import { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileUp, Send, Users } from 'lucide-react';
import { apiRequest } from '../lib/api';
import {
  MAX_BULK_RECIPIENTS,
  MAX_PERSONAL_SMS_LENGTH,
  calculateSmsSegmentInfo,
  extractTemplateVariables,
  isValidE164,
  maskE164,
  normalizeE164,
  parseBulkPhoneList,
} from '../shared/smsRules';
import type {
  ApplicationRecord,
  BulkSmsResponse,
  NavSection,
  OverviewResponse,
  PersonalSmsResponse,
  TemplateRecord,
} from '../types';

interface ComposeSmsViewProps {
  applications: ApplicationRecord[];
  overview: OverviewResponse | null;
  onNavigate: (section: NavSection) => void;
  onSent: () => void;
}

type ComposeMode = 'personal' | 'bulk';
type BulkContentMode = 'custom' | 'template';

export function ComposeSmsView({ applications, overview, onNavigate, onSent }: ComposeSmsViewProps) {
  const [mode, setMode] = useState<ComposeMode>('personal');
  const [templates, setTemplates] = useState<TemplateRecord[]>([]);
  const [appId, setAppId] = useState(applications[0]?.id || '');

  // Personal SMS state
  const [personalTo, setPersonalTo] = useState('');
  const [personalBody, setPersonalBody] = useState('');
  const [personalTtl, setPersonalTtl] = useState('300');
  const [personalIdempotency, setPersonalIdempotency] = useState('');
  const [personalSending, setPersonalSending] = useState(false);
  const [personalError, setPersonalError] = useState<string | null>(null);
  const [personalResult, setPersonalResult] = useState<PersonalSmsResponse | null>(null);

  // Bulk SMS state
  const [bulkRecipientsRaw, setBulkRecipientsRaw] = useState('');
  const [bulkContentMode, setBulkContentMode] = useState<BulkContentMode>('custom');
  const [bulkBody, setBulkBody] = useState('');
  const [bulkTemplateCode, setBulkTemplateCode] = useState('login_notice');
  const [bulkVariables, setBulkVariables] = useState<Record<string, string>>({});
  const [bulkBatchLabel, setBulkBatchLabel] = useState('');
  const [bulkTtl, setBulkTtl] = useState('600');
  const [bulkSending, setBulkSending] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bulkResult, setBulkResult] = useState<BulkSmsResponse | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    apiRequest<{ templates: TemplateRecord[] }>('/api/admin/templates')
      .then((res) => setTemplates(res.templates.filter((t) => t.status === 'approved')))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!appId && applications.length > 0) {
      const preferred = applications.find((a) => a.status === 'active') ?? applications[0];
      setAppId(preferred.id);
    }
  }, [applications, appId]);

  const selectedApp = applications.find((a) => a.id === appId) ?? applications[0];
  const onlineDevicesCount = useMemo(
    () => (overview?.devices ?? []).filter((d) => d.status === 'online' && d.sim_ready).length,
    [overview]
  );

  // Live Personal SMS calculations
  const normalizedPersonalTo = normalizeE164(personalTo);
  const personalToValid = personalTo.trim().length > 0 && isValidE164(normalizedPersonalTo);
  const personalSegments = useMemo(() => calculateSmsSegmentInfo(personalBody), [personalBody]);

  // Live Bulk SMS calculations
  const parsedBulk = useMemo(() => parseBulkPhoneList(bulkRecipientsRaw), [bulkRecipientsRaw]);
  const activeTemplate = useMemo(
    () => templates.find((t) => t.code === bulkTemplateCode) ?? templates[0],
    [templates, bulkTemplateCode]
  );
  const requiredVars = useMemo(
    () => (activeTemplate ? extractTemplateVariables(activeTemplate.body) : []),
    [activeTemplate]
  );

  const renderedTemplatePreview = useMemo(() => {
    if (!activeTemplate) return '';
    return activeTemplate.body.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_m, k: string) => {
      const val = bulkVariables[k];
      return val && val.trim().length > 0 ? val.trim() : `{{${k}}}`;
    });
  }, [activeTemplate, bulkVariables]);

  const bulkMessageText = bulkContentMode === 'custom' ? bulkBody : renderedTemplatePreview;
  const bulkSegments = useMemo(() => calculateSmsSegmentInfo(bulkMessageText), [bulkMessageText]);
  const estimatedTotalUnits = parsedBulk.validNumbers.length * Math.max(1, bulkSegments.segments);

  const handlePersonalSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setPersonalError(null);
    setPersonalResult(null);
    setPersonalSending(true);
    try {
      const res = await apiRequest<PersonalSmsResponse>('/api/admin/messages/personal', {
        method: 'POST',
        body: JSON.stringify({
          application_id: appId,
          to: personalTo.trim(),
          body: personalBody,
          ttl_seconds: Number(personalTtl) || 300,
          idempotency_key: personalIdempotency.trim() || undefined,
        }),
      });
      setPersonalResult(res);
      onSent();
    } catch (err) {
      setPersonalError(err instanceof Error ? err.message : 'Failed to queue personal SMS');
    } finally {
      setPersonalSending(false);
    }
  };

  const handleBulkSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBulkError(null);
    setBulkResult(null);
    setBulkSending(true);
    try {
      const payload: Record<string, unknown> = {
        application_id: appId,
        recipients: bulkRecipientsRaw,
        ttl_seconds: Number(bulkTtl) || 600,
        batch_label: bulkBatchLabel.trim() || undefined,
      };
      if (bulkContentMode === 'template' && activeTemplate) {
        const vars: Record<string, string> = {};
        for (const v of requiredVars) {
          vars[v] = bulkVariables[v] ?? '';
        }
        payload.template_id = activeTemplate.code;
        payload.variables = vars;
        payload.purpose = activeTemplate.purpose;
      } else {
        payload.body = bulkBody;
      }

      const res = await apiRequest<BulkSmsResponse>('/api/admin/messages/bulk', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setBulkResult(res);
      onSent();
    } catch (err) {
      setBulkError(err instanceof Error ? err.message : 'Failed to queue bulk SMS batch');
    } finally {
      setBulkSending(false);
    }
  };

  const handleFileImport = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      if (text.trim()) {
        setBulkRecipientsRaw((prev) => (prev.trim() ? `${prev.trim()}\n${text.trim()}` : text.trim()));
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  return (
    <div className="space-y-5">
      {/* Header & Mode Switch */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Personal &amp; Bulk SMS Dispatcher
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Send direct personal SMS without templates or broadcast custom / templated messages to up to{' '}
            <span className="font-mono tabular-nums">{MAX_BULK_RECIPIENTS}</span> recipients per batch.
          </p>
        </div>

        <div
          role="tablist"
          aria-label="Composer mode"
          className="inline-flex border border-slate-200 dark:border-slate-700 rounded-md bg-white dark:bg-slate-900 p-0.5 self-start sm:self-auto"
        >
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'personal'}
            onClick={() => setMode('personal')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded transition-colors ${
              mode === 'personal'
                ? 'bg-slate-900 dark:bg-blue-600 text-white'
                : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Send className="w-3.5 h-3.5" aria-hidden="true" />
            Personal Message
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'bulk'}
            onClick={() => setMode('bulk')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded transition-colors ${
              mode === 'bulk'
                ? 'bg-slate-900 dark:bg-blue-600 text-white'
                : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Users className="w-3.5 h-3.5" aria-hidden="true" />
            Bulk SMS
          </button>
        </div>
      </div>

      {/* Global Alerts */}
      {overview?.global_paused && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-xs text-amber-900 flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>
            Global Kill Switch is active. Outbound personal &amp; bulk requests will return HTTP 503 until resumed from the header bar.
          </span>
        </div>
      )}

      {overview && onlineDevicesCount === 0 && !overview.global_paused && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-2.5 text-xs text-amber-900 flex items-center justify-between gap-3">
          <span>
            No Android SIM gateway device is currently online with SIM Ready. Messages will stay queued until a paired device polls within their TTL window.
          </span>
          <button
            type="button"
            onClick={() => onNavigate('gateway-devices')}
            className="text-xs font-medium underline whitespace-nowrap shrink-0"
          >
            Check Devices
          </button>
        </div>
      )}

      {selectedApp?.allowlist_only === 1 && (
        <div className="bg-slate-100 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2.5 text-xs text-slate-700 dark:text-slate-300 flex items-center justify-between gap-3">
          <span>
            <strong>{selectedApp.name}</strong> has Destination Allowlist Only enabled. Only allowlisted E.164 numbers will be accepted.
          </span>
          <button
            type="button"
            onClick={() => onNavigate('security')}
            className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline whitespace-nowrap shrink-0"
          >
            Manage Allowlist
          </button>
        </div>
      )}

      {/* Personal Message Composer */}
      {mode === 'personal' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <form
            onSubmit={handlePersonalSubmit}
            className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4"
          >
            <div className="border-b border-slate-100 dark:border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Direct Personal SMS</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Encrypted at rest with AES-256-GCM before queueing to your Android SIM. No pre-approved template needed.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor="personal-app" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Sending Application
                </label>
                <select
                  id="personal-app"
                  value={appId}
                  onChange={(e) => setAppId(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
                >
                  {applications.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.environment}) — {a.daily_limit}/day
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="personal-to" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Recipient Phone (E.164)
                </label>
                <input
                  id="personal-to"
                  type="text"
                  required
                  value={personalTo}
                  onChange={(e) => setPersonalTo(e.target.value)}
                  placeholder="+919876543210"
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                />
                {personalTo.trim().length > 0 && !personalToValid && (
                  <p className="text-[11px] text-rose-700 mt-1">Must be valid E.164 format (e.g. +919876543210).</p>
                )}
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label htmlFor="personal-body" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  Message Text
                </label>
                <span className="text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
                  {personalSegments.length}/{MAX_PERSONAL_SMS_LENGTH} chars · {personalSegments.encoding} ·{' '}
                  {personalSegments.segments} {personalSegments.segments === 1 ? 'SMS' : 'SMS parts'}
                </span>
              </div>
              <textarea
                id="personal-body"
                required
                rows={5}
                maxLength={MAX_PERSONAL_SMS_LENGTH}
                value={personalBody}
                onChange={(e) => setPersonalBody(e.target.value)}
                placeholder="Hi, your order #4821 has been dispatched and will arrive today by 6 PM."
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900 leading-relaxed"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor="personal-ttl" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Queue Expiry (TTL Seconds)
                </label>
                <select
                  id="personal-ttl"
                  value={personalTtl}
                  onChange={(e) => setPersonalTtl(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
                >
                  <option value="120">120s (2 minutes)</option>
                  <option value="300">300s (5 minutes)</option>
                  <option value="900">900s (15 minutes)</option>
                  <option value="1800">1800s (30 minutes)</option>
                </select>
              </div>
              <div>
                <label htmlFor="personal-idem" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Idempotency Key (Optional)
                </label>
                <input
                  id="personal-idem"
                  type="text"
                  value={personalIdempotency}
                  onChange={(e) => setPersonalIdempotency(e.target.value)}
                  placeholder="personal_order_4821"
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                />
              </div>
            </div>

            {personalError && (
              <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md p-3">
                {personalError}
              </div>
            )}

            {personalResult && (
              <div className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-md p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-mono">
                  <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span>
                    {personalResult.deduplicated ? 'Idempotent replay: ' : 'Queued '}
                    {personalResult.message_id} ({personalResult.destination_masked}) ·{' '}
                    {personalResult.segment_info.segments} part(s)
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate('messages')}
                  className="text-xs font-medium underline self-start sm:self-auto"
                >
                  View in Messages
                </button>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
              <button
                type="submit"
                disabled={personalSending || !appId || !personalBody.trim()}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-blue-700 dark:bg-blue-600 text-white rounded-md hover:bg-blue-800 dark:hover:bg-blue-500 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" aria-hidden="true" />
                {personalSending ? 'Queueing SMS...' : 'Queue Personal SMS'}
              </button>
            </div>
          </form>

          {/* Summary Side Card */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 self-start">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 border-b border-slate-100 dark:border-slate-800 pb-3">
              Dispatch Summary
            </h3>
            <dl className="space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">Mode</dt>
                <dd className="font-mono text-slate-900 dark:text-slate-100">
                  {selectedApp?.environment === 'test' ? 'Test (Simulated)' : 'Live SIM'}
                </dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">Encoding</dt>
                <dd className="font-mono text-slate-900 dark:text-slate-100">{personalSegments.encoding}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">Characters</dt>
                <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100">
                  {personalSegments.length} / {MAX_PERSONAL_SMS_LENGTH}
                </dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">SIM Parts / Message</dt>
                <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100">
                  {personalSegments.segments} ({personalSegments.perSegmentLimit} chars/part)
                </dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">Masked Target</dt>
                <dd className="font-mono text-slate-900 dark:text-slate-100">
                  {personalTo.trim() ? maskE164(normalizedPersonalTo) : '—'}
                </dd>
              </div>
            </dl>
            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
              Standard English/ASCII uses GSM-7 (160 chars single, 153 chars/part multipart). Hindi, emojis, or Unicode switch to UCS-2 (70 chars single, 67 chars/part).
            </div>
          </div>
        </div>
      )}

      {/* Bulk SMS Composer */}
      {mode === 'bulk' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <form
              onSubmit={handleBulkSubmit}
              className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Bulk SMS Batch</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Deduplicates phone numbers automatically, enforces per-number daily caps, and reports per-recipient outcomes.
                  </p>
                </div>
                <div className="shrink-0">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,.csv,text/plain,text/csv"
                    onChange={handleFileImport}
                    className="hidden"
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800"
                  >
                    <FileUp className="w-3.5 h-3.5" aria-hidden="true" />
                    Import CSV / TXT
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="bulk-app" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Sending Application
                  </label>
                  <select
                    id="bulk-app"
                    value={appId}
                    onChange={(e) => setAppId(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
                  >
                    {applications.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.environment}) — {a.daily_limit}/day
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="bulk-label" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Batch Label (Audit Trail)
                  </label>
                  <input
                    id="bulk-label"
                    type="text"
                    maxLength={64}
                    value={bulkBatchLabel}
                    onChange={(e) => setBulkBatchLabel(e.target.value)}
                    placeholder="november_maintenance_notice"
                    className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label htmlFor="bulk-recipients" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Recipients (E.164 — newline, comma, or semicolon separated)
                  </label>
                  <span className="text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
                    {parsedBulk.validNumbers.length} valid · {parsedBulk.duplicateCount} dup ·{' '}
                    {parsedBulk.invalidInputs.length} invalid
                  </span>
                </div>
                <textarea
                  id="bulk-recipients"
                  rows={4}
                  required
                  value={bulkRecipientsRaw}
                  onChange={(e) => setBulkRecipientsRaw(e.target.value)}
                  placeholder={'+919876543210\n+919811223344, +919900112233'}
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900 leading-relaxed"
                />
                {parsedBulk.invalidInputs.length > 0 && (
                  <p className="text-[11px] text-amber-800 mt-1">
                    Invalid entries will be skipped safely ({parsedBulk.invalidInputs.slice(0, 3).map((x) => maskE164(normalizeE164(x))).join(', ')}
                    {parsedBulk.invalidInputs.length > 3 ? ` +${parsedBulk.invalidInputs.length - 3} more` : ''}).
                  </p>
                )}
                {parsedBulk.validNumbers.length > MAX_BULK_RECIPIENTS && (
                  <p className="text-[11px] text-rose-700 mt-1">
                    Exceeds maximum {MAX_BULK_RECIPIENTS} unique recipients per batch. Split into smaller batches.
                  </p>
                )}
              </div>

              {/* Content Source Toggle */}
              <div className="space-y-3 pt-1">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Message Content</span>
                  <div className="inline-flex border border-slate-200 dark:border-slate-700 rounded-md p-0.5 bg-slate-50 dark:bg-slate-950">
                    <button
                      type="button"
                      onClick={() => setBulkContentMode('custom')}
                      className={`px-2.5 py-1 text-[11px] font-medium rounded ${
                        bulkContentMode === 'custom'
                          ? 'bg-slate-900 dark:bg-blue-600 text-white'
                          : 'text-slate-600 dark:text-slate-300'
                      }`}
                    >
                      Custom Message
                    </button>
                    <button
                      type="button"
                      onClick={() => setBulkContentMode('template')}
                      className={`px-2.5 py-1 text-[11px] font-medium rounded ${
                        bulkContentMode === 'template'
                          ? 'bg-slate-900 dark:bg-blue-600 text-white'
                          : 'text-slate-600 dark:text-slate-300'
                      }`}
                    >
                      Approved Template
                    </button>
                  </div>
                </div>

                {bulkContentMode === 'custom' ? (
                  <div>
                    <div className="flex items-center justify-end mb-1">
                      <span className="text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
                        {bulkSegments.length}/{MAX_PERSONAL_SMS_LENGTH} chars · {bulkSegments.encoding} ·{' '}
                        {bulkSegments.segments} part(s)/SMS
                      </span>
                    </div>
                    <textarea
                      id="bulk-body"
                      required={bulkContentMode === 'custom'}
                      rows={4}
                      maxLength={MAX_PERSONAL_SMS_LENGTH}
                      value={bulkBody}
                      onChange={(e) => setBulkBody(e.target.value)}
                      placeholder="Scheduled maintenance tonight from 11:30 PM to 12:00 AM IST. No action required."
                      className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900 leading-relaxed"
                    />
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div>
                      <label htmlFor="bulk-template" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Template
                      </label>
                      <select
                        id="bulk-template"
                        value={activeTemplate?.code || bulkTemplateCode}
                        onChange={(e) => setBulkTemplateCode(e.target.value)}
                        className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md bg-white text-slate-900"
                      >
                        {templates.map((t) => (
                          <option key={t.id} value={t.code}>
                            {t.code} ({t.purpose})
                          </option>
                        ))}
                      </select>
                    </div>

                    {requiredVars.length > 0 && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {requiredVars.map((v) => (
                          <div key={v}>
                            <label htmlFor={`bulk-var-${v}`} className="block text-xs font-mono text-slate-700 dark:text-slate-300 mb-1">
                              {`{{${v}}}`}
                            </label>
                            <input
                              id={`bulk-var-${v}`}
                              type="text"
                              required={bulkContentMode === 'template'}
                              value={bulkVariables[v] ?? ''}
                              onChange={(e) => setBulkVariables((prev) => ({ ...prev, [v]: e.target.value }))}
                              className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-md text-slate-900"
                            />
                          </div>
                        ))}
                      </div>
                    )}

                    {activeTemplate && (
                      <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded p-3 text-xs text-slate-700 dark:text-slate-300">
                        {renderedTemplatePreview}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="bulk-ttl" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Batch Expiry (TTL Seconds)
                  </label>
                  <select
                    id="bulk-ttl"
                    value={bulkTtl}
                    onChange={(e) => setBulkTtl(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
                  >
                    <option value="300">300s (5 minutes)</option>
                    <option value="600">600s (10 minutes)</option>
                    <option value="1800">1800s (30 minutes)</option>
                    <option value="3600">3600s (1 hour)</option>
                  </select>
                </div>
              </div>

              {bulkError && (
                <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md p-3">
                  {bulkError}
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                <button
                  type="submit"
                  disabled={
                    bulkSending ||
                    !appId ||
                    parsedBulk.validNumbers.length === 0 ||
                    parsedBulk.validNumbers.length > MAX_BULK_RECIPIENTS ||
                    (bulkContentMode === 'custom' && !bulkBody.trim())
                  }
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-blue-700 dark:bg-blue-600 text-white rounded-md hover:bg-blue-800 dark:hover:bg-blue-500 disabled:opacity-50"
                >
                  <Users className="w-3.5 h-3.5" aria-hidden="true" />
                  {bulkSending
                    ? 'Queueing Batch...'
                    : `Queue ${parsedBulk.validNumbers.length} Bulk SMS`}
                </button>
              </div>
            </form>

            {/* Bulk Estimator Card */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 self-start">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 border-b border-slate-100 dark:border-slate-800 pb-3">
                Batch Estimator
              </h3>
              <dl className="space-y-3 text-xs">
                <div className="flex items-center justify-between">
                  <dt className="text-slate-500">Valid Unique Numbers</dt>
                  <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {parsedBulk.validNumbers.length} / {MAX_BULK_RECIPIENTS}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-500">Duplicates Removed</dt>
                  <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100">{parsedBulk.duplicateCount}</dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-500">Invalid Skipped</dt>
                  <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100">{parsedBulk.invalidInputs.length}</dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-500">Encoding &amp; Parts</dt>
                  <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {bulkSegments.encoding} · {bulkSegments.segments} part(s)
                  </dd>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-slate-100 dark:border-slate-800">
                  <dt className="font-medium text-slate-700 dark:text-slate-300">Estimated SIM Units</dt>
                  <dd className="font-mono font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                    {estimatedTotalUnits} SMS
                  </dd>
                </div>
              </dl>
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                Android Gateway dispatches queued bulk messages sequentially via SmsManager to keep carrier pacing stable.
              </div>
            </div>
          </div>

          {/* Bulk Result Breakdown */}
          {bulkResult && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 font-mono">
                    Batch {bulkResult.batch_id}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 tabular-nums">
                    Queued: <strong>{bulkResult.queued_count}</strong> · Duplicates removed: {bulkResult.duplicate_count} ·
                    Invalid skipped: {bulkResult.skipped_invalid_count} · Failed quota/policy: {bulkResult.failed_count}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate('messages')}
                  className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline self-start sm:self-auto"
                >
                  Monitor in Messages Queue
                </button>
              </div>
              <div className="overflow-x-auto max-h-80">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                      <th className="py-2 px-4">Destination (Masked)</th>
                      <th className="py-2 px-4">Outcome</th>
                      <th className="py-2 px-4">Message ID / Detail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {bulkResult.results.map((r, idx) => (
                      <tr key={`${r.to_masked}-${idx}`}>
                        <td className="py-2 px-4 font-mono text-slate-900">{r.to_masked}</td>
                        <td className="py-2 px-4 font-mono">
                          <span
                            className={
                              r.status === 'queued'
                                ? 'text-emerald-700 dark:text-emerald-400'
                                : r.status === 'skipped_invalid'
                                ? 'text-amber-700 dark:text-amber-400'
                                : 'text-rose-700 dark:text-rose-400'
                            }
                          >
                            {r.status}
                          </span>
                        </td>
                        <td className="py-2 px-4 font-mono text-slate-600">
                          {r.message_id ? r.message_id : `${r.error_code ?? ''} ${r.error_message ?? ''}`.trim()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
