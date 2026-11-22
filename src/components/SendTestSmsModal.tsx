import { FormEvent, useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import { apiRequest } from '../lib/api';
import { MAX_PERSONAL_SMS_LENGTH, calculateSmsSegmentInfo, extractTemplateVariables } from '../shared/smsRules';
import type { ApplicationRecord, TemplateRecord } from '../types';

interface SendTestSmsModalProps {
  open: boolean;
  onClose: () => void;
  applications: ApplicationRecord[];
  onSent: () => void;
  onOpenBulkCompose?: () => void;
}

export function SendTestSmsModal({ open, onClose, applications, onSent, onOpenBulkCompose }: SendTestSmsModalProps) {
  const [mode, setMode] = useState<'personal' | 'template'>('personal');
  const [templates, setTemplates] = useState<TemplateRecord[]>([]);
  const [appId, setAppId] = useState('');
  const [toPhone, setToPhone] = useState('');
  const [personalBody, setPersonalBody] = useState('');
  const [templateCode, setTemplateCode] = useState('login_notice');
  const [variables, setVariables] = useState<Record<string, string>>({});
  const [idempotencyKey, setIdempotencyKey] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successInfo, setSuccessInfo] = useState<{ message_id: string; deduplicated: boolean } | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setSuccessInfo(null);
    apiRequest<{ templates: TemplateRecord[] }>('/api/admin/templates')
      .then((res) => setTemplates(res.templates.filter((t) => t.status === 'approved')))
      .catch(() => {});
  }, [open]);

  useEffect(() => {
    if (!appId && applications.length > 0) {
      setAppId(applications[0].id);
    }
  }, [applications, appId]);

  const personalSegments = useMemo(() => calculateSmsSegmentInfo(personalBody), [personalBody]);

  if (!open) return null;

  const activeTemplate = templates.find((t) => t.code === templateCode) ?? templates[0];
  const requiredVars = activeTemplate ? extractTemplateVariables(activeTemplate.body) : ['name', 'device_label'];

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setSuccessInfo(null);
    try {
      if (mode === 'personal') {
        const res = await apiRequest<{ message_id: string; deduplicated: boolean }>('/api/admin/messages/personal', {
          method: 'POST',
          body: JSON.stringify({
            application_id: appId,
            to: toPhone.trim(),
            body: personalBody,
            idempotency_key: idempotencyKey.trim() || undefined,
          }),
        });
        setSuccessInfo(res);
      } else {
        const payloadVars: Record<string, string> = {};
        for (const v of requiredVars) {
          payloadVars[v] = variables[v] ?? '';
        }
        const res = await apiRequest<{ message_id: string; deduplicated: boolean }>('/api/admin/messages/send', {
          method: 'POST',
          body: JSON.stringify({
            application_id: appId,
            to: toPhone.trim(),
            template_id: activeTemplate?.code || templateCode,
            variables: payloadVars,
            purpose: activeTemplate?.purpose || 'account_transactional',
            idempotency_key: idempotencyKey.trim() || undefined,
          }),
        });
        setSuccessInfo(res);
      }
      onSent();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to queue SMS');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="send-sms-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4"
    >
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg w-full max-w-lg shadow-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 id="send-sms-modal-title" className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Send Live SMS
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Queue a personal message or approved template directly to your paired Android SIM gateway.
            </p>
          </div>
          <button
            type="button"
            aria-label="Close modal"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div className="inline-flex border border-slate-200 dark:border-slate-700 rounded-md p-0.5 bg-slate-50 dark:bg-slate-950">
              <button
                type="button"
                onClick={() => setMode('personal')}
                className={`px-3 py-1 text-xs font-medium rounded ${
                  mode === 'personal'
                    ? 'bg-slate-900 dark:bg-blue-600 text-white'
                    : 'text-slate-600 dark:text-slate-300'
                }`}
              >
                Personal Message
              </button>
              <button
                type="button"
                onClick={() => setMode('template')}
                className={`px-3 py-1 text-xs font-medium rounded ${
                  mode === 'template'
                    ? 'bg-slate-900 dark:bg-blue-600 text-white'
                    : 'text-slate-600 dark:text-slate-300'
                }`}
              >
                Templated SMS
              </button>
            </div>
            {onOpenBulkCompose && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onOpenBulkCompose();
                }}
                className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline"
              >
                Need Bulk SMS?
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="modal-app" className="block text-xs font-medium text-slate-700 mb-1">
                Application
              </label>
              <select
                id="modal-app"
                value={appId}
                onChange={(e) => setAppId(e.target.value)}
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
              >
                {applications.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.environment})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="modal-to" className="block text-xs font-medium text-slate-700 mb-1">
                Destination (E.164)
              </label>
              <input
                id="modal-to"
                type="text"
                required
                value={toPhone}
                onChange={(e) => setToPhone(e.target.value)}
                placeholder="+919876543210"
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
          </div>

          {mode === 'personal' ? (
            <>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label htmlFor="modal-personal-body" className="block text-xs font-medium text-slate-700">
                    Custom Message
                  </label>
                  <span className="text-[11px] font-mono tabular-nums text-slate-500">
                    {personalSegments.length}/{MAX_PERSONAL_SMS_LENGTH} · {personalSegments.encoding} ·{' '}
                    {personalSegments.segments} SMS
                  </span>
                </div>
                <textarea
                  id="modal-personal-body"
                  required
                  rows={4}
                  maxLength={MAX_PERSONAL_SMS_LENGTH}
                  value={personalBody}
                  onChange={(e) => setPersonalBody(e.target.value)}
                  placeholder="Write your custom message..."
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
                />
              </div>
              <div>
                <label htmlFor="modal-idem-personal" className="block text-xs font-medium text-slate-700 mb-1">
                  Idempotency Key (Optional)
                </label>
                <input
                  id="modal-idem-personal"
                  type="text"
                  value={idempotencyKey}
                  onChange={(e) => setIdempotencyKey(e.target.value)}
                  placeholder="req_unique_001"
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                />
              </div>
            </>
          ) : (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="modal-tpl" className="block text-xs font-medium text-slate-700 mb-1">
                    Approved Template
                  </label>
                  <select
                    id="modal-tpl"
                    value={activeTemplate?.code || templateCode}
                    onChange={(e) => setTemplateCode(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md bg-white text-slate-900"
                  >
                    {templates.map((t) => (
                      <option key={t.id} value={t.code}>
                        {t.code} ({t.purpose})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label htmlFor="modal-idem" className="block text-xs font-medium text-slate-700 mb-1">
                    Idempotency Key (Optional)
                  </label>
                  <input
                    id="modal-idem"
                    type="text"
                    value={idempotencyKey}
                    onChange={(e) => setIdempotencyKey(e.target.value)}
                    placeholder="req_unique_001"
                    className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                  />
                </div>
              </div>

              {activeTemplate && (
                <div className="bg-slate-50 border border-slate-200 rounded p-2.5 text-xs text-slate-700">
                  {activeTemplate.body}
                </div>
              )}

              {requiredVars.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {requiredVars.map((v) => (
                    <div key={v}>
                      <label htmlFor={`var-${v}`} className="block text-xs font-medium text-slate-700 mb-1 font-mono">
                        {`{{${v}}}`}
                      </label>
                      <input
                        id={`var-${v}`}
                        type="text"
                        required
                        value={variables[v] ?? ''}
                        onChange={(e) => setVariables((prev) => ({ ...prev, [v]: e.target.value }))}
                        className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-md text-slate-900"
                      />
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {error && <p className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded p-2.5">{error}</p>}
          {successInfo && (
            <p className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded p-2.5 font-mono">
              {successInfo.deduplicated
                ? `Idempotent replay: returned existing ${successInfo.message_id}`
                : `Queued message ${successInfo.message_id}`}
            </p>
          )}

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 text-xs font-medium border border-slate-300 text-slate-700 rounded-md hover:bg-slate-50"
            >
              Close
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800 disabled:opacity-50"
            >
              {submitting ? 'Queueing...' : 'Queue SMS'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
