import { FormEvent, useEffect, useState } from 'react';
import { Copy, Plus, Send } from 'lucide-react';
import { apiRequest, formatRelativeTime } from '../lib/api';
import { extractTemplateVariables, VALID_MESSAGE_PURPOSES } from '../shared/smsRules';
import type { ApplicationRecord, TemplateRecord, WebhookDeliveryRecord, WebhookEndpointRecord } from '../types';
import { StatusText } from './StatusText';

export function TemplatesView() {
  const [templates, setTemplates] = useState<TemplateRecord[]>([]);
  const [code, setCode] = useState('');
  const [purpose, setPurpose] = useState<string>('account_transactional');
  const [body, setBody] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const loadTemplates = async () => {
    const res = await apiRequest<{ templates: TemplateRecord[] }>('/api/admin/templates');
    setTemplates(res.templates);
  };

  useEffect(() => {
    void loadTemplates();
  }, []);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      await apiRequest('/api/admin/templates', {
        method: 'POST',
        body: JSON.stringify({ code, purpose, body, status: 'approved' }),
      });
      setCode('');
      setBody('');
      await loadTemplates();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to create template');
    }
  };

  const toggleStatus = async (tpl: TemplateRecord) => {
    setErr(null);
    const nextStatus = tpl.status === 'approved' ? 'archived' : 'approved';
    try {
      await apiRequest(`/api/admin/templates/${tpl.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      await loadTemplates();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to update template status');
    }
  };

  const extractedVars = extractTemplateVariables(body);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-slate-900">Approved Message Templates</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Arbitrary bulk text is rejected by default. Applications may only reference approved transactional or OTP templates.
        </p>
      </div>

      <form onSubmit={handleCreate} className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <h3 className="text-sm font-semibold text-slate-900">Create Approved Template</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label htmlFor="tpl-code" className="block text-xs font-medium text-slate-700 mb-1">
              Template Code
            </label>
            <input
              id="tpl-code"
              type="text"
              required
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="invoice_paid_notice"
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <div>
            <label htmlFor="tpl-purpose" className="block text-xs font-medium text-slate-700 mb-1">
              Permitted Purpose
            </label>
            <select
              id="tpl-purpose"
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
            >
              {VALID_MESSAGE_PURPOSES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <label htmlFor="tpl-body" className="block text-xs font-medium text-slate-700 mb-1">
            Template Body (use <code className="font-mono">{'{{variable}}'}</code> placeholders)
          </label>
          <textarea
            id="tpl-body"
            required
            rows={2}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Payment of {{amount}} confirmed for account {{account_label}}."
            className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
          />
          {extractedVars.length > 0 && (
            <p className="text-[11px] text-slate-500 mt-1 font-mono">
              Detected variables: {extractedVars.join(', ')}
            </p>
          )}
        </div>
        {err && <p className="text-xs text-rose-700">{err}</p>}
        <button
          type="submit"
          className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800"
        >
          <Plus className="w-3.5 h-3.5" aria-hidden="true" />
          Save Template
        </button>
      </form>

      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-2.5 px-4">Code</th>
                <th className="py-2.5 px-4">Purpose</th>
                <th className="py-2.5 px-4">Body</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {templates.map((t) => (
                <tr key={t.id} className="hover:bg-slate-50/70">
                  <td className="py-3 px-4 font-mono font-medium text-slate-900 whitespace-nowrap">{t.code}</td>
                  <td className="py-3 px-4 text-slate-600 whitespace-nowrap">{t.purpose}</td>
                  <td className="py-3 px-4 text-slate-700 max-w-md">{t.body}</td>
                  <td className="py-3 px-4">
                    <StatusText status={t.status} />
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => void toggleStatus(t)}
                      className="text-xs font-medium text-blue-700 hover:underline"
                    >
                      {t.status === 'approved' ? 'Archive' : 'Approve'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function parseEventsSafe(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function WebhooksView({ applications }: { applications: ApplicationRecord[] }) {
  const [endpoints, setEndpoints] = useState<WebhookEndpointRecord[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryRecord[]>([]);
  const [appId, setAppId] = useState(applications[0]?.id || '');
  const [url, setUrl] = useState('');
  const [secretOnce, setSecretOnce] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadWebhooks = async () => {
    try {
      const res = await apiRequest<{ endpoints: WebhookEndpointRecord[]; deliveries: WebhookDeliveryRecord[] }>('/api/admin/webhooks');
      setEndpoints(res.endpoints);
      setDeliveries(res.deliveries);
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to load webhooks');
    }
  };

  useEffect(() => {
    void loadWebhooks();
  }, []);

  useEffect(() => {
    if (!appId && applications[0]) setAppId(applications[0].id);
  }, [applications, appId]);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      const res = await apiRequest<{ signing_secret_once: string }>('/api/admin/webhooks', {
        method: 'POST',
        body: JSON.stringify({ application_id: appId, url: url.trim() }),
      });
      setSecretOnce(res.signing_secret_once);
      setUrl('');
      await loadWebhooks();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to create webhook');
    }
  };

  const handleTest = async (id: string) => {
    setErr(null);
    try {
      await apiRequest(`/api/admin/webhooks/${id}/test`, { method: 'POST' });
      await loadWebhooks();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to queue webhook event');
    }
  };

  const handleToggle = async (id: string) => {
    setErr(null);
    try {
      await apiRequest(`/api/admin/webhooks/${id}/toggle`, { method: 'PATCH' });
      await loadWebhooks();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to update webhook endpoint');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-slate-900">Webhooks &amp; HMAC Signing</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Events are signed with HMAC-SHA256 (<code className="font-mono">X-SimVault-Signature</code>) and dispatched only to public HTTPS endpoints (private/loopback hosts are blocked).
        </p>
      </div>

      {secretOnce && (
        <div className="bg-amber-50 border border-amber-300 rounded-lg p-4 text-xs space-y-2">
          <div className="font-semibold text-amber-950">Webhook Signing Secret (Shown Once)</div>
          <div className="flex items-center justify-between gap-2 bg-white border border-amber-200 rounded px-3 py-2 font-mono text-slate-900">
            <span>{secretOnce}</span>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(secretOnce)}
              className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-slate-950"
            >
              <Copy className="w-3.5 h-3.5" aria-hidden="true" /> Copy
            </button>
          </div>
        </div>
      )}

      <form onSubmit={handleCreate} className="bg-white border border-slate-200 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-slate-900 mb-3">Add Public HTTPS Webhook Endpoint</h3>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div>
            <label htmlFor="wh-app" className="block text-xs font-medium text-slate-700 mb-1">
              Application
            </label>
            <select
              id="wh-app"
              value={appId}
              onChange={(e) => setAppId(e.target.value)}
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
            >
              {applications.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="wh-url" className="block text-xs font-medium text-slate-700 mb-1">
              Public HTTPS Callback URL
            </label>
            <input
              id="wh-url"
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://api.yourdomain.com/webhooks/simvault"
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800 whitespace-nowrap"
          >
            Add Endpoint
          </button>
        </div>
        {err && <p className="text-xs text-rose-700 mt-2">{err}</p>}
      </form>

      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">Configured Endpoints</h3>
        </div>
        <div className="divide-y divide-slate-100">
          {endpoints.length === 0 ? (
            <div className="px-5 py-6 text-xs text-slate-500 text-center">No webhook endpoints configured yet.</div>
          ) : (
            endpoints.map((ep) => (
              <div key={ep.id} className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div>
                  <div className="font-mono font-medium text-slate-900">{ep.url}</div>
                  <div className="text-slate-500 mt-0.5">
                    {ep.application_name} · Events: <span className="font-mono">{parseEventsSafe(ep.event_types_json).join(', ')}</span>
                  </div>
                </div>
              <div className="flex items-center gap-3 shrink-0">
                <StatusText status={ep.enabled ? 'active' : 'paused'} />
                <button
                  type="button"
                  onClick={() => void handleTest(ep.id)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 border border-slate-300 rounded hover:bg-slate-50 text-slate-700"
                >
                  <Send className="w-3 h-3" aria-hidden="true" />
                  Send Test Event
                </button>
                <button
                  type="button"
                  onClick={() => void handleToggle(ep.id)}
                  className="text-blue-700 hover:underline font-medium"
                >
                  {ep.enabled ? 'Disable' : 'Enable'}
                </button>
              </div>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">Recent Webhook Deliveries</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-2.5 px-4">Event</th>
                <th className="py-2.5 px-4">Endpoint</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">HTTP / Attempts</th>
                <th className="py-2.5 px-4 text-right">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {deliveries.map((d) => (
                <tr key={d.id}>
                  <td className="py-2.5 px-4 font-mono text-slate-900">
                    {d.event_type} <span className="text-slate-400">({d.event_id})</span>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-600 truncate max-w-xs">{d.url}</td>
                  <td className="py-2.5 px-4">
                    <StatusText status={d.status} />
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-700">
                    {d.last_http_status ?? '—'} · {d.attempt_count} tries
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-500">
                    {formatRelativeTime(d.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
