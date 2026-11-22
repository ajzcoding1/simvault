import { useEffect, useState } from 'react';
import { Copy } from 'lucide-react';
import { apiRequest } from '../lib/api';
import { buildNextJsSafeOtpSnippet } from '../utils/publicApiDocs';
import type { ApiKeyRecord, ApplicationRecord } from '../types';

function parsePurposesSafe(raw?: string): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function ApiDocsView({ applications }: { applications: ApplicationRecord[] }) {
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [selectedAppId, setSelectedAppId] = useState(applications[0]?.id || '');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    apiRequest<{ api_keys: ApiKeyRecord[] }>('/api/admin/api-keys')
      .then((r) => setKeys(r.api_keys))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedAppId && applications[0]) setSelectedAppId(applications[0].id);
  }, [applications, selectedAppId]);

  const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'https://your-simvault-domain.com';
  const selectedApp = applications.find((a) => a.id === selectedAppId) || applications[0];
  const appKey = keys.find((k) => k.application_id === selectedApp?.id && k.status === 'active');
  const enabledPurposes = parsePurposesSafe(selectedApp?.allowed_purposes_json);

  const curlSnippet = `curl -X POST "${baseUrl}/v1/otp/challenges" \\
  -H "Authorization: Bearer ${appKey?.key_prefix || 'sv_live_xxxxxxxx'}••••••••" \\
  -H "Content-Type: application/json" \\
  -d '{
    "to": "+919876543210",
    "purpose": "registration",
    "ttl_seconds": 300
  }'`;

  const nextJsOtpSnippet = buildNextJsSafeOtpSnippet(baseUrl);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">API Integration &amp; Documentation</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Never embed API keys in frontend JavaScript or mobile binaries. Route all requests through your own trusted application backend.
          </p>
        </div>
        <a
          href="/v1/openapi.json"
          target="_blank"
          rel="noreferrer"
          className="px-3 py-1.5 text-xs font-medium border border-slate-300 bg-white text-slate-700 rounded-md hover:bg-slate-50 self-start sm:self-auto"
        >
          OpenAPI 3.1 JSON
        </a>
      </div>

      {/* Integration Config Summary */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <h3 className="text-sm font-semibold text-slate-900">Private Application Integration Configuration</h3>
          <select
            aria-label="Select application for snippets"
            value={selectedAppId}
            onChange={(e) => setSelectedAppId(e.target.value)}
            className="px-3 py-1.5 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
          >
            {applications.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.environment})
              </option>
            ))}
          </select>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div>
            <span className="text-slate-500 block">Private API Base URL (no /v1 suffix)</span>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="font-mono text-slate-900 break-all">{baseUrl}</span>
              <button
                type="button"
                onClick={() => copyText('base-url', baseUrl)}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-700 hover:underline shrink-0"
              >
                <Copy className="w-3 h-3" aria-hidden="true" />
                {copiedId === 'base-url' ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
          <div>
            <span className="text-slate-500 block">Application ID</span>
            <span className="font-mono text-slate-900">{selectedApp?.id ?? '—'}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Active Key Prefix</span>
            <span className="font-mono text-slate-900">{appKey ? `${appKey.key_prefix}••••` : 'No active key'}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Daily Cap &amp; Mode</span>
            <span className="font-mono text-slate-900 tabular-nums">
              {selectedApp?.daily_limit ?? 0}/day · {selectedApp?.environment ?? 'live'}
            </span>
          </div>
        </div>

        {enabledPurposes.length > 0 && (
          <div className="pt-3 border-t border-slate-100 text-xs">
            <span className="text-slate-500 mr-2">Enabled Purposes:</span>
            <span className="font-mono text-slate-800">{enabledPurposes.join(', ')}</span>
            <p className="text-[11px] text-slate-500 mt-1">
              Set <code className="font-mono">SIMVAULT_BASE_URL={baseUrl}</code> in your backend (do not append <code className="font-mono">/v1</code>; endpoint paths already start with <code className="font-mono">/v1</code>).
            </p>
          </div>
        )}
      </div>

      {/* Snippets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 text-slate-100 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-300">cURL — POST /v1/otp/challenges (otp:create)</span>
            <button
              type="button"
              onClick={() => copyText('curl', curlSnippet)}
              className="inline-flex items-center gap-1 text-[11px] text-slate-300 hover:text-white"
            >
              <Copy className="w-3 h-3" aria-hidden="true" />
              {copiedId === 'curl' ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="text-xs font-mono overflow-x-auto leading-relaxed text-slate-200">{curlSnippet}</pre>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 text-slate-100 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-300">Next.js Backend — Safe OTP Call &amp; Error Details</span>
            <button
              type="button"
              onClick={() => copyText('nextjs', nextJsOtpSnippet)}
              className="inline-flex items-center gap-1 text-[11px] text-slate-300 hover:text-white"
            >
              <Copy className="w-3 h-3" aria-hidden="true" />
              {copiedId === 'nextjs' ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="text-xs font-mono overflow-x-auto leading-relaxed text-slate-200">{nextJsOtpSnippet}</pre>
        </div>
      </div>

      {/* Endpoint Reference */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">Production REST API Endpoints</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                <th className="py-2.5 px-4">Endpoint</th>
                <th className="py-2.5 px-4">Required Scope</th>
                <th className="py-2.5 px-4">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">POST /v1/sms</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">sms:send</td>
                <td className="py-2.5 px-4 text-slate-600">Queue an approved templated SMS for Android gateway dispatch</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">POST /v1/sms/personal</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">sms:send</td>
                <td className="py-2.5 px-4 text-slate-600">Queue a custom direct personal SMS (1–640 chars) without needing a template</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">POST /v1/sms/bulk</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">sms:send</td>
                <td className="py-2.5 px-4 text-slate-600">Queue a bulk SMS batch (custom body or template) up to 100 unique recipients</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">POST /v1/otp/challenges</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">otp:create</td>
                <td className="py-2.5 px-4 text-slate-600">Generate CSPRNG 6-digit OTP, store HMAC hash, and queue SMS (supports login, signup, registration, password_reset, mfa)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">POST /v1/otp/verify</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">otp:verify</td>
                <td className="py-2.5 px-4 text-slate-600">Verify and atomically consume an active OTP challenge</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">GET /v1/messages/:id</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">any active key</td>
                <td className="py-2.5 px-4 text-slate-600">Inspect lifecycle state (queued, leased, sent_to_network, delivered, failed)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-900">GET /v1/usage</td>
                <td className="py-2.5 px-4 font-mono text-slate-600">usage:read</td>
                <td className="py-2.5 px-4 text-slate-600">Read application daily cap, usage count, and estimated SIM quota</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
