import { FormEvent, useEffect, useState } from 'react';
import { Copy, KeyRound, Plus, RotateCw, ShieldAlert } from 'lucide-react';
import { apiRequest, formatRelativeTime, formatUtcShort } from '../lib/api';
import { ALL_API_SCOPES, type ApiKeyScope } from '../shared/smsRules';
import type { ApiKeyRecord, ApplicationRecord } from '../types';
import { StatusText } from './StatusText';

interface AppsViewProps {
  applications: ApplicationRecord[];
  onRefresh: () => void;
}

export function ApplicationsView({ applications, onRefresh }: AppsViewProps) {
  const [name, setName] = useState('');
  const [env, setEnv] = useState<'test' | 'live'>('live');
  const [dailyLimit, setDailyLimit] = useState(200);
  const [allowlistOnly, setAllowlistOnly] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      await apiRequest('/api/admin/applications', {
        method: 'POST',
        body: JSON.stringify({ name, environment: env, daily_limit: dailyLimit, allowlist_only: allowlistOnly }),
      });
      setName('');
      onRefresh();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to create application');
    }
  };

  const toggleAppStatus = async (app: ApplicationRecord) => {
    setErr(null);
    const nextStatus = app.status === 'active' ? 'paused' : 'active';
    try {
      await apiRequest(`/api/admin/applications/${app.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      onRefresh();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to update application status');
    }
  };

  const toggleAllowlistMode = async (app: ApplicationRecord) => {
    setErr(null);
    try {
      await apiRequest(`/api/admin/applications/${app.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ allowlist_only: !app.allowlist_only }),
      });
      onRefresh();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to update allowlist policy');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-slate-900">Owned Applications</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Register each website or backend service separately to isolate API keys, daily quotas, and destination allowlist rules.
        </p>
      </div>

      <form onSubmit={handleCreate} className="bg-white border border-slate-200 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-slate-900 mb-3">Register Owned Application</h3>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div>
            <label htmlFor="app-name" className="block text-xs font-medium text-slate-700 mb-1">
              Application Name
            </label>
            <input
              id="app-name"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Checkout & Billing Service"
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <div>
            <label htmlFor="app-env" className="block text-xs font-medium text-slate-700 mb-1">
              Environment
            </label>
            <select
              id="app-env"
              value={env}
              onChange={(e) => setEnv(e.target.value as 'test' | 'live')}
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
            >
              <option value="live">live (Android Gateway Queue)</option>
              <option value="test">test (Sandbox Mode)</option>
            </select>
          </div>
          <div>
            <label htmlFor="app-cap" className="block text-xs font-medium text-slate-700 mb-1">
              Daily Cap
            </label>
            <input
              id="app-cap"
              type="number"
              min={1}
              value={dailyLimit}
              onChange={(e) => setDailyLimit(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <div className="flex items-center justify-between gap-3">
            <label className="inline-flex items-center gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                checked={allowlistOnly}
                onChange={(e) => setAllowlistOnly(e.target.checked)}
                className="rounded border-slate-300"
              />
              Allowlist only
            </label>
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800 whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5" aria-hidden="true" />
              Create App
            </button>
          </div>
        </div>
        {err && <p className="mt-2 text-xs text-rose-700">{err}</p>}
      </form>

      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-2.5 px-4">Application</th>
                <th className="py-2.5 px-4">Env</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Allowlist Policy</th>
                <th className="py-2.5 px-4 text-right">Daily Cap</th>
                <th className="py-2.5 px-4 text-right">Active Keys</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {applications.map((app) => (
                <tr key={app.id} className="hover:bg-slate-50/70">
                  <td className="py-3 px-4">
                    <div className="font-medium text-slate-900">{app.name}</div>
                    <div className="font-mono text-[11px] text-slate-500">{app.id}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-700">{app.environment}</td>
                  <td className="py-3 px-4">
                    <StatusText status={app.status} />
                  </td>
                  <td className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => void toggleAllowlistMode(app)}
                      className="text-xs text-slate-700 underline hover:text-slate-950"
                    >
                      {app.allowlist_only ? 'Allowlist enforced' : 'Open (Unrestricted)'}
                    </button>
                  </td>
                  <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-800">{app.daily_limit}</td>
                  <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-800">{app.active_keys_count ?? 0}</td>
                  <td className="py-3 px-4 text-right">
                    <button
                      type="button"
                      onClick={() => void toggleAppStatus(app)}
                      className="text-xs font-medium text-blue-700 hover:underline"
                    >
                      {app.status === 'active' ? 'Pause' : 'Activate'}
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

interface ApiKeysViewProps {
  applications: ApplicationRecord[];
  onRefresh: () => void;
}

function parseScopesSafe(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function ApiKeysView({ applications, onRefresh }: ApiKeysViewProps) {
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [appId, setAppId] = useState(applications[0]?.id || '');
  const [keyName, setKeyName] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<ApiKeyScope[]>(['sms:send', 'otp:create', 'otp:verify', 'usage:read']);
  const [revealedSecret, setRevealedSecret] = useState<{ secret: string; prefix: string; overlapUntil?: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [keyErr, setKeyErr] = useState<string | null>(null);

  const loadKeys = async () => {
    setLoading(true);
    try {
      const res = await apiRequest<{ api_keys: ApiKeyRecord[] }>('/api/admin/api-keys');
      setKeys(res.api_keys);
    } catch (error) {
      setKeyErr(error instanceof Error ? error.message : 'Failed to load API keys');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadKeys();
  }, []);

  useEffect(() => {
    if (!appId && applications[0]) setAppId(applications[0].id);
  }, [applications, appId]);

  const toggleScope = (scope: ApiKeyScope) => {
    setSelectedScopes((prev) => (prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]));
  };

  const handleCreateKey = async (e: FormEvent) => {
    e.preventDefault();
    setKeyErr(null);
    try {
      const res = await apiRequest<{ api_key: ApiKeyRecord; secret_once: string }>('/api/admin/api-keys', {
        method: 'POST',
        body: JSON.stringify({ application_id: appId, name: keyName, scopes: selectedScopes }),
      });
      setRevealedSecret({ secret: res.secret_once, prefix: res.api_key.key_prefix });
      setKeyName('');
      setCopied(false);
      await loadKeys();
      onRefresh();
    } catch (error) {
      setKeyErr(error instanceof Error ? error.message : 'Failed to create API key');
    }
  };

  const handleRotate = async (id: string) => {
    setKeyErr(null);
    try {
      const res = await apiRequest<{ api_key: ApiKeyRecord; secret_once: string; overlap_expires_at: string }>(
        `/api/admin/api-keys/${id}/rotate`,
        { method: 'POST' }
      );
      setRevealedSecret({ secret: res.secret_once, prefix: res.api_key.key_prefix, overlapUntil: res.overlap_expires_at });
      setCopied(false);
      await loadKeys();
      onRefresh();
    } catch (error) {
      setKeyErr(error instanceof Error ? error.message : 'Failed to rotate API key');
    }
  };

  const handleRevoke = async (id: string) => {
    setKeyErr(null);
    try {
      await apiRequest(`/api/admin/api-keys/${id}/revoke`, { method: 'POST' });
      await loadKeys();
      onRefresh();
    } catch (error) {
      setKeyErr(error instanceof Error ? error.message : 'Failed to revoke API key');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-slate-900">API Keys</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Keys are hashed at rest with a server-side pepper. Raw secrets are shown exactly once upon creation or rotation and never retrievable again.
        </p>
      </div>
      {keyErr && <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{keyErr}</div>}

      {/* One-time secret reveal panel */}
      {revealedSecret && (
        <div className="bg-amber-50 border border-amber-300 rounded-lg p-4 space-y-2.5">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-amber-950">
              <ShieldAlert className="w-4 h-4 text-amber-700 shrink-0" aria-hidden="true" />
              <span>Copy your API key now — it will never be shown again</span>
            </div>
            <button
              type="button"
              onClick={() => setRevealedSecret(null)}
              className="text-xs font-medium text-amber-900 underline"
            >
              Dismiss
            </button>
          </div>
          <div className="flex items-center justify-between gap-2 bg-white border border-amber-200 rounded px-3 py-2 font-mono text-xs text-slate-900">
            <span className="break-all select-all" data-testid="one-time-api-secret">
              {revealedSecret.secret}
            </span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard?.writeText(revealedSecret.secret);
                setCopied(true);
              }}
              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-slate-900 text-white rounded hover:bg-slate-800 shrink-0"
            >
              <Copy className="w-3.5 h-3.5" aria-hidden="true" />
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          {revealedSecret.overlapUntil && (
            <p className="text-xs text-amber-800">
              Rotation overlap window active: the previous key remains valid until <span className="font-mono">{formatUtcShort(revealedSecret.overlapUntil)}</span>.
            </p>
          )}
        </div>
      )}

      {/* Create Key Form */}
      <form onSubmit={handleCreateKey} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <h3 className="text-sm font-semibold text-slate-900">Generate Scoped API Key</h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label htmlFor="key-app" className="block text-xs font-medium text-slate-700 mb-1">
              Application
            </label>
            <select
              id="key-app"
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
            <label htmlFor="key-label" className="block text-xs font-medium text-slate-700 mb-1">
              Key Label
            </label>
            <input
              id="key-label"
              type="text"
              required
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
              placeholder="Backend Production Worker"
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              className="inline-flex items-center justify-center gap-1.5 w-full py-2 px-4 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800"
            >
              <KeyRound className="w-3.5 h-3.5" aria-hidden="true" />
              Create API Key
            </button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4 pt-1">
          <span className="text-xs font-medium text-slate-600">Scopes:</span>
          {ALL_API_SCOPES.map((scope) => (
            <label key={scope} className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-700">
              <input
                type="checkbox"
                checked={selectedScopes.includes(scope)}
                onChange={() => toggleScope(scope)}
                className="rounded border-slate-300"
              />
              {scope}
            </label>
          ))}
        </div>
      </form>

      {/* Keys Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Loading API keys...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-4">Key Label & Prefix</th>
                  <th className="py-2.5 px-4">Application</th>
                  <th className="py-2.5 px-4">Scopes</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Last Used</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {keys.map((k) => {
                  const scopes = parseScopesSafe(k.scopes_json);
                  return (
                    <tr key={k.id} className="hover:bg-slate-50/70">
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-900">{k.name}</div>
                        <div className="font-mono text-[11px] text-slate-500 mt-0.5">{k.key_prefix}••••••••</div>
                      </td>
                      <td className="py-3 px-4 text-slate-700">
                        {k.application_name} · <span className="font-mono text-slate-500">{k.environment}</span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-600">{scopes.join(', ')}</td>
                      <td className="py-3 px-4">
                        <StatusText status={k.status} />
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-500">
                        {formatRelativeTime(k.last_used_at)}
                      </td>
                      <td className="py-3 px-4 text-right space-x-3 whitespace-nowrap">
                        {k.status === 'active' && (
                          <button
                            type="button"
                            onClick={() => void handleRotate(k.id)}
                            className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:underline"
                          >
                            <RotateCw className="w-3 h-3" aria-hidden="true" />
                            Rotate
                          </button>
                        )}
                        {k.status !== 'revoked' && (
                          <button
                            type="button"
                            onClick={() => void handleRevoke(k.id)}
                            className="text-xs font-medium text-rose-700 hover:underline"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
