import { FormEvent, useEffect, useState } from 'react';
import { PauseOctagon, Play, RefreshCw } from 'lucide-react';
import { apiRequest } from '../lib/api';

interface SettingsAndInfraViewProps {
  settings: Record<string, string>;
  onUpdated: () => void;
}

export function SettingsAndInfraView({ settings, onUpdated }: SettingsAndInfraViewProps) {
  const [globalPaused, setGlobalPaused] = useState(settings.global_paused === 'true');
  const [leaseTimeout, setLeaseTimeout] = useState(settings.lease_timeout_seconds || '30');
  const [maxRetries, setMaxRetries] = useState(settings.max_send_retries || '3');
  const [retentionDays, setRetentionDays] = useState(settings.retention_days || '30');
  const [sweeperResult, setSweeperResult] = useState<string | null>(null);
  const [dockerSnippet, setDockerSnippet] = useState('');
  const [saved, setSaved] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    setGlobalPaused(settings.global_paused === 'true');
    setLeaseTimeout(settings.lease_timeout_seconds || '30');
    setMaxRetries(settings.max_send_retries || '3');
    setRetentionDays(settings.retention_days || '30');
  }, [settings]);

  useEffect(() => {
    apiRequest<{ docker_compose_snippet: string }>('/api/admin/blueprints')
      .then((b) => setDockerSnippet(b.docker_compose_snippet))
      .catch(() => {});
  }, []);

  const handleToggleKillSwitch = async () => {
    setErrorMsg(null);
    const next = !globalPaused;
    try {
      await apiRequest('/api/admin/settings', {
        method: 'PATCH',
        body: JSON.stringify({ global_paused: String(next) }),
      });
      setGlobalPaused(next);
      onUpdated();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to toggle kill switch');
    }
  };

  const handleSaveWorker = async (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    setErrorMsg(null);
    try {
      await apiRequest('/api/admin/settings', {
        method: 'PATCH',
        body: JSON.stringify({
          lease_timeout_seconds: leaseTimeout,
          max_send_retries: maxRetries,
          retention_days: retentionDays,
        }),
      });
      setSaved(true);
      onUpdated();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to save worker settings');
    }
  };

  const handleRunSweeper = async () => {
    setErrorMsg(null);
    try {
      const res = await apiRequest<Record<string, number>>('/api/admin/sweeper/run', { method: 'POST' });
      setSweeperResult(JSON.stringify(res));
      onUpdated();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to run background sweeper');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-slate-900">Platform Settings, Kill Switch &amp; Deployment</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Live operational controls, queue recovery parameters, compliance boundaries, and self-hosted Docker Compose deployment layout.
        </p>
      </div>

      {errorMsg && (
        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{errorMsg}</div>
      )}

      {/* Global Kill Switch */}
      <div
        className={`border rounded-lg p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
          globalPaused ? 'bg-rose-50 border-rose-200' : 'bg-white border-slate-200'
        }`}
      >
        <div>
          <h3 className="text-sm font-semibold text-slate-900">Global Emergency Kill Switch</h3>
          <p className="text-xs text-slate-600 mt-0.5">
            Immediately pauses all outbound gateway leasing and rejects new <code className="font-mono">/v1/sms</code> and <code className="font-mono">/v1/otp/challenges</code> calls with HTTP 503.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void handleToggleKillSwitch()}
          className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-md whitespace-nowrap shrink-0 ${
            globalPaused ? 'bg-emerald-700 text-white hover:bg-emerald-800' : 'bg-rose-700 text-white hover:bg-rose-800'
          }`}
        >
          {globalPaused ? (
            <>
              <Play className="w-3.5 h-3.5" aria-hidden="true" />
              Resume Outbound Traffic
            </>
          ) : (
            <>
              <PauseOctagon className="w-3.5 h-3.5" aria-hidden="true" />
              Activate Global Pause
            </>
          )}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Worker & Retention Settings */}
        <form onSubmit={handleSaveWorker} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">Queue &amp; Retention Configuration</h3>
            <button
              type="button"
              onClick={() => void handleRunSweeper()}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:underline"
            >
              <RefreshCw className="w-3 h-3" aria-hidden="true" />
              Run Sweeper Now
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label htmlFor="set-lease" className="block text-xs font-medium text-slate-700 mb-1">
                Lease Timeout (s)
              </label>
              <input
                id="set-lease"
                type="number"
                min={10}
                max={300}
                value={leaseTimeout}
                onChange={(e) => setLeaseTimeout(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div>
              <label htmlFor="set-retries" className="block text-xs font-medium text-slate-700 mb-1">
                Max Lease Retries
              </label>
              <input
                id="set-retries"
                type="number"
                min={1}
                max={10}
                value={maxRetries}
                onChange={(e) => setMaxRetries(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div>
              <label htmlFor="set-retention" className="block text-xs font-medium text-slate-700 mb-1">
                Data Retention (days)
              </label>
              <input
                id="set-retention"
                type="number"
                min={1}
                max={365}
                value={retentionDays}
                onChange={(e) => setRetentionDays(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
          </div>

          {sweeperResult && (
            <div className="text-xs font-mono bg-slate-50 border border-slate-200 rounded p-2 text-slate-700">
              Sweeper result: {sweeperResult}
            </div>
          )}
          {saved && <p className="text-xs text-emerald-700">Configuration updated.</p>}

          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800"
          >
            Save Settings
          </button>
        </form>

        {/* Compliance & Production Topology */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <h3 className="text-sm font-semibold text-slate-900">Operational &amp; Compliance Boundaries</h3>
          <ul className="space-y-2 text-xs text-slate-600 list-disc pl-4 leading-relaxed">
            <li>Private orchestration only: never use a personal SIM for bulk marketing, unsolicited traffic, or third-party resale.</li>
            <li>Confirm carrier plan terms and applicable Indian telecom / DLT / privacy rules before production sends.</li>
            <li>Never auto-failover to third-party SMS providers without explicit owner approval.</li>
            <li>Android <code className="font-mono">SEND_SMS</code> requires explicit user grant and private/managed distribution outside Play restrictions.</li>
          </ul>
          <div className="pt-2">
            <div className="text-xs font-medium text-slate-700 mb-1.5">AWS EC2 Docker Compose Reference</div>
            <pre className="bg-slate-900 text-slate-200 rounded p-3 text-[11px] font-mono overflow-x-auto leading-relaxed">
              {dockerSnippet}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
