import { FormEvent, useEffect, useState } from 'react';
import { Copy, Download, RefreshCw, Smartphone } from 'lucide-react';
import { apiRequest, formatRelativeTime, formatUtcShort } from '../lib/api';
import type { GatewayDevice, MessageRecord, SimRecord } from '../types';
import { StatusText } from './StatusText';

interface EnrollmentTokenRow {
  id: string;
  device_name: string;
  expires_at: string;
  used_at: string | null;
  created_at: string;
}

interface GatewayDevicesViewProps {
  onDataChanged: () => void;
}

export function GatewayDevicesView({ onDataChanged }: GatewayDevicesViewProps) {
  const [devices, setDevices] = useState<GatewayDevice[]>([]);
  const [tokens, setTokens] = useState<EnrollmentTokenRow[]>([]);
  const [sims, setSims] = useState<SimRecord[]>([]);
  const [pendingJobs, setPendingJobs] = useState<MessageRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Enrollment token creator
  const [newDeviceName, setNewDeviceName] = useState('');
  const [oneTimeEnrollToken, setOneTimeEnrollToken] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  // Android project viewer
  const [androidFiles, setAndroidFiles] = useState<Array<{ path: string; content: string }>>([]);
  const [selectedAndroidFile, setSelectedAndroidFile] = useState('');
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const [showAndroidProject, setShowAndroidProject] = useState(false);

  const loadDevices = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await apiRequest<{
        devices: GatewayDevice[];
        enrollment_tokens: EnrollmentTokenRow[];
        sims: SimRecord[];
        pending_jobs: MessageRecord[];
      }>('/api/admin/devices');
      setDevices(res.devices);
      setTokens(res.enrollment_tokens);
      setSims(res.sims);
      setPendingJobs(res.pending_jobs);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to load gateway devices');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadDevices();
    apiRequest<{ files: Array<{ path: string; content: string }> }>('/api/admin/android-project')
      .then((res) => {
        setAndroidFiles(res.files);
        if (res.files[0]) setSelectedAndroidFile(res.files[0].path);
      })
      .catch(() => {});
  }, []);

  const handleCreateToken = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    try {
      const res = await apiRequest<{ enrollment_token_once: string; device_name: string }>('/api/admin/devices/enrollment-tokens', {
        method: 'POST',
        body: JSON.stringify({ device_name: newDeviceName.trim() || 'Android Gateway', ttl_minutes: 15 }),
      });
      setOneTimeEnrollToken(res.enrollment_token_once);
      setCopiedToken(false);
      setNewDeviceName('');
      await loadDevices();
      onDataChanged();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to generate enrollment token');
    }
  };

  const handleDeviceAction = async (id: string, action: 'pause' | 'resume' | 'revoke') => {
    setErrorMsg(null);
    try {
      await apiRequest(`/api/admin/devices/${id}/action`, {
        method: 'POST',
        body: JSON.stringify({ action }),
      });
      await loadDevices();
      onDataChanged();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : `Failed to ${action} device`);
    }
  };

  const serverOrigin = typeof window !== 'undefined' ? window.location.origin : '';

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Android Gateway Devices</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Live physical Android phones authenticate with Keystore-backed credentials and poll outbound HTTPS endpoints. Carrier SIM permissions and limits are strictly enforced on-device.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setShowAndroidProject((s) => !s)}
            className="px-3 py-1.5 text-xs font-medium border border-slate-300 bg-white text-slate-700 rounded-md hover:bg-slate-50"
          >
            {showAndroidProject ? 'Hide Android App Source' : `Android App Source (${androidFiles.length} files)`}
          </button>
          <button
            type="button"
            onClick={() => void loadDevices()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 bg-white text-slate-700 rounded-md hover:bg-slate-50"
          >
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{errorMsg}</div>
      )}

      {showAndroidProject && (
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Kotlin Android Gateway Project (/android-gateway)</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Download the ZIP and open <code className="font-mono text-slate-700">android-gateway/</code> in Android Studio to compile and install the APK on your Android phone.
              </p>
            </div>
            <div className="flex items-center gap-2 self-start sm:self-auto">
              <a
                href="/api/admin/android-project.zip"
                download="simvault-android-gateway.zip"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800"
              >
                <Download className="w-3.5 h-3.5" aria-hidden="true" />
                Download ZIP
              </a>
              <button
                type="button"
                onClick={() => {
                  const active = androidFiles.find((f) => f.path === selectedAndroidFile);
                  if (active) {
                    navigator.clipboard?.writeText(active.content);
                    setCopiedPath(active.path);
                    setTimeout(() => setCopiedPath((prev) => (prev === active.path ? null : prev)), 1500);
                  }
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 text-slate-700 rounded-md hover:bg-slate-50"
              >
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                {copiedPath === selectedAndroidFile ? 'Copied' : 'Copy File'}
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-4">
            <div className="border-b lg:border-b-0 lg:border-r border-slate-200 bg-slate-50 p-2 max-h-96 overflow-y-auto space-y-0.5">
              {androidFiles.map((f) => {
                const parts = f.path.split('/');
                const fileName = parts[parts.length - 1] || f.path;
                const dirName = parts
                  .slice(0, -1)
                  .join('/')
                  .replace('app/src/main/java/com/simvault/gateway', '…/gateway')
                  .replace('app/src/main/res', '…/res');
                const isSelected = selectedAndroidFile === f.path;
                return (
                  <button
                    key={f.path}
                    type="button"
                    title={f.path}
                    onClick={() => setSelectedAndroidFile(f.path)}
                    className={`w-full text-left px-2.5 py-1.5 rounded ${
                      isSelected ? 'bg-slate-900 text-white' : 'text-slate-800 hover:bg-slate-200/70'
                    }`}
                  >
                    <div className="text-xs font-mono font-medium truncate">{fileName}</div>
                    {dirName && (
                      <div className={`text-[10px] font-mono truncate ${isSelected ? 'text-slate-300' : 'text-slate-500'}`}>
                        {dirName}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
            <div className="lg:col-span-3 bg-slate-950 text-slate-100 flex flex-col max-h-96">
              <div className="px-4 py-2 border-b border-slate-800 text-[11px] font-mono text-slate-400 truncate">
                {selectedAndroidFile || 'Select a file'}
              </div>
              <div className="p-4 overflow-auto flex-1">
                <pre className="text-xs font-mono leading-relaxed">
                  {androidFiles.find((f) => f.path === selectedAndroidFile)?.content ?? 'Loading...'}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Devices List */}
      {loading && devices.length === 0 ? (
        <div className="p-8 text-center text-xs text-slate-500 bg-white border border-slate-200 rounded-lg">
          Loading gateway devices...
        </div>
      ) : devices.length === 0 ? (
        <div className="p-8 text-center bg-white border border-slate-200 rounded-lg space-y-2">
          <p className="text-sm font-medium text-slate-800">No Android Gateway Devices Paired Yet</p>
          <p className="text-xs text-slate-500 max-w-lg mx-auto">
            Generate a one-time enrollment token below, install the SimVault Gateway Android app on your phone, and enter this server URL and token to begin live SMS dispatch.
          </p>
        </div>
      ) : (
        <div className={`grid grid-cols-1 ${devices.length > 1 ? 'xl:grid-cols-2' : ''} gap-4`}>
          {devices.map((dev) => {
            const devSim = sims.find((s) => s.device_id === dev.id);
            return (
              <div key={dev.id} className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col justify-between gap-4">
                <div>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <Smartphone className="w-4 h-4 text-slate-600" aria-hidden="true" />
                        <h3 className="text-sm font-semibold text-slate-900">{dev.name}</h3>
                      </div>
                      <p className="text-xs font-mono text-slate-500 mt-0.5">
                        {dev.id} · Android {dev.android_version} · App v{dev.app_version}
                      </p>
                    </div>
                    <StatusText status={dev.status} />
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-3 border-t border-slate-100 text-xs">
                    <div>
                      <span className="text-slate-500 block">SEND_SMS Perm</span>
                      <span className={`font-medium ${dev.permission_send_sms ? 'text-emerald-700' : 'text-rose-700'}`}>
                        {dev.permission_send_sms ? 'Granted' : 'Denied'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">SIM Status</span>
                      <span className={`font-medium ${dev.sim_ready ? 'text-emerald-700' : 'text-rose-700'}`}>
                        {dev.sim_ready ? devSim?.carrier_label || 'Ready' : 'No SIM'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Network / Battery</span>
                      <span className="font-mono text-slate-800 tabular-nums">
                        {dev.network_type} · {dev.battery_pct}%
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Last Heartbeat</span>
                      <span className="font-mono text-slate-800 tabular-nums">{formatRelativeTime(dev.last_heartbeat_at)}</span>
                    </div>
                  </div>
                </div>

                {dev.status !== 'revoked' && (
                  <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-slate-100">
                    {dev.status === 'paused' ? (
                      <button
                        type="button"
                        onClick={() => void handleDeviceAction(dev.id, 'resume')}
                        className="px-2.5 py-1 text-xs font-medium bg-emerald-700 text-white rounded hover:bg-emerald-800"
                      >
                        Resume Device
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void handleDeviceAction(dev.id, 'pause')}
                        className="px-2.5 py-1 text-xs font-medium border border-amber-300 bg-amber-50 text-amber-900 rounded hover:bg-amber-100"
                      >
                        Pause Dispatching
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => void handleDeviceAction(dev.id, 'revoke')}
                      className="px-2.5 py-1 text-xs font-medium text-rose-700 hover:bg-rose-50 rounded ml-auto"
                    >
                      Revoke Device
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Pending Dispatch Queue & One-Time Enrollment */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Pending Outbound Dispatch Queue</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Live messages awaiting lease by an online Android gateway via <code className="font-mono">GET /v1/gateway/jobs/next</code>.
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-600 whitespace-nowrap shrink-0">
              {pendingJobs.length} pending
            </span>
          </div>

          {pendingJobs.length === 0 ? (
            <div className="py-10 text-center text-xs text-slate-400 border border-dashed border-slate-200 rounded-md">
              Queue is currently empty. All queued messages have been leased or finalized.
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-200 rounded-md">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-slate-500">
                    <th className="py-2 px-3">Message ID</th>
                    <th className="py-2 px-3">Destination</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3 text-right">TTL Expires</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {pendingJobs.map((job) => (
                    <tr key={job.id}>
                      <td className="py-2 px-3 font-mono text-slate-900">{job.id}</td>
                      <td className="py-2 px-3 font-mono text-slate-700">{job.destination_masked}</td>
                      <td className="py-2 px-3">
                        <StatusText status={job.status} />
                      </td>
                      <td className="py-2 px-3 text-right font-mono text-slate-500 whitespace-nowrap">
                        {formatUtcShort(job.ttl_expires_at).slice(11, 19)}Z
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* One-time Enrollment Token Generator */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">Pair Physical Android Gateway (One-Time Token)</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Generate a 15-minute single-use token and enter it inside the SimVault Android app alongside your Server Base URL.
            </p>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-md px-3 py-2 text-xs flex items-center justify-between gap-2">
            <span className="text-slate-500 shrink-0">Server URL:</span>
            <code className="font-mono text-slate-900 truncate">{serverOrigin}</code>
            <button
              type="button"
              aria-label="Copy server URL"
              onClick={() => navigator.clipboard?.writeText(serverOrigin)}
              className="text-slate-500 hover:text-slate-900 shrink-0"
            >
              <Copy className="w-3.5 h-3.5" />
            </button>
          </div>

          <form onSubmit={handleCreateToken} className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              aria-label="New gateway device label"
              value={newDeviceName}
              onChange={(e) => setNewDeviceName(e.target.value)}
              placeholder="Pixel 8 — Primary SIM Gateway"
              className="flex-1 px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
            />
            <button
              type="submit"
              className="px-3.5 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800 whitespace-nowrap"
            >
              Generate Token
            </button>
          </form>

          {oneTimeEnrollToken && (
            <div className="bg-amber-50 border border-amber-200 rounded-md p-3 text-xs space-y-2">
              <div className="font-medium text-amber-950">One-Time Enrollment Token (Shown Once)</div>
              <div className="flex items-center justify-between gap-2 bg-white border border-amber-200 rounded px-2.5 py-1.5 font-mono text-slate-900">
                <span className="truncate">{oneTimeEnrollToken}</span>
                <button
                  type="button"
                  aria-label="Copy enrollment token"
                  onClick={() => {
                    navigator.clipboard?.writeText(oneTimeEnrollToken);
                    setCopiedToken(true);
                  }}
                  className="text-slate-500 hover:text-slate-900 shrink-0"
                >
                  {copiedToken ? <span className="text-[11px] font-sans text-emerald-700">Copied</span> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <p className="text-[11px] text-amber-900">
                Open the SimVault Gateway APK on your Android phone, grant SEND_SMS &amp; READ_PHONE_STATE permissions, and paste this token to pair.
              </p>
            </div>
          )}

          <div className="border-t border-slate-100 pt-3">
            <div className="text-xs font-medium text-slate-700 mb-2">Recent Enrollment Tokens</div>
            <div className="space-y-1.5 max-h-28 overflow-y-auto text-xs">
              {tokens.length === 0 ? (
                <p className="text-slate-400 py-1">No enrollment tokens generated yet.</p>
              ) : (
                tokens.map((t) => (
                  <div key={t.id} className="flex items-center justify-between text-slate-600 py-1 border-b border-slate-50">
                    <span className="truncate">{t.device_name}</span>
                    <span className="font-mono text-[11px] text-slate-500 shrink-0">
                      {t.used_at ? `Used ${formatRelativeTime(t.used_at)}` : `Expires ${formatUtcShort(t.expires_at).slice(11, 19)}Z`}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
