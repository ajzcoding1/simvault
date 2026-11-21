import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, RefreshCw, Search, X } from 'lucide-react';
import { apiRequest, formatUtcShort } from '../lib/api';
import type { ApplicationRecord, MessageRecord, OverviewResponse } from '../types';
import { StatusText } from './StatusText';

interface MessagesViewProps {
  applications: ApplicationRecord[];
  overview?: OverviewResponse | null;
  onOpenSendModal: () => void;
  onNavigateToDevices?: () => void;
  refreshSignal: number;
  backgroundTick?: number;
}

const STATUS_FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'queued', label: 'Queued' },
  { id: 'leased', label: 'Leased' },
  { id: 'sent_to_network', label: 'Sent to Network' },
  { id: 'delivered', label: 'Delivered' },
  { id: 'delivery_unknown', label: 'Unknown' },
  { id: 'failed', label: 'Failed' },
  { id: 'expired', label: 'Expired' },
];

export function MessagesView({
  applications,
  overview,
  onOpenSendModal,
  onNavigateToDevices,
  refreshSignal,
  backgroundTick = 0,
}: MessagesViewProps) {
  const [messages, setMessages] = useState<MessageRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [appFilter, setAppFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [selectedMsg, setSelectedMsg] = useState<MessageRecord | null>(null);

  const loadMessages = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      setLoadError(null);
      try {
        const params = new URLSearchParams();
        if (statusFilter !== 'all') params.set('status', statusFilter);
        if (appFilter !== 'all') params.set('application_id', appFilter);
        if (query.trim()) params.set('q', query.trim());
        const res = await apiRequest<{ messages: MessageRecord[] }>(`/api/admin/messages?${params.toString()}`);
        setMessages(res.messages);
        setSelectedMsg((prev) => (prev ? res.messages.find((m) => m.id === prev.id) ?? prev : null));
      } catch (err) {
        setLoadError(err instanceof Error ? err.message : 'Failed to load messages');
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [statusFilter, appFilter, query]
  );

  useEffect(() => {
    void loadMessages(false);
  }, [statusFilter, appFilter, refreshSignal]);

  useEffect(() => {
    if (backgroundTick === 0) return;
    void loadMessages(true);
  }, [backgroundTick, loadMessages]);

  const hasQueuedWork = messages.some(
    (m) => m.status === 'queued' || m.status === 'leased' || m.status === 'accepted_by_device'
  );
  const readyOnlineDevices = (overview?.devices ?? []).filter(
    (d) => d.status === 'online' && Boolean(d.permission_send_sms) && Boolean(d.sim_ready)
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Message Queue &amp; Delivery History</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Plaintext message bodies and full phone numbers are encrypted at rest and redacted from dashboard views. Auto-refreshes every 6s.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => void loadMessages(false)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 bg-white text-slate-700 rounded-md hover:bg-slate-50"
          >
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            Refresh
          </button>
          <button
            type="button"
            onClick={onOpenSendModal}
            className="px-3.5 py-1.5 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800 whitespace-nowrap"
          >
            Send SMS
          </button>
        </div>
      </div>

      {loadError && (
        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{loadError}</div>
      )}

      {hasQueuedWork && overview?.global_paused && (
        <div className="bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5 text-xs text-rose-900 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>
            Global Kill Switch is active — pending messages stay queued until outbound traffic is resumed.
          </span>
        </div>
      )}

      {hasQueuedWork && overview && !overview.global_paused && readyOnlineDevices.length === 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-md px-4 py-2.5 text-xs text-amber-900 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span>
              Messages are waiting in queue, but no online Android gateway with <code className="font-mono">SEND_SMS</code> + active SIM is polling right now.
            </span>
          </div>
          {onNavigateToDevices && (
            <button
              type="button"
              onClick={onNavigateToDevices}
              className="font-medium underline whitespace-nowrap shrink-0"
            >
              Inspect Devices
            </button>
          )}
        </div>
      )}

      {/* Filters Bar */}
      <div className="bg-white border border-slate-200 rounded-lg p-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex items-center gap-1 overflow-x-auto pb-1 lg:pb-0">
          {STATUS_FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setStatusFilter(f.id)}
              className={`px-2.5 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
                statusFilter === f.id
                  ? 'bg-slate-900 text-white'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <select
            aria-label="Filter by application"
            value={appFilter}
            onChange={(e) => setAppFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-slate-300 rounded-md bg-white text-slate-800"
          >
            <option value="all">All applications</option>
            {applications.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.environment})
              </option>
            ))}
          </select>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void loadMessages(false);
            }}
            className="relative flex items-center"
          >
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" aria-hidden="true" />
            <input
              type="text"
              aria-label="Search message ID or phone mask"
              placeholder="Search ID, mask, template..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs border border-slate-300 rounded-md bg-white text-slate-900 w-48 sm:w-56"
            />
          </form>
        </div>
      </div>

      {/* Data Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Loading messages...</div>
        ) : messages.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm font-medium text-slate-900">No messages recorded yet</p>
            <p className="text-xs text-slate-500 mt-1">Adjust status filters or queue a live SMS via Send SMS or POST /v1/sms.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-4">Message ID</th>
                  <th className="py-2.5 px-4">Application</th>
                  <th className="py-2.5 px-4">Destination</th>
                  <th className="py-2.5 px-4">Template / Purpose</th>
                  <th className="py-2.5 px-4">Lifecycle State</th>
                  <th className="py-2.5 px-4 text-right">Created (UTC)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {messages.map((m) => (
                  <tr
                    key={m.id}
                    onClick={() => setSelectedMsg(m)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-4 font-mono text-slate-900">{m.id}</td>
                    <td className="py-2.5 px-4 text-slate-700">
                      <span>{m.application_name}</span>
                      <span className="text-slate-400 mx-1">·</span>
                      <span className="font-mono text-[11px] text-slate-500">{m.is_test ? 'test' : 'live'}</span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-800 whitespace-nowrap">{m.destination_masked}</td>
                    <td className="py-2.5 px-4">
                      <span className="font-mono text-slate-800">{m.template_id}</span>
                      <span className="text-slate-400 mx-1">·</span>
                      <span className="text-slate-500">{m.purpose}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      <StatusText status={m.status} />
                      {m.error_code && <div className="font-mono text-[11px] text-rose-700 mt-0.5">{m.error_code}</div>}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-500 whitespace-nowrap">
                      {formatUtcShort(m.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Lifecycle Timestamp Detail Panel */}
      {selectedMsg && (
        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-start justify-between gap-4 pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 font-mono">{selectedMsg.id}</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                {selectedMsg.application_name} · {selectedMsg.destination_masked} · Template {selectedMsg.template_id}
              </p>
            </div>
            <button
              type="button"
              aria-label="Close message details"
              onClick={() => setSelectedMsg(null)}
              className="p-1 text-slate-400 hover:text-slate-700"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 text-xs">
            <div>
              <div className="text-slate-500">Queued</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.queued_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">Leased to Device</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.leased_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">Accepted by Device</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.accepted_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">Sent to Network</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.sent_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">Delivered (Receipt)</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.delivered_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">Failed / Expired At</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.failed_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">TTL Deadline</div>
              <div className="font-mono text-slate-900 mt-0.5 tabular-nums">{formatUtcShort(selectedMsg.ttl_expires_at)}</div>
            </div>
            <div>
              <div className="text-slate-500">Idempotency Key</div>
              <div className="font-mono text-slate-900 mt-0.5 truncate">{selectedMsg.idempotency_key || 'None'}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
