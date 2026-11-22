import { ArrowRight, PauseOctagon } from 'lucide-react';
import { formatRelativeTime, formatUtcShort } from '../lib/api';
import type { NavSection, OverviewResponse } from '../types';
import { StatusText } from './StatusText';

interface OverviewViewProps {
  data: OverviewResponse | null;
  loading: boolean;
  onNavigate: (section: NavSection) => void;
  onOpenSendModal: () => void;
}

export function OverviewView({
  data,
  loading,
  onNavigate,
  onOpenSendModal,
}: OverviewViewProps) {
  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 bg-white border border-slate-200 rounded-lg" />
          ))}
        </div>
        <div className="h-72 bg-white border border-slate-200 rounded-lg" />
      </div>
    );
  }

  if (!data) return null;

  const primaryDevice = data.devices[0];
  const primarySim = data.sims[0];
  const breakdownMap = new Map(data.kpis.status_breakdown.map((s) => [s.status, s.count]));
  const deliveredCount = breakdownMap.get('delivered') ?? 0;
  const sentToNetworkCount = breakdownMap.get('sent_to_network') ?? 0;
  const unknownOrFailedCount = (breakdownMap.get('delivery_unknown') ?? 0) + (breakdownMap.get('failed') ?? 0);

  return (
    <div className="space-y-6">
      {data.global_paused && (
        <div className="flex items-center justify-between gap-4 bg-rose-50 border border-rose-200 rounded-lg px-4 py-3 text-sm text-rose-900">
          <div className="flex items-center gap-2.5">
            <PauseOctagon className="w-4 h-4 text-rose-700 shrink-0" aria-hidden="true" />
            <span>
              <strong>Global Kill Switch Active:</strong> Outbound SMS dispatching is paused. New requests are rejected with HTTP 503 until resumed.
            </span>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('settings')}
            className="text-xs font-medium text-rose-800 underline hover:text-rose-950 whitespace-nowrap shrink-0"
          >
            Manage in Settings
          </button>
        </div>
      )}

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Gateway Device</span>
            <button
              type="button"
              onClick={() => onNavigate('gateway-devices')}
              className="text-blue-700 hover:underline font-medium"
            >
              {primaryDevice ? 'Inspect' : 'Pair Phone'}
            </button>
          </div>
          <div className="mt-2">
            {primaryDevice ? (
              <>
                <StatusText status={primaryDevice.status} />
                <p className="mt-1 text-sm font-medium text-slate-900 truncate">{primaryDevice.name}</p>
                <p className="mt-0.5 text-xs text-slate-500 font-mono tabular-nums">
                  Heartbeat {formatRelativeTime(primaryDevice.last_heartbeat_at)} · {primaryDevice.network_type}
                </p>
              </>
            ) : (
              <>
                <p className="text-sm font-medium text-slate-700">No live gateway paired</p>
                <p className="mt-0.5 text-xs text-slate-500">Open Gateway Devices to enroll your Android phone.</p>
              </>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>SIM &amp; Plan Estimate</span>
            <button
              type="button"
              onClick={() => onNavigate('sim-usage')}
              className="text-blue-700 hover:underline font-medium"
            >
              Reconcile
            </button>
          </div>
          <div className="mt-2">
            {primarySim && primaryDevice?.sim_ready ? (
              <>
                <div className="flex items-baseline gap-1.5">
                  <span className="text-2xl font-semibold text-slate-900 font-mono tabular-nums">
                    {primarySim.estimated_sms_remaining.toLocaleString()}
                  </span>
                  <span className="text-xs text-slate-500">est. left</span>
                </div>
                <p className="mt-1 text-xs text-slate-600 truncate">
                  {primarySim.carrier_label} · <span className="font-mono">{primarySim.masked_msisdn}</span>
                </p>
              </>
            ) : (
              <p className="text-sm font-medium text-slate-600">
                {primaryDevice ? 'SIM not ready on device' : 'Awaiting paired SIM'}
              </p>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Requests Today</span>
            <span className="font-mono">UTC</span>
          </div>
          <div className="mt-2">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-semibold text-slate-900 font-mono tabular-nums">
                {data.kpis.requests_today}
              </span>
              <span className="text-xs text-slate-500 font-mono tabular-nums">
                {data.kpis.sent_to_network_today} sent to network
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
              {deliveredCount} receipted · {unknownOrFailedCount} unknown/failed
            </p>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Queue Depth</span>
            <span className="font-mono tabular-nums">{data.kpis.active_otps} active OTPs</span>
          </div>
          <div className="mt-2 flex items-end justify-between gap-2">
            <div>
              <span className="text-2xl font-semibold text-slate-900 font-mono tabular-nums">
                {data.kpis.queue_depth}
              </span>
              <p className="mt-1 text-xs text-slate-500">Pending Android gateway poll</p>
            </div>
            <button
              type="button"
              onClick={onOpenSendModal}
              className="px-2.5 py-1.5 text-xs font-medium border border-slate-300 text-slate-700 rounded-md hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              Send SMS
            </button>
          </div>
        </div>
      </div>

      {/* Truthful Message State Breakdown + Quick Actions */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Message Lifecycle Accounting</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Android <code className="font-mono text-slate-700">sent_to_network</code> confirms handoff to the carrier radio, not recipient delivery. Only explicit carrier receipts mark <code className="font-mono text-slate-700">delivered</code>.
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate('messages')}
              className="px-3 py-1.5 text-xs font-medium border border-slate-300 text-slate-700 rounded-md hover:bg-slate-50 whitespace-nowrap"
            >
              Inspect Queue
            </button>
            <button
              type="button"
              onClick={() => onNavigate('otp-challenges')}
              className="px-3 py-1.5 text-xs font-medium border border-slate-300 text-slate-700 rounded-md hover:bg-slate-50 whitespace-nowrap"
            >
              Open OTP Console
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 pt-4">
          {[
            { key: 'queued', label: 'Queued' },
            { key: 'leased', label: 'Leased' },
            { key: 'sent_to_network', label: 'Sent to Network' },
            { key: 'delivered', label: 'Delivered' },
            { key: 'delivery_unknown', label: 'Delivery Unknown' },
            { key: 'failed', label: 'Failed / Expired' },
          ].map((item) => {
            const count =
              item.key === 'failed'
                ? (breakdownMap.get('failed') ?? 0) + (breakdownMap.get('expired') ?? 0)
                : item.key === 'leased'
                  ? (breakdownMap.get('leased') ?? 0) + (breakdownMap.get('accepted_by_device') ?? 0)
                  : (breakdownMap.get(item.key as never) ?? 0);
            return (
              <div key={item.key} className="py-1">
                <div className="text-xs text-slate-500">{item.label}</div>
                <div className="mt-1 text-xl font-semibold text-slate-900 font-mono tabular-nums">{count}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Messages + Audit Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-200">
            <h2 className="text-sm font-semibold text-slate-900">Recent Messages</h2>
            <button
              type="button"
              onClick={() => onNavigate('messages')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:underline"
            >
              View all <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>

          {data.recent_messages.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No messages recorded yet. Queue a live SMS or call <code className="font-mono text-slate-700">POST /v1/sms</code> to dispatch via your paired Android gateway.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                    <th className="py-2.5 px-4">Message</th>
                    <th className="py-2.5 px-4">Destination</th>
                    <th className="py-2.5 px-4">Template</th>
                    <th className="py-2.5 px-4">State</th>
                    <th className="py-2.5 px-4 text-right">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {data.recent_messages.map((msg) => (
                    <tr key={msg.id} className="hover:bg-slate-50/70">
                      <td className="py-2.5 px-4">
                        <div className="font-mono text-slate-900">{msg.id}</div>
                        <div className="text-slate-500 mt-0.5">
                          {msg.application_name} · {msg.is_test ? 'Sandbox' : 'Live'}
                        </div>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-800 whitespace-nowrap">{msg.destination_masked}</td>
                      <td className="py-2.5 px-4 font-mono text-slate-700">{msg.template_id}</td>
                      <td className="py-2.5 px-4">
                        <StatusText status={msg.status} />
                        {msg.error_code && <div className="font-mono text-[11px] text-slate-500 mt-0.5">{msg.error_code}</div>}
                      </td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-500 whitespace-nowrap">
                        {formatRelativeTime(msg.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden flex flex-col">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-200">
            <h2 className="text-sm font-semibold text-slate-900">Security Audit Trail</h2>
            <button
              type="button"
              onClick={() => onNavigate('audit-logs')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:underline"
            >
              Audit log <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
          <div className="divide-y divide-slate-100 flex-1">
            {data.recent_audit.map((log) => (
              <div key={log.id} className="px-4 py-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-medium text-slate-900 truncate">{log.action}</span>
                  <span className="font-mono tabular-nums text-slate-400 shrink-0">{formatRelativeTime(log.created_at)}</span>
                </div>
                <div className="mt-1 text-slate-500 flex items-center gap-1.5 truncate">
                  <span>{log.actor_type}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{log.target_id}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{formatUtcShort(log.created_at).slice(11, 19)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Carrier Delivery Summary */}
      <div className="text-xs text-slate-500 pt-1">
        Network handoffs recorded:{' '}
        <strong className="font-mono text-slate-700 tabular-nums">{sentToNetworkCount + deliveredCount}</strong>
      </div>
    </div>
  );
}
