import { FormEvent, useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { apiRequest, formatUtcShort } from '../lib/api';
import { calculateSimRemainingEstimate } from '../shared/smsRules';
import type { SimRecord } from '../types';
import { StatusText } from './StatusText';

interface UsageByAppRow {
  application_id: string;
  application_name: string;
  environment: 'test' | 'live';
  daily_limit: number;
  total_messages: number;
  sent_to_network: number;
  delivered: number;
  failed: number;
  delivery_unknown: number;
}

interface SimUsageViewProps {
  onDataChanged: () => void;
}

export function SimUsageView({ onDataChanged }: SimUsageViewProps) {
  const [sims, setSims] = useState<SimRecord[]>([]);
  const [usageByApp, setUsageByApp] = useState<UsageByAppRow[]>([]);
  const [loading, setLoading] = useState(true);

  // Manual reconciliation form state
  const [selectedSimId, setSelectedSimId] = useState('');
  const [planLimit, setPlanLimit] = useState(3000);
  const [estSent, setEstSent] = useState(0);
  const [warnThreshold, setWarnThreshold] = useState(300);
  const [carrierLabel, setCarrierLabel] = useState('');
  const [notes, setNotes] = useState('');
  const [savedNotice, setSavedNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await apiRequest<{ sims: SimRecord[]; usage_by_app: UsageByAppRow[] }>('/api/admin/sim-usage');
      setSims(res.sims);
      setUsageByApp(res.usage_by_app);
      if (res.sims[0]) {
        const s = res.sims[0];
        setSelectedSimId(s.id);
        setPlanLimit(s.plan_sms_limit);
        setEstSent(s.estimated_sms_sent);
        setWarnThreshold(s.warning_threshold);
        setCarrierLabel(s.carrier_label);
        setNotes(s.notes);
      } else {
        setSelectedSimId('');
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to load SIM usage');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const handleReconcile = async (e: FormEvent) => {
    e.preventDefault();
    setSavedNotice(null);
    setErrorMsg(null);
    try {
      await apiRequest(`/api/admin/sim-usage/${selectedSimId}/reconcile`, {
        method: 'PATCH',
        body: JSON.stringify({
          plan_sms_limit: Number(planLimit),
          estimated_sms_sent: Number(estSent),
          warning_threshold: Number(warnThreshold),
          carrier_label: carrierLabel,
          notes,
        }),
      });
      setSavedNotice('SIM plan estimate reconciled and recorded in audit log.');
      await loadData();
      onDataChanged();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to reconcile SIM estimate');
    }
  };

  if (loading && sims.length === 0) {
    return <div className="p-8 text-center text-xs text-slate-500 bg-white border border-slate-200 rounded-lg">Loading SIM usage...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-slate-900">SIM Plan &amp; Usage Estimates</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Remaining SMS counts are local estimates based on tracked network handoffs. Reconcile manually against your carrier account portal.
        </p>
      </div>

      {errorMsg && (
        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{errorMsg}</div>
      )}

      {/* SIM Cards */}
      {sims.length === 0 ? (
        <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-xs text-slate-500">
          No live SIM registered yet. Pair an Android gateway device with an active SIM card under Gateway Devices to track carrier quota.
        </div>
      ) : (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {sims.map((sim) => {
          const { remaining, utilizationPct } = calculateSimRemainingEstimate(sim.plan_sms_limit, sim.estimated_sms_sent);
          const lowRemaining = remaining <= sim.warning_threshold;
          return (
            <div key={sim.id} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">{sim.carrier_label}</h3>
                  <p className="text-xs text-slate-500 mt-0.5 font-mono">
                    {sim.masked_msisdn} · Slot {sim.slot_index} · {sim.device_name}
                  </p>
                </div>
                <StatusText status={sim.device_status || 'online'} />
              </div>

              <div className="space-y-2">
                <div className="flex items-baseline justify-between text-xs">
                  <span className="text-slate-600">
                    Estimated used: <strong className="font-mono text-slate-900 tabular-nums">{sim.estimated_sms_sent.toLocaleString()}</strong> /{' '}
                    <span className="font-mono tabular-nums">{sim.plan_sms_limit.toLocaleString()}</span>
                  </span>
                  <span className="font-mono font-semibold text-slate-900 tabular-nums">
                    ~{remaining.toLocaleString()} est. remaining
                  </span>
                </div>
                <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all ${lowRemaining ? 'bg-amber-600' : 'bg-blue-700'}`}
                    style={{ width: `${utilizationPct}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>Cycle: {sim.period_start} to {sim.period_end}</span>
                  <span>Alert below {sim.warning_threshold}</span>
                </div>
              </div>

              {lowRemaining && (
                <div className="flex items-center gap-2 text-xs text-amber-900 bg-amber-50 border border-amber-200 rounded p-2.5">
                  <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0" aria-hidden="true" />
                  <span>Estimated remaining SMS is at or below warning threshold ({sim.warning_threshold}).</span>
                </div>
              )}

              <p className="text-xs text-slate-600 border-t border-slate-100 pt-3">
                {sim.notes} <span className="text-slate-400 font-mono">· Updated {formatUtcShort(sim.updated_at)}</span>
              </p>
            </div>
          );
        })}

        {/* Manual Carrier Reconciliation Form */}
        {selectedSimId && (
          <form onSubmit={handleReconcile} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Manual Carrier Reconciliation</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Update estimated counts after checking your official carrier balance or cycle reset.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="sim-carrier" className="block text-xs font-medium text-slate-700 mb-1">
                  Carrier Plan Label
                </label>
                <input
                  id="sim-carrier"
                  type="text"
                  value={carrierLabel}
                  onChange={(e) => setCarrierLabel(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
                />
              </div>
              <div>
                <label htmlFor="sim-limit" className="block text-xs font-medium text-slate-700 mb-1">
                  Cycle SMS Limit
                </label>
                <input
                  id="sim-limit"
                  type="number"
                  min={0}
                  value={planLimit}
                  onChange={(e) => setPlanLimit(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                />
              </div>
              <div>
                <label htmlFor="sim-sent" className="block text-xs font-medium text-slate-700 mb-1">
                  Reconciled Sent Count
                </label>
                <input
                  id="sim-sent"
                  type="number"
                  min={0}
                  value={estSent}
                  onChange={(e) => setEstSent(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                />
              </div>
              <div>
                <label htmlFor="sim-threshold" className="block text-xs font-medium text-slate-700 mb-1">
                  Low Balance Warning Threshold
                </label>
                <input
                  id="sim-threshold"
                  type="number"
                  min={0}
                  value={warnThreshold}
                  onChange={(e) => setWarnThreshold(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                />
              </div>
            </div>

            <div>
              <label htmlFor="sim-notes" className="block text-xs font-medium text-slate-700 mb-1">
                Reconciliation Notes
              </label>
              <input
                id="sim-notes"
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
              />
            </div>

            {savedNotice && <p className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded p-2">{savedNotice}</p>}

            <button
              type="submit"
              className="px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800"
            >
              Save Reconciled Estimate
            </button>
          </form>
        )}
      </div>
      )}

      {/* Per-Application Usage Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">Usage Breakdown by Application</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-2.5 px-4">Application</th>
                <th className="py-2.5 px-4">Environment</th>
                <th className="py-2.5 px-4 text-right">Daily Cap</th>
                <th className="py-2.5 px-4 text-right">Total Requests</th>
                <th className="py-2.5 px-4 text-right">Sent to Network</th>
                <th className="py-2.5 px-4 text-right">Delivered (Receipt)</th>
                <th className="py-2.5 px-4 text-right">Failed / Unknown</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {usageByApp.map((row) => (
                <tr key={row.application_id} className="hover:bg-slate-50/70">
                  <td className="py-2.5 px-4 font-medium text-slate-900">{row.application_name}</td>
                  <td className="py-2.5 px-4 font-mono text-slate-600">{row.environment}</td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-700">{row.daily_limit}</td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-900">{row.total_messages}</td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-blue-700">{row.sent_to_network}</td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-emerald-700">{row.delivered}</td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-rose-700">
                    {row.failed + row.delivery_unknown}
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
