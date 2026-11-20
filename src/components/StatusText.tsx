import { Check, AlertTriangle, X, Clock, Radio, ShieldAlert } from 'lucide-react';

const STATUS_META: Record<
  string,
  { label: string; colorClass: string; icon: 'check' | 'warn' | 'fail' | 'clock' | 'radio' | 'lock' }
> = {
  // Message statuses (truthful lifecycle)
  delivered: { label: 'Delivered (Receipt)', colorClass: 'text-emerald-700 dark:text-emerald-400', icon: 'check' },
  sent_to_network: { label: 'Sent to Network', colorClass: 'text-blue-700 dark:text-blue-400', icon: 'radio' },
  accepted_by_device: { label: 'Accepted by Device', colorClass: 'text-slate-700 dark:text-slate-300', icon: 'clock' },
  leased: { label: 'Leased to Gateway', colorClass: 'text-slate-700 dark:text-slate-300', icon: 'clock' },
  queued: { label: 'Queued', colorClass: 'text-amber-700 dark:text-amber-400', icon: 'clock' },
  created: { label: 'Created', colorClass: 'text-slate-600 dark:text-slate-400', icon: 'clock' },
  delivery_unknown: { label: 'Delivery Unknown', colorClass: 'text-amber-700 dark:text-amber-400', icon: 'warn' },
  failed: { label: 'Failed', colorClass: 'text-rose-700 dark:text-rose-400', icon: 'fail' },
  expired: { label: 'Expired', colorClass: 'text-slate-500 dark:text-slate-400', icon: 'warn' },

  // OTP / Key / Device / App statuses
  verified: { label: 'Verified', colorClass: 'text-emerald-700 dark:text-emerald-400', icon: 'check' },
  sent: { label: 'Dispatched', colorClass: 'text-blue-700 dark:text-blue-400', icon: 'radio' },
  locked: { label: 'Locked (Max Attempts)', colorClass: 'text-rose-700 dark:text-rose-400', icon: 'lock' },
  online: { label: 'Online', colorClass: 'text-emerald-700 dark:text-emerald-400', icon: 'check' },
  offline: { label: 'Offline', colorClass: 'text-rose-700 dark:text-rose-400', icon: 'warn' },
  paused: { label: 'Paused', colorClass: 'text-amber-700 dark:text-amber-400', icon: 'warn' },
  revoked: { label: 'Revoked', colorClass: 'text-rose-700 dark:text-rose-400', icon: 'fail' },
  active: { label: 'Active', colorClass: 'text-emerald-700 dark:text-emerald-400', icon: 'check' },
  rotating: { label: 'Rotating (Overlap)', colorClass: 'text-amber-700 dark:text-amber-400', icon: 'clock' },
  disabled: { label: 'Disabled', colorClass: 'text-slate-500 dark:text-slate-400', icon: 'fail' },
  approved: { label: 'Approved', colorClass: 'text-emerald-700 dark:text-emerald-400', icon: 'check' },
  draft: { label: 'Draft', colorClass: 'text-amber-700 dark:text-amber-400', icon: 'clock' },
  archived: { label: 'Archived', colorClass: 'text-slate-500 dark:text-slate-400', icon: 'warn' },
  pending: { label: 'Pending', colorClass: 'text-amber-700 dark:text-amber-400', icon: 'clock' },
};

export function StatusText({ status }: { status: string }) {
  const meta = STATUS_META[status] ?? {
    label: status,
    colorClass: 'text-slate-700 dark:text-slate-300',
    icon: 'clock' as const,
  };
  const Icon =
    meta.icon === 'check'
      ? Check
      : meta.icon === 'warn'
        ? AlertTriangle
        : meta.icon === 'fail'
          ? X
          : meta.icon === 'radio'
            ? Radio
            : meta.icon === 'lock'
              ? ShieldAlert
              : Clock;

  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${meta.colorClass}`}>
      <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>{meta.label}</span>
    </span>
  );
}
