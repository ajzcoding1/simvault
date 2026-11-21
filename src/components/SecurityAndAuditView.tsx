import { FormEvent, useEffect, useState } from 'react';
import { Copy, Lock, Search, ShieldCheck, Trash2 } from 'lucide-react';
import { apiRequest, formatUtcShort } from '../lib/api';
import type { AllowlistEntry, ApplicationRecord, AuditLogRecord } from '../types';

export function SecurityView({
  applications,
  settings,
  onSettingsUpdated,
  onLockWorkspace,
}: {
  applications: ApplicationRecord[];
  settings: Record<string, string>;
  onSettingsUpdated: () => void;
  onLockWorkspace: () => void;
}) {
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [appId, setAppId] = useState(applications[0]?.id || '');
  const [phone, setPhone] = useState('');
  const [label, setLabel] = useState('');
  const [allowErr, setAllowErr] = useState<string | null>(null);

  // Rate-limit & OTP policy
  const [otpTtl, setOtpTtl] = useState(settings.otp_ttl_seconds || '300');
  const [otpAttempts, setOtpAttempts] = useState(settings.otp_max_attempts || '5');
  const [otpCooldown, setOtpCooldown] = useState(settings.otp_resend_cooldown_seconds || '45');
  const [perNumberHourly, setPerNumberHourly] = useState(settings.rate_limit_per_number_hourly || '6');
  const [globalCap, setGlobalCap] = useState(settings.global_daily_sim_cap || '300');
  const [policySaved, setPolicySaved] = useState(false);
  const [policyErr, setPolicyErr] = useState<string | null>(null);

  // Owner Password Change
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwdMsg, setPwdMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // MFA State (never leaks current_demo_code)
  const [mfaState, setMfaState] = useState<{
    mfa_enabled: boolean;
    secret_preview: string;
    otpauth_uri: string | null;
  } | null>(null);
  const [totpInput, setTotpInput] = useState('');
  const [disableMfaCredential, setDisableMfaCredential] = useState('');
  const [mfaErr, setMfaErr] = useState<string | null>(null);

  useEffect(() => {
    setOtpTtl(settings.otp_ttl_seconds || '300');
    setOtpAttempts(settings.otp_max_attempts || '5');
    setOtpCooldown(settings.otp_resend_cooldown_seconds || '45');
    setPerNumberHourly(settings.rate_limit_per_number_hourly || '6');
    setGlobalCap(settings.global_daily_sim_cap || '300');
  }, [settings]);

  const loadAllowlist = async () => {
    try {
      const res = await apiRequest<{ entries: AllowlistEntry[] }>('/api/admin/allowlist');
      setAllowlist(res.entries);
    } catch (err) {
      setAllowErr(err instanceof Error ? err.message : 'Failed to load allowlist');
    }
  };

  const loadMfa = async () => {
    try {
      const res = await apiRequest<{
        mfa_enabled: boolean;
        secret_preview: string;
        otpauth_uri: string | null;
      }>('/api/admin/security/mfa');
      setMfaState(res);
    } catch (err) {
      setMfaErr(err instanceof Error ? err.message : 'Failed to load MFA configuration');
    }
  };

  useEffect(() => {
    void loadAllowlist();
    void loadMfa();
  }, []);

  useEffect(() => {
    if (!appId && applications[0]) setAppId(applications[0].id);
  }, [applications, appId]);

  const handleAddAllowlist = async (e: FormEvent) => {
    e.preventDefault();
    setAllowErr(null);
    try {
      await apiRequest('/api/admin/allowlist', {
        method: 'POST',
        body: JSON.stringify({ application_id: appId, phone: phone.trim(), label: label.trim() }),
      });
      setPhone('');
      setLabel('');
      await loadAllowlist();
    } catch (err) {
      setAllowErr(err instanceof Error ? err.message : 'Failed to add destination');
    }
  };

  const handleDeleteAllowlist = async (id: string) => {
    setAllowErr(null);
    try {
      await apiRequest(`/api/admin/allowlist/${id}`, { method: 'DELETE' });
      await loadAllowlist();
    } catch (err) {
      setAllowErr(err instanceof Error ? err.message : 'Failed to remove destination');
    }
  };

  const handleSavePolicies = async (e: FormEvent) => {
    e.preventDefault();
    setPolicySaved(false);
    setPolicyErr(null);
    try {
      await apiRequest('/api/admin/settings', {
        method: 'PATCH',
        body: JSON.stringify({
          otp_ttl_seconds: otpTtl,
          otp_max_attempts: otpAttempts,
          otp_resend_cooldown_seconds: otpCooldown,
          rate_limit_per_number_hourly: perNumberHourly,
          global_daily_sim_cap: globalCap,
        }),
      });
      setPolicySaved(true);
      onSettingsUpdated();
    } catch (err) {
      setPolicyErr(err instanceof Error ? err.message : 'Failed to save policies');
    }
  };

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    setPwdMsg(null);
    if (newPassword !== confirmPassword) {
      setPwdMsg({ ok: false, text: 'New password and confirmation do not match.' });
      return;
    }
    try {
      await apiRequest('/api/admin/security/password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPwdMsg({ ok: true, text: 'Owner password rotated. Other active sessions were invalidated.' });
    } catch (err) {
      setPwdMsg({ ok: false, text: err instanceof Error ? err.message : 'Failed to update password' });
    }
  };

  const handleEnableMfa = async (e: FormEvent) => {
    e.preventDefault();
    setMfaErr(null);
    try {
      await apiRequest('/api/admin/security/mfa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: totpInput.trim() }),
      });
      setTotpInput('');
      await loadMfa();
    } catch (err) {
      setMfaErr(err instanceof Error ? err.message : 'Failed to verify authenticator code');
    }
  };

  const handleDisableMfa = async (e: FormEvent) => {
    e.preventDefault();
    setMfaErr(null);
    const cred = disableMfaCredential.trim();
    if (!cred) {
      setMfaErr('Enter your current owner password or a 6-digit authenticator code to disable MFA.');
      return;
    }
    const payload = /^\d{6}$/.test(cred) ? { totp_code: cred } : { current_password: cred };
    try {
      await apiRequest('/api/admin/security/mfa/disable', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setDisableMfaCredential('');
      await loadMfa();
    } catch (err) {
      setMfaErr(err instanceof Error ? err.message : 'Failed to disable MFA');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Security, Rate Limits &amp; Allowlist</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Enforce destination allowlists, OTP brute-force lockouts, per-number throttles, owner password rotation, and TOTP MFA.
          </p>
        </div>
        <button
          type="button"
          onClick={onLockWorkspace}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 bg-white text-slate-700 rounded-md hover:bg-slate-50 self-start sm:self-auto"
        >
          <Lock className="w-3.5 h-3.5" aria-hidden="true" />
          Lock &amp; Sign Out
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Rate Limits & OTP Policy */}
        <form onSubmit={handleSavePolicies} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-900">OTP &amp; Abuse Throttle Policies</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="pol-ttl" className="block text-xs font-medium text-slate-700 mb-1">
                OTP Expiry (seconds)
              </label>
              <input
                id="pol-ttl"
                type="number"
                min={60}
                max={600}
                value={otpTtl}
                onChange={(e) => setOtpTtl(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div>
              <label htmlFor="pol-attempts" className="block text-xs font-medium text-slate-700 mb-1">
                Max Verify Attempts
              </label>
              <input
                id="pol-attempts"
                type="number"
                min={1}
                max={10}
                value={otpAttempts}
                onChange={(e) => setOtpAttempts(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div>
              <label htmlFor="pol-cooldown" className="block text-xs font-medium text-slate-700 mb-1">
                Resend Cooldown (seconds)
              </label>
              <input
                id="pol-cooldown"
                type="number"
                min={0}
                max={300}
                value={otpCooldown}
                onChange={(e) => setOtpCooldown(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div>
              <label htmlFor="pol-hourly" className="block text-xs font-medium text-slate-700 mb-1">
                Per-Number Hourly Cap
              </label>
              <input
                id="pol-hourly"
                type="number"
                min={1}
                max={50}
                value={perNumberHourly}
                onChange={(e) => setPerNumberHourly(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div className="sm:col-span-2">
              <label htmlFor="pol-global-cap" className="block text-xs font-medium text-slate-700 mb-1">
                Global Daily Live SIM Cap
              </label>
              <input
                id="pol-global-cap"
                type="number"
                min={1}
                value={globalCap}
                onChange={(e) => setGlobalCap(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
              />
            </div>
          </div>
          {policyErr && <p className="text-xs text-rose-700">{policyErr}</p>}
          {policySaved && <p className="text-xs text-emerald-700">Policies updated and logged.</p>}
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800"
          >
            Save Security Policies
          </button>
        </form>

        {/* Owner Password + TOTP MFA */}
        <div className="space-y-6">
          <form onSubmit={handleChangePassword} className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900">Change Owner Password</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label htmlFor="pwd-current" className="block text-xs font-medium text-slate-700 mb-1">
                  Current Password
                </label>
                <input
                  id="pwd-current"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
                />
              </div>
              <div>
                <label htmlFor="pwd-new" className="block text-xs font-medium text-slate-700 mb-1">
                  New Password (10+ chars)
                </label>
                <input
                  id="pwd-new"
                  type="password"
                  required
                  minLength={10}
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
                />
              </div>
              <div>
                <label htmlFor="pwd-confirm" className="block text-xs font-medium text-slate-700 mb-1">
                  Confirm New Password
                </label>
                <input
                  id="pwd-confirm"
                  type="password"
                  required
                  minLength={10}
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
                />
              </div>
            </div>
            {pwdMsg && (
              <p className={`text-xs ${pwdMsg.ok ? 'text-emerald-700' : 'text-rose-700'}`}>{pwdMsg.text}</p>
            )}
            <button
              type="submit"
              className="px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800"
            >
              Update Owner Password
            </button>
          </form>

          <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">Owner Multi-Factor Authentication (TOTP)</h3>
              <span className={`text-xs font-medium ${mfaState?.mfa_enabled ? 'text-emerald-700' : 'text-amber-700'}`}>
                {mfaState?.mfa_enabled ? 'MFA Enabled' : 'MFA Setup Ready'}
              </span>
            </div>

            {mfaState?.mfa_enabled ? (
              <form onSubmit={(e) => void handleDisableMfa(e)} className="space-y-3 text-xs text-slate-600">
                <div className="flex items-center gap-2 text-emerald-800 bg-emerald-50 border border-emerald-200 rounded p-3">
                  <ShieldCheck className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span>RFC 6238 TOTP authenticator is active for owner logins.</span>
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="password"
                    aria-label="Current password or 6-digit TOTP code to disable MFA"
                    value={disableMfaCredential}
                    onChange={(e) => setDisableMfaCredential(e.target.value)}
                    placeholder="Current password or 6-digit TOTP"
                    autoComplete="current-password"
                    className="flex-1 px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
                  />
                  <button
                    type="submit"
                    className="px-3 py-2 text-xs font-medium border border-rose-300 text-rose-700 rounded-md hover:bg-rose-50 whitespace-nowrap"
                  >
                    Disable MFA
                  </button>
                </div>
                {mfaErr && <p className="text-rose-700">{mfaErr}</p>}
              </form>
            ) : (
              <form onSubmit={handleEnableMfa} className="space-y-3 text-xs">
                <p className="text-slate-600">
                  Add this Base32 secret to your authenticator app (Google Authenticator, 1Password, Authy), then enter the 6-digit code to activate MFA.
                </p>
                <div className="bg-slate-50 border border-slate-200 rounded p-2.5 font-mono text-[11px] text-slate-800 break-all flex items-center justify-between gap-2">
                  <span>Secret: {mfaState?.secret_preview || 'Loading...'}</span>
                  {mfaState?.otpauth_uri && (
                    <button
                      type="button"
                      onClick={() => navigator.clipboard?.writeText(mfaState.otpauth_uri!)}
                      className="inline-flex items-center gap-1 text-[11px] font-sans font-medium text-blue-700 hover:underline shrink-0"
                    >
                      <Copy className="w-3 h-3" aria-hidden="true" />
                      Copy URI
                    </button>
                  )}
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    aria-label="TOTP verification code"
                    value={totpInput}
                    onChange={(e) => setTotpInput(e.target.value)}
                    placeholder="6-digit code"
                    className="flex-1 px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800"
                  >
                    Enable MFA
                  </button>
                </div>
                {mfaErr && <p className="text-rose-700">{mfaErr}</p>}
              </form>
            )}
          </div>
        </div>
      </div>

      {/* Destination Allowlist */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">Approved Destination Allowlist</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Applications with <code className="font-mono">allowlist_only</code> enabled can only message numbers listed here.
          </p>
        </div>

        <form onSubmit={handleAddAllowlist} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div>
            <label htmlFor="al-app" className="block text-xs font-medium text-slate-700 mb-1">
              Application
            </label>
            <select
              id="al-app"
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
          <div>
            <label htmlFor="al-phone" className="block text-xs font-medium text-slate-700 mb-1">
              E.164 Number
            </label>
            <input
              id="al-phone"
              type="text"
              required
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+919876543210"
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <div>
            <label htmlFor="al-label" className="block text-xs font-medium text-slate-700 mb-1">
              Owner Label
            </label>
            <input
              id="al-label"
              type="text"
              required
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Operator Handset"
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md text-slate-900"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800 whitespace-nowrap"
          >
            Add Approved Number
          </button>
        </form>
        {allowErr && <p className="text-xs text-rose-700">{allowErr}</p>}

        <div className="overflow-x-auto border-t border-slate-100 pt-3">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500">
                <th className="py-2 pr-4">Masked Number</th>
                <th className="py-2 pr-4">Label</th>
                <th className="py-2 pr-4">Application</th>
                <th className="py-2 text-right">Remove</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {allowlist.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-4 text-center text-slate-400">
                    No allowlist restrictions configured yet.
                  </td>
                </tr>
              ) : (
                allowlist.map((entry) => (
                  <tr key={entry.id}>
                    <td className="py-2.5 pr-4 font-mono text-slate-900">{entry.e164_masked}</td>
                    <td className="py-2.5 pr-4 text-slate-700">{entry.label}</td>
                    <td className="py-2.5 pr-4 text-slate-500">{entry.application_name}</td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        aria-label={`Remove ${entry.e164_masked}`}
                        onClick={() => void handleDeleteAllowlist(entry.id)}
                        className="text-rose-700 hover:text-rose-900 p-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export function AuditLogsView() {
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [query, setQuery] = useState('');
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const loadLogs = async (q = query) => {
    setLoadErr(null);
    try {
      const res = await apiRequest<{ logs: AuditLogRecord[] }>(`/api/admin/audit-logs?q=${encodeURIComponent(q)}`);
      setLogs(res.logs);
    } catch (err) {
      setLoadErr(err instanceof Error ? err.message : 'Failed to load audit logs');
    }
  };

  useEffect(() => {
    void loadLogs('');
  }, []);

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Append-Only Audit Logs</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            All administrative actions, key events, device pairings, and policy changes. Secrets, OTP codes, and full phone numbers are redacted.
          </p>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void loadLogs(query);
          }}
          className="relative flex items-center"
        >
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" aria-hidden="true" />
          <input
            type="text"
            aria-label="Search audit logs"
            placeholder="Filter action or target..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-xs border border-slate-300 rounded-md bg-white text-slate-900 w-56"
          />
        </form>
      </div>

      {loadErr && (
        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{loadErr}</div>
      )}

      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-2.5 px-4">Timestamp (UTC)</th>
                <th className="py-2.5 px-4">Action</th>
                <th className="py-2.5 px-4">Actor</th>
                <th className="py-2.5 px-4">Target</th>
                <th className="py-2.5 px-4">Redacted Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {logs.map((l) => (
                <tr key={l.id} className="hover:bg-slate-50/70">
                  <td className="py-2.5 px-4 font-mono tabular-nums text-slate-500 whitespace-nowrap">
                    {formatUtcShort(l.created_at)}
                  </td>
                  <td className="py-2.5 px-4 font-mono font-medium text-slate-900 whitespace-nowrap">{l.action}</td>
                  <td className="py-2.5 px-4 text-slate-700 whitespace-nowrap">
                    {l.actor_type} · <span className="font-mono text-slate-500">{l.actor_id}</span>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-700 whitespace-nowrap">
                    {l.target_type}:{l.target_id}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px] text-slate-600 max-w-md truncate">
                    {l.metadata_redacted_json}
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
