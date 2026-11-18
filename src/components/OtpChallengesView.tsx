import { FormEvent, useEffect, useState } from 'react';
import { CheckCircle2, Lock, RefreshCw } from 'lucide-react';
import { apiRequest, formatUtcShort } from '../lib/api';
import type { ApplicationRecord, OtpChallengeRecord } from '../types';
import { StatusText } from './StatusText';

interface OtpChallengesViewProps {
  applications: ApplicationRecord[];
  onDataChanged: () => void;
}

export function OtpChallengesView({ applications, onDataChanged }: OtpChallengesViewProps) {
  const [challenges, setChallenges] = useState<OtpChallengeRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Create OTP form
  const [appId, setAppId] = useState(applications[0]?.id || '');
  const [toPhone, setToPhone] = useState('');
  const [purpose, setPurpose] = useState('login');
  const [createResult, setCreateResult] = useState<{ challenge_id: string; expires_at: string } | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);

  // Verify OTP form
  const [verifyChallengeId, setVerifyChallengeId] = useState('');
  const [verifyCode, setVerifyCode] = useState('');
  const [verifyFeedback, setVerifyFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const loadOtps = async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await apiRequest<{ challenges: OtpChallengeRecord[] }>('/api/admin/otp-challenges');
      setChallenges(res.challenges);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load OTP challenges');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadOtps();
  }, []);

  useEffect(() => {
    if (!appId && applications.length > 0) {
      setAppId(applications[0].id);
    }
  }, [applications, appId]);

  const handleCreateOtp = async (e: FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    setCreateResult(null);
    setVerifyFeedback(null);
    try {
      const res = await apiRequest<{ challenge_id: string; message_id: string; expires_at: string }>(
        '/api/admin/otp-challenges/create',
        {
          method: 'POST',
          body: JSON.stringify({
            application_id: appId,
            to: toPhone.trim(),
            purpose,
            bypass_cooldown: true,
          }),
        }
      );
      setCreateResult({ challenge_id: res.challenge_id, expires_at: res.expires_at });
      setVerifyChallengeId(res.challenge_id);
      await loadOtps();
      onDataChanged();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create OTP challenge');
    }
  };

  const handleVerifyOtp = async (e: FormEvent) => {
    e.preventDefault();
    setVerifyFeedback(null);
    try {
      const res = await apiRequest<{ verified: boolean; verified_at: string }>('/api/admin/otp-challenges/verify', {
        method: 'POST',
        body: JSON.stringify({
          challenge_id: verifyChallengeId.trim(),
          code: verifyCode.trim(),
        }),
      });
      if (res.verified) {
        setVerifyFeedback({ ok: true, text: `Verified and consumed at ${formatUtcShort(res.verified_at)}` });
        setVerifyCode('');
      }
      await loadOtps();
      onDataChanged();
    } catch (err) {
      setVerifyFeedback({ ok: false, text: err instanceof Error ? err.message : 'Verification failed' });
      await loadOtps();
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">OTP Challenges &amp; Verification Console</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Codes are generated via CSPRNG, dispatched via your live Android SIM gateway, stored strictly as keyed HMAC-SHA256 hashes, and verified atomically in constant time.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadOtps()}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 bg-white text-slate-700 rounded-md hover:bg-slate-50 self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
          Refresh
        </button>
      </div>

      {loadError && (
        <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-4 py-2.5">{loadError}</div>
      )}

      {/* Interactive Live OTP Creation + Verification */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form onSubmit={handleCreateOtp} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">1. Issue Live OTP Challenge</h3>
            <p className="text-xs text-slate-500 mt-0.5">Queues an SMS OTP to the handset. API response never returns plaintext OTP.</p>
          </div>

          <div>
            <label htmlFor="otp-app" className="block text-xs font-medium text-slate-700 mb-1">
              Application
            </label>
            <select
              id="otp-app"
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
            <label htmlFor="otp-phone" className="block text-xs font-medium text-slate-700 mb-1">
              Recipient E.164 Number
            </label>
            <input
              id="otp-phone"
              type="text"
              required
              value={toPhone}
              onChange={(e) => setToPhone(e.target.value)}
              placeholder="+919876543210"
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          <div>
            <label htmlFor="otp-purpose" className="block text-xs font-medium text-slate-700 mb-1">
              Purpose
            </label>
            <select
              id="otp-purpose"
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white text-slate-900"
            >
              <option value="login">login</option>
              <option value="mfa">mfa</option>
              <option value="password_reset">password_reset</option>
              <option value="signup">signup</option>
            </select>
          </div>

          {createError && <p className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded p-2">{createError}</p>}
          {createResult && (
            <div className="text-xs text-emerald-900 bg-emerald-50 border border-emerald-200 rounded p-2.5 space-y-1">
              <div className="font-medium">Live challenge queued for Android gateway</div>
              <div className="font-mono text-[11px]">ID: {createResult.challenge_id}</div>
              <div className="text-[11px] text-emerald-700">Expires {formatUtcShort(createResult.expires_at)}</div>
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2 px-4 text-xs font-medium bg-blue-700 text-white rounded-md hover:bg-blue-800"
          >
            Issue Live OTP Challenge
          </button>
        </form>

        <form onSubmit={handleVerifyOtp} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">2. Verify Received Code</h3>
            <p className="text-xs text-slate-500 mt-0.5">Atomic single-use verification with automatic replay protection and max-attempt lockout.</p>
          </div>

          <div>
            <label htmlFor="verify-challenge-id" className="block text-xs font-medium text-slate-700 mb-1">
              Challenge ID
            </label>
            <input
              id="verify-challenge-id"
              type="text"
              required
              value={verifyChallengeId}
              onChange={(e) => setVerifyChallengeId(e.target.value)}
              placeholder="otp_..."
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          <div>
            <label htmlFor="verify-code" className="block text-xs font-medium text-slate-700 mb-1">
              6-Digit Code Received on Handset
            </label>
            <input
              id="verify-code"
              type="text"
              required
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value)}
              placeholder="123456"
              className="w-full px-3 py-2 text-sm font-mono tracking-widest border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          {verifyFeedback && (
            <div
              className={`text-xs rounded p-2.5 border flex items-start gap-2 ${
                verifyFeedback.ok
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  : 'bg-rose-50 border-rose-200 text-rose-900'
              }`}
            >
              {verifyFeedback.ok ? (
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-700" aria-hidden="true" />
              ) : (
                <Lock className="w-4 h-4 shrink-0 mt-0.5 text-rose-700" aria-hidden="true" />
              )}
              <span>{verifyFeedback.text}</span>
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2 px-4 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800"
          >
            Verify Code
          </button>
        </form>
      </div>

      {/* Challenges History Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">OTP Challenge History</h3>
        </div>
        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Loading challenges...</div>
        ) : challenges.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">No OTP challenges issued yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-4">Challenge ID</th>
                  <th className="py-2.5 px-4">Application</th>
                  <th className="py-2.5 px-4">Destination</th>
                  <th className="py-2.5 px-4">Purpose</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Attempts</th>
                  <th className="py-2.5 px-4 text-right">Expires (UTC)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {challenges.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => setVerifyChallengeId(c.id)}
                    className="hover:bg-slate-50 cursor-pointer"
                  >
                    <td className="py-2.5 px-4 font-mono text-slate-900">{c.id}</td>
                    <td className="py-2.5 px-4 text-slate-700">
                      {c.application_name} · <span className="font-mono text-slate-500">{c.is_test ? 'sandbox' : 'live'}</span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-800">{c.destination_masked}</td>
                    <td className="py-2.5 px-4 text-slate-600">{c.purpose}</td>
                    <td className="py-2.5 px-4">
                      <StatusText status={c.status} />
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-700">
                      {c.attempts} / {c.max_attempts}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-500 whitespace-nowrap">
                      {formatUtcShort(c.expires_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
