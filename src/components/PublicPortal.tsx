import { FormEvent, RefObject, useMemo, useRef, useState } from 'react';
import { ArrowRight, Check, Copy, ExternalLink, Lock, Monitor, Moon, Sun } from 'lucide-react';
import type { ThemeMode } from '../utils/theme';
import {
  type CodeLanguage,
  PUBLIC_ENDPOINTS,
  PUBLIC_PLACEHOLDER_BASE_URL,
  WEBHOOK_VERIFY_SNIPPET,
  buildNextJsSafeOtpSnippet,
  buildQuickstartSnippet,
} from '../utils/publicApiDocs';

interface PublicPortalProps {
  loginEmail: string;
  onLoginEmailChange: (value: string) => void;
  loginPassword: string;
  onLoginPasswordChange: (value: string) => void;
  loginTotp: string;
  onLoginTotpChange: (value: string) => void;
  mfaPrompt: boolean;
  loginError: string | null;
  onLoginSubmit: (e: FormEvent) => void;
  themeMode: ThemeMode;
  themeLabel: string;
  onCycleTheme: () => void;
}

const LANGUAGE_TABS: Array<{ id: CodeLanguage; label: string }> = [
  { id: 'curl', label: 'cURL' },
  { id: 'node', label: 'Node.js' },
  { id: 'python', label: 'Python' },
  { id: 'php', label: 'PHP' },
];

const ERROR_CODES = [
  { status: '400', code: 'BAD_REQUEST / INVALID_JSON', meaning: 'Malformed JSON body or missing required fields.' },
  { status: '401', code: 'UNAUTHORIZED', meaning: 'Missing, malformed, expired, or revoked Bearer API key.' },
  { status: '403', code: 'INSUFFICIENT_SCOPE', meaning: 'API key lacks the required scope (e.g. sms:send, otp:create, otp:verify).' },
  { status: '403', code: 'PURPOSE_NOT_ALLOWED', meaning: 'Requested purpose is disabled on this application (e.g. login, signup, registration).' },
  { status: '403', code: 'DESTINATION_NOT_ALLOWLISTED', meaning: 'Live application has Allowlist Only enabled and recipient is not allowlisted.' },
  { status: '422', code: 'INVALID_PHONE / OTP_INVALID', meaning: 'Non-E.164 phone number, or wrong/expired/5-attempt locked OTP code.' },
  { status: '429', code: 'RESEND_COOLDOWN / RATE_LIMITED', meaning: 'OTP resend cooldown active, per-number hourly cap, or daily limit reached.' },
  { status: '503', code: 'GATEWAY_PAUSED', meaning: 'Global owner kill switch is active; outbound dispatching paused.' },
];

export function PublicPortal({
  loginEmail,
  onLoginEmailChange,
  loginPassword,
  onLoginPasswordChange,
  loginTotp,
  onLoginTotpChange,
  mfaPrompt,
  loginError,
  onLoginSubmit,
  themeMode,
  themeLabel,
  onCycleTheme,
}: PublicPortalProps) {
  const [selectedLang, setSelectedLang] = useState<CodeLanguage>('node');
  const [selectedEndpointId, setSelectedEndpointId] = useState<string>(PUBLIC_ENDPOINTS[0].id);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const emailInputRef: RefObject<HTMLInputElement | null> = useRef<HTMLInputElement | null>(null);

  const quickstartCode = useMemo(
    () => buildQuickstartSnippet(selectedLang, PUBLIC_PLACEHOLDER_BASE_URL),
    [selectedLang]
  );

  const activeEndpoint = useMemo(
    () => PUBLIC_ENDPOINTS.find((e) => e.id === selectedEndpointId) ?? PUBLIC_ENDPOINTS[0],
    [selectedEndpointId]
  );

  const ThemeIcon = themeMode === 'dark' ? Moon : themeMode === 'light' ? Sun : Monitor;

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1600);
  };

  const focusOwnerLogin = () => {
    const el = document.getElementById('owner-login');
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => emailInputRef.current?.focus(), 200);
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* 3-Zone Top Bar */}
      <header className="sticky top-0 z-30 h-16 bg-white/95 dark:bg-slate-950/95 backdrop-blur border-b border-slate-200 dark:border-slate-800">
        <div className="max-w-7xl mx-auto h-full px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-8">
          <a
            href="#top"
            className="font-display text-lg font-bold tracking-tight text-slate-900 dark:text-slate-50 whitespace-nowrap shrink-0"
          >
            SimVault
          </a>

          <nav aria-label="Public navigation" className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-600 dark:text-slate-300">
            <a
              href="#architecture"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 whitespace-nowrap shrink-0 transition-colors"
            >
              Overview
            </a>
            <a
              href="#quickstart"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 whitespace-nowrap shrink-0 transition-colors"
            >
              Quickstart
            </a>
            <a
              href="#endpoints"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 whitespace-nowrap shrink-0 transition-colors"
            >
              Endpoints
            </a>
            <a
              href="#webhooks"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 whitespace-nowrap shrink-0 transition-colors"
            >
              Webhooks
            </a>
          </nav>

          <div className="shrink-0">
            <button
              type="button"
              onClick={focusOwnerLogin}
              className="px-4 py-2 text-xs font-semibold bg-slate-900 dark:bg-blue-600 text-white rounded-md hover:bg-slate-800 dark:hover:bg-blue-500 whitespace-nowrap shrink-0 transition-colors"
            >
              Sign In
            </button>
          </div>
        </div>
      </header>

      <main id="top" className="flex-1">
        {/* Hero Split + Console Sign In */}
        <section className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/40">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-16">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center">
              {/* Left: Product Statement + Docs Navigation */}
              <div className="lg:col-span-7 space-y-6">
                <h1 className="font-display text-[clamp(2.25rem,3.9vw,3.4rem)] font-bold tracking-tight leading-[1.08] text-slate-900 dark:text-slate-50 text-balance max-w-2xl">
                  SMS and OTP delivery over your own SIM.
                </h1>

                <p className="text-base text-slate-600 dark:text-slate-300 leading-relaxed max-w-xl">
                  Send transactional messages and single-use 6-digit verification codes through an enrolled Android device. Browse the REST endpoints below or sign in to manage keys and gateways.
                </p>

                <div className="flex flex-wrap items-center gap-3 pt-1">
                  <a
                    href="#quickstart"
                    className="inline-flex items-center gap-2 px-5 py-2.5 text-xs font-semibold bg-blue-700 dark:bg-blue-600 text-white rounded-md hover:bg-blue-800 dark:hover:bg-blue-500 whitespace-nowrap transition-colors"
                  >
                    API Reference
                    <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                  </a>

                  <a
                    href="/v1/openapi.json"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap transition-colors"
                  >
                    OpenAPI 3.1
                    <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                  </a>

                  <button
                    type="button"
                    onClick={onCycleTheme}
                    aria-label={`Switch color theme (current: ${themeLabel})`}
                    title={`Theme: ${themeLabel}`}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2.5 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap transition-colors"
                  >
                    <ThemeIcon className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>{themeLabel}</span>
                  </button>
                </div>
              </div>

              {/* Right: Operator Login Form */}
              <div id="owner-login" className="lg:col-span-5">
                <form
                  onSubmit={onLoginSubmit}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 sm:p-7 space-y-4"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-50">
                        Operator Sign In
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                        Access gateway status, applications, and scoped API keys.
                      </p>
                    </div>
                    <Lock className="w-4 h-4 text-slate-400 dark:text-slate-500 shrink-0 mt-1" aria-hidden="true" />
                  </div>

                  <div>
                    <label
                      htmlFor="login-email"
                      className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                    >
                      Email
                    </label>
                    <input
                      ref={emailInputRef}
                      id="login-email"
                      type="email"
                      required
                      autoComplete="username"
                      value={loginEmail}
                      onChange={(e) => onLoginEmailChange(e.target.value)}
                      placeholder="you@domain.com"
                      className="w-full px-3 py-2 text-xs border border-slate-300 dark:border-slate-700 rounded-md bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="login-password"
                      className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                    >
                      Password
                    </label>
                    <input
                      id="login-password"
                      type="password"
                      required
                      autoComplete="current-password"
                      value={loginPassword}
                      onChange={(e) => onLoginPasswordChange(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full px-3 py-2 text-xs border border-slate-300 dark:border-slate-700 rounded-md bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                    />
                  </div>

                  {mfaPrompt && (
                    <div>
                      <label
                        htmlFor="login-totp"
                        className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                      >
                        Authenticator Code
                      </label>
                      <input
                        id="login-totp"
                        type="text"
                        required
                        value={loginTotp}
                        onChange={(e) => onLoginTotpChange(e.target.value)}
                        placeholder="6-digit code"
                        className="w-full px-3 py-2 text-xs font-mono border border-slate-300 dark:border-slate-700 rounded-md bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                      />
                    </div>
                  )}

                  {loginError && (
                    <p className="text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-800 rounded-md p-2.5">
                      {loginError}
                    </p>
                  )}

                  <button
                    type="submit"
                    className="w-full py-2.5 px-4 text-xs font-semibold bg-slate-900 dark:bg-blue-600 text-white rounded-md hover:bg-slate-800 dark:hover:bg-blue-500 transition-colors"
                  >
                    {mfaPrompt ? 'Verify & Sign In' : 'Sign In'}
                  </button>
                </form>
              </div>
            </div>
          </div>
        </section>

        {/* Dispatch Pipeline Overview */}
        <section id="architecture" className="scroll-mt-20 border-b border-slate-200 dark:border-slate-800">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-start">
              <div className="lg:col-span-4 space-y-2">
                <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
                  How routing works
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                  Backend requests queue over HTTPS while your enrolled Android handset handles carrier transmission.
                </p>
              </div>

              <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-8 border-t lg:border-t-0 pt-6 lg:pt-0 border-slate-200 dark:border-slate-800">
                <div className="space-y-1.5">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">Scoped Bearer Auth</h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Authenticate server requests using <code className="font-mono">sv_live_</code> or{' '}
                    <code className="font-mono">sv_test_</code> keys scoped to <code className="font-mono">sms:send</code>,{' '}
                    <code className="font-mono">otp:create</code>, and <code className="font-mono">otp:verify</code>.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">Atomic Job Leases</h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Paired devices poll over HTTPS, claim queued dispatches with short-lived lease tokens, and transmit over your chosen SIM slot.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">Carrier Receipt Lifecycle</h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    <code className="font-mono">sent_to_network</code> confirms radio handoff.{' '}
                    <code className="font-mono">delivered</code> updates only when an explicit SMS delivery receipt arrives.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">Signed Webhooks</h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Receive status callbacks verified with <code className="font-mono">X-SimVault-Signature</code>{' '}
                    HMAC-SHA256 digests on HTTPS endpoints.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Quickstart & Integration Setup */}
        <section id="quickstart" className="scroll-mt-20 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/30">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
              <div className="lg:col-span-5 space-y-6">
                <div>
                  <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
                    Integration Quickstart
                  </h2>
                  <p className="text-sm text-slate-600 dark:text-slate-300 mt-2 leading-relaxed">
                    Configure your backend to send SMS notices and verify one-time codes in three parts.
                  </p>
                </div>

                <ol className="space-y-5">
                  <li className="border-b border-slate-200 dark:border-slate-800 pb-4">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                      1. Pair a device and create an API key
                    </h3>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
                      Sign in to enroll your Android handset under <strong>Gateway Devices</strong> and generate an application key under{' '}
                      <strong>Integration → API Keys</strong>.
                    </p>
                  </li>
                  <li className="border-b border-slate-200 dark:border-slate-800 pb-4">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                      2. Set your private Base URL on the server
                    </h3>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
                      Copy your private root host (without <code className="font-mono">/v1</code>) from{' '}
                      <strong>API Docs</strong> after sign-in and store <code className="font-mono">SIMVAULT_BASE_URL</code> and{' '}
                      <code className="font-mono">SIMVAULT_API_KEY</code> in backend environment variables only.
                    </p>
                  </li>
                  <li>
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                      3. Send E.164 phone numbers
                    </h3>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
                      Format recipients in E.164 (such as <code className="font-mono">+919876543210</code>) and include an{' '}
                      <code className="font-mono">Idempotency-Key</code> header when retrying requests.
                    </p>
                  </li>
                </ol>
              </div>

              <div className="lg:col-span-7">
                <div className="bg-slate-900 dark:bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-slate-800">
                    <div className="flex items-center gap-1" role="tablist" aria-label="Quickstart code language">
                      {LANGUAGE_TABS.map((tab) => {
                        const active = selectedLang === tab.id;
                        return (
                          <button
                            key={tab.id}
                            type="button"
                            role="tab"
                            aria-selected={active}
                            onClick={() => setSelectedLang(tab.id)}
                            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
                              active
                                ? 'bg-blue-600 text-white'
                                : 'text-slate-300 hover:text-white hover:bg-slate-800'
                            }`}
                          >
                            {tab.label}
                          </button>
                        );
                      })}
                    </div>

                    <button
                      type="button"
                      onClick={() => handleCopy('quickstart', quickstartCode)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white rounded hover:bg-slate-800 whitespace-nowrap transition-colors"
                    >
                      {copiedId === 'quickstart' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>

                  <pre className="p-5 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                    {quickstartCode}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Interactive Public Endpoint Explorer */}
        <section id="endpoints" className="scroll-mt-20 border-b border-slate-200 dark:border-slate-800">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14 space-y-8">
            <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
              <div>
                <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
                  REST API Endpoint Reference
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 mt-1.5">
                  Select any endpoint to inspect required Bearer scopes, headers, and exact JSON request/response contracts.
                </p>
              </div>
              <a
                href="/v1/openapi.json"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline whitespace-nowrap shrink-0"
              >
                View raw /v1/openapi.json
                <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
              </a>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* Endpoint Selector List */}
              <div className="lg:col-span-4 space-y-1.5" role="tablist" aria-label="API endpoints">
                {PUBLIC_ENDPOINTS.map((ep) => {
                  const active = ep.id === activeEndpoint.id;
                  return (
                    <button
                      key={ep.id}
                      type="button"
                      role="tab"
                      aria-selected={active}
                      onClick={() => setSelectedEndpointId(ep.id)}
                      className={`w-full text-left px-4 py-3 rounded-lg border transition-colors ${
                        active
                          ? 'bg-slate-900 dark:bg-blue-600 border-slate-900 dark:border-blue-600 text-white'
                          : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-semibold truncate">
                          {ep.method} {ep.path}
                        </span>
                        <span
                          className={`font-mono text-[11px] shrink-0 ${
                            active ? 'text-slate-200' : 'text-slate-500 dark:text-slate-400'
                          }`}
                        >
                          {ep.scope}
                        </span>
                      </div>
                      <div
                        className={`text-xs mt-1 ${
                          active ? 'text-slate-200' : 'text-slate-500 dark:text-slate-400'
                        }`}
                      >
                        {ep.title}
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Endpoint Details Panel */}
              <div className="lg:col-span-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 space-y-6">
                <div className="border-b border-slate-200 dark:border-slate-800 pb-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-mono text-base font-bold text-slate-900 dark:text-slate-50">
                      {activeEndpoint.method} {activeEndpoint.path}
                    </h3>
                    <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                      Scope: {activeEndpoint.scope}
                    </span>
                  </div>
                  <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                    {activeEndpoint.summary}
                  </p>
                </div>

                {/* Headers Table */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    Request Headers
                  </h4>
                  <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                          <th className="py-2 px-3">Header</th>
                          <th className="py-2 px-3">Required</th>
                          <th className="py-2 px-3">Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                        {activeEndpoint.headers.map((h) => (
                          <tr key={h.name}>
                            <td className="py-2 px-3 font-mono text-slate-900 dark:text-slate-100 whitespace-nowrap">
                              {h.name}
                            </td>
                            <td className="py-2 px-3 text-slate-600 dark:text-slate-300">
                              {h.required ? 'Yes' : 'Optional'}
                            </td>
                            <td className="py-2 px-3 text-slate-600 dark:text-slate-300">{h.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Request & Response JSON */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {activeEndpoint.requestExample ? (
                    <div className="bg-slate-900 dark:bg-slate-950 border border-slate-800 rounded-lg overflow-hidden flex flex-col">
                      <div className="px-3.5 py-2 border-b border-slate-800 flex items-center justify-between">
                        <span className="text-[11px] font-medium text-slate-300">Request JSON</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(`req-${activeEndpoint.id}`, activeEndpoint.requestExample!)}
                          className="text-[11px] text-slate-300 hover:text-white"
                        >
                          {copiedId === `req-${activeEndpoint.id}` ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <pre className="p-3.5 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                        {activeEndpoint.requestExample}
                      </pre>
                    </div>
                  ) : (
                    <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-4 flex items-center text-xs text-slate-600 dark:text-slate-400">
                      This GET endpoint takes no JSON request body. Pass your Bearer API key in the Authorization header.
                    </div>
                  )}

                  <div className="bg-slate-900 dark:bg-slate-950 border border-slate-800 rounded-lg overflow-hidden flex flex-col">
                    <div className="px-3.5 py-2 border-b border-slate-800 flex items-center justify-between gap-2">
                      <span className="text-[11px] font-medium text-slate-300 truncate">
                        {activeEndpoint.responseStatus}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(`res-${activeEndpoint.id}`, activeEndpoint.responseExample)}
                        className="text-[11px] text-slate-300 hover:text-white shrink-0"
                      >
                        {copiedId === `res-${activeEndpoint.id}` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <pre className="p-3.5 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                      {activeEndpoint.responseExample}
                    </pre>
                  </div>
                </div>

                {/* Operational Notes */}
                <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-300 list-disc pl-4">
                  {activeEndpoint.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Standard Error Reference */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                  Standard API Error Codes
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                      <th className="py-2.5 px-4">HTTP</th>
                      <th className="py-2.5 px-4">Error Code</th>
                      <th className="py-2.5 px-4">Meaning</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {ERROR_CODES.map((err) => (
                      <tr key={err.code}>
                        <td className="py-2.5 px-4 font-mono tabular-nums text-slate-900 dark:text-slate-100">
                          {err.status}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-slate-800 dark:text-slate-200">{err.code}</td>
                        <td className="py-2.5 px-4 text-slate-600 dark:text-slate-300">{err.meaning}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Next.js / Backend Proxy Safe Upstream Error Handling */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                    Next.js Backend — Safe Upstream Error Inspection (Avoiding Generic 502s)
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
                    Read the private root host (without <code className="font-mono">/v1</code>) from Owner Console → Integration → API Docs, parse{' '}
                    <code className="font-mono">error.code</code> &amp; <code className="font-mono">error.request_id</code> safely, and never log API keys.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy('nextjs-safe', buildNextJsSafeOtpSnippet(PUBLIC_PLACEHOLDER_BASE_URL))}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:underline self-start sm:self-auto"
                >
                  {copiedId === 'nextjs-safe' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-500" aria-hidden="true" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Copy Snippet</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-5 bg-slate-900 dark:bg-slate-950 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                {buildNextJsSafeOtpSnippet(PUBLIC_PLACEHOLDER_BASE_URL)}
              </pre>
            </div>
          </div>
        </section>

        {/* Webhook Signature Verification Section */}
        <section id="webhooks" className="scroll-mt-20 bg-white dark:bg-slate-900/30">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
              <div className="lg:col-span-5 space-y-4">
                <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
                  Webhook Signature Verification
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                  Every outbound webhook request is signed with an HMAC-SHA256 digest of{' '}
                  <code className="font-mono text-xs">timestamp.eventId.rawBody</code> so your endpoint can reject forged or replayed payloads.
                </p>
                <dl className="space-y-2.5 text-xs pt-2 border-t border-slate-200 dark:border-slate-800">
                  <div>
                    <dt className="font-mono font-semibold text-slate-900 dark:text-slate-100">X-SimVault-Event-Id</dt>
                    <dd className="text-slate-600 dark:text-slate-300 mt-0.5">Unique delivery event identifier for idempotent processing.</dd>
                  </div>
                  <div>
                    <dt className="font-mono font-semibold text-slate-900 dark:text-slate-100">X-SimVault-Timestamp</dt>
                    <dd className="text-slate-600 dark:text-slate-300 mt-0.5">Unix epoch seconds; reject requests older than 300 seconds.</dd>
                  </div>
                  <div>
                    <dt className="font-mono font-semibold text-slate-900 dark:text-slate-100">X-SimVault-Signature</dt>
                    <dd className="text-slate-600 dark:text-slate-300 mt-0.5">Hex digest formatted as <code className="font-mono">v1=&lt;hex&gt;</code>.</dd>
                  </div>
                </dl>
              </div>

              <div className="lg:col-span-7 bg-slate-900 dark:bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-300">Node.js — Verify X-SimVault-Signature</span>
                  <button
                    type="button"
                    onClick={() => handleCopy('webhook', WEBHOOK_VERIFY_SNIPPET)}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-300 hover:text-white"
                  >
                    {copiedId === 'webhook' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-5 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                  {WEBHOOK_VERIFY_SNIPPET}
                </pre>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500 dark:text-slate-400">
          <div>
            <span className="font-display font-semibold text-slate-900 dark:text-slate-100">SimVault</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span>&copy; 2026</span>
          </div>
          <div className="flex flex-wrap items-center gap-5">
            <a href="#quickstart" className="hover:text-slate-900 dark:hover:text-white">
              Quickstart
            </a>
            <a href="#endpoints" className="hover:text-slate-900 dark:hover:text-white">
              Endpoints
            </a>
            <a href="#webhooks" className="hover:text-slate-900 dark:hover:text-white">
              Webhooks
            </a>
            <a href="/v1/openapi.json" target="_blank" rel="noreferrer" className="hover:text-slate-900 dark:hover:text-white">
              OpenAPI
            </a>
            <button
              type="button"
              onClick={focusOwnerLogin}
              className="font-medium text-slate-700 dark:text-slate-200 hover:underline"
            >
              Sign In
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
