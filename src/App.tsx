import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AppWindow,
  BookOpen,
  FileText,
  KeyRound,
  LayoutDashboard,
  Lock,
  Menu,
  MessageSquare,
  Monitor,
  Moon,
  PauseOctagon,
  ScrollText,
  Settings,
  ShieldCheck,
  Smartphone,
  Sun,
  Webhook,
  X,
} from 'lucide-react';
import { apiRequest, registerUnauthorizedHandler, setCsrfToken } from './lib/api';
import {
  THEME_STORAGE_KEY,
  type ThemeMode,
  getNextThemeMode,
  getThemeLabel,
  normalizeThemeMode,
  resolveIsDark,
} from './utils/theme';
import type { ApplicationRecord, NavSection, OverviewResponse } from './types';
import { OverviewView } from './components/OverviewView';
import { MessagesView } from './components/MessagesView';
import { OtpChallengesView } from './components/OtpChallengesView';
import { GatewayDevicesView } from './components/GatewayDevicesView';
import { SimUsageView } from './components/SimUsageView';
import { ApiKeysView, ApplicationsView } from './components/AppsAndKeysView';
import { TemplatesView, WebhooksView } from './components/TemplatesAndWebhooksView';
import { ApiDocsView } from './components/ApiDocsView';
import { AuditLogsView, SecurityView } from './components/SecurityAndAuditView';
import { SettingsAndInfraView } from './components/SettingsAndInfraView';
import { SendTestSmsModal } from './components/SendTestSmsModal';
import { PublicPortal } from './components/PublicPortal';

const NAV_GROUPS: Array<{
  heading: string;
  items: Array<{ id: NavSection; label: string; icon: typeof LayoutDashboard }>;
}> = [
  {
    heading: 'Operations',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard },
      { id: 'messages', label: 'Messages', icon: MessageSquare },
      { id: 'otp-challenges', label: 'OTP Challenges', icon: ShieldCheck },
    ],
  },
  {
    heading: 'Gateway & SIM',
    items: [
      { id: 'gateway-devices', label: 'Gateway Devices', icon: Smartphone },
      { id: 'sim-usage', label: 'SIM & Usage', icon: Activity },
    ],
  },
  {
    heading: 'Integration',
    items: [
      { id: 'applications', label: 'Applications', icon: AppWindow },
      { id: 'api-keys', label: 'API Keys', icon: KeyRound },
      { id: 'api-docs', label: 'API Docs', icon: BookOpen },
      { id: 'templates', label: 'Templates', icon: FileText },
      { id: 'webhooks', label: 'Webhooks', icon: Webhook },
    ],
  },
  {
    heading: 'Governance',
    items: [
      { id: 'security', label: 'Security & Limits', icon: Lock },
      { id: 'audit-logs', label: 'Audit Logs', icon: ScrollText },
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

const SECTION_TITLES: Record<NavSection, string> = {
  overview: 'Overview',
  applications: 'Applications',
  'api-keys': 'API Keys',
  'api-docs': 'API Documentation',
  messages: 'Messages',
  'otp-challenges': 'OTP Challenges',
  'gateway-devices': 'Gateway Devices',
  'sim-usage': 'SIM & Usage',
  templates: 'Templates',
  webhooks: 'Webhooks',
  security: 'Security & Rate Limits',
  'audit-logs': 'Audit Logs',
  settings: 'Settings',
};

export default function App() {
  const [section, setSection] = useState<NavSection>('overview');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [applications, setApplications] = useState<ApplicationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [sendModalOpen, setSendModalOpen] = useState(false);
  const [refreshSignal, setRefreshSignal] = useState(0);

  // Auth lock state (fail-closed until server confirms active session)
  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [ownerEmail, setOwnerEmail] = useState('');
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginTotp, setLoginTotp] = useState('');
  const [mfaPrompt, setMfaPrompt] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    try {
      return normalizeThemeMode(localStorage.getItem(THEME_STORAGE_KEY));
    } catch {
      return 'system';
    }
  });

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      const isDark = resolveIsDark(themeMode, media.matches);
      document.documentElement.classList.toggle('dark', isDark);
      document.documentElement.style.colorScheme = isDark ? 'dark' : 'light';
    };
    applyTheme();
    try {
      localStorage.setItem(THEME_STORAGE_KEY, themeMode);
    } catch {
      // Ignore storage failures in private browsing
    }
    media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [themeMode]);

  const cycleTheme = () => {
    setThemeMode((prev) => getNextThemeMode(prev));
  };

  const ThemeIcon = themeMode === 'dark' ? Moon : themeMode === 'light' ? Sun : Monitor;
  const themeLabel = getThemeLabel(themeMode);

  useEffect(() => {
    registerUnauthorizedHandler(() => {
      setAuthenticated(false);
      setAuthChecked(true);
      setOverview(null);
      setMfaPrompt(false);
    });
    return () => registerUnauthorizedHandler(null);
  }, []);

  const loadCoreData = useCallback(async () => {
    try {
      const sess = await apiRequest<{
        authenticated: boolean;
        user?: { email: string };
        csrf_token?: string | null;
      }>('/api/admin/auth/session');

      if (!sess.authenticated) {
        setAuthenticated(false);
        setCsrfToken(null);
        setAuthChecked(true);
        setLoading(false);
        return;
      }

      setAuthenticated(true);
      setCsrfToken(sess.csrf_token ?? null);
      if (sess.user?.email) setOwnerEmail(sess.user.email);

      const [ov, apps] = await Promise.all([
        apiRequest<OverviewResponse>('/api/admin/overview'),
        apiRequest<{ applications: ApplicationRecord[] }>('/api/admin/applications'),
      ]);
      setOverview(ov);
      setApplications(apps.applications);
      setLoginError(null);
      setAuthChecked(true);
    } catch (err) {
      if (err instanceof Error && err.message) {
        setLoginError(err.message);
      }
      setAuthChecked(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCoreData();
  }, [loadCoreData, refreshSignal]);

  // Gentle background refresh every 6s when authenticated
  useEffect(() => {
    if (!authenticated) return;
    const timer = setInterval(() => {
      void loadCoreData();
    }, 6000);
    return () => clearInterval(timer);
  }, [authenticated, loadCoreData]);

  const triggerRefresh = () => {
    setRefreshSignal((s) => s + 1);
  };

  const handleToggleGlobalPause = async () => {
    if (!overview) return;
    const next = !overview.global_paused;
    try {
      await apiRequest('/api/admin/settings', {
        method: 'PATCH',
        body: JSON.stringify({ global_paused: String(next) }),
      });
      triggerRefresh();
    } catch (err) {
      setActionFeedback(err instanceof Error ? err.message : 'Failed to toggle kill switch');
      setTimeout(() => setActionFeedback(null), 4000);
    }
  };

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    try {
      const res = await apiRequest<{
        authenticated: boolean;
        mfa_required?: boolean;
        csrf_token?: string;
        user?: { email: string };
      }>('/api/admin/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: loginEmail.trim(),
          password: loginPassword,
          totp_code: mfaPrompt ? loginTotp : undefined,
        }),
      });
      if (res.mfa_required) {
        setMfaPrompt(true);
        return;
      }
      if (res.authenticated) {
        setCsrfToken(res.csrf_token ?? null);
        setAuthenticated(true);
        setMfaPrompt(false);
        setLoginPassword('');
        setLoginTotp('');
        if (res.user?.email) setOwnerEmail(res.user.email);
        triggerRefresh();
      }
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : 'Sign-in failed');
    }
  };

  const handleLockWorkspace = async () => {
    try {
      await apiRequest('/api/admin/auth/logout', { method: 'POST' });
    } finally {
      setCsrfToken(null);
      setAuthenticated(false);
      setOverview(null);
      setMfaPrompt(false);
    }
  };

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center p-4">
        <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Verifying console session...</div>
      </div>
    );
  }

  if (!authenticated) {
    return (
      <PublicPortal
        loginEmail={loginEmail}
        onLoginEmailChange={setLoginEmail}
        loginPassword={loginPassword}
        onLoginPasswordChange={setLoginPassword}
        loginTotp={loginTotp}
        onLoginTotpChange={setLoginTotp}
        mfaPrompt={mfaPrompt}
        loginError={loginError}
        onLoginSubmit={handleLogin}
        themeMode={themeMode}
        themeLabel={themeLabel}
        onCycleTheme={cycleTheme}
      />
    );
  }

  const navigateTo = (next: NavSection) => {
    setSection(next);
    setMobileNavOpen(false);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-64 lg:fixed lg:inset-y-0 bg-white border-r border-slate-200">
        <div className="h-14 px-5 flex items-center border-b border-slate-200">
          <span className="font-display text-base font-bold tracking-tight text-slate-900 whitespace-nowrap">
            SimVault
          </span>
        </div>

        <nav aria-label="Primary navigation" className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
          {NAV_GROUPS.map((group) => (
            <div key={group.heading}>
              <div className="px-2.5 mb-1.5 text-[11px] font-semibold text-slate-400 tracking-wide">
                {group.heading}
              </div>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = section === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => navigateTo(item.id)}
                      className={`w-full flex items-center gap-2.5 px-2.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                        active
                          ? 'bg-slate-900 dark:bg-blue-600 text-white'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="p-4 border-t border-slate-200 text-xs">
          <div className="font-medium text-slate-900 truncate">{ownerEmail}</div>
          <div className="text-slate-500 mt-0.5">Owner · Self-Hosted</div>
        </div>
      </aside>

      {/* Mobile Navigation Drawer */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div className="fixed inset-0 bg-slate-950/40" onClick={() => setMobileNavOpen(false)} />
          <aside className="relative w-64 max-w-full bg-white h-full border-r border-slate-200 flex flex-col z-10">
            <div className="h-14 px-4 flex items-center justify-between border-b border-slate-200">
              <span className="font-display text-base font-bold text-slate-900">SimVault</span>
              <button
                type="button"
                aria-label="Close navigation menu"
                onClick={() => setMobileNavOpen(false)}
                className="p-1.5 text-slate-500 hover:text-slate-900"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <nav aria-label="Mobile navigation" className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
              {NAV_GROUPS.map((group) => (
                <div key={group.heading}>
                  <div className="px-2.5 mb-1.5 text-[11px] font-semibold text-slate-400">{group.heading}</div>
                  <div className="space-y-0.5">
                    {group.items.map((item) => {
                      const Icon = item.icon;
                      const active = section === item.id;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => navigateTo(item.id)}
                          className={`w-full flex items-center gap-2.5 px-2.5 py-2 text-xs font-medium rounded-md ${
                            active
                              ? 'bg-slate-900 dark:bg-blue-600 text-white'
                              : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                          }`}
                        >
                          <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                          <span>{item.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        {/* Top Bar Contract: Breadcrumb on left, concise primary controls on right */}
        <header className="h-14 bg-white border-b border-slate-200 px-4 sm:px-6 flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileNavOpen(true)}
              className="lg:hidden p-1.5 text-slate-600 hover:text-slate-900 rounded-md border border-slate-200"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-400 font-medium hidden sm:inline">SimVault</span>
              <span className="text-slate-300 hidden sm:inline" aria-hidden="true">/</span>
              <h1 className="font-display font-semibold text-slate-900 truncate">
                {SECTION_TITLES[section]}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <button
              type="button"
              onClick={cycleTheme}
              aria-label={`Switch color theme (current: ${themeLabel})`}
              title={`Theme: ${themeLabel} (click to cycle Auto / Dark / Light)`}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 transition-colors"
            >
              <ThemeIcon className="w-3.5 h-3.5" aria-hidden="true" />
              <span className="hidden md:inline">{themeLabel}</span>
            </button>
            {overview && (
              <button
                type="button"
                aria-label={overview.global_paused ? 'Resume global gateway traffic' : 'Activate global kill switch'}
                title={overview.global_paused ? 'Resume global gateway traffic' : 'Activate global kill switch'}
                onClick={() => void handleToggleGlobalPause()}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border whitespace-nowrap shrink-0 transition-colors ${
                  overview.global_paused
                    ? 'bg-rose-700 border-rose-700 text-white hover:bg-rose-800'
                    : 'bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                <PauseOctagon className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="hidden sm:inline">{overview.global_paused ? 'Gateway Paused' : 'Kill Switch'}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => setSendModalOpen(true)}
              className="px-3.5 py-1.5 text-xs font-medium bg-blue-700 dark:bg-blue-600 text-white rounded-md hover:bg-blue-800 dark:hover:bg-blue-500 whitespace-nowrap shrink-0 transition-colors"
            >
              Send SMS
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto">
          {actionFeedback && (
            <div className="mb-4 bg-slate-900 dark:bg-slate-800 border border-slate-800 dark:border-slate-700 text-white text-xs font-mono px-4 py-2.5 rounded-md">
              {actionFeedback}
            </div>
          )}

          {section === 'overview' && (
            <OverviewView
              data={overview}
              loading={loading}
              onNavigate={navigateTo}
              onOpenSendModal={() => setSendModalOpen(true)}
            />
          )}
          {section === 'applications' && <ApplicationsView applications={applications} onRefresh={triggerRefresh} />}
          {section === 'api-keys' && <ApiKeysView applications={applications} onRefresh={triggerRefresh} />}
          {section === 'api-docs' && <ApiDocsView applications={applications} />}
          {section === 'messages' && (
            <MessagesView
              applications={applications}
              onOpenSendModal={() => setSendModalOpen(true)}
              refreshSignal={refreshSignal}
            />
          )}
          {section === 'otp-challenges' && (
            <OtpChallengesView applications={applications} onDataChanged={triggerRefresh} />
          )}
          {section === 'gateway-devices' && <GatewayDevicesView onDataChanged={triggerRefresh} />}
          {section === 'sim-usage' && <SimUsageView onDataChanged={triggerRefresh} />}
          {section === 'templates' && <TemplatesView />}
          {section === 'webhooks' && <WebhooksView applications={applications} />}
          {section === 'security' && (
            <SecurityView
              applications={applications}
              settings={overview?.settings ?? {}}
              onSettingsUpdated={triggerRefresh}
              onLockWorkspace={handleLockWorkspace}
            />
          )}
          {section === 'audit-logs' && <AuditLogsView />}
          {section === 'settings' && (
            <SettingsAndInfraView settings={overview?.settings ?? {}} onUpdated={triggerRefresh} />
          )}
        </main>
      </div>

      <SendTestSmsModal
        open={sendModalOpen}
        onClose={() => setSendModalOpen(false)}
        applications={applications}
        onSent={triggerRefresh}
      />
    </div>
  );
}
