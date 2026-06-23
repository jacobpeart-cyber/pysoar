import { Link, useLocation, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import {
  Shield,
  AlertTriangle,
  FileWarning,
  Users,
  LogOut,
  Menu,
  X,
  LayoutDashboard,
  Zap,
  Server,
  Wifi,
  WifiOff,
  Settings,
  FileText,
  BarChart3,
  Sun,
  Moon,
  User,
  Key,
  Building2,
  TrendingUp,
  Globe,
  Monitor,
  Search,
  ShieldAlert,
  Target,
  EyeOff,
  Wrench,
  ClipboardCheck,
  ShieldCheck,
  FileCheck,
  ScrollText,
  FileSearch,
  Fingerprint,
  Bug,
  Package,
  Eye,
  Plug,
  Bot,
  Workflow,
  ShieldOff,
  Calculator,
  Factory,
  Container,
  Lock,
  Map,
  Code,
  Database,
  MessageSquare,
  Mail,
  Ticket,
  Cpu,
  Terminal,
  Swords,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import clsx from 'clsx';
import { useWebSocket } from '../hooks/useWebSocket';
import NotificationToast from './NotificationToast';

// Navigation is grouped into collapsible sections so the sidebar reads as
// ~7 scannable categories instead of 40+ flat links. Every route stays
// reachable — nothing is removed, only organized. Related/overlapping pages
// (Playbooks + Playbook Builder, Analytics + Reports) sit adjacent within
// their group.
const navGroups = [
  {
    label: 'Core SOC',
    items: [
      { name: 'Dashboard', href: '/', icon: LayoutDashboard },
      { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
      { name: 'Incidents', href: '/incidents', icon: FileWarning },
      { name: 'War Room', href: '/warroom', icon: MessageSquare },
      { name: 'Ticket Hub', href: '/ticket-hub', icon: Ticket },
      { name: 'Agentic SOC', href: '/agentic', icon: Bot },
    ],
  },
  {
    label: 'Detect & Hunt',
    items: [
      { name: 'SIEM', href: '/siem', icon: Monitor },
      { name: 'Threat Intel', href: '/threat-intel', icon: Globe },
      { name: 'Threat Hunting', href: '/hunting', icon: Search },
      { name: 'UEBA', href: '/ueba', icon: Users },
      { name: 'Dark Web', href: '/darkweb', icon: Eye },
    ],
  },
  {
    label: 'Respond',
    items: [
      { name: 'Remediation', href: '/remediation', icon: Wrench },
      { name: 'Playbooks', href: '/playbooks', icon: Zap },
      { name: 'Playbook Builder', href: '/playbook-builder', icon: Workflow },
      { name: 'DFIR', href: '/dfir', icon: FileSearch },
      { name: 'Live Response', href: '/live-response', icon: Terminal },
      { name: 'Endpoint Agents', href: '/agents', icon: Cpu },
    ],
  },
  {
    label: 'Exposure & Risk',
    items: [
      { name: 'Vuln Mgmt', href: '/vulnmgmt', icon: Bug },
      { name: 'Exposure Mgmt', href: '/exposure', icon: ShieldAlert },
      { name: 'Threat Model', href: '/threat-modeling', icon: Map },
      { name: 'Risk (FAIR)', href: '/risk', icon: Calculator },
      { name: 'Supply Chain', href: '/supplychain', icon: Package },
    ],
  },
  {
    label: 'Validate',
    items: [
      { name: 'Attack Sim', href: '/simulation', icon: Target },
      { name: 'Purple Team', href: '/purple-team', icon: Swords },
      { name: 'Phishing Sim', href: '/phishing', icon: Mail },
      { name: 'Deception', href: '/deception', icon: EyeOff },
    ],
  },
  {
    label: 'Govern',
    items: [
      { name: 'Compliance', href: '/compliance', icon: ClipboardCheck },
      { name: 'STIG/SCAP', href: '/stig', icon: FileCheck },
      { name: 'FedRAMP', href: '/fedramp', icon: Shield },
      { name: 'Zero Trust', href: '/zerotrust', icon: ShieldCheck },
      { name: 'Audit Evidence', href: '/audit-evidence', icon: ScrollText },
      { name: 'Privacy', href: '/privacy', icon: Lock },
    ],
  },
  {
    label: 'Platform',
    items: [
      { name: 'Assets', href: '/assets', icon: Server },
      { name: 'Integrations', href: '/integrations', icon: Plug },
      { name: 'Data Lake', href: '/data-lake', icon: Database },
      { name: 'OT/ICS', href: '/ot-security', icon: Factory },
      { name: 'Container Sec', href: '/container-security', icon: Container },
      { name: 'API Security', href: '/api-security', icon: Code },
      { name: 'DLP', href: '/dlp', icon: ShieldOff },
      { name: 'ITDR', href: '/itdr', icon: Fingerprint },
      { name: 'Analytics', href: '/analytics', icon: TrendingUp },
      { name: 'Reports', href: '/reports', icon: BarChart3 },
    ],
  },
];

const adminNavigation = [
  { name: 'Users', href: '/users', icon: Users },
  { name: 'Organizations', href: '/organizations', icon: Building2 },
  { name: 'API Keys', href: '/api-keys', icon: Key },
  { name: 'Audit Logs', href: '/audit', icon: FileText },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const { resolvedTheme, setTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { isConnected } = useWebSocket();
  const [apiLive, setApiLive] = useState(true);

  // Which nav groups are expanded. Default: only the group holding the
  // current route (Core SOC included), so the sidebar opens compact.
  const groupForPath = (path: string) =>
    navGroups.find((g) =>
      g.items.some(
        (it) => it.href === path || (it.href !== '/' && path.startsWith(it.href))
      )
    )?.label;

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(() => {
    const initial = new Set<string>(['Core SOC']);
    const active = groupForPath(location.pathname);
    if (active) initial.add(active);
    return initial;
  });

  // Keep the active route's group open as the user navigates.
  useEffect(() => {
    const active = groupForPath(location.pathname);
    if (active) {
      setExpandedGroups((prev) =>
        prev.has(active) ? prev : new Set(prev).add(active)
      );
    }
  }, [location.pathname]);

  const toggleGroup = (label: string) =>
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      next.has(label) ? next.delete(label) : next.add(label);
      return next;
    });

  // Poll API health every 30 seconds
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch('/api/v1/health/live');
        setApiLive(res.ok);
      } catch {
        setApiLive(false);
      }
    };
    check();
    const interval = setInterval(check, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const toggleTheme = () => {
    setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
  };

  const isAdmin = user?.role === 'admin' || user?.is_superuser;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-gray-600 bg-opacity-75 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div
        className={clsx(
          'fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 dark:bg-gray-950 transform transition-transform duration-300 ease-in-out lg:translate-x-0 flex flex-col',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="flex items-center justify-between h-16 px-4 bg-gray-800 dark:bg-gray-900">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-blue-500" />
            <span className="text-xl font-bold text-white">PySOAR</span>
          </Link>
          <button
            className="lg:hidden text-gray-400 hover:text-white"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto mt-6 px-3 space-y-1 pb-4">
          {navGroups.map((group) => {
            const isExpanded = expandedGroups.has(group.label);
            const groupHasActive = group.items.some(
              (it) =>
                location.pathname === it.href ||
                (it.href !== '/' && location.pathname.startsWith(it.href))
            );
            return (
              <div key={group.label} className="mb-1">
                <button
                  onClick={() => toggleGroup(group.label)}
                  className="w-full flex items-center justify-between px-3 py-1.5 text-xs font-semibold text-gray-400 uppercase tracking-wider hover:text-gray-200 transition-colors"
                >
                  <span className={clsx(groupHasActive && !isExpanded && 'text-blue-400')}>
                    {group.label}
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4" />
                  ) : (
                    <ChevronRight className="w-4 h-4" />
                  )}
                </button>
                {isExpanded && (
                  <div className="space-y-1 mt-1">
                    {group.items.map((item) => {
                      const isActive =
                        location.pathname === item.href ||
                        (item.href !== '/' && location.pathname.startsWith(item.href));
                      return (
                        <Link
                          key={item.name}
                          to={item.href}
                          className={clsx(
                            'flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                            isActive
                              ? 'bg-gray-800 text-white'
                              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                          )}
                          onClick={() => setSidebarOpen(false)}
                        >
                          <item.icon className="w-5 h-5 mr-3" />
                          {item.name}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {isAdmin && (
            <>
              <p className="px-3 text-xs font-semibold text-gray-400 uppercase tracking-wider mt-6 mb-2">
                Administration
              </p>
              {adminNavigation.map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    className={clsx(
                      'flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-gray-800 text-white'
                        : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                    )}
                    onClick={() => setSidebarOpen(false)}
                  >
                    <item.icon className="w-5 h-5 mr-3" />
                    {item.name}
                  </Link>
                );
              })}
            </>
          )}
        </nav>

        <div className="flex-shrink-0 p-4 border-t border-gray-800">
          <Link
            to="/profile"
            className="flex items-center p-2 rounded-lg hover:bg-gray-800 transition-colors"
          >
            <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-medium">
              {user?.full_name?.[0] || user?.email?.[0]?.toUpperCase() || 'U'}
            </div>
            <div className="ml-3 flex-1">
              <p className="text-sm font-medium text-white truncate max-w-[120px]">
                {user?.full_name || user?.email}
              </p>
              <p className="text-xs text-gray-400 capitalize">{user?.role}</p>
            </div>
          </Link>
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-800">
            <button
              onClick={toggleTheme}
              className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800"
              title={resolvedTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {resolvedTheme === 'dark' ? (
                <Sun className="w-5 h-5" />
              ) : (
                <Moon className="w-5 h-5" />
              )}
            </button>
            <button
              onClick={handleLogout}
              className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <header className="sticky top-0 z-30 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between h-16 px-4">
            <button
              className="lg:hidden text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="w-6 h-6" />
            </button>
            <div className="flex-1" />
            <div className="flex items-center space-x-4">
              <div
                className={clsx(
                  'flex items-center gap-1 px-2 py-1 rounded-full text-xs',
                  apiLive
                    ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                    : 'bg-red-100 text-red-500 dark:bg-red-900 dark:text-red-400'
                )}
                title={apiLive ? 'Platform is live' : 'API unreachable'}
              >
                {apiLive ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                <span>{apiLive ? 'Live' : 'Offline'}</span>
              </div>
              <span className="text-sm text-gray-500 dark:text-gray-400">
                {new Date().toLocaleDateString('en-US', {
                  weekday: 'long',
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                })}
              </span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="p-6">
          <Outlet />
        </main>
      </div>

      {/* Real-time notifications */}
      <NotificationToast />
    </div>
  );
}
