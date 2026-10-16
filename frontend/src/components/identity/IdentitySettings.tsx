import { useState } from 'react';
import clsx from 'clsx';
import { useRoleGate } from '../../lib/roles';
import SSOConfigPanel from './SSOConfigPanel';
import SCIMPanel from './SCIMPanel';
import RolesEditor from './RolesEditor';

const PANELS = [
  { id: 'sso', name: 'Single sign-on' },
  { id: 'scim', name: 'SCIM provisioning' },
  { id: 'roles', name: 'Roles' },
] as const;

/**
 * Settings > Identity. Admin routes throughout (admin tier in `settings` for
 * SSO and SCIM, in `roles` for the roles editor). A custom-role holder's tiers
 * are not known to the client, so for them the panels load and render the
 * server's insufficient_tier answer instead of being hidden.
 */
export default function IdentitySettings() {
  const gate = useRoleGate();
  const [panel, setPanel] = useState<(typeof PANELS)[number]['id']>('sso');
  return (
    <div className="space-y-6">
      <div className="flex gap-2 border-b border-gray-200 dark:border-gray-700">
        {PANELS.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => setPanel(p.id)}
            className={clsx(
              'px-3 py-2 text-sm font-medium -mb-px border-b-2',
              panel === p.id
                ? 'border-blue-600 text-blue-700 dark:text-blue-300'
                : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200',
            )}
          >
            {p.name}
          </button>
        ))}
      </div>
      {gate.hasCustomRole && (
        <p className="text-xs text-gray-500">
          You hold a custom role: what you may change here is decided by its admin tier in Settings and Roles, and the
          server's answer is shown when it refuses. Trust settings, SCIM tokens and group mappings need the built-in
          admin role.
        </p>
      )}
      {panel === 'sso' && <SSOConfigPanel />}
      {panel === 'scim' && <SCIMPanel />}
      {panel === 'roles' && <RolesEditor />}
    </div>
  );
}
