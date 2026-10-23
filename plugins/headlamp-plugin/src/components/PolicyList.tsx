// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Lists every KubeArmor policy (namespaced, host and cluster) in one table so
// operators can see enforcement coverage without leaving Headlamp.

import { SectionBox, SimpleTable } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box, Link as MuiLink } from '@mui/material';
import { KubeArmorPolicyRow, useKubeArmorPolicies } from '../hooks/useKubeArmorPolicies';
import { getPolicyAction, getPolicySelectorText, getPolicySpec } from '../model';
import { PolicyKind } from '../types';
import { ActionBadge, SeverityBadge } from './StatusBadge';

function kindToShort(kind: PolicyKind): string {
  switch (kind) {
    case 'KubeArmorPolicy':
      return 'KSP';
    case 'KubeArmorHostPolicy':
      return 'HSP';
    case 'KubeArmorClusterPolicy':
      return 'CSP';
    default: {
      const _exhaustive: never = kind;
      return _exhaustive;
    }
  }
}

export function PolicyList() {
  const { rows, loading, errors } = useKubeArmorPolicies();

  return (
    <SectionBox title="KubeArmor Policies" backLink>
      {errors.length > 0 && (
        <Box sx={{ color: 'error.main', mb: 1 }}>
          Failed to load some policies. Confirm the <code>security.kubearmor.com</code> CRDs are
          installed and that you have permission to list them.
        </Box>
      )}
      <SimpleTable
        emptyMessage={loading ? 'Loading policies…' : 'No KubeArmor policies found.'}
        columns={[
          {
            label: 'Name',
            getter: (r: KubeArmorPolicyRow) => r.name,
            sort: (a: KubeArmorPolicyRow, b: KubeArmorPolicyRow) => a.name.localeCompare(b.name),
          },
          { label: 'Kind', getter: (r: KubeArmorPolicyRow) => kindToShort(r.kind) },
          {
            label: 'Scope',
            getter: (r: KubeArmorPolicyRow) => r.namespace ?? 'cluster-wide',
          },
          {
            label: 'Action',
            getter: (r: KubeArmorPolicyRow) => <ActionBadge action={getPolicyAction(r.obj)} />,
          },
          {
            label: 'Severity',
            getter: (r: KubeArmorPolicyRow) => (
              <SeverityBadge severity={getPolicySpec(r.obj).severity} />
            ),
          },
          {
            label: 'Selector',
            getter: (r: KubeArmorPolicyRow) => getPolicySelectorText(r.obj),
          },
          {
            label: 'Created',
            getter: (r: KubeArmorPolicyRow) =>
              r.obj.metadata?.creationTimestamp
                ? new Date(r.obj.metadata.creationTimestamp).toLocaleString()
                : '—',
          },
        ]}
        data={rows}
      />
      <Box sx={{ mt: 2, fontSize: '0.85rem', color: 'text.secondary' }}>
        Learn more in the{' '}
        <MuiLink
          href="https://docs.kubearmor.io/kubearmor/documentation/security_policy_specification"
          target="_blank"
          rel="noopener"
        >
          KubeArmor policy specification
        </MuiLink>
        .
      </Box>
    </SectionBox>
  );
}
