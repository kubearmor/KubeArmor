// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// At-a-glance summary of KubeArmor's footprint in the cluster: how many
// policies exist, how they break down by enforcement action, and whether the
// relay (the source of live alerts) is reachable.

import { SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box, Paper, Typography } from '@mui/material';
import { useRelayStatus } from '../api/relayStream';
import { useKubeArmorPolicies } from '../hooks/useKubeArmorPolicies';
import { getPolicyAction } from '../model';
import { PolicyAction } from '../types';

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number | string;
  color?: string;
}) {
  return (
    <Paper elevation={1} sx={{ p: 2, minWidth: 140, textAlign: 'center', flex: '1 1 140px' }}>
      <Typography variant="h4" sx={{ fontWeight: 700, color }}>
        {value}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
    </Paper>
  );
}

function countByAction(
  items: ReturnType<typeof useKubeArmorPolicies>['all'],
  action: PolicyAction
): number {
  return items.filter(p => getPolicyAction(p) === action).length;
}

export function Overview() {
  const { ksp, hsp, csp, all } = useKubeArmorPolicies();
  const { podFound } = useRelayStatus();

  const total = all.length;
  const blocked = countByAction(all, 'Block');
  const audited = countByAction(all, 'Audit');
  const allowed = countByAction(all, 'Allow');

  const relayState = podFound
    ? { label: 'Relay: running', color: 'success.main' }
    : { label: 'Relay: not running', color: 'error.main' };

  return (
    <SectionBox title="KubeArmor Overview" backLink>
      <Typography variant="h6" sx={{ mb: 1 }}>
        Policies
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <StatCard label="Total policies" value={total} />
        <StatCard label="Block" value={blocked} color="error.main" />
        <StatCard label="Audit" value={audited} color="warning.main" />
        <StatCard label="Allow" value={allowed} color="success.main" />
      </Box>

      <Typography variant="h6" sx={{ mb: 1 }}>
        Policy types
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <StatCard label="Namespaced (KSP)" value={(ksp ?? []).length} />
        <StatCard label="Host (HSP)" value={(hsp ?? []).length} />
        <StatCard label="Cluster (CSP)" value={(csp ?? []).length} />
      </Box>

      <Typography variant="h6" sx={{ mb: 1 }}>
        Telemetry source
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
        <StatCard label={relayState.label} value={podFound ? 1 : 0} color={relayState.color} />
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
        Live alerts and telemetry stream from the kubearmor-relay pod. See the Alerts and Telemetry
        pages for the live feeds.
      </Typography>
    </SectionBox>
  );
}
