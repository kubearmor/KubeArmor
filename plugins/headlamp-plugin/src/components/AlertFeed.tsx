// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Live feed of KubeArmor security alerts (blocked / audited process, file and
// network operations) streamed from the kubearmor-relay pod's stdout.

import { SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box, Typography } from '@mui/material';
import { useRelayAlerts, useRelayStatus } from '../api/relayStream';
import { formatRelayTime } from '../utils/time';
import { RelayStatusHint } from './RelayStatusHint';
import { ActionBadge, SeverityBadge } from './StatusBadge';

export function AlertFeed() {
  const alerts = useRelayAlerts();
  const { podFound, error } = useRelayStatus();

  return (
    <SectionBox title="KubeArmor Security Alerts" backLink>
      <RelayStatusHint
        podFound={podFound}
        error={error}
        received={alerts.length > 0}
        kind="alerts"
      />
      <Box sx={{ maxHeight: '70vh', overflowY: 'auto' }}>
        {alerts.map((alert, i) => (
          <Box
            key={`${alert.Timestamp ?? ''}-${alert.PolicyName ?? ''}-${i}`}
            sx={{
              p: 1.5,
              mb: 1,
              borderLeft: 4,
              borderColor: alert.Action === 'Block' ? 'error.main' : 'warning.main',
              bgcolor: 'background.paper',
              borderRadius: 1,
              boxShadow: 1,
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <ActionBadge action={alert.Action} />
                <Typography component="span" sx={{ fontWeight: 600 }}>
                  {alert.Operation ?? 'Event'}
                </Typography>
                <SeverityBadge severity={alert.Severity} />
              </Box>
              <Typography variant="caption" color="text.secondary">
                {formatRelayTime(alert)}
              </Typography>
            </Box>
            <Typography variant="body2">
              Pod <code>{alert.PodName ?? '—'}</code> · Namespace{' '}
              <code>{alert.NamespaceName ?? '—'}</code>
              {alert.ContainerName ? (
                <>
                  {' '}
                  · Container <code>{alert.ContainerName}</code>
                </>
              ) : null}
            </Typography>
            {alert.Resource && (
              <Typography variant="body2">
                Resource: <code>{alert.Resource}</code>
              </Typography>
            )}
            <Typography variant="body2" color="text.secondary">
              Policy: <code>{alert.PolicyName ?? '—'}</code>
              {alert.Result ? ` · Result: ${alert.Result}` : ''}
            </Typography>
          </Box>
        ))}
      </Box>
    </SectionBox>
  );
}
