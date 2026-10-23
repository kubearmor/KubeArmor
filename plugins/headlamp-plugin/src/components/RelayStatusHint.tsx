// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Explains the state of the kubearmor-relay stdout stream so empty alert /
// telemetry views are never silent: the relay pod may be missing, or stdout
// alerts/logs may simply not be enabled on the relay deployment yet.

import type { ApiError } from '@kinvolk/headlamp-plugin/lib/k8s/apiProxy';
import { Alert, AlertTitle, Box, Typography } from '@mui/material';

interface RelayStatusHintProps {
  podFound: boolean;
  error: ApiError | null;
  /** Whether at least one record of this kind has arrived. */
  received: boolean;
  kind: 'alerts' | 'telemetry';
}

const ENV_VAR = {
  alerts: 'ENABLE_STDOUT_ALERTS',
  telemetry: 'ENABLE_STDOUT_LOGS',
} as const;

export function RelayStatusHint({ podFound, error, received, kind }: RelayStatusHintProps) {
  if (error) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        <AlertTitle>Cannot reach the kubearmor-relay pod</AlertTitle>
        {error.message}
      </Alert>
    );
  }

  if (!podFound) {
    return (
      <Alert severity="warning" sx={{ mb: 2 }}>
        <AlertTitle>kubearmor-relay pod not found</AlertTitle>
        No pod labelled <code>kubearmor-app=kubearmor-relay</code> was found in the{' '}
        <code>kubearmor</code> namespace. Install KubeArmor (<code>karmor install</code>) and ensure
        the relay is running.
      </Alert>
    );
  }

  if (received) {
    return null;
  }

  return (
    <Alert severity="info" sx={{ mb: 2 }}>
      <AlertTitle>Listening for {kind}…</AlertTitle>
      <Typography variant="body2">
        Connected to the relay but no {kind} have arrived yet. If none appear, enable stdout
        streaming on the relay:
      </Typography>
      <Box
        component="pre"
        sx={{ mt: 1, p: 1, bgcolor: 'action.hover', borderRadius: 1, overflowX: 'auto' }}
      >
        kubectl set env deployment/kubearmor-relay -n kubearmor {ENV_VAR[kind]}=true
      </Box>
    </Alert>
  );
}
