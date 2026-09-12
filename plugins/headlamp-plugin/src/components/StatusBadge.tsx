// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Small reusable colour-coded indicators for policy actions and alert severity.

import { Chip } from '@mui/material';
import { PolicyAction } from '../types';

const ACTION_COLORS: Record<string, string> = {
  Block: '#d32f2f', // red — enforced/blocked
  Audit: '#ed6c02', // orange — observed/audited
  Allow: '#2e7d32', // green — explicitly allowed
};

export function ActionBadge({ action }: { action?: PolicyAction }) {
  const label = action ?? 'Unset';
  const color = action ? ACTION_COLORS[action] ?? '#616161' : '#616161';
  return (
    <Chip
      size="small"
      label={label}
      sx={{ backgroundColor: color, color: '#fff', fontWeight: 600 }}
    />
  );
}

/** KubeArmor severity is 1 (low) .. 10 (high); colour by band. */
export function SeverityBadge({ severity }: { severity?: string | number }) {
  if (severity === undefined || severity === '' || severity === null) {
    return <span>—</span>;
  }
  const value = Number(severity);
  let color = '#616161';
  if (!Number.isNaN(value)) {
    if (value >= 7) {
      color = '#d32f2f';
    } else if (value >= 4) {
      color = '#ed6c02';
    } else {
      color = '#2e7d32';
    }
  }
  return (
    <Chip
      size="small"
      variant="outlined"
      label={String(severity)}
      sx={{ borderColor: color, color }}
    />
  );
}
