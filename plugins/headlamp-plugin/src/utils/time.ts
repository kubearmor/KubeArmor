// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

/** Formats relay stdout timestamps (unix seconds or ISO string). */
export function formatRelayTime(record: { Timestamp?: number; UpdatedTime?: string }): string {
  if (record.Timestamp) {
    return new Date(record.Timestamp * 1000).toLocaleTimeString();
  }
  if (record.UpdatedTime) {
    return new Date(record.UpdatedTime).toLocaleTimeString();
  }
  return '';
}
