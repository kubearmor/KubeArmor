// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

import { KubeArmorAlert, PolicyAction, TelemetryEvent } from '../types';

type RelayRecord = Record<string, unknown>;

export type ClassifyResult =
  | { kind: 'skip' }
  | { kind: 'alert'; alert: KubeArmorAlert }
  | { kind: 'telemetry'; event: TelemetryEvent };

const POLICY_ACTIONS: PolicyAction[] = ['Allow', 'Audit', 'Block'];

function isPolicyAction(value: unknown): value is PolicyAction {
  return typeof value === 'string' && POLICY_ACTIONS.includes(value as PolicyAction);
}

function looksLikeTelemetry(record: RelayRecord): boolean {
  return typeof record.Operation === 'string' && record.Operation.length > 0;
}

/**
 * Alerts carry a policy name, a Block|Audit action, or a Matched* type.
 * Everything else with an Operation is telemetry.
 */
function looksLikeAlert(record: RelayRecord): boolean {
  const type = String(record.Type ?? '');
  const action = record.Action;
  return (
    Boolean(record.PolicyName) ||
    type.startsWith('Matched') ||
    action === 'Block' ||
    action === 'Audit'
  );
}

function toKubeArmorAlert(record: RelayRecord): KubeArmorAlert {
  return {
    Timestamp: typeof record.Timestamp === 'number' ? record.Timestamp : undefined,
    UpdatedTime: typeof record.UpdatedTime === 'string' ? record.UpdatedTime : undefined,
    ClusterName: typeof record.ClusterName === 'string' ? record.ClusterName : undefined,
    HostName: typeof record.HostName === 'string' ? record.HostName : undefined,
    NamespaceName: typeof record.NamespaceName === 'string' ? record.NamespaceName : undefined,
    PodName: typeof record.PodName === 'string' ? record.PodName : undefined,
    ContainerName: typeof record.ContainerName === 'string' ? record.ContainerName : undefined,
    ContainerImage: typeof record.ContainerImage === 'string' ? record.ContainerImage : undefined,
    Type: typeof record.Type === 'string' ? record.Type : undefined,
    PolicyName: typeof record.PolicyName === 'string' ? record.PolicyName : undefined,
    Severity:
      typeof record.Severity === 'string' || typeof record.Severity === 'number'
        ? record.Severity
        : undefined,
    Operation: typeof record.Operation === 'string' ? record.Operation : undefined,
    Source: typeof record.Source === 'string' ? record.Source : undefined,
    Resource: typeof record.Resource === 'string' ? record.Resource : undefined,
    Data: typeof record.Data === 'string' ? record.Data : undefined,
    Enforcer: typeof record.Enforcer === 'string' ? record.Enforcer : undefined,
    Action: isPolicyAction(record.Action) ? record.Action : undefined,
    Result: typeof record.Result === 'string' ? record.Result : undefined,
  };
}

function toTelemetryEvent(record: RelayRecord): TelemetryEvent {
  return {
    Timestamp: typeof record.Timestamp === 'number' ? record.Timestamp : undefined,
    UpdatedTime: typeof record.UpdatedTime === 'string' ? record.UpdatedTime : undefined,
    ClusterName: typeof record.ClusterName === 'string' ? record.ClusterName : undefined,
    HostName: typeof record.HostName === 'string' ? record.HostName : undefined,
    NamespaceName: typeof record.NamespaceName === 'string' ? record.NamespaceName : undefined,
    PodName: typeof record.PodName === 'string' ? record.PodName : undefined,
    ContainerName: typeof record.ContainerName === 'string' ? record.ContainerName : undefined,
    Type: typeof record.Type === 'string' ? record.Type : undefined,
    Operation: typeof record.Operation === 'string' ? record.Operation : undefined,
    Source: typeof record.Source === 'string' ? record.Source : undefined,
    Resource: typeof record.Resource === 'string' ? record.Resource : undefined,
    Data: typeof record.Data === 'string' ? record.Data : undefined,
    Result: typeof record.Result === 'string' ? record.Result : undefined,
  };
}

/** Classifies one JSON line from kubearmor-relay stdout. Non-JSON lines are skipped. */
export function classifyRelayLine(line: string): ClassifyResult {
  let record: RelayRecord;
  try {
    record = JSON.parse(line) as RelayRecord;
  } catch {
    return { kind: 'skip' };
  }
  if (!record || typeof record !== 'object') {
    return { kind: 'skip' };
  }

  if (looksLikeAlert(record)) {
    return { kind: 'alert', alert: toKubeArmorAlert(record) };
  }
  if (looksLikeTelemetry(record)) {
    return { kind: 'telemetry', event: toTelemetryEvent(record) };
  }
  return { kind: 'skip' };
}
