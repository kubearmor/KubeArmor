// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// TypeScript shapes for the KubeArmor data the plugin renders.
// Policy shapes mirror the `security.kubearmor.com/v1` CRDs; the alert and
// telemetry shapes mirror the JSON lines emitted on the kubearmor-relay pod's
// stdout when ENABLE_STDOUT_ALERTS / ENABLE_STDOUT_LOGS are enabled.

export type PolicyAction = 'Allow' | 'Audit' | 'Block';

/** A label/expression selector as used by KubeArmor policy specs. */
export interface KubeArmorSelector {
  matchLabels?: Record<string, string>;
  matchExpressions?: Array<{
    key?: string;
    operator?: string;
    values?: string[];
  }>;
}

/** Common spec fields shared across KSP/HSP/CSP for display purposes. */
export interface KubeArmorPolicySpec {
  selector?: KubeArmorSelector;
  nodeSelector?: KubeArmorSelector;
  action?: PolicyAction | '';
  severity?: number;
  tags?: string[];
  message?: string;
  [key: string]: unknown;
}

/** Logical kinds of KubeArmor policies the plugin lists. */
export type PolicyKind = 'KubeArmorPolicy' | 'KubeArmorHostPolicy' | 'KubeArmorClusterPolicy';

/**
 * A KubeArmor alert as emitted on kubearmor-relay stdout. Fields follow the
 * KubeArmor protobuf Alert message; not every field is always present.
 */
export interface KubeArmorAlert {
  Timestamp?: number;
  UpdatedTime?: string;
  ClusterName?: string;
  HostName?: string;
  NamespaceName?: string;
  PodName?: string;
  ContainerName?: string;
  ContainerImage?: string;
  Type?: string;
  PolicyName?: string;
  Severity?: string | number;
  Operation?: string;
  Source?: string;
  Resource?: string;
  Data?: string;
  Enforcer?: string;
  Action?: PolicyAction;
  Result?: string;
}

/**
 * A KubeArmor telemetry/system log event as emitted on kubearmor-relay stdout.
 */
export interface TelemetryEvent {
  Timestamp?: number;
  UpdatedTime?: string;
  ClusterName?: string;
  HostName?: string;
  NamespaceName?: string;
  PodName?: string;
  ContainerName?: string;
  Type?: string;
  Operation?: string;
  Source?: string;
  Resource?: string;
  Data?: string;
  Result?: string;
}
