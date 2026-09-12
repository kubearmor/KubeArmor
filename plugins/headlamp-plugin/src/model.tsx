// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Custom-resource classes for the KubeArmor security CRDs. Using
// makeCustomResourceClass + the generated `.useList()` hook means every query
// goes through Headlamp's authenticated client, so the views are RBAC-aware:
// a user only sees the policies their kubeconfig/token is allowed to read.

import { makeCustomResourceClass } from '@kinvolk/headlamp-plugin/lib/k8s/crd';
import { KubeArmorPolicySpec, PolicyAction, PolicyKind } from './types';

export const KUBEARMOR_GROUP = 'security.kubearmor.com';
export const KUBEARMOR_VERSION = 'v1';

/** Namespace KubeArmor components (incl. the relay) are deployed into. */
export const KUBEARMOR_NAMESPACE = 'kubearmor';

/** Label selector for the kubearmor-relay deployment pod. */
export const RELAY_LABEL_SELECTOR = 'kubearmor-app=kubearmor-relay';

/** Primary relay container name; falls back to containers[0] if absent. */
export const RELAY_CONTAINER_NAME = 'kubearmor-relay-server';

/** Namespaced policies that apply to selected pods/containers. */
export const KubeArmorPolicy = makeCustomResourceClass({
  apiInfo: [{ group: KUBEARMOR_GROUP, version: KUBEARMOR_VERSION }],
  isNamespaced: true,
  singularName: 'kubearmorpolicy',
  pluralName: 'kubearmorpolicies',
  kind: 'KubeArmorPolicy',
});

/** Policies that apply to nodes/hosts. Stored in the kubearmor namespace. */
export const KubeArmorHostPolicy = makeCustomResourceClass({
  apiInfo: [{ group: KUBEARMOR_GROUP, version: KUBEARMOR_VERSION }],
  isNamespaced: true,
  singularName: 'kubearmorhostpolicy',
  pluralName: 'kubearmorhostpolicies',
  kind: 'KubeArmorHostPolicy',
});

/** Cluster-scoped policies that apply across namespaces. */
export const KubeArmorClusterPolicy = makeCustomResourceClass({
  apiInfo: [{ group: KUBEARMOR_GROUP, version: KUBEARMOR_VERSION }],
  isNamespaced: false,
  singularName: 'kubearmorclusterpolicy',
  pluralName: 'kubearmorclusterpolicies',
  kind: 'KubeArmorClusterPolicy',
});

/** A KubeObject with a typed KubeArmor spec, regardless of which CRD it is. */
export interface KubeArmorPolicyObject {
  kind: PolicyKind;
  metadata: {
    name: string;
    namespace?: string;
    creationTimestamp?: string;
    uid?: string;
  };
  jsonData?: { spec?: KubeArmorPolicySpec };
  spec?: KubeArmorPolicySpec;
}

/** Reads the spec off a KubeObject regardless of how it exposes it. */
export function getPolicySpec(obj: KubeArmorPolicyObject): KubeArmorPolicySpec {
  return obj.spec ?? obj.jsonData?.spec ?? {};
}

/** Top-level enforcement action of a policy, when set to a known value. */
export function getPolicyAction(obj: KubeArmorPolicyObject): PolicyAction | undefined {
  const action = getPolicySpec(obj).action;
  if (action === 'Allow' || action === 'Audit' || action === 'Block') {
    return action;
  }
  return undefined;
}

/** Human-readable selector summary (labels or expressions, host or cluster). */
export function getPolicySelectorText(obj: KubeArmorPolicyObject): string {
  const spec = getPolicySpec(obj);
  const selector = spec.selector ?? spec.nodeSelector;
  const labels = selector?.matchLabels;
  if (labels && Object.keys(labels).length > 0) {
    return Object.entries(labels)
      .map(([k, v]) => `${k}=${v}`)
      .join(', ');
  }
  const expressions = selector?.matchExpressions;
  if (expressions && expressions.length > 0) {
    return expressions
      .map(e => `${e.key ?? ''} ${e.operator ?? ''} [${(e.values ?? []).join(',')}]`)
      .join('; ');
  }
  return '—';
}
