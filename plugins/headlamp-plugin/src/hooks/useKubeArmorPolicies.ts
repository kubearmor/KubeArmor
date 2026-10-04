// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

import type { ApiError } from '@kinvolk/headlamp-plugin/lib/k8s/apiProxy';
import { useMemo } from 'react';
import {
  KubeArmorClusterPolicy,
  KubeArmorHostPolicy,
  KubeArmorPolicy,
  KubeArmorPolicyObject,
} from '../model';
import { PolicyKind } from '../types';

export interface KubeArmorPolicyRow {
  kind: PolicyKind;
  name: string;
  namespace?: string;
  obj: KubeArmorPolicyObject;
}

function toRows(items: KubeArmorPolicyObject[] | null, kind: PolicyKind): KubeArmorPolicyRow[] {
  return (items ?? []).map(obj => ({
    kind,
    name: obj.metadata?.name,
    namespace: obj.metadata?.namespace,
    obj,
  }));
}

export interface KubeArmorPoliciesState {
  ksp: KubeArmorPolicyObject[] | null;
  hsp: KubeArmorPolicyObject[] | null;
  csp: KubeArmorPolicyObject[] | null;
  all: KubeArmorPolicyObject[];
  rows: KubeArmorPolicyRow[];
  loading: boolean;
  errors: ApiError[];
}

/** Single hook for all three KubeArmor policy CRDs (RBAC-aware via Headlamp). */
export function useKubeArmorPolicies(): KubeArmorPoliciesState {
  const [ksp, kspError] = KubeArmorPolicy.useList();
  const [hsp, hspError] = KubeArmorHostPolicy.useList();
  const [csp, cspError] = KubeArmorClusterPolicy.useList();

  const all = useMemo(() => [...(ksp ?? []), ...(hsp ?? []), ...(csp ?? [])], [ksp, hsp, csp]);

  const rows = useMemo(
    () => [
      ...toRows(ksp, 'KubeArmorPolicy'),
      ...toRows(hsp, 'KubeArmorHostPolicy'),
      ...toRows(csp, 'KubeArmorClusterPolicy'),
    ],
    [ksp, hsp, csp]
  );

  const loading = ksp === null && hsp === null && csp === null;
  const errors = [kspError, hspError, cspError].filter((e): e is ApiError => Boolean(e));

  return { ksp, hsp, csp, all, rows, loading, errors };
}
