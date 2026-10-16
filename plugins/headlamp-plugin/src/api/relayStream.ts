// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Singleton relay stdout stream shared across all KubeArmor pages. KubeArmor's
// native feed is gRPC; the relay can emit JSON lines on stdout when
// ENABLE_STDOUT_ALERTS / ENABLE_STDOUT_LOGS are set.

import type { ApiError } from '@kinvolk/headlamp-plugin/lib/k8s/apiProxy';
import Pod from '@kinvolk/headlamp-plugin/lib/k8s/pod';
import { useEffect, useSyncExternalStore } from 'react';
import { KUBEARMOR_NAMESPACE, RELAY_CONTAINER_NAME, RELAY_LABEL_SELECTOR } from '../model';
import { KubeArmorAlert, TelemetryEvent } from '../types';
import { classifyRelayLine } from './classifyRelayLine';

export { RELAY_LABEL_SELECTOR } from '../model';

const MAX_ALERTS = 100;
const MAX_EVENTS = 200;

export interface RelayStreamSnapshot {
  alerts: readonly KubeArmorAlert[];
  telemetry: readonly TelemetryEvent[];
  podFound: boolean;
  podName?: string;
  error: ApiError | null;
}

const EMPTY_SNAPSHOT: RelayStreamSnapshot = {
  alerts: [],
  telemetry: [],
  podFound: false,
  error: null,
};

let snapshot: RelayStreamSnapshot = EMPTY_SNAPSHOT;
const listeners = new Set<() => void>();

function emit(next: RelayStreamSnapshot): void {
  snapshot = next;
  listeners.forEach(listener => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): RelayStreamSnapshot {
  return snapshot;
}

function prependAlert(alert: KubeArmorAlert): void {
  emit({
    ...snapshot,
    alerts: [alert, ...snapshot.alerts].slice(0, MAX_ALERTS),
  });
}

function prependTelemetry(event: TelemetryEvent): void {
  emit({
    ...snapshot,
    telemetry: [event, ...snapshot.telemetry].slice(0, MAX_EVENTS),
  });
}

function getRelayContainerName(pod: Pod): string | undefined {
  const named = pod.spec?.containers?.find(c => c.name === RELAY_CONTAINER_NAME)?.name;
  return named ?? pod.spec?.containers?.[0]?.name;
}

let stopStream: (() => void) | undefined;
let connectedPodUid: string | undefined;

function startRelayStream(relayPod: Pod): () => void {
  const container = getRelayContainerName(relayPod);
  if (!container) {
    return () => undefined;
  }

  emit({
    ...snapshot,
    podFound: true,
    podName: relayPod.metadata?.name,
    error: null,
  });

  // Headlamp delivers the full accumulated log array on each callback; only
  // classify lines past the last processed index.
  let processed = 0;
  const cancel = relayPod.getLogs(
    container,
    ({ logs }: { logs: string[] }) => {
      if (logs.length < processed) {
        processed = 0;
      }
      for (let i = processed; i < logs.length; i++) {
        logs[i].split('\n').forEach(line => {
          const trimmed = line.trim();
          if (!trimmed) {
            return;
          }
          const result = classifyRelayLine(trimmed);
          if (result.kind === 'alert') {
            prependAlert(result.alert);
          } else if (result.kind === 'telemetry') {
            prependTelemetry(result.event);
          }
        });
      }
      processed = logs.length;
    },
    { follow: true, tailLines: 200 }
  );

  return () => cancel?.();
}

/** Keeps one relay log stream alive while any KubeArmor page is mounted. */
export function RelayStreamConnector() {
  const [pods, error] = Pod.useList({
    namespace: KUBEARMOR_NAMESPACE,
    labelSelector: RELAY_LABEL_SELECTOR,
  });

  const relayPod = pods?.find(p => p.status?.phase === 'Running') ?? pods?.[0] ?? null;
  const podUid = relayPod?.metadata?.uid;

  useEffect(() => {
    if (error) {
      emit({ ...snapshot, podFound: false, error });
      return;
    }
    if (pods !== null && !relayPod) {
      emit({ ...snapshot, podFound: false, podName: undefined, error: null });
      return;
    }
    if (!relayPod || !podUid) {
      return;
    }

    // Keep one stream alive across KubeArmor page navigations; reconnect only
    // when the relay pod identity changes.
    if (connectedPodUid === podUid && stopStream) {
      return;
    }

    stopStream?.();
    connectedPodUid = podUid;
    stopStream = startRelayStream(relayPod);
  }, [error, pods, relayPod, podUid]);

  return null;
}

export function useRelayStreamSnapshot(): RelayStreamSnapshot {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function useRelayAlerts(): readonly KubeArmorAlert[] {
  return useRelayStreamSnapshot().alerts;
}

export function useRelayTelemetry(): readonly TelemetryEvent[] {
  return useRelayStreamSnapshot().telemetry;
}

export function useRelayStatus(): Pick<RelayStreamSnapshot, 'podFound' | 'podName' | 'error'> {
  const { podFound, podName, error } = useRelayStreamSnapshot();
  return { podFound, podName, error };
}
