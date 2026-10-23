// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Live feed of KubeArmor telemetry / system log events (process, file and
// network activity observed in workloads) streamed from kubearmor-relay stdout.

import { SectionBox, SimpleTable } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { useRelayStatus, useRelayTelemetry } from '../api/relayStream';
import { TelemetryEvent } from '../types';
import { formatRelayTime } from '../utils/time';
import { RelayStatusHint } from './RelayStatusHint';

export function TelemetryView() {
  const events = useRelayTelemetry();
  const { podFound, error } = useRelayStatus();

  return (
    <SectionBox title="KubeArmor Telemetry" backLink>
      <RelayStatusHint
        podFound={podFound}
        error={error}
        received={events.length > 0}
        kind="telemetry"
      />
      <SimpleTable
        emptyMessage="No telemetry events yet."
        columns={[
          { label: 'Time', getter: (e: TelemetryEvent) => formatRelayTime(e) },
          { label: 'Operation', getter: (e: TelemetryEvent) => e.Operation ?? '—' },
          { label: 'Namespace', getter: (e: TelemetryEvent) => e.NamespaceName ?? '—' },
          { label: 'Pod', getter: (e: TelemetryEvent) => e.PodName ?? '—' },
          { label: 'Container', getter: (e: TelemetryEvent) => e.ContainerName ?? '—' },
          { label: 'Source', getter: (e: TelemetryEvent) => e.Source ?? '—' },
          { label: 'Resource', getter: (e: TelemetryEvent) => e.Resource ?? '—' },
          { label: 'Result', getter: (e: TelemetryEvent) => e.Result ?? '—' },
        ]}
        data={[...events]}
      />
    </SectionBox>
  );
}
