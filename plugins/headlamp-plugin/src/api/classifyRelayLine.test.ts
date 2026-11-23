// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

import { describe, expect, it } from 'vitest';
import { classifyRelayLine } from './classifyRelayLine';

/** Block alert captured from kubearmor-relay stdout (MatchedPolicy /etc/passwd). */
const BLOCK_ALERT_LINE = JSON.stringify({
  Timestamp: 1710000000,
  Type: 'MatchedPolicy',
  PolicyName: 'block-secret-access',
  Action: 'Block',
  Operation: 'File',
  Resource: '/etc/passwd',
  Severity: '7',
  NamespaceName: 'default',
  PodName: 'test-pod',
  ContainerName: 'test-pod',
  Result: 'Permission denied',
});

/** Telemetry line captured from kubearmor-relay stdout (HostLog / network). */
const HOST_LOG_LINE = JSON.stringify({
  Timestamp: 1710000001,
  Type: 'HostLog',
  Operation: 'NetworkFirewall',
  HostName: 'node-1',
  Source: '10.0.0.1',
  Resource: 'tcp:80',
});

describe('classifyRelayLine', () => {
  it('classifies a MatchedPolicy block alert', () => {
    const result = classifyRelayLine(BLOCK_ALERT_LINE);
    expect(result.kind).toBe('alert');
    if (result.kind !== 'alert') {
      return;
    }
    expect(result.alert.PolicyName).toBe('block-secret-access');
    expect(result.alert.Action).toBe('Block');
    expect(result.alert.Operation).toBe('File');
    expect(result.alert.Resource).toBe('/etc/passwd');
    expect(result.alert.Severity).toBe('7');
  });

  it('classifies a HostLog telemetry event', () => {
    const result = classifyRelayLine(HOST_LOG_LINE);
    expect(result.kind).toBe('telemetry');
    if (result.kind !== 'telemetry') {
      return;
    }
    expect(result.event.Type).toBe('HostLog');
    expect(result.event.Operation).toBe('NetworkFirewall');
    expect('PolicyName' in result.event).toBe(false);
  });

  it('skips non-JSON relay banner lines', () => {
    expect(classifyRelayLine('KubeArmor relay started')).toEqual({ kind: 'skip' });
  });

  it('skips JSON without alert or telemetry signals', () => {
    expect(classifyRelayLine(JSON.stringify({ Type: 'Status', Message: 'ok' }))).toEqual({
      kind: 'skip',
    });
  });
});
