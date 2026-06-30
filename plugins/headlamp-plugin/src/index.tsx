// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

import { registerRoute, registerSidebarEntry } from '@kinvolk/headlamp-plugin/lib';
import type { ComponentType } from 'react';
import { RelayStreamConnector } from './api/relayStream';
import { AlertFeed } from './components/AlertFeed';
import { Overview } from './components/Overview';
import { PolicyList } from './components/PolicyList';
import { TelemetryView } from './components/TelemetryView';

const ROUTES = {
  overview: '/kubearmor/overview',
  policies: '/kubearmor/policies',
  alerts: '/kubearmor/alerts',
  telemetry: '/kubearmor/telemetry',
} as const;

const PAGES = [
  { id: 'kubearmor-overview', label: 'Overview', path: ROUTES.overview, Component: Overview },
  { id: 'kubearmor-policies', label: 'Policies', path: ROUTES.policies, Component: PolicyList },
  { id: 'kubearmor-alerts', label: 'Alerts', path: ROUTES.alerts, Component: AlertFeed },
  {
    id: 'kubearmor-telemetry',
    label: 'Telemetry',
    path: ROUTES.telemetry,
    Component: TelemetryView,
  },
] as const;

function withKubeArmorPage(Component: ComponentType) {
  return function KubeArmorPage() {
    return (
      <>
        <RelayStreamConnector />
        <Component />
      </>
    );
  };
}

registerSidebarEntry({
  parent: null,
  name: 'kubearmor',
  label: 'KubeArmor',
  url: ROUTES.overview,
  icon: 'mdi:shield-lock',
});

for (const page of PAGES) {
  registerSidebarEntry({
    parent: 'kubearmor',
    name: page.id,
    label: page.label,
    url: page.path,
  });

  registerRoute({
    path: page.path,
    sidebar: page.id,
    name: page.id,
    exact: true,
    component: withKubeArmorPage(page.Component),
  });
}
