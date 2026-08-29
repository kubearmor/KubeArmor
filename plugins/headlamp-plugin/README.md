# KubeArmor Headlamp Plugin

A [Headlamp](https://headlamp.dev) plugin that brings KubeArmor runtime-security
visibility directly into the Headlamp Kubernetes dashboard, so teams no longer
have to switch between the CLI, logs, and separate tools to investigate blocked
actions or check policy enforcement.

Implements [kubearmor/KubeArmor#2564](https://github.com/kubearmor/KubeArmor/issues/2564).

## Features

A **KubeArmor** section is added to the Headlamp sidebar with four pages:

| Page | What it shows | Data source |
|---|---|---|
| **Overview** | Policy counts by enforcement action (Block/Audit/Allow), breakdown by policy type, and relay status | Kubernetes API |
| **Policies** | All `KubeArmorPolicy` (KSP), `KubeArmorHostPolicy` (HSP) and `KubeArmorClusterPolicy` (CSP) resources with action, severity and selector | Kubernetes API (CRDs) |
| **Alerts** | Live feed of blocked/audited process, file and network violations | kubearmor-relay stdout |
| **Telemetry** | Live feed of observed system events with pod/namespace/container context | kubearmor-relay stdout |

All views are **RBAC-aware**: policy queries go through Headlamp's authenticated
client, so a user only sees what their kubeconfig/token is permitted to read.

## How it works

- **Policies** are read from the `security.kubearmor.com/v1` CRDs using Headlamp's
  custom-resource classes (`src/model.tsx`) and the `.useList()` hook.
- **Alerts & telemetry** are streamed from the `kubearmor-relay` pod's stdout via
  Headlamp's pod-log streaming API (`src/api/relayLogs.ts`). KubeArmor's native
  feed is gRPC (port 32767), which a browser cannot reach directly; the relay can
  instead emit alerts/logs as JSON lines on stdout, which the plugin parses.

### Enabling the live feeds

The relay does not print to stdout by default. Enable it once per cluster:

```bash
kubectl set env deployment/kubearmor-relay -n kubearmor \
  ENABLE_STDOUT_ALERTS=true ENABLE_STDOUT_LOGS=true
```

The Alerts and Telemetry pages show an inline hint with this command when no
events are arriving.

## Development

```bash
npm install
npm run tsc      # type-check
npm run lint     # lint (use lint-fix to auto-fix)
npm run build    # produce dist/main.js
npm run start    # run against a local Headlamp for live development
```

### Trying it locally

1. Build the plugin: `npm run build`.
2. Install it into Headlamp's plugin directory:
   ```bash
   mkdir -p ~/.config/Headlamp/plugins/kubearmor-security
   cp -r dist/* ~/.config/Headlamp/plugins/kubearmor-security/
   ```
   (or run `npm run start` for hot-reload development).
3. Install KubeArmor: `karmor install`, then enable stdout streaming (above).
4. Apply a policy and trigger a violation, e.g.:
   ```bash
   kubectl run test-pod --image=nginx --labels="app=test-nginx"
   cat <<EOF | kubectl apply -f -
   apiVersion: security.kubearmor.com/v1
   kind: KubeArmorPolicy
   metadata:
     name: block-secret-access
     namespace: default
   spec:
     selector:
       matchLabels:
         app: test-nginx
     file:
       matchPaths:
       - path: /etc/passwd
     action: Block
   EOF
   kubectl exec test-pod -- cat /etc/passwd   # blocked
   ```
5. Open Headlamp → **KubeArmor** sidebar → verify Policies lists the policy and
   Alerts shows the block event.

## More

- [KubeArmor policy specification](https://docs.kubearmor.io/kubearmor/documentation/security_policy_specification)
- [Headlamp plugin development](https://headlamp.dev/docs/latest/development/plugins/)
