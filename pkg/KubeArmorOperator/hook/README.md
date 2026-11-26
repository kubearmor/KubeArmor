# KubeArmor for Kata Containers & Confidential Containers

KubeArmor protects Kata Containers and Confidential Containers (CoCo) workloads by running as a sidecar inside each Kata microVM alongside a lightweight guest OCI hook binary (`pkg/KubeArmorOperator/hook`).

---

## 1. Overview & Architecture

In standard Kubernetes nodes, KubeArmor runs as a host DaemonSet and observes container syscalls through the shared host Linux kernel. In **Kata Containers**, each Pod runs inside its own hardware-isolated microVM with a **dedicated guest Linux kernel**—syscalls executed by workload containers never traverse the host kernel, and UNIX domain sockets on the host cannot directly bridge across the microVM boundary.

To enforce policies inside the guest kernel, KubeArmor uses a **sidecar + guest OCI hook** model:

1. **Guest OCI Hooks (`prestart` and `poststop`):** `kata-agent` invokes the KubeArmor OCI hook binary inside the microVM whenever a container starts (`prestart`) or stops (`poststop`). When `/var/run/kata-containers/shared` is present, the hook automatically switches to Kata rootfs-injection mode (in standard host setups without that directory, it streams events over `/var/run/kubearmor/ka.sock`).
2. **Metadata & Rootfs Bridge (`/opt/kubearmor_hook_output.json`):** The hook skips pause sandboxes and KubeArmor itself (identified by container name `kubearmor` or `Args[0] == "/KubeArmor/kubearmor"`), maintains an active container map in `/tmp/output.json`, and atomically writes `map[string]types.Container` (containing `ContainerID`, `ContainerName`, `EndPointName`, `NamespaceName`, `PidNS`, `MntNS`, and `AppArmorProfile`) into KubeArmor's container rootfs at `/opt/kubearmor_hook_output.json`.
3. **In-Guest Enforcement:** The `kubearmor` sidecar runs with `-useOCIHooks=true` and `-hookFilePath=/opt/kubearmor_hook_output.json`, watches `/opt/kubearmor_hook_output.json` via `fsnotify`, maps container namespace IDs (`PidNS`/`MntNS`) into its eBPF maps, and enforces `KubeArmorPolicy` rules directly inside the guest kernel.

```text
+------------------------------------------------------------------------------+
| Host Node                                                                    |
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  | Kata MicroVM (Guest Kernel with BPF-LSM + BTF)                         |  |
|  |                                                                        |  |
|  |  +------------+   prestart/poststop   +-----------------------------+  |  |
|  |  | kata-agent | --------------------> | Guest OCI Hook binary       |  |  |
|  |  +------------+                       +--------------+--------------+  |  |
|  |                                                      |                 |  |
|  |                             atomic write             v                 |  |
|  |                        /opt/kubearmor_hook_output.json                 |  |
|  |                                                      |                 |  |
|  |  +-------------------+   fsnotify                    v                 |  |
|  |  | Workload          |                +-----------------------------+  |  |
|  |  | Container (nginx) | <-- enforced --| kubearmor sidecar           |  |  |
|  |  +-------------------+   via guest    | (-useOCIHooks=true,         |  |  |
|  |                          BPF-LSM      |  -hookFilePath=...)         |  |  |
|  |                                       +--------------+--------------+  |  |
|  +------------------------------------------------------|-----------------+  |
|                                                         | gRPC (:32767)      |
+---------------------------------------------------------|--------------------+
                                                          v
                                          +-------------------------------+
                                          | kubearmor-relay               |
                                          | (discovers pods labeled       |
                                          |  kubearmor.io/kata-sidecar)   |
                                          +-------------------------------+
```

---

## 2. Supported Enforcers

* **BPF-LSM (`bpf`)** is the supported enforcer for Kata Containers and Confidential Containers. It requires a Kata guest kernel built with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`, with `bpf` enabled in the kernel LSM list.
* **SELinux** (not supported for container-level policies / disabled in Kubernetes mode) and **AppArmor** (not enabled or attached by stock Kata guest kernels and `kata-agent`) are not supported.
* If the guest kernel lacks BPF-LSM, KubeArmor falls back to **eBPF Monitor** (observability/telemetry only, without blocking enforcement).

---

## 3. Build Steps (Prerequisites)

### Step 1: Build the Guest OCI Hook Binary

The hook source lives under `pkg/KubeArmorOperator/hook/` (using the module at `pkg/KubeArmorOperator/go.mod`). Build a **static Linux binary** so it runs inside minimal Kata guest rootfs/`initrd` images without `glibc` mismatches:

```bash
cd pkg/KubeArmorOperator
CGO_ENABLED=0 GOOS=linux go build -o hook/hook ./hook
```

*(You can also run `make hook` in `pkg/KubeArmorOperator/` for a default native build via `pkg/KubeArmorOperator/Makefile`.)*

### Step 2: Build / Configure a BPF-LSM Kata Guest Kernel

Ensure the Kata guest kernel is compiled with the following options enabled:

```kconfig
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
```

Activate `bpf` in the kernel LSM chain either at compile time or at boot time:
* **Built-in kernel config:** `CONFIG_LSM="lockdown,yama,integrity,bpf"`
* **Boot parameter (`kernel_params`):** `lsm=lockdown,yama,integrity,bpf`

### Step 3: Bundle the OCI Hook into the Kata Guest `initrd` / Image

Place the compiled `hook` binary under **both** `prestart/` and `poststop/` inside your configured `guest_hook_path` (the same binary handles container creation and removal based on OCI state):

* **If using a rootfs disk image (`kata-containers.img`):**
  ```bash
  sudo kpartx -av /opt/kata/share/kata-containers/kata-containers.img
  sudo mount /dev/mapper/loop0p1 /mnt
  sudo mkdir -p /mnt/usr/share/oci/hooks/prestart /mnt/usr/share/oci/hooks/poststop
  sudo cp pkg/KubeArmorOperator/hook/hook /mnt/usr/share/oci/hooks/prestart/hook
  sudo cp pkg/KubeArmorOperator/hook/hook /mnt/usr/share/oci/hooks/poststop/hook
  sudo chmod +x /mnt/usr/share/oci/hooks/prestart/hook /mnt/usr/share/oci/hooks/poststop/hook
  sudo umount /mnt
  sudo kpartx -dv /opt/kata/share/kata-containers/kata-containers.img
  ```

* **If using a compressed `initrd` (`kata-containers-initrd.img`):**
  ```bash
  mkdir -p /tmp/kata-initrd && cd /tmp/kata-initrd
  gzip -dc /opt/kata/share/kata-containers/kata-containers-initrd.img | cpio -idmv
  mkdir -p usr/share/oci/hooks/prestart usr/share/oci/hooks/poststop
  cp /path/to/KubeArmor/pkg/KubeArmorOperator/hook/hook usr/share/oci/hooks/prestart/hook
  cp /path/to/KubeArmor/pkg/KubeArmorOperator/hook/hook usr/share/oci/hooks/poststop/hook
  chmod +x usr/share/oci/hooks/prestart/hook usr/share/oci/hooks/poststop/hook
  find . | cpio -o -H newc | gzip -9 > /opt/kata/share/kata-containers/kata-containers-initrd-kubearmor.img
  ```

Next, configure Kata (for example, `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml`) to use the BPF-LSM kernel, updated `initrd`/`image`, `guest_hook_path`, and `lsm` kernel parameter:

```toml
[hypervisor.qemu]
kernel = "/opt/kata/share/kata-containers/vmlinux-bpflsm"
initrd = "/opt/kata/share/kata-containers/kata-containers-initrd-kubearmor.img" # or image = "..."
guest_hook_path = "/usr/share/oci/hooks"
kernel_params = "lsm=lockdown,yama,integrity,bpf"
```

Restart the container runtime / node service so the updated Kata configuration takes effect (e.g., `sudo systemctl restart k3s.service` or `containerd`).

### Step 4: Build KubeArmor Image from Source (Optional / Pre-release)

> **Note:** Official `stable` images will include Kata support after the next release. Until then, use `latest` (post-merge) or build locally from the repository root and override the image tag at deploy time.

```bash
docker build --target kubearmor -t docker.io/kubearmor/kubearmor:kata-test -f Dockerfile .
```

If using k3s, import the locally built image into k3s containerd (`docker save docker.io/kubearmor/kubearmor:kata-test | sudo k3s ctr images import -`).

---

## 4. Deployment

> **Prerequisite:** Make sure KubeArmor CRDs (`KubeArmorPolicy`, `KubeArmorClusterPolicy`, `KubeArmorHostPolicy`, `KubeArmorNetworkPolicy` under `deployments/CRD/`) are already installed in your cluster.

### Option A: Helm Chart (Recommended) — `deployments/helm/KubeArmorKata`

Install the chart with default values:

```bash
helm install kubearmor-kata ./deployments/helm/KubeArmorKata \
  --namespace kubearmor --create-namespace
```

Override for a locally built image (`kata-test`) and custom `RuntimeClass`:

```bash
helm install kubearmor-kata ./deployments/helm/KubeArmorKata \
  --namespace kubearmor --create-namespace \
  --set runtimeClassName=kata-qemu \
  --set kubearmor.image.tag=kata-test \
  --set kubearmor.image.pullPolicy=Never
```

Install only the shared RBAC and `ServiceAccount` prerequisites (when injecting the `kubearmor` sidecar into your own workload Deployments):

```bash
helm install kubearmor-kata ./deployments/helm/KubeArmorKata \
  --namespace kubearmor --create-namespace \
  --set sampleWorkload.enabled=false
```

#### Key `values.yaml` Options

| Key | Default | Description |
| :--- | :--- | :--- |
| `runtimeClassName` | `kata-qemu` | Kubernetes `RuntimeClass` for Kata Pods (e.g. `kata-qemu`, `kata-clh`, `kata-qemu-coco-dev`). |
| `kubearmor.image.repository` | `docker.io/kubearmor/kubearmor` | KubeArmor sidecar image repository. |
| `kubearmor.image.tag` | `stable` | KubeArmor sidecar image tag (`kata-test` for local dev builds). |
| `kubearmor.image.pullPolicy` | `IfNotPresent` | Image pull policy for the KubeArmor sidecar. |
| `kubearmor.args` | `["-untrackedNs=", "-useOCIHooks=true", "-hookFilePath=/opt/kubearmor_hook_output.json"]` | CLI arguments passed to the KubeArmor sidecar. |
| `initContainer.image.repository` | `docker.io/kubearmor/kubearmor-init` | KubeArmor init container image repository. |
| `initContainer.image.tag` | `stable` | KubeArmor init container image tag. |
| `initContainer.image.pullPolicy` | `IfNotPresent` | Image pull policy for the init container. |
| `sampleWorkload.enabled` | `true` | Deploy the sample `nginx` + `kubearmor` Kata Deployment (`false` installs RBAC/SA only). |
| `rbac.create` | `true` | Create the `ClusterRole` and `ClusterRoleBinding` for the sidecar. |
| `serviceAccount.create` | `true` | Create the `ServiceAccount` used by the Kata Pod. |

### Option B: Raw Sample Manifest — `pkg/KubeArmorOperator/hook/sample/kubearmor-kata.yaml`

Update `runtimeClassName`, `nodeSelector`, and the `init` / `kubearmor` container images in [kubearmor-kata.yaml](sample/kubearmor-kata.yaml) for your cluster, then apply from the repository root:

```bash
kubectl apply -f pkg/KubeArmorOperator/hook/sample/kubearmor-kata.yaml
```

When adapting the `kubearmor` sidecar into your own Kata Pods, keep the following required fields:
* **Sidecar container name `kubearmor`:** The guest OCI hook identifies KubeArmor by `name: kubearmor` (or `Args[0] == "/KubeArmor/kubearmor"`).
* **`hostPID: true`:** Required on the Pod spec so KubeArmor can observe sibling containers inside the microVM.
* **`init` container & volumes:** Include the `init` container sharing the `bpf` `emptyDir` (`/opt/kubearmor/BPF`) along with `/lib/modules`, `/sys/fs/bpf`, `/sys/kernel/debug`, and `/usr/src` mounts.
* **Sidecar flags & env:** Keep `-useOCIHooks=true`, `-hookFilePath=/opt/kubearmor_hook_output.json`, and `KUBEARMOR_NODENAME` (from `spec.nodeName`).
* **Discovery label:** Keep `kubearmor.io/kata-sidecar: "true"` on the Pod template metadata for `kubearmor-relay`.

---

## 5. End-to-End Sample Test

1. **Wait for the Pod to become `2/2 Running` and inspect KubeArmor logs:**

   ```bash
   kubectl rollout status deployment/kubearmor-kata -n kubearmor --timeout=120s
   kubectl get pods -n kubearmor -l app=kubearmor-kata
   kubectl logs -n kubearmor -l app=kubearmor-kata -c kubearmor
   ```

   Confirm the logs show BPF-LSM initialization (`Initialized BPF-LSM Enforcer`) and container detection (`Detected a container (added/.../pidns=.../mntns=...)`).

2. **Apply a `KubeArmorPolicy` blocking `/usr/bin/sleep` on the `kubearmor-kata` Pod:**

   ```bash
   kubectl apply -f - <<'EOF'
   apiVersion: security.kubearmor.com/v1
   kind: KubeArmorPolicy
   metadata:
     name: block-sleep-kata
     namespace: kubearmor
   spec:
     severity: 5
     selector:
       matchLabels:
         app: kubearmor-kata
     process:
       matchPaths:
         - path: /usr/bin/sleep
     action: Block
   EOF
   ```

3. **Verify enforcement inside the `nginx` container:**

   ```bash
   kubectl exec -n kubearmor deploy/kubearmor-kata -c nginx -- /usr/bin/sleep 1
   ```

   Expected result: command fails with **Permission denied** and **exit code `13`**.

4. **Verify enforcement persists across a container restart:**

   ```bash
   kubectl exec -n kubearmor deploy/kubearmor-kata -c nginx -- nginx -s stop
   kubectl wait --for=condition=Ready pod -n kubearmor -l app=kubearmor-kata --timeout=60s
   kubectl exec -n kubearmor deploy/kubearmor-kata -c nginx -- /usr/bin/sleep 1
   ```

   The poststop + prestart hooks update `/opt/kubearmor_hook_output.json` with the restarted container's new `PidNS`/`MntNS`, and `/usr/bin/sleep 1` still fails with **exit code `13`**.

5. **Delete the policy and confirm execution succeeds again:**

   ```bash
   kubectl delete kubearmorpolicy block-sleep-kata -n kubearmor
   kubectl exec -n kubearmor deploy/kubearmor-kata -c nginx -- /usr/bin/sleep 1
   ```

   Expected result: exits with code `0`.

---

## 6. Log & Alert Aggregation

Each KubeArmor sidecar serves its gRPC `LogService` (`WatchAlerts`, `WatchLogs`, `WatchMessages`) on port `32767`. Kata sidecar Pod templates carry the dedicated label:

```yaml
kubearmor.io/kata-sidecar: "true"
```

`kubearmor-relay` discovers Pods labeled with `kubearmor.io/kata-sidecar: "true"` alongside standard DaemonSet Pods (`kubearmor-app=kubearmor`), aggregating alerts and telemetry from all Kata sidecars into the central `kubearmor` Relay Service. Using a dedicated `kubearmor.io/kata-sidecar` label avoids triggering `kubearmor-app` exemptions in `KubeArmorController` (which would otherwise force `kubearmor-policy: audited` on the workload Pod).

---

## 7. Confidential Containers (CoCo) Notes & Roadmap

The same sidecar + guest OCI hook + BPF-LSM architecture works inside Confidential Containers (CoCo) confidential VMs (CVMs) when the BPF-LSM kernel, static `hook` binary, and `lsm=...,bpf` kernel parameter are included in the measured guest image/`initrd`.

### Current Caveats & Roadmap

* **CoCo `kata-agent` policy (`genpolicy`):** Hardened CoCo deployments enforce a Rego policy inside `kata-agent` that restricts allowed containers, args, mounts, and privileged execution. You must update the Pod's `kata-agent` policy to permit the `init` and `kubearmor` sidecar containers and their required BPF/kernel mounts.
* **Policy Delivery:** Policies are currently watched from the Kubernetes API server (`-k8s=true`) or restored from local YAML files (`-k8s=false -restorePath=<dir>`).
* **Planned Improvements:**
  * Attested policy delivery for confidential pods via `cc_init_data` / Trustee KBS without relying on direct K8s API access from inside the CVM.
  * Automatic sidecar injection via `kubearmor-operator` / mutating webhook for Pods using Kata `RuntimeClass`es.
