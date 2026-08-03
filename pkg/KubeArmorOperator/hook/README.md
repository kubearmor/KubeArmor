# KubeArmor OCI Prestart Hook

The KubeArmor OCI Prestart Hook is a lightweight binary invoked by container runtimes (containerd, CRI-O, Kata Containers) during container lifecycle events. It collects process ID namespaces and security metadata, delivering them directly to KubeArmor to enable BPF-LSM policy enforcement.

---

## Operational Modes (Auto-Detecting Hybrid)

The hook binary automatically adapts its communication mechanism based on the runtime environment:

### 1. Standard Mode (UNIX Domain Socket)
In standard Linux host environments, the hook streams container lifecycle events directly to the KubeArmor daemon over a UNIX domain socket (`/var/run/kubearmor/ka.sock`).

### 2. Kata Containers Mode (Filesystem Rootfs Injection)
In isolated Kata Containers microVMs, UNIX domain sockets cannot easily bridge across the host and guest filesystem boundaries. When the hook detects a Kata microVM environment automatically (by checking for the presence of `/var/run/kata-containers/shared` on disk):
1. It identifies KubeArmor's sidecar container ID on startup and caches it in `/tmp/id.json` on the guest root filesystem.
2. For all incoming container events, it extracts process namespace IDs and writes them to `/tmp/output.json`.
3. It directly mirrors these events across the shared filesystem bridge into KubeArmor's container root filesystem at `/var/run/kata-containers/shared/containers/<KUBEARMOR_ID>/rootfs/opt/kubearmor_hook_output.json` (which appears inside the KubeArmor container as `/opt/kubearmor_hook_output.json`).

---

## Building the Hook Binary

You can compile the hook binary independently using the `KubeArmorOperator` Makefile:

```bash
cd KubeArmor/pkg/KubeArmorOperator
make hook
```

The compiled binary will be placed at `KubeArmor/pkg/KubeArmorOperator/hook/hook`.


---

## Preparing a Kata Containers Machine 

To enable KubeArmor enforcement inside Kata Containers, the compiled OCI hook binary must be injected into the base Kata Containers guest root filesystem image (`kata-containers.img`). 

Follow these step-by-step instructions on your target host machine:

### Step 1: Map the Kata Rootfs Partitions
Use `kpartx` to create loop device mappings for the partitions inside the Kata image:
```bash
sudo kpartx -av /opt/kata/share/kata-containers/kata-containers.img
```
*Note: Make note of the loop partition name printed in the output (typically `loop0p1` or similar).*

### Step 2: Mount the Loop Partition
Mount the mapped root filesystem partition to `/mnt`:
```bash
sudo mount /dev/mapper/loop0p1 /mnt
```

### Step 3: Inject the Compiled Hook Binary
Copy your newly compiled `hook` binary into the Kata OCI prestart directory and set appropriate executable permissions:
```bash
sudo mkdir -p /mnt/usr/share/oci/hooks/prestart/
sudo cp /path/to/KubeArmor/pkg/KubeArmorOperator/hook/hook /mnt/usr/share/oci/hooks/prestart/hook
sudo chmod +x /mnt/usr/share/oci/hooks/prestart/hook
```

### Step 4: Unmount and Detach Partitions
unmount the filesystem, and delete the partition mappings and restart k3s:
```bash
sudo umount /mnt
sudo kpartx -dv /opt/kata/share/kata-containers/kata-containers.img
sudo systemctl restart k3s.service
```

---

## Configuring KubeArmor for Kata Workloads

When deploying KubeArmor in Kubernetes environments utilizing Kata Containers, pass the `-useOCIHooks=true` flag to the KubeArmor daemon (or set `useOCIHooks: true` in your deployment configuration). 
