## Profiling of Kubearmor Logs using karmor

`karmor profile` provides a real-time terminal UI that visualizes security-relevant activity observed by KubeArmor, including Process, File, and Network events. It fetches live data from the KubeArmor logs API, displays counters and key details for each event type, and supports easy navigation and filtering.

![Profile](https://user-images.githubusercontent.com/23097199/213850468-2462e8b2-b4f6-491f-a174-42d217cbfd28.gif)

### 🔍 Filtering Logs with `karmor profile`

The `karmor profile` command allows you to filter logs or alerts using a set of useful flags. These filters help narrow down the output to specific Kubernetes objects like containers, pods, and namespaces.

### 🧰 Available Filters

| Flag                | Description                               |
| ------------------- | ----------------------------------------- |
| `-c`, `--container` | Filters logs by **container name**.       |
| `-n`, `--namespace` | Filters logs by **Kubernetes namespace**. |
| `--pod`             | Filters logs by **pod name**.             |

---

### 📌 Usage Examples

#### ✅ Filter by Container Name

```bash
karmor profile -c nginx
```

> Outputs logs only from the container named `nginx`.

---

#### ✅ Filter by Namespace

```bash
karmor profile -n nginx1
```

> Outputs logs only from the namespace `nginx1`.

---

#### ✅ Filter by Pod

```bash
karmor profile --pod nginx-pod-1
```

> Outputs logs only from the pod named `nginx-pod-1`.

---

### 🔗 Combine Multiple Filters

You can combine filters to narrow down the logs even further.

```bash
karmor profile -n nginx1 -c nginx
```

> Outputs logs **only** from the `nginx` container in the `nginx1` namespace.

---

### 💡 Tip

Use these filters during profiling sessions to quickly isolate behavior or security events related to a specific pod, container, or namespace.
