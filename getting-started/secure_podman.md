
# Securing Podman Workloads using KubeArmor
## Setup

In this quick start guide, we will deploy KubeArmor to secure your workloads on Podman containers, both in rootful Podman and rootless Podman.
### Pre-requisites

- Podman Compose to install and run KubeArmor in Podman
- Podman v5+ to work with OCI and Podman Go binding client
- Karmor client to set up OCI Hook
  
## Inject OCI Hook Configuration

To inject the OCI hook configuration, use the `karmor inject` command:

```
$ karmor inject --hook-dir <hook_directory> --cri-socket <cri_socket>

```

This command takes two flags:
- `--hook-dir <hook_directory>`: Specifies the directory containing the OCI hook scripts.
- `--cri-socket <cri_socket>`: Indicates the socket path of the container runtime interface (CRI) to be enforced. This can be either rootful (`/run/podman/podman.sock`) or rootless (`/run/user/${UID}/podman/podman.sock`).

### Example

To secure workload on rootless Podman, run:

```sh
$ karmor inject --hook-dir /etc/containers/oci/hooks.d --cri-socket /run/user/1000/podman/podman.sock
```

**NOTE:** If you don’t have the socket running for a user (rootless), start the service like this:

```sh
$ systemctl start --user podman.socket
```

Check if the socket exists by running:

```sh
$ ls run/user/${UID}/podman/podman.sock
```

## Run KubeArmor

Run KubeArmor with `sudo`, which spins up the `kubearmor-init` and `kubearmor` containers:

```sh
$ sudo podman-compose up
```

**NOTE:** Downloading Podman Compose will download Compose in the user `$PATH`. Add the `$PATH` to `sudo` in order to use it with `sudo`.

## Testing

Run a Podman container:

```sh
$ podman run --name=test-rootless-podman --detach --rm nginx
```

## Apply Policy

Let's apply a policy to block the execution of `sleep` in `test-rootless-podman`.

Create a file named `test-policy.yaml` with the following content:

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: block-sleep-exec
spec:
  selector:
    kubearmor.io/container.name: test-rootless-podman
  process:
    matchPaths:
    - path: /usr/bin/sleep
  action:
    Block
```

Apply the policy using:

```sh
$ karmor vm policy add test-policy.yaml
```

Now, exec into the container:

```sh
$ podman exec -it test-rootless-podman bash
```

Try to execute the `sleep` command:

```sh
$ sleep 1
```

You will be denied permission to execute the command.

---

