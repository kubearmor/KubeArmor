# KubeArmor on VM/Bare-Metal

This recipe explains how to use KubeArmor directly on a VM/Bare-Metal machine, and we tested the following steps on Ubuntu hosts.

`KubeArmor` can be used to protect VM's and Bare-Metal machines in 2 different ways:

1. As a `systemd` service.
2. Using `docker-compose`

The [`karmor`](https://docs.kubearmor.io/kubearmor/quick-links/deployment_guide#install-karmor-cli-optional) cli tool can be used to manage policies and show alerts/telemetry.

## Systemd Installation

### Download and Install KubeArmor

1. Download the [latest release](https://github.com/kubearmor/KubeArmor/releases) or KubeArmor.
2. Install KubeArmor (VER is the kubearmor release version)
  ```
  sudo apt --no-install-recommends install ./kubearmor_${VER}_linux-amd64.deb
  ```
  > Note that the above command doesn't installs the recommended packages, as we ship object files along with the package file. In case you don't have BTF, consider removing `--no-install-recommends` flag.
  
<details><summary>For distributions other than Ubuntu/Debian</summary>
<p>

1. Refer [Installing BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md#installing-bcc) to install pre-requisites.

2. Download release tarball from KubeArmor releases for the version you want
  ```
  wget https://github.com/KubeArmor/KubeArmor/releases/download/v${VER}/kubearmor_${VER}_linux-amd64.tar.gz
  ```

3. Unpack the tarball to the root directory:
  ```
  sudo tar --no-overwrite-dir -C / -xzf kubearmor_${VER}_linux-amd64.tar.gz
  sudo systemctl daemon-reload
  ```
</p>
</details>

### Start KubeArmor

```
sudo systemctl start kubearmor
```

Check the status of KubeArmor using `sudo systemctl status kubearmor` or use `sudo journalctl -u kubearmor -f` to continuously monitor kubearmor logs.

## Using Docker Compose 

1. Ensure [Docker](https://docs.docker.com/desktop/install/linux-install/) and Docker Compose are installed on your system.
2. Download the `docker-compose.yaml` file from `KubeArmor` repository:
    
    `curl -o docker-compose.yaml https://raw.githubusercontent.com/kubearmor/KubeArmor/main/docker-compose.yaml`

3. Start KubeArmor using Docker Compose:
    `docker compose up`

## Apply sample policy

Following policy is to deny execution of `sleep` binary on the host:

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: hsp-kubearmor-dev-proc-path-block
spec:
  nodeSelector:
    matchLabels:
      kubearmor.io/hostname: "*" # Apply to all hosts
  process:
    matchPaths:
    - path: /usr/bin/sleep # try sleep 1
  action:
    Block
```

Save the above policy to _`hostpolicy.yaml`_ and apply:
```
karmor vm policy add hostpolicy.yaml
```

**Now if you run `sleep` command, the process would be denied execution.**

> Note that `sleep` may not be blocked if you run it in the same terminal where you apply the above policy. In that case, please open a new terminal and run `sleep` again to see if the command is blocked.

## Get Alerts for policies and telemetry

```
karmor logs --gRPC=:32767 --json
```

```json
{
"Timestamp":1717259989,
"UpdatedTime":"2024-06-01T16:39:49.360067Z",
"HostName":"kubearmor-dev",
"HostPPID":1582,
"HostPID":2420,
"PPID":1582,
"PID":2420,
"UID":1000,
"ParentProcessName":"/usr/bin/bash",
"ProcessName":"/usr/bin/sleep",
"PolicyName":"hsp-kubearmor-dev-proc-path-block",
"Severity":"1",
"Type":"MatchedHostPolicy",
"Source":"/usr/bin/bash",
"Operation":"Process",
"Resource":"/usr/bin/sleep",
"Data":"lsm=SECURITY_BPRM_CHECK",
"Enforcer":"BPFLSM",
"Action":"Block",
"Result":"Permission denied",
"Cwd":"/"
}
```
