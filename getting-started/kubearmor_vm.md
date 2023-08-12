# KubeArmor on VM/Bare-Metal

This recipe explains how to use KubeArmor directly on a VM/Bare-Metal machine, and we tested the following steps on Ubuntu hosts.

The recipe installs `kubearmor` as systemd process and `karmor` cli tool to manage policies and show alerts/telemetry.

## Download and Install KubeArmor

1. Download the [latest release](https://github.com/kubearmor/KubeArmor/releases) or KubeArmor.
2. Install KubeArmor (VER is the kubearmor release version)
  ```
  sudo apt install ./kubearmor_${VER}_linux-amd64.deb
  ```

  > Note that the above automatically installs `bpfcc-tools` with our package, but your distribution might have an older version of BCC. In case of errors, consider installing `bcc` from [source](https://github.com/iovisor/bcc/blob/master/INSTALL.md#source).

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

## Start KubeArmor

```
sudo systemctl start kubearmor
```

Check the status of KubeArmor using `sudo systemctl status kubearmor` or use `sudo journalctl -u kubearmor -f` to continuously monitor kubearmor logs.

## Apply sample policy

Following policy is to deny execution of `sleep` binary on the host:

```yaml=
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: hsp-kubearmor-dev-proc-path-block
spec:
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

> Note that `sleep` may not blocked if you run it in the same terminal where you apply the above policy. In that case, please open a new terminal and run `sleep` again to see if the command is blocked.

## Get Alerts for policies and telemetry

```
karmor logs --json
```

```json=
{
  "Timestamp": 1639803960,
  "UpdatedTime": "2021-12-18T05:06:00.077564Z",
  "ClusterName": "Default",
  "HostName": "pandora",
  "HostPID": 3390423,
  "PPID": 168556,
  "PID": 3390423,
  "UID": 1000,
  "PolicyName": "hsp-kubearmor-dev-proc-path-block",
  "Severity": "1",
  "Type": "MatchedHostPolicy",
  "Source": "zsh",
  "Operation": "Process",
  "Resource": "/usr/bin/sleep",
  "Data": "syscall=SYS_EXECVE",
  "Action": "Block",
  "Result": "Permission denied"
}
```
