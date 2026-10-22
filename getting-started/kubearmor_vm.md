# KubeArmor on VM/Bare-Metal

This recipe explains how to use KubeArmor directly on a VM/Bare-Metal machine,
using Ubuntu/Debian package commands or a manual tarball installation.

The recipe installs `kubearmor` as a systemd process and uses the `karmor` CLI to
manage policies and show alerts/telemetry. Install a compatible
[karmor client](https://github.com/kubearmor/kubearmor-client) with management mTLS
and `logs --nonk8s` / `probe --nonk8s` support (introduced in
[client PR #561](https://github.com/kubearmor/kubearmor-client/pull/561)). These client
and agent changes must be deployed together; older standalone management clients
send policy and probe RPCs to the log port and are incompatible.

For an existing installation, follow the
[upgrade instructions](kubearmor-security-enhancements.md#upgrade-a-standalone-deployment)
before replacing the agent or certificates.

## Prepare certificates before installation

KubeArmor enables mTLS by default. The packaged service uses `tlsCertProvider: self`,
which requires pre-provisioned CAs. The `.deb` post-install script starts the
service immediately, so prepare the certificates **before** installing the package.

Obtain two independent CA identities from your PKI administrator: one for logs and
one for management. Each CA must have a PEM certificate and an RSA private key in
PKCS#1 format. Also obtain a separate client certificate/key pair signed by each
CA with client-authentication usage. For a fresh installation, arrange the files as:

```text
/var/lib/kubearmor/tls/
├── log/
│   ├── ca.crt
│   ├── ca.key
│   ├── client.crt
│   └── client.key
└── management/
    ├── ca.crt
    ├── ca.key
    ├── client.crt
    └── client.key
```

Use root-owned directories with mode `0700` and private keys with mode `0600`.
The agent reads `ca.crt` and `ca.key` in each directory and generates its server
certificates in memory. The client files are for local `karmor` commands; the agent
does not generate them with `self`. Do not reuse the log CA for management, and
do not replace existing CAs when upgrading.

If your PKI keeps CA private keys off the agent, use the
[`external` provider](kubearmor-security-enhancements.md#certificate-providers-and-directories)
instead: provision `ca.crt`, `server.crt`, and `server.key` for each endpoint and
configure `tlsCertProvider: external` before starting the service. Each server
certificate must cover the hostname/IP clients use, including `localhost` for the
commands below. For a fresh installation using only external certificates, use the
[manual tarball installation](#manual-tarball-installation), update
`/opt/kubearmor/kubearmor.yaml` after unpacking, and then start the service. The
default `.deb` installation below assumes the `self` CA files are already present.
`dev` bootstrapping is for development and CI, not production.

## Download and Install KubeArmor

1. Download a [KubeArmor release](https://github.com/kubearmor/KubeArmor/releases) compatible with the client above.
2. Set `VER` to the downloaded release version and install KubeArmor:

   ```shell
   sudo apt --no-install-recommends install ./kubearmor_${VER}_linux-amd64.deb
   ```

   The package includes BPF object files. On hosts without BTF, omit
   `--no-install-recommends` to install the build prerequisites.

### Manual tarball installation

Use these steps for distributions other than Ubuntu/Debian, or to configure
external certificates before the first service start.

1. Refer [Installing BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md#installing-bcc) to install pre-requisites.

2. Download the release tarball, setting `VER` to the desired release version:

   ```shell
   wget https://github.com/KubeArmor/KubeArmor/releases/download/v${VER}/kubearmor_${VER}_linux-amd64.tar.gz
   ```

3. Unpack the tarball to the root directory:

   ```shell
   sudo tar --no-overwrite-dir -C / -xzf kubearmor_${VER}_linux-amd64.tar.gz
   sudo systemctl daemon-reload
   ```
For `external`, add `tlsCertProvider: external` to
`/opt/kubearmor/kubearmor.yaml`, preserving the packaged settings. Set
`tlsCertPath` and `managementTLSCertPath` if using directories other than the
defaults above. Ensure both server identities and the corresponding client
credentials are provisioned before starting KubeArmor.

## Start KubeArmor

```shell
sudo systemctl start kubearmor
```

Check the status of KubeArmor using `sudo systemctl status kubearmor` or use `sudo journalctl -u kubearmor -f` to continuously monitor kubearmor logs.

Management requests now use `localhost:32765`; logs use `localhost:32767`. With the
root-owned credentials above, check the management endpoint using:

```shell
sudo karmor probe --nonk8s --gRPC localhost:32765 \
  --managementTLSCertPath /var/lib/kubearmor/tls/management
```

The management TCP listener binds to all interfaces by default. If only local
administration is needed, set `managementFallbackAddr: "127.0.0.1:32765"` in
`/opt/kubearmor/kubearmor.yaml` and restart the service. See the
[endpoint reference](kubearmor-security-enhancements.md#endpoints) for health probes
and other listener settings.

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

```shell
sudo karmor vm policy add hostpolicy.yaml \
  --gRPC localhost:32765 \
  --managementTLSCertPath /var/lib/kubearmor/tls/management
```

**Now if you run `sleep` command, the process would be denied execution.**

> Note that `sleep` may not be blocked if you run it in the same terminal where you apply the above policy. In that case, please open a new terminal and run `sleep` again to see if the command is blocked.

## Get Alerts for policies and telemetry

```shell
sudo karmor logs --nonk8s --gRPC localhost:32767 \
  --tlsCertPath /var/lib/kubearmor/tls/log --json
```

`--nonk8s` uses mTLS and local client credentials without requiring a kubeconfig.
To run `karmor` as another user or on another host, securely provision only the
appropriate `ca.crt`, `client.crt`, and `client.key` in an owner-only directory and
pass that directory to the command. Do not distribute `ca.key`, and give log
readers only log credentials. Remote addresses must match the server certificate's
SANs and be reachable through the configured listener/firewall.

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
