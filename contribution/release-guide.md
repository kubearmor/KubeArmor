# Release Guide: Verify signed release artifacts

## Overview
KubeArmor publishes release artifacts that are signed with Sigstore cosign via GoReleaser. Starting with cosign v3, the signer must explicitly choose bundle behavior. KubeArmor signs with `--bundle=false`, which matches the previous behavior: the signature and the signing certificate are published alongside each artifact. Use them to verify what you download.

## Prerequisites
- Install cosign (v2.2+ or v3.x)
- Have sha256sum or shasum available in your shell

## What you download from a release
- The artifact you want (for example, a tarball or binary)
- The artifact’s detached signature file: <artifact>.sig
- The artifact’s signing certificate: <artifact>.cert
- The checksums file for your platform (named like kubearmor_<version>_*_checksums.txt)

## Verify the signature
1. Save the files in the same directory.
2. Run cosign verify-blob with the certificate and signature:

```
cosign verify-blob \
  --yes \
  --certificate "./<artifact>.cert" \
  --signature   "./<artifact>.sig" \
  "./<artifact>"
```

If the output contains "Verified OK", the signature is valid for that artifact.

## Verify the signer identity (recommended)
Add issuer and identity constraints to tie the signature to GitHub Actions OIDC for this repository:

```
cosign verify-blob \
  --yes \
  --certificate "./<artifact>.cert" \
  --signature   "./<artifact>.sig" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/kubearmor/KubeArmor/.github/workflows/.*' \
  "./<artifact>"
```

- --certificate-oidc-issuer ensures the certificate was issued by GitHub Actions.
- --certificate-identity-regexp scopes the workflow identity to this repo’s workflows.

## Verify checksums
After verifying the signature, confirm file integrity with the checksums file included in the release.

- Linux:
```
sha256sum -c kubearmor_*_checksums.txt | grep OK
```
- macOS:
```
shasum -a 256 -c kubearmor_*_checksums.txt | grep OK
```

## Troubleshooting
- Error about bundle or Rekor: Because we sign with `--bundle=false`, do not expect an embedded bundle. Always pass both --certificate and --signature to cosign verify-blob.
- Identity mismatch: Check that you used the correct repo-regexp and issuer. If you use a narrower identity, ensure it matches the exact workflow and ref that produced the release tag.
- Unknown command/options: Update cosign to a recent version.

## Maintainers note
- Release signing is configured in KubeArmor/.goreleaser.yaml under signs. We explicitly pass `--bundle=false` to keep certificates and signatures as separate files and preserve the previous verification flow. If signing behavior changes, update this guide accordingly.

For command help, run:
```
cosign help verify-blob
```
