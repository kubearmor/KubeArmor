Signed Releases Attestation Baseline
====================================

What was implemented
--------------------

- `.github/workflows/signed-releases-baseline.yml`
  - builds `kubearmor-linux-amd64.tar.gz`,
  - generates a minimal SLSA provenance predicate,
  - creates keyless attestations with `cosign attest-blob --type slsaprovenance` for both manifest and binary,
  - uploads DSSE bundles (`*.sigstore.json`) and a combined provenance file (`multiple.intoto.jsonl-linux-amd64`).
   - pins all workflow actions used in this pipeline to immutable commit SHAs.

- `.github/workflows/signed-releases-verify.yml`
  - downloads release assets,
  - verifies blob attestations using `cosign verify-blob-attestation`,
  - validates each JSONL line contains SLSA provenance payload (`predicateType == https://slsa.dev/provenance/v1`).

- `scripts/verify-release-artifacts.sh`
  - reproducible local verification for a release tag,
  - verifies attestation bundle and validates combined `.intoto.jsonl` payloads.

Why this is stronger
--------------------

Blob signatures alone can improve Signed-Releases but typically cap the score. DSSE-based attestations and
`.intoto.jsonl` provenance are the expected release assets to demonstrate provenance-aware signed releases and
support the path to a full Signed-Releases score.

Assets produced per release
---------------------------

- `release-manifest-<tag>.txt`
- `release-manifest-<tag>.txt.sigstore.json`
- `release-manifest-<tag>.txt.attestation.json`
- `kubearmor-linux-amd64.tar.gz`
- `kubearmor-linux-amd64.tar.gz.sigstore.json`
- `kubearmor-linux-amd64.tar.gz.attestation.json`
- `multiple.intoto.jsonl-linux-amd64`

How to run and verify
---------------------

1. Trigger baseline workflow manually (or create a release):

   `gh workflow run "Signed Releases Baseline" -R <owner>/<repo> -f tag=<tag>`

2. Verify workflow on release publish, or run manual verification workflow:

   `gh workflow run "Signed Releases Verification" -R <owner>/<repo> -f tag=<tag>`

3. Verify locally with script:

   `bash scripts/verify-release-artifacts.sh <owner>/<repo> <tag>`

4. Manual binary attestation verification example:

   `cosign verify-blob-attestation --bundle kubearmor-linux-amd64.tar.gz.sigstore.json --type slsaprovenance --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*" kubearmor-linux-amd64.tar.gz`


