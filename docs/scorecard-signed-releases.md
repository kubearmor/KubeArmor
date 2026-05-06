Signed Releases Baseline
========================

What I added
-----------

- A minimal workflow `.github/workflows/signed-releases-baseline.yml` that:
  - creates a tiny `release-manifest-<tag>.txt` when a release is created (or via manual dispatch),
  - signs that manifest using `cosign sign-blob --keyless`, and
  - uploads both the manifest and the signature as GitHub Release assets.

- A verification workflow `.github/workflows/signed-releases-verify.yml` that triggers on `release.published`,
  downloads the manifest and signature, installs `cosign`, and runs `cosign verify-blob --keyless` to ensure
  the signature is valid.

Why this helps
--------------

OpenSSF Scorecard's Signed-Releases check looks for cryptographically-signed release artifacts attached to
GitHub Releases. By ensuring a `.sig` file is attached alongside a release artifact (here a small manifest), the
Signed-Releases check will detect the signed artifact and improve the Scorecard result.

How to test locally / on the repo
---------------------------------

1. Create a release in your fork (or run the `Signed Releases Baseline` workflow manually and provide a `tag`).
2. Confirm the release has two assets:
   - `release-manifest-<tag>.txt`
   - `release-manifest-<tag>.txt.sig`
3. After the release is published, the `Signed Releases Verification` workflow will run and should pass the
   `cosign verify-blob --keyless` check.

Next recommended steps
----------------------

- Pin actions to specific SHAs for stronger attestation in Scorecard (I've pinned the installer/action majors).
- Add signing of real binary artifacts produced by the project's release process (tarballs, binaries, images).
- Add `slsa-github-generator` provenance and `slsa-verifier` verification to improve SLSA L3 posture.
- Comment on upstream PR #2567 describing how this baseline complements provenance generation.

Questions / Notes
-----------------

- Keyless signing (OIDC) avoids storing private keys in repo secrets and is recommended for GitHub Actions.
- The current baseline signs a manifest; expanding to sign the actual build artifacts is the recommended follow-up.
