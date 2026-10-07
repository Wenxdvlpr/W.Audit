# Release provenance preparation

This is a checklist for future official releases, not a claim that signatures or a public repository already exist.

1. Confirm the copyright holder, canonical repository, GitHub private vulnerability reporting setting, and rights to license included work under Apache-2.0.
2. Use a SemVer version and matching Git tag. Preserve the Git history; prefer signed commits and signed release tags when the maintainer has a suitable signing setup.
3. Build source and wheel artifacts from the tagged revision. Record the build environment and publish SHA-256 checksums for each artifact.
4. Generate and publish a version-matched SBOM. Describe the ecosystems it covers and any omitted dependency sources.
5. Publish the changelog and release notes with the exact tag and artifact checksums.
6. Add provenance or artifact signing where practical. Keep signing keys and credentials outside the repository, and verify published signatures before claiming a signed release.

No signing key, fake signature, or canonical URL is included in this repository preparation.
