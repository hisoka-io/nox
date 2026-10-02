# Releasing

Releases are cut from `main` by pushing a tag `v<version>`. The tag drives `.github/workflows/docker.yml`.

## Versioning

- All crates share one version, set once in `[workspace.package]` in the root `Cargo.toml`. Member crates use
  `version.workspace = true`.
- Path dependencies between workspace crates repeat that version (`version = "0.4.0-rc.2"`) so the crates stay
  publishable. `scripts/check-release.sh` fails if any of them disagree.
- `main` carries the version of the next release. Builds from untagged commits report it with the commit hash
  appended (`x-nox-version: 0.4.0-rc.2+<sha>`), so the hash tells them apart from the tagged image.

## Changelog

Every user-visible change adds a line to `## [Unreleased]` in `CHANGELOG.md` in the same PR. Write it for
operators: what changes for them, and anything they must do when upgrading (volume ownership, config keys,
state that is dropped or replayed). Put required actions under an `### Upgrade notes` heading.

## Cutting a release

1. On a branch from `main`:
   - set `[workspace.package] version` and the internal path-dependency versions to the new version, then run
     `cargo update --workspace` so `Cargo.lock` follows;
   - rename `## [Unreleased]` to `## [<version>] - <YYYY-MM-DD>` and add an empty `## [Unreleased]` above it;
   - run `bash scripts/check-release.sh v<version>`.
2. Merge the PR once CI is green.
3. Tag the merge commit on `main` and push the tag:

   ```bash
   git tag -a v<version> -m "nox v<version>" <merge-commit>
   git push origin v<version>
   ```

Only tags that look like versions (`v1.2.3`, `v1.2.3-rc.1`) start the workflow. It then:

1. checks that the tag equals the crate version and that `CHANGELOG.md` has a dated section for it;
2. runs the full CI workflow (`ci.yml`) on the tagged commit;
3. builds and pushes `ghcr.io/hisoka-io/nox:<version>` and `:sha-<short>` only if both pass;
4. creates the GitHub release `v<version>` with the changelog section as notes and the image digest. Versions
   with a pre-release suffix (`-rc.N`) are marked as pre-releases.

If a step fails before the image is pushed, nothing is published: fix the problem on `main`, delete the tag, and
tag the fixed commit. Once an image or release exists for a version, do not move its tag; cut the next version
instead.

Deploy by digest (`ghcr.io/hisoka-io/nox@sha256:...`) from the release notes, not by tag.
