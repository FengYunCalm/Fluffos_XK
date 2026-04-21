# Release Policy

## Release shape

This fork uses workflow-driven tagged releases for runtime binaries and container images.

## Versioning

- Release tags are generated as `vYYYY.MMDD.N`.
- Use the release workflow to create the tag rather than inventing a second versioning scheme.

## Before release

- Update `CHANGELOG.md` with the fork-specific changes.
- Verify the Windows and Linux build paths you expect the workflow to exercise.
- Keep release notes scoped to the fork changes: build reliability, warning cleanup, and packaging hygiene.

## Automation

The release workflow creates the tag, builds platform assets, uploads them to the GitHub Release, and publishes container images.

## Notes

- Use prerelease mode when the build is not yet final.
- Do not describe upstream history as if it were a fork-specific release change.
