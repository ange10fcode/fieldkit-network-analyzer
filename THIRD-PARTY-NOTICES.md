# Third-party notices

The FieldKit application code is MIT licensed. Its runtime and build dependencies
retain their original licenses, which are not replaced by the repository license.

- Android: see `android/THIRD-PARTY-NOTICES.md` and the original notices bundled
  under `android/app/src/main/assets/licenses`. Runtime versions are locked in
  `android/app/gradle.lockfile`.
- Desktop: see `desktop/THIRD-PARTY-NOTICES.md` and the NuGet lock files. The
  desktop release bundles the .NET runtime and required native rendering libraries.
- iOS: uses Apple system frameworks; Apple's SDK and distribution terms apply
  separately from FieldKit's source-code license.

Developer toolchains are not included in source releases. Build workflows fetch
pinned dependencies from their official distribution repositories.
