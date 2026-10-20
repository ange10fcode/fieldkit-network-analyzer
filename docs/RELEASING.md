# Releasing FieldKit

Keep `VERSION`, Android `versionName`, desktop `Version` and iOS `MARKETING_VERSION` aligned. Android `versionCode` must increase even when the public version starts below a prototype label. Public 1.0.0 uses Android code 7 and iOS build 1.

Run checks and builds before dispatching `Prepare release` on `main`. It verifies all platforms again, collects packages and creates a **draft** release. Review artifacts, notes and checksums before publication. Reruns must not overwrite published releases.

## Packages

- Signed Android APK.
- Self-contained Windows x64 ZIP and Linux x64 tar.gz, including dependency licenses.
- iOS Simulator ZIP and explicitly **unsigned** device archive ZIP.
- `SHA256SUMS.txt` for packages; GitHub also offers source archives.

Simulator apps and unsigned archives are not installable signed iPhone applications. Physical radio/ranging checks are separate from compiler validation; see [VALIDATION](VALIDATION.md).

## Private Android signing

Official 1.0 certificate SHA-256:

```text
bd24e9cfcfc0f5774ed521fec724e39e6dd41c57c5c6167f2e790b3ff8201e92
```

Keep its keystore/passwords in private access-controlled storage with an independent encrypted offline backup. Losing them prevents ordinary signed updates. Never upload private signing files or backups to GitHub, including release assets. Certificate fingerprints are public.

Local Gradle signing reads environment variables:

| Variable | Meaning |
| --- | --- |
| `FIELDKIT_KEYSTORE_PATH` | Absolute private keystore path |
| `FIELDKIT_KEYSTORE_PASSWORD` | Keystore password |
| `FIELDKIT_KEY_ALIAS` | Signing-key alias |
| `FIELDKIT_KEY_PASSWORD` | Key password |

Use a private password manager or shell session; never commit actual passwords or log them. Run `:app:assembleRelease` without `-PfieldkitUnsigned`. Verify with Android SDK `apksigner verify --verbose --print-certs` and `zipalign -c -p 4`.

Actions uses encrypted repository secrets `FIELDKIT_KEYSTORE_B64`, `FIELDKIT_KEYSTORE_PASSWORD`, `FIELDKIT_KEY_PASSWORD` and `FIELDKIT_KEY_ALIAS`. Base64 itself is **not** encryption: store the keystore value only as a secret. The workflow creates a temporary runner key, signs, verifies and removes it. Restrict workflow edits to trusted maintainers.

The old private prototype used a different development key. Export wanted data, uninstall it, then install public 1.0. The package identifier remains the same, so both cannot coexist. A higher version code cannot overcome a certificate mismatch.

## Apple signing

No Apple credentials are included. On macOS, configure the project with your Apple team/provisioning, archive and distribute through Xcode Organizer. Signed IPA/TestFlight/App Store distribution is a separate step requiring that account. Review App Privacy answers and permissions before store submission.

## Publication checklist

1. All required CI jobs pass for the exact tagged commit.
2. Version labels, platform limits and Android certificate fingerprint match.
3. Extracted desktop bundles contain libraries/licenses; Linux executable permissions survive packaging.
4. Source/packages contain no keys, tokens, reports or private network screenshots. Create source archives from tracked files with `git archive`.
5. Verify downloaded packages against `SHA256SUMS.txt`.
6. Publish the reviewed draft. Keep private backups separate from public downloads.
