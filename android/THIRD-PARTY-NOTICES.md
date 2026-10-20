# FieldKit 1.0.0 third-party notices

Version 1.0.0 uses the published `androidx.core.uwb:uwb-rxjava3:1.0.0` AndroidX UWB implementation and its transitive runtime dependencies. The exact resolved set is pinned in [app/gradle.lockfile](app/gradle.lockfile). This record was prepared by inspecting those artifacts' resolved upstream Maven POM license declarations, Guava parent POM declarations and license/notice files supplied in their published JARs/AARs. Library source has not been modified for this build.

The readable inventory is also packaged in the APK as [app/src/main/assets/third_party_notices.txt](app/src/main/assets/third_party_notices.txt). Full texts and the supplied upstream component notices are retained under [app/src/main/assets/licenses](app/src/main/assets/licenses). Settings provides the bundled notice inventory and license texts. A locked metadata/BOM or empty annotation artifact does not necessarily contribute executable classes.

## Declared runtime licenses

| Components | Versions in the lockfile | Upstream declared license |
|---|---|---|
| AndroidX Activity | 1.0.0 | Apache License 2.0 |
| AndroidX Annotation / annotation-jvm | 1.8.1 | Apache License 2.0 |
| AndroidX Arch Core common / runtime | 2.1.0 / 2.0.0 | Apache License 2.0 |
| AndroidX Collection | 1.1.0 | Apache License 2.0 |
| AndroidX UWB / UWB RxJava3 | 1.0.0 | Apache License 2.0 |
| AndroidX Core / Core KTX | 1.2.0 | Apache License 2.0 |
| AndroidX CustomView | 1.0.0 | Apache License 2.0 |
| AndroidX Fragment | 1.1.0 | Apache License 2.0 |
| AndroidX Lifecycle common / runtime / viewmodel | 2.1.0 | Apache License 2.0 |
| AndroidX Lifecycle livedata / livedata-core | 2.0.0 | Apache License 2.0 |
| AndroidX Loader / SavedState | 1.0.0 | Apache License 2.0 |
| AndroidX VersionedParcelable | 1.1.0 | Apache License 2.0 |
| AndroidX ViewPager | 1.0.0 | Apache License 2.0 |
| Google Play Services base / basement | 18.6.0 | Android Software Development Kit License |
| Google Play Services nearby | 19.2.0 | Android Software Development Kit License |
| Google Play Services tasks | 18.2.1 | Android Software Development Kit License |
| FindBugs jsr305 | 3.0.2 | Apache License 2.0 |
| Error Prone annotations | 2.18.0 | Apache License 2.0 |
| Guava | 32.0.1-android | Apache License 2.0, inherited from its parent POM |
| Guava failureaccess | 1.0.1 | Apache License 2.0, inherited from its parent POM |
| Guava listenablefuture empty conflict-avoidance artifact | 9999.0-empty-to-avoid-conflict-with-guava | Apache License 2.0, inherited from its parent POM |
| J2ObjC annotations | 2.8 | Apache License 2.0 |
| RxJava3 | 3.0.2 | Apache License 2.0 |
| Checker Framework checker-qual | 3.33.0 | MIT |
| Kotlin standard library | 2.1.20 | Apache License 2.0 |
| Kotlin coroutines android / core / core-jvm / play-services / reactive / rx3 / BOM | 1.9.0 | Apache License 2.0 |
| JetBrains annotations | 23.0.0 | Apache License 2.0 |
| Reactive Streams | 1.0.3 | CC0 1.0 |

The inventory contains 43 locked Maven coordinates. The Apache-licensed dependencies' declarations do not replace any additional component-specific attribution shipped inside a library. Google Play Services itself declares the [Android SDK terms](https://developer.android.com/studio/terms), and its bundled third-party notices contain several license families, including GPL with a Classpath exception and other component-specific terms. Their original complete texts and indexes are preserved rather than relabeled Apache. These upstream notice bundles do not establish that FieldKit separately links every component referenced by a bundle.

## Included full texts and upstream attribution

- [Apache License 2.0](app/src/main/assets/licenses/apache-2.0.txt), obtained unchanged from the [Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt). SHA-256: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
- [CC0 1.0 Universal](app/src/main/assets/licenses/cc0-1.0.txt), obtained unchanged from [Creative Commons](https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt). SHA-256: `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499`.
- [Checker Framework qualifiers MIT license](app/src/main/assets/licenses/org.checkerframework-checker-qual-3.33.0-LICENSE.txt), including its original copyright notice, copied verbatim from the resolved JAR.
- AndroidX UWB and UWB RxJava3 supplied `LICENSE.txt` files, copied verbatim from their AARs into the licenses directory.
- The `third_party_licenses.txt` and matching JSON component index from each resolved Google Play Services AAR: base 18.6.0, basement 18.6.0, nearby 19.2.0 and tasks 18.2.1. All eight files are retained verbatim with coordinate-prefixed filenames. The indexes refer to offsets/lengths in the corresponding original text file.

The full Android SDK, Gradle distribution and Android build tools are development tools and are not shipped as application runtime code. Their own terms apply separately. The JSON-java implementation used by the pure JVM tests is a test-only dependency and is not bundled in the Android APK. See [BUILD-DEPENDENCIES.md](BUILD-DEPENDENCIES.md) for build setup.
