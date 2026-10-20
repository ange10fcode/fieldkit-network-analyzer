# FieldKit 1.0.0 Android build dependencies

The Android app uses Android Gradle Plugin 8.10.1 and Gradle 8.11.1. The committed Gradle wrapper downloads the official distribution and verifies its SHA-256:

`f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6`

The SDK must contain standard `platforms/android-36` and `build-tools/36.0.0` directories. CI uses JDK 21; source targets Java 8 and Android API 26. Set `ANDROID_HOME` to your SDK, then run `./gradlew --no-daemon :app:assembleRelease -PfieldkitUnsigned=true` from `android/` (`gradlew.bat` on Windows).

The direct runtime dependency is `androidx.core.uwb:uwb-rxjava3:1.0.0`. It provides Java/RxJava access to real Android UWB sessions. Gradle resolves the AAR resources, runtime libraries, manifest entries and DEX classes.

The UWB RxJava library declares API 31 as its minimum. The app deliberately overrides that library manifest requirement because UWB is optional: the capability check on older Android versions returns unsupported before initializing the UWB implementation. The app's other tools retain API 26 support. This boundary must be checked whenever UWB dependencies or entry points change.

Dependency versions are pinned in `app/gradle.lockfile`. Dependency updates should be deliberate and followed by a complete APK build and device compatibility checks. No analytics, advertising or application server dependency is included.

Public source contains no signing key. The command above generates an unsigned verification APK. Installable releases require the private signing environment described in [RELEASING](../docs/RELEASING.md).

Official build compatibility: https://developer.android.com/build/releases/agp-8-10-0-release-notes

Official Gradle distribution: https://services.gradle.org/distributions/gradle-8.11.1-bin.zip

Official checksum: https://services.gradle.org/distributions/gradle-8.11.1-bin.zip.sha256
