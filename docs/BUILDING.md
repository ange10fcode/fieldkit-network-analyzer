# Building FieldKit 1.0.0

Use the committed dependency locks. Python 3 runs repository checks and packaging; it adds no app runtime dependency.

```sh
python3 scripts/verify_release.py
```

## Android

Install JDK 21 and an Android SDK containing `platforms;android-36` and `build-tools;36.0.0`. Set `ANDROID_HOME` to that SDK. The wrapper pins Gradle 8.11.1 and its SHA-256; Android Gradle Plugin 8.10.1 resolves locked dependencies.

```sh
python3 scripts/test_android.py
cd android
./gradlew --no-daemon --console=plain :app:assembleRelease -PfieldkitUnsigned=true
```

On Windows, use `python` and `gradlew.bat`. Output is `android/app/build/outputs/apk/release/app-release-unsigned.apk`; it needs signing before installation. For private signed builds, provide the four signing variables in [RELEASING](RELEASING.md) and omit `-PfieldkitUnsigned=true`.

The app supports API 26 and later. Optional AndroidX UWB declares API 31; its manifest override is intentional and guarded before initializing UWB. Preserve that boundary when changing UWB code. See [Android dependencies](../android/BUILD-DEPENDENCIES.md).

## Windows and Linux

Install .NET SDK 10.0.402, pinned in `desktop/global.json`. From the repository root:

```sh
dotnet restore desktop/FieldKit.Desktop/FieldKit.Desktop.csproj --locked-mode
dotnet run --project desktop/FieldKit.Core.Tests -c Release
dotnet build desktop/FieldKit.Desktop/FieldKit.Desktop.csproj -c Release --no-restore
dotnet publish desktop/FieldKit.Desktop/FieldKit.Desktop.csproj -c Release -r win-x64 --self-contained true -o artifacts/publish/win-x64
python3 scripts/package_desktop.py win-x64 artifacts/publish/win-x64 artifacts
dotnet publish desktop/FieldKit.Desktop/FieldKit.Desktop.csproj -c Release -r linux-x64 --self-contained true -o artifacts/publish/linux-x64
python3 scripts/package_desktop.py linux-x64 artifacts/publish/linux-x64 artifacts
```

UI verification uses `--smoke-ui --data-dir <temporary-directory>`; prefix with `xvfb-run -a` on Linux CI. `--smoke-test` checks inventory/storage without network probes. Core tests use actual loopback sockets, never a connected LAN. See [desktop requirements](../desktop/README.md).

## iOS

Use macOS with Xcode 16 or later. There are no external Swift packages.

```sh
swift test --package-path ios
xcodebuild -project ios/FieldKit.xcodeproj -scheme FieldKit -sdk iphonesimulator -configuration Release -destination 'generic/platform=iOS Simulator' -derivedDataPath work/ios-derived CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ios/FieldKit.xcodeproj -scheme FieldKit -configuration Release -destination 'generic/platform=iOS' -archivePath artifacts/FieldKit-1.0.0-iOS-UNSIGNED.xcarchive CODE_SIGNING_ALLOWED=NO archive
```

These create a Simulator application and an unsigned device archive. Neither is a signed iPhone IPA. Configure your Apple team and provisioning in Xcode to run on a physical phone. App Store/TestFlight distribution needs the appropriate Apple account. See [iOS instructions](../ios/README.md).

## CI

`Build and verify` runs on `main`, pull requests and manual dispatch. Android runs on Ubuntu, desktop on Windows/Ubuntu, and iOS on macOS. Pull requests never receive release signing keys. A missing signing secret produces an explicitly named unsigned Android artifact; the release workflow requires the signed artifact.
