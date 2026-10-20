# Desktop third-party notices

FieldKit source is MIT licensed. Dependencies retain their own licenses; the app license does not replace the notices below. Full notices are distributed under `licenses/` beside the executable. Version/content hashes are recorded in `FieldKit.Desktop/packages.lock.json`.

| Component | Pinned version | License and upstream |
| --- | --- | --- |
| Avalonia, Desktop, Fluent theme, Native, Skia backend, Win32, X11, FreeDesktop, Remote.Protocol, Fonts.Inter wrapper | 11.3.22 | [MIT](https://github.com/AvaloniaUI/Avalonia/blob/11.3.22/licence.md) |
| Avalonia.BuildServices (build only) | 11.3.2 | MIT, distributed package metadata |
| Inter typeface | Bundled by Avalonia.Fonts.Inter 11.3.22 | [SIL Open Font License 1.1](https://github.com/rsms/inter/blob/v4.0/LICENSE.txt); copyright The Inter Project Authors |
| MicroCom.Runtime | 0.11.0 | MIT; copyright Nikita Tsukanov; [upstream](https://github.com/kekekeks/MicroCom) |
| Tmds.DBus.Protocol | 0.21.3 | MIT; copyright Tom Deseyn; [upstream](https://github.com/tmds/Tmds.DBus/tree/8cb04f66c330b64244e996ff68f685f27f7381a0) |
| SkiaSharp and native assets | 2.88.9 | MIT managed wrapper, plus the full bundled native third-party notices including Skia, FreeType, libpng, ICU and other components; [upstream](https://github.com/mono/SkiaSharp/tree/v2.88.9) |
| HarfBuzzSharp and native assets | 8.3.1.1 | MIT managed wrapper, plus the full bundled native third-party notices; [upstream](https://github.com/mono/SkiaSharp) |
| Avalonia ANGLE Windows natives | 2.1.25547.20250602 | BSD-style ANGLE license and bundled third-party notices, reproduced from the package's `LICENSE` |
| Microsoft .NET self-contained runtime | 10.0.13 | [MIT and third-party notices](https://github.com/dotnet/runtime/tree/v10.0.13) |

The native Skia/HarfBuzz/ANGLE components are **not all MIT licensed**. Consult their complete copied notices before redistributing a modified package. Packages for other operating systems can appear in the restore graph; only applicable native binaries are included in each self-contained publish.
