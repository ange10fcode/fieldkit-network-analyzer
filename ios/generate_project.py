"""Deterministic, dependency-free Xcode project and vector-derived app icon generation."""
from pathlib import Path
import hashlib
import json
import math
import struct
import zlib

ROOT = Path(__file__).resolve().parent
def ident(label):
    return hashlib.sha256(label.encode()).hexdigest()[:24].upper()
def quoted(value):
    return json.dumps(str(value))

def app_icon():
    size = 1024
    background = (11,22,34)
    teal = (33,198,183)
    pale = (221,255,248)
    pixels = bytearray(bytes(background) * size * size)
    def line_distance(x,y,a,b):
        dx,dy = b[0]-a[0],b[1]-a[1]
        t = max(0,min(1,((x-a[0])*dx+(y-a[1])*dy)/(dx*dx+dy*dy)))
        return math.hypot(x-a[0]-t*dx,y-a[1]-t*dy)
    points = [(512,300),(278,640),(746,640)]
    lines = [(points[0],points[1]),(points[0],points[2]),(points[1],points[2])]
    for y in range(size):
        for x in range(size):
            color = background
            if any(line_distance(x,y,a,b) <= 16 for a,b in lines): color = teal
            for cx,cy in points:
                distance = math.hypot(x-cx,y-cy)
                if distance <= 82: color = pale
                if distance < 52: color = background
            if line_distance(x,y,(438,796),(586,796)) <= 11: color = teal
            offset = (y*size+x)*3
            pixels[offset:offset+3] = bytes(color)
    def chunk(kind,data):
        return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    rows = b''.join(b'\0'+pixels[y*size*3:(y+1)*size*3] for y in range(size))
    png = b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(rows,9))+chunk(b'IEND',b'')
    (ROOT/'FieldKit/Assets.xcassets/AppIcon.appiconset/AppIcon.png').write_bytes(png)

def project():
    objects = []
    def add(name,body): objects.append(f'\t\t{ident(name)} = {{ {body} }};')
    sources = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'FieldKit').glob('*.swift')) + ['Sources/FieldKitCore/Core.swift']
    resources = ['FieldKit/Assets.xcassets','FieldKit/PrivacyInfo.xcprivacy','FieldKit/LICENSE.txt']
    file_ids = []
    for path in sources+resources+['FieldKit/Info.plist','FieldKit/FieldKit.entitlements']:
        kind = 'sourcecode.swift' if path.endswith('.swift') else 'folder.assetcatalog' if path.endswith('.xcassets') else 'text' if path.endswith('.txt') else 'text.plist.xml'
        add('file:'+path,f'isa = PBXFileReference; lastKnownFileType = {kind}; path = {quoted(path)}; sourceTree = SOURCE_ROOT;')
        file_ids.append(ident('file:'+path))
        if path in sources+resources:
            add('build:'+path,f'isa = PBXBuildFile; fileRef = {ident("file:"+path)};')
    add('app','isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = FieldKit.app; sourceTree = BUILT_PRODUCTS_DIR;')
    add('products',f'isa = PBXGroup; children = ({ident("app")}); name = Products; sourceTree = "<group>";')
    add('main',f'isa = PBXGroup; children = ({", ".join(file_ids)}, {ident("products")}); sourceTree = "<group>";')
    for name,kind,paths in [('sources','PBXSourcesBuildPhase',sources),('resources','PBXResourcesBuildPhase',resources),('frameworks','PBXFrameworksBuildPhase',[])]:
        add(name,f'isa = {kind}; buildActionMask = 2147483647; files = ({", ".join(ident("build:"+p) for p in paths)}); runOnlyForDeploymentPostprocessing = 0;')
    add('target',f'isa = PBXNativeTarget; buildConfigurationList = {ident("target-configs")}; buildPhases = ({ident("sources")}, {ident("frameworks")}, {ident("resources")}); buildRules = (); dependencies = (); name = FieldKit; productName = FieldKit; productReference = {ident("app")}; productType = "com.apple.product-type.application";')
    add('project',f'isa = PBXProject; attributes = {{ BuildIndependentTargetsInParallel = YES; LastSwiftUpdateCheck = 1600; LastUpgradeCheck = 1600; TargetAttributes = {{ {ident("target")} = {{ CreatedOnToolsVersion = 16.0; }}; }}; }}; buildConfigurationList = {ident("project-configs")}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base); mainGroup = {ident("main")}; productRefGroup = {ident("products")}; projectDirPath = ""; projectRoot = ""; targets = ({ident("target")});')
    for config in ['Debug','Release']:
        common = {'CLANG_ENABLE_MODULES':'YES','IPHONEOS_DEPLOYMENT_TARGET':'16.0','SDKROOT':'iphoneos','SWIFT_VERSION':'5.0','SWIFT_STRICT_CONCURRENCY':'minimal','ENABLE_USER_SCRIPT_SANDBOXING':'YES'}
        if config == 'Debug': common.update(SWIFT_OPTIMIZATION_LEVEL='-Onone',DEBUG_INFORMATION_FORMAT='dwarf',SWIFT_ACTIVE_COMPILATION_CONDITIONS='DEBUG')
        else: common.update(SWIFT_COMPILATION_MODE='wholemodule',SWIFT_OPTIMIZATION_LEVEL='-O',DEBUG_INFORMATION_FORMAT='dwarf-with-dsym')
        target = {'PRODUCT_BUNDLE_IDENTIFIER':'com.fieldkit.analyzer','PRODUCT_NAME':'$(TARGET_NAME)','INFOPLIST_FILE':'FieldKit/Info.plist','GENERATE_INFOPLIST_FILE':'NO','CODE_SIGN_ENTITLEMENTS':'FieldKit/FieldKit.entitlements','CODE_SIGN_STYLE':'Automatic','CURRENT_PROJECT_VERSION':'1','MARKETING_VERSION':'1.0.0','TARGETED_DEVICE_FAMILY':'1,2','SUPPORTED_PLATFORMS':'iphoneos iphonesimulator','SUPPORTS_MACCATALYST':'NO','ASSETCATALOG_COMPILER_APPICON_NAME':'AppIcon','LD_RUNPATH_SEARCH_PATHS':'$(inherited) @executable_path/Frameworks','SWIFT_EMIT_LOC_STRINGS':'YES'}
        for label,settings in [('project',common),('target',target)]:
            body = ' '.join(f'{key} = {quoted(value)};' for key,value in settings.items())
            add(label+':'+config,f'isa = XCBuildConfiguration; buildSettings = {{ {body} }}; name = {config};')
    for label in ['project','target']:
        add(label+'-configs',f'isa = XCConfigurationList; buildConfigurations = ({ident(label+":Debug")}, {ident(label+":Release")}); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
    folder = ROOT/'FieldKit.xcodeproj'
    folder.mkdir(exist_ok=True)
    (folder/'project.pbxproj').write_text('// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tclasses = {};\n\tobjectVersion = 56;\n\tobjects = {\n'+'\n'.join(objects)+'\n\t};\n\trootObject = '+ident('project')+';\n}\n',encoding='utf-8')
    schemes = folder/'xcshareddata/xcschemes'; schemes.mkdir(parents=True,exist_ok=True)
    reference = f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ident("target")}" BuildableName="FieldKit.app" BlueprintName="FieldKit" ReferencedContainer="container:FieldKit.xcodeproj"/>'
    (schemes/'FieldKit.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{reference}</BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables/></TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0">{reference}</BuildableProductRunnable></LaunchAction>
<ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0">{reference}</BuildableProductRunnable></ProfileAction>
<AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''',encoding='utf-8')

if __name__ == '__main__':
    project()
    app_icon()
    print('Generated FieldKit.xcodeproj, shared scheme and 1024 px app icon.')
