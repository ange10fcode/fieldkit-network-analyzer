"""Static integrity checks only; these do not replace Xcode or Swift compiler validation."""
from pathlib import Path
import json
import plistlib
import re
import struct

root = Path(__file__).resolve().parent
project = (root/'FieldKit.xcodeproj/project.pbxproj').read_text(encoding='utf-8')
definitions = re.findall(r'^\s*([0-9A-F]{24}) = \{', project, re.M)
assert len(definitions) == len(set(definitions)), 'Duplicate Xcode object identifiers'
references = set(re.findall(r'\b[0-9A-F]{24}\b', project))
assert references == set(definitions), 'Unresolved Xcode object identifiers'
for path in re.findall(r'path = "([^"]+)"; sourceTree = SOURCE_ROOT;', project):
    assert (root/path).exists(), f'Missing project file: {path}'
for source in list((root/'FieldKit').glob('*.swift')) + list((root/'Sources/FieldKitCore').glob('*.swift')):
    assert source.relative_to(root).as_posix() in project, f'Source omitted: {source}'
for path in root.rglob('*.plist'):
    with path.open('rb') as stream: plistlib.load(stream)
for path in root.rglob('*.json'):
    json.loads(path.read_text(encoding='utf-8'))
with (root/'FieldKit/PrivacyInfo.xcprivacy').open('rb') as stream: privacy = plistlib.load(stream)
assert privacy['NSPrivacyTracking'] is False
with (root/'FieldKit/Info.plist').open('rb') as stream: info = plistlib.load(stream)
for key in ['NSNearbyInteractionUsageDescription','NSLocalNetworkUsageDescription','NSBluetoothAlwaysUsageDescription']:
    assert info[key]
assert '_fieldkit-ni._tcp' in info['NSBonjourServices']
assert '_fieldkit-ni._udp' in info['NSBonjourServices']
png = (root/'FieldKit/Assets.xcassets/AppIcon.appiconset/AppIcon.png').read_bytes()
assert png[:8] == b'\x89PNG\r\n\x1a\n'
width,height,depth,color = struct.unpack('!IIBB',png[16:26])
assert (width,height,depth,color) == (1024,1024,8,2), 'App icon must be opaque 1024px RGB'
assert (root/'FieldKit.xcodeproj/xcshareddata/xcschemes/FieldKit.xcscheme').exists()
print(f'iOS static project checks passed: {len(definitions)} objects, all sources/resources, privacy/permission keys, scheme, opaque icon.')
