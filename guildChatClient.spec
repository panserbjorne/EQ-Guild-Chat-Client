# guildChatClient.spec
# Run with: pyinstaller guildChatClient.spec
#
# Before building, run: python generate_icons.py
# This generates icon_r.png, icon_y.png, icon_g.png from icons/icon.png
# All four icon files are then bundled into the exe.

import re

from PyInstaller.building.build_main import Analysis, PYZ, EXE
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct,
    VarFileInfo, VarStruct,
)

# Windows version resource. An exe with real publisher/product metadata looks
# less like anonymous malware to AV heuristics. Version comes from config.py
# (read as text so the spec doesn't need to import the app's dependencies).
with open('config.py', encoding='utf-8') as f:
    APP_VERSION = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', f.read(), re.M).group(1)
_v = tuple((list(map(int, re.findall(r'\d+', APP_VERSION))) + [0, 0, 0, 0])[:4])

version_info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=_v, prodvers=_v),
    kids=[
        StringFileInfo([StringTable('040904B0', [
            StringStruct('CompanyName',      'EQ Guild Chat'),
            StringStruct('FileDescription',  'EQ Guild Chat Client'),
            StringStruct('FileVersion',      APP_VERSION),
            StringStruct('InternalName',     'guildChatClient'),
            StringStruct('OriginalFilename', 'guildChatClient.exe'),
            StringStruct('ProductName',      'EQ Guild Chat Client'),
            StringStruct('ProductVersion',   APP_VERSION),
        ])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])]),
    ],
)

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('icons/icon.png',   'icons'),
        ('icons/icon_r.png', 'icons'),
        ('icons/icon_y.png', 'icons'),
        ('icons/icon_g.png', 'icons'),
    ],
    hiddenimports=[
        'pystray',
        'pystray._win32',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        'websockets',
        'websockets.legacy',
        'websockets.legacy.client',
        'websockets.legacy.server',
        'yaml',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='guildChatClient',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX packing is a classic malware trait and a common cause of AV false
    # positives, so leave the binaries uncompressed.
    upx=False,
    upx_exclude=[],
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icons/icon.ico',
    version=version_info,
)