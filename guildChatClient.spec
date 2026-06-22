# guildChatClient.spec
# Run with: pyinstaller guildChatClient.spec
#
# Before building, run: python generate_icons.py
# This generates icon_r.png, icon_y.png, icon_g.png from icons/icon.png
# All four icon files are then bundled into the exe.

from PyInstaller.building.build_main import Analysis, PYZ, EXE

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
    upx=True,
    upx_exclude=[],
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)