# -*- mode: python ; coding: utf-8 -*-
from datetime import date

today = date.today()
block_cipher = None


a = Analysis(['mtk.py'],
             pathex=[],
             binaries=[],
             datas=[('mtkclient/payloads', 'mtkclient/payloads'), ('mtkclient/Loader', 'mtkclient/Loader')],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
          name='mtk_console_' + today.strftime("%Y%m%d"),
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None)
