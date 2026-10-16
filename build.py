#!/usr/bin/env python3
"""
Build FloatControl as a single-file Windows .exe with embedded version info.

Usage (on Windows, Python 3.10+):
    pip install -r requirements.txt pyinstaller
    python build.py

Output: dist/FloatControl-<version>.exe
Version, publisher and App ID are read from floatcontrol.py, so bump
APP_VERSION there and rebuild.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "floatcontrol.py"
ICON = ROOT / "assets" / "floatcontrol.ico"
BUILD = ROOT / "build"
DIST = ROOT / "dist"


def read_const(name: str) -> str:
    m = re.search(rf'^{name}\s*=\s*"([^"]*)"', SRC.read_text(encoding="utf-8"), re.MULTILINE)
    if not m:
        sys.exit(f"{name} not found in {SRC.name}")
    return m.group(1)


def write_version_file(path: Path, name: str, version: str, publisher: str, description: str, guid: str):
    nums = [int(x) for x in re.findall(r"\d+", version)][:4]
    nums += [0] * (4 - len(nums))
    tup = ", ".join(map(str, nums))
    app_id = f"{publisher}.{name}.NetMonitor.{guid}"
    path.write_text(
        f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({tup}),
    prodvers=({tup}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'{publisher}'),
         StringStruct(u'FileDescription', u'{description}'),
         StringStruct(u'FileVersion', u'{version}'),
         StringStruct(u'InternalName', u'{name}'),
         StringStruct(u'LegalCopyright', u'Copyright (c) {publisher}'),
         StringStruct(u'OriginalFilename', u'{name}.exe'),
         StringStruct(u'ProductName', u'{name}'),
         StringStruct(u'ProductVersion', u'{version}'),
         StringStruct(u'AppId', u'{app_id}'),
         StringStruct(u'AppGuid', u'{{{guid}}}')])
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
""",
        encoding="utf-8",
    )


def main():
    if sys.platform != "win32":
        print("warning: PyInstaller cannot cross-compile; run this on Windows (or under Wine) to get an .exe")

    name = read_const("APP_NAME")
    version = read_const("APP_VERSION")
    publisher = read_const("APP_PUBLISHER")
    description = read_const("APP_DESCRIPTION")
    guid = read_const("APP_GUID")

    BUILD.mkdir(exist_ok=True)
    version_file = BUILD / "version_info.txt"
    write_version_file(version_file, name, version, publisher, description, guid)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", name,
        "--icon", str(ICON),
        "--add-data", f"{ICON}{os.pathsep}.",
        "--version-file", str(version_file),
        "--workpath", str(BUILD / "pyinstaller"),
        "--specpath", str(BUILD),
        "--distpath", str(DIST),
        "--exclude-module", "unittest",
        "--exclude-module", "pydoc",
        "--exclude-module", "doctest",
        str(SRC),
    ]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)

    exe = DIST / f"{name}.exe"
    versioned = DIST / f"{name}-{version}.exe"
    shutil.copyfile(exe, versioned)
    print(f"\nBuilt {versioned} ({versioned.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
