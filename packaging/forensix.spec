from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPEC).resolve().parents[1]
web_root = project_root / "apps" / "web" / "dist"
if not (web_root / "index.html").is_file():
    raise SystemExit("Build apps/web before creating the desktop bundle.")

datas = [
    (str(web_root), "web"),
    (str(project_root / "server" / "alembic"), "migrations/alembic"),
    (str(project_root / "server" / "alembic.ini"), "migrations"),
]
datas += collect_data_files("alembic")
datas += collect_data_files("reportlab")
hiddenimports = (
    collect_submodules("forensix_api")
    + collect_submodules("forensix_server")
    + collect_submodules("forensix_forensic")
)

analysis = Analysis(
    [str(project_root / "apps" / "api" / "src" / "forensix_api" / "desktop.py")],
    pathex=[
        str(project_root / "apps" / "api" / "src"),
        str(project_root / "server" / "src"),
        str(project_root / "forensic" / "src"),
    ],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="ForensiX",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
collection = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="ForensiX",
)
