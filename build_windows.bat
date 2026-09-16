@echo off
setlocal
py -m pip install --upgrade pyinstaller cryptography
py -m PyInstaller --onefile --clean --name hichip-analyze hichip_analyze_launcher.py
py -m PyInstaller --onefile --clean --name hichip-probe hichip_probe_launcher.py
py -m PyInstaller --onefile --clean --name hichip-client222 hichip_client_launcher.py
echo.
echo Executables created in dist\
echo NOTE: private_material is intentionally not bundled into the executable.
