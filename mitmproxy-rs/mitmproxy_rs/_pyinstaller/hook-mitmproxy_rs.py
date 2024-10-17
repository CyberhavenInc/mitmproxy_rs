import sys
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("mitmproxy_rs")

hiddenimports = []

if sys.platform == "win32":
    hiddenimports.append("mitmproxy_windows")
