import os, sys
import pythoncom
from win32com.shell import shell, shellcon

shortcut = pythoncom.CoCreateInstance (
  shell.CLSID_ShellLink,
  None,
  pythoncom.CLSCTX_INPROC_SERVER,
  shell.IID_IShellLink
)
desktop_path = shell.SHGetFolderPath (0, shellcon.CSIDL_DESKTOP, 0, 0)
shortcut_path = os.path.join (desktop_path, "python.lnk")
persist_file = shortcut.QueryInterface (pythoncom.IID_IPersistFile)
persist_file.Load (shortcut_path)

shortcut.SetDescription ("Updated Python %s" % sys.version)
mydocs_path = shell.SHGetFolderPath (0, shellcon.CSIDL_PERSONAL, 0, 0)
shortcut.SetWorkingDirectory (mydocs_path)

persist_file.Save (shortcut_path, 0)