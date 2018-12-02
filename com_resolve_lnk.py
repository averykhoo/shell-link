import os, sys
import glob
import pythoncom
from win32com.shell import shell, shellcon


def shortcut_target(filename):
    shortcut = pythoncom.CoCreateInstance(
        shell.CLSID_ShellLink,
        None,
        pythoncom.CLSCTX_INPROC_SERVER,
        shell.IID_IShellLink
    )
    shortcut.QueryInterface(pythoncom.IID_IPersistFile).Load(filename)
    #
    # GetPath returns the name and a WIN32_FIND_DATA structure
    # which we're ignoring. The parameter indicates whether
    # shortname, UNC or the "raw path" are to be
    # returned. Bizarrely, the docs indicate that the
    # flags can be combined.
    #
    name, _ = shortcut.GetPath(shell.SLGP_UNCPRIORITY)
    return name


def shell_glob(pattern):
    for filename in glob.glob(pattern):
        if filename.endswith(".lnk"):
            yield "%s => %s" % (filename, shortcut_target(filename))
        else:
            yield filename


desktop = shell.SHGetSpecialFolderPath(None, shellcon.CSIDL_DESKTOP)
for filename in shell_glob(os.path.join(desktop, "*")):
    print(filename)
