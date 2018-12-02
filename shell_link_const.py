CLSID = '\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F'

LINK_FLAGS_NAMES = [
    'HasLinkTargetIDList',  # LinkTargetIDList struct follows the ShellLinkHeader struct
    'HasLinkInfo',  # LinkInfo struct present
    'HasName',  # NameString present as a StringData struct
    'HasRelativePath',  # RelativePath present as a StringData struct
    'HasWorkingDir',  # WorkingDir present as a StringData struct
    'HasArguments',  # CommandLineArguments present as a StringData struct
    'HasIconLocation',  # IconLocation present as a StringData struct
    'IsUnicode',  # StringData section contains Unicode-encoded strings, otherwise, system default code page
    'ForceNoLinkInfo',  # ignore LinkInfo struct
    'HasExpString',  # The shell link is saved with an EnvironmentVariableDataBlock
    'RunInSeparateProcess',  # target is run in a separate VM if it is a 16-bit application
    'Unused1',  # must be ignored
    'HasDarwinID',  # The shell link is saved with a DarwinDataBlock
    'RunAsUser',  # The application is run as a different user when the target of the shell link is activated.
    'HasExpIcon',  # The shell link is saved with an IconEnvironmentDataBlock
    'NoPidlAlias',  # item path represented in the shell namespace when parsed into an IDList.
    'Unused2',  # must be ignored
    'RunWithShimLayer',  # The shell link is saved with a ShimDataBlock
    'ForceNoLinkTrack',  # ignore TrackerDataBlock
    'EnableTargetMetadata',  # shell link attempts to collect and store target properties in PropertyStoreDataBlock
    'DisableLinkPathTracking',  # ignore EnvironmentVariableDataBlock
    'DisableKnownFolderTracking',  # ignore and don't store SpecialFolderDataBlock and KnownFolderDataBlock
    'DisableKnownFolderAlias',  # tldr
    'AllowLinkToLink',  # link can link to another link
    'UnaliasOnSave',  # tldr
    'PreferEnvironmentPath',  # ignore and don't store target IDList, use EnvironmentVariableDataBlock
    'KeepLocalIDListForUNCTarget',  # tldr
]

FILE_ATTRS_FLAGS_NAMES = [
    'FILE_ATTRIBUTE_READONLY',  # can read, cannot write/del target file (if dir cannot delete)
    'FILE_ATTRIBUTE_HIDDEN',  # target is hidden
    'FILE_ATTRIBUTE_SYSTEM',  # target is system file
    'Reserved1',  # must be zero
    'FILE_ATTRIBUTE_DIRECTORY',  # target is dir
    'FILE_ATTRIBUTE_ARCHIVE',  # target is archivable
    'Reserved2',  # must be zero
    'FILE_ATTRIBUTE_NORMAL',  # no flags, all others must be zero
    'FILE_ATTRIBUTE_TEMPORARY',  # target is temp storge
    'FILE_ATTRIBUTE_SPARSE_FILE',  # target is sparse file
    'FILE_ATTRIBUTE_REPARSE_POINT',  # target has reparse point (?)
    'FILE_ATTRIBUTE_COMPRESSED',  # target is ntfs compressed (if dir, all new subdirs will be too)
    'FILE_ATTRIBUTE_OFFLINE',  # might not be immeduately available
    'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',  # target contents still not indexed
    'FILE_ATTRIBUTE_ENCRYPTED',  # encrypted (if dir, all new subdirs will be too
]

HOT_KEY_LOW = {
    0x30: '0',
    0x31: '1',
    0x32: '2',
    0x33: '3',
    0x34: '4',
    0x35: '5',
    0x36: '6',
    0x37: '7',
    0x38: '8',
    0x39: '9',
    0x41: 'A',
    0x42: 'B',
    0x43: 'C',
    0x44: 'D',
    0x45: 'E',
    0x46: 'F',
    0x47: 'G',
    0x48: 'H',
    0x49: 'I',
    0x4A: 'J',
    0x4B: 'K',
    0x4C: 'L',
    0x4D: 'M',
    0x4E: 'N',
    0x4F: 'O',
    0x50: 'P',
    0x51: 'Q',
    0x52: 'R',
    0x53: 'S',
    0x54: 'T',
    0x55: 'U',
    0x56: 'V',
    0x57: 'W',
    0x58: 'X',
    0x59: 'Y',
    0x5A: 'Z',
    0x70: 'F1',
    0x71: 'F2',
    0x72: 'F3',
    0x73: 'F4',
    0x74: 'F5',
    0x75: 'F6',
    0x76: 'F7',
    0x77: 'F8',
    0x78: 'F9',
    0x79: 'F10',
    0x7A: 'F11',
    0x7B: 'F12',
    0x7C: 'F13',
    0x7D: 'F14',
    0x7E: 'F15',
    0x7F: 'F16',
    0x80: 'F17',
    0x81: 'F18',
    0x82: 'F19',
    0x83: 'F20',
    0x84: 'F21',
    0x85: 'F22',
    0x86: 'F23',
    0x87: 'F24',
    0x90: 'NUM LOCK',
    0x91: 'SCROLL LOCK',
}

HOT_KEY_HIGH = {
    0x01: 'SHIFT',
    0x02: 'CTRL',
    0x04: 'ALT',
}

SHOW_OPTIONS = {
    0x00000001: 'SW_SHOWNORMAL',
    0x00000003: 'SW_SHOWMAXIMIZED',
    0x00000007: 'SW_SHOWMINNOACTIVE',
}

LINK_INFO_FLAGS_NAMES = [
    'VolumeIDAndLocalBasePath',  # VolumeID and LocalBasePath (and LocalBasePathUnicode) exist, else offsets zeroed
    'CommonNetworkRelativeLinkAndPathSuffix',  # CommonNetworkRelativeLink exists, else offset zeroed
]

NET_REL_LINK_FLAGS_NAMES = [
    'ValidDevice',  # DeviceNameOffset field contains an offset to the device name, else equals zero
    'ValidNetType',  # NetProviderType field contains the network provider type, else equals zero
]

DRIVE_TYPES = {

    0x00000000: 'DRIVE_UNKNOWN',  # The drive type cannot be determined.
    0x00000001: 'DRIVE_NO_ROOT_DIR',  # The root path is invalid; for example, there is no volume mounted at the path.
    0x00000002: 'DRIVE_REMOVABLE',  # removable media, such as a floppy drive, thumb drive, or flash card reader.
    0x00000003: 'DRIVE_FIXED',  # The drive has fixed media, such as a hard drive or flash drive.
    0x00000004: 'DRIVE_REMOTE',  # The drive is a remote (network) drive.
    0x00000005: 'DRIVE_CDROM',  # The drive is a CD-ROM drive.
    0x00000006: 'DRIVE_RAMDISK',  # The drive is a RAM disk.
}

NETWORK_PROVIDER_TYPES = {
    0x001A0000: 'WNNC_NET_AVID',
    0x001B0000: 'WNNC_NET_DOCUSPACE',
    0x001C0000: 'WNNC_NET_MANGOSOFT',
    0x001D0000: 'WNNC_NET_SERNET',
    0x001E0000: 'WNNC_NET_RIVERFRONT1',
    0x001F0000: 'WNNC_NET_RIVERFRONT2',
    0x00200000: 'WNNC_NET_DECORB',
    0x00210000: 'WNNC_NET_PROTSTOR',
    0x00220000: 'WNNC_NET_FJ_REDIR',
    0x00230000: 'WNNC_NET_DISTINCT',
    0x00240000: 'WNNC_NET_TWINS',
    0x00250000: 'WNNC_NET_RDR2SAMPLE',
    0x00260000: 'WNNC_NET_CSC',
    0x00270000: 'WNNC_NET_3IN1',
    0x00290000: 'WNNC_NET_EXTENDNET',
    0x002A0000: 'WNNC_NET_STAC',
    0x002B0000: 'WNNC_NET_FOXBAT',
    0x002C0000: 'WNNC_NET_YAHOO',
    0x002D0000: 'WNNC_NET_EXIFS',
    0x002E0000: 'WNNC_NET_DAV',
    0x002F0000: 'WNNC_NET_KNOWARE',
    0x00300000: 'WNNC_NET_OBJECT_DIRE',
    0x00310000: 'WNNC_NET_MASFAX',
    0x00320000: 'WNNC_NET_HOB_NFS',
    0x00330000: 'WNNC_NET_SHIVA',
    0x00340000: 'WNNC_NET_IBMAL',
    0x00350000: 'WNNC_NET_LOCK',
    0x00360000: 'WNNC_NET_TERMSRV',
    0x00370000: 'WNNC_NET_SRT',
    0x00380000: 'WNNC_NET_QUINCY',
    0x00390000: 'WNNC_NET_OPENAFS',
    0x003A0000: 'WNNC_NET_AVID1',
    0x003B0000: 'WNNC_NET_DFS',
    0x003C0000: 'WNNC_NET_KWNP',
    0x003D0000: 'WNNC_NET_ZENWORKS',
    0x003E0000: 'WNNC_NET_DRIVEONWEB',
    0x003F0000: 'WNNC_NET_VMWARE',
    0x00400000: 'WNNC_NET_RSFX',
    0x00410000: 'WNNC_NET_MFILES',
    0x00420000: 'WNNC_NET_MS_NFS',
    0x00430000: 'WNNC_NET_GOOGLE',
}

FILL_ATTRIBUTES = {
    0x0001: 'FOREGROUND_BLUE',  # The foreground text color contains blue.
    0x0002: 'FOREGROUND_GREEN',  # The foreground text color contains green.
    0x0004: 'FOREGROUND_RED',  # The foreground text color contains red.
    0x0008: 'FOREGROUND_INTENSITY',  # The foreground text color is intensified.
    0x0010: 'BACKGROUND_BLUE',  # The background text color contains blue.
    0x0020: 'BACKGROUND_GREEN',  # The background text color contains green.
    0x0040: 'BACKGROUND_RED',  # The background text color contains red.
    0x0080: 'BACKGROUND_INTENSITY',  # The background text color is intensified.
}

FONT_FAMILY = {
    0x0000: 'FF_DONTCARE',  # The font family is unknown.
    0x0010: 'FF_ROMAN',  # The font is variable-width with serifs; for example, "Times New Roman".
    0x0020: 'FF_SWISS',  # The font is variable-width without serifs; for example, "Arial".
    0x0030: 'FF_MODERN',  # The font is fixed-width, with or without serifs; for example, "Courier New".
    0x0040: 'FF_SCRIPT',  # The font is designed to look like handwriting; for example, "Cursive".
    0x0050: 'FF_DECORATIVE',  # The font is a novelty font; for example, "Old English".
}
