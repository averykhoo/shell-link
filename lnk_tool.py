import calendar
import io
import os

import datetime
import pprint

from shell_link_const import *


def format_bytes(num):
    unit = 0
    while num >= 1024 and unit < 8:
        num /= 1024.0
        unit += 1
    unit = ['Bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'][unit]
    return ('%.2f %s' if num % 1 else '%d %s') % (num, unit)


def utc_to_local(datetime_utc):
    timestamp = calendar.timegm(datetime_utc.timetuple())
    local_dt = datetime.datetime.fromtimestamp(timestamp)
    assert datetime_utc.resolution >= datetime.timedelta(microseconds=1)
    return local_dt.replace(microsecond=datetime_utc.microsecond)


def parse_datetime(windows_filetime_bytes):
    assert len(windows_filetime_bytes) == 8
    windows_time = parse_int_unsigned_little_endian(windows_filetime_bytes)
    if not windows_time:
        return None  # undocumented but possible
    WINDOWS_TO_UNIX_EPOCH = (datetime.datetime(1601, 1, 1) - datetime.datetime(1970, 1, 1)).total_seconds()
    unix_time = windows_time / 1e7 + WINDOWS_TO_UNIX_EPOCH
    return datetime.datetime.fromtimestamp(unix_time)


def parse_binary_flag_list(flag_bytes):
    flag_int = parse_int_unsigned_little_endian(flag_bytes)
    return [bool(flag_int >> flag_index & 1) for flag_index in xrange(8 * len(flag_bytes))]


def parse_int_unsigned_little_endian(int_bytes):
    return sum(ord(byte) * (0x100 ** i) for i, byte in enumerate(int_bytes))


def parse_int_signed_little_endian(int_bytes):
    out = parse_int_unsigned_little_endian(int_bytes)
    if out >> (len(int_bytes) * 8 - 1):
        out -= (0x100 ** len(int_bytes))
    return out


class MemFile(object):
    def __init__(self, path):
        self.pos = 0
        self.seen = []
        self.seeks = []
        with io.open(path, mode='rb') as f:
            self.data = f.read()
        self.size = len(self.data)

    def read(self, length):
        prev = self.pos
        self.pos += length
        assert self.pos < self.size
        self.seen.append(range(prev, self.pos))
        return self.data[prev:self.pos]

    def seek(self, pos):
        assert 0 <= pos < self.size
        self.seeks.append(pos)
        self.pos = pos

    def tell(self):
        return self.pos


class ShellLink(object):
    def __init__(self, path):
        self.info = {}
        if os.path.isfile(path):
            self.file = MemFile(path)
            self.parse_lnk()

    def read_null_terminated_string_ascii(self):
        out = self.file.read(1)
        while out[-1] != '\x00':
            out += self.file.read(1)
        out = out[:-1]
        return out

    def read_null_terminated_string_utf16(self):
        out = '\xfe\xff'
        while out[-2:] != '\x00\x00':
            out += self.file.read(2)
        out = out[:-2].decode('utf16')
        return out

    def parse_header(self):
        parsed_data = self.info.setdefault('ShellLinkHeader', {})
        validity = parsed_data.setdefault('validity_checks', {})

        header_size_bytes = self.file.read(4)
        header_size = parse_int_unsigned_little_endian(header_size_bytes)
        validity['header_size'] = header_size == 0x0000004c

        link_class_identifier_bytes = self.file.read(16)
        validity['CLSID'] = link_class_identifier_bytes == CLSID

        link_flags_bytes = self.file.read(4)
        link_flags = parse_binary_flag_list(link_flags_bytes)
        validity['link_flags_tail'] = not any(link_flags[27:])
        parsed_data['LinkFlags'] = dict(zip(LINK_FLAGS_NAMES, link_flags))

        file_attrs_bytes = self.file.read(4)
        file_attrs = parse_binary_flag_list(file_attrs_bytes)
        validity['file_attrs_flags_tail'] = not any(file_attrs[15:])
        validity['file_attrs_flags_reserved_1'] = not file_attrs[3]
        validity['file_attrs_flags_reserved_2'] = not file_attrs[6]
        if file_attrs[7]:
            validity['normal_file_attrs_are_blank'] = not any(attr for i, attr in enumerate(file_attrs) if i != 7)
        parsed_data['file_attrs'] = dict(zip(FILE_ATTRS_FLAGS_NAMES, file_attrs))

        create_time_bytes = self.file.read(8)
        create_time = parse_datetime(create_time_bytes)
        # header['create_time_fmt'] = str(create_time)
        parsed_data['create_time'] = create_time

        access_time_bytes = self.file.read(8)
        access_time = parse_datetime(access_time_bytes)
        # header['access_time_fmt'] = str(access_time)
        parsed_data['access_time'] = access_time

        write_time_bytes = self.file.read(8)
        write_time = parse_datetime(write_time_bytes)
        # header['write_time_fmt'] = str(write_time)
        parsed_data['write_time'] = write_time

        file_size_bytes = self.file.read(4)
        file_size = parse_int_unsigned_little_endian(file_size_bytes)
        # header['file_size_fmt'] = format_bytes(file_size)
        parsed_data['file_size'] = file_size

        icon_index_bytes = self.file.read(4)
        icon_index = parse_int_unsigned_little_endian(icon_index_bytes)
        parsed_data['icon_index'] = icon_index

        show_command_bytes = self.file.read(4)
        show_command = SHOW_OPTIONS.get(parse_int_unsigned_little_endian(show_command_bytes), 'SW_SHOWNORMAL')
        parsed_data['show_command'] = show_command

        hot_key_bytes = self.file.read(2)
        if hot_key_bytes == '\x00\x00':
            parsed_data['hotkey'] = None
        else:
            print(ord(hot_key_bytes[0]))
            key = HOT_KEY_LOW[ord(hot_key_bytes[0])]
            modifiers = [val for mask, val in HOT_KEY_HIGH.items() if mask & ord(hot_key_bytes[1])]
            assert modifiers
            parsed_data['hotkey'] = modifiers + [key]

        reserved_1_bytes = self.file.read(2)
        reserved_1 = parse_int_unsigned_little_endian(reserved_1_bytes)
        validity['reserved_1'] = reserved_1 == 0

        reserved_2_bytes = self.file.read(4)
        reserved_2 = parse_int_unsigned_little_endian(reserved_2_bytes)
        validity['reserved_2'] = reserved_2 == 0

        reserved_3_bytes = self.file.read(4)
        reserved_3 = parse_int_unsigned_little_endian(reserved_3_bytes)
        validity['reserved_3'] = reserved_3 == 0

        validity['read_0x4c_byte_header'] = self.file.tell() == 0x0000004c

    def parse_id_list(self):
        parsed_data = self.info.setdefault('link_target_id_list', {})
        validity = parsed_data.setdefault('validity_checks', {})

        # sanity check
        validity['read_0x4c_byte_header'] = self.file.tell() == 0x0000004c

        id_list_size_bytes = self.file.read(2)
        id_list_size = parse_int_unsigned_little_endian(id_list_size_bytes)
        parsed_data['id_list_size'] = id_list_size
        validity['sane_id_list_size'] = id_list_size > 2

        # read item_id
        i = 0
        remaining_size = id_list_size
        while remaining_size > 2:
            i += 1
            item_id_size_bytes = self.file.read(2)
            item_id_size = parse_int_unsigned_little_endian(item_id_size_bytes)
            item_data_bytes = self.file.read(item_id_size - 2)
            parsed_data['item_id_%d' % i] = item_data_bytes
            remaining_size -= item_id_size

        # read terminal_id
        validity['id_list_byte_count_okay'] = remaining_size == 2
        terminal_id_bytes = self.file.read(2)
        terminal_id = parse_int_unsigned_little_endian(terminal_id_bytes)
        validity['terminal_id_zeroes'] = terminal_id == 0

        validity['read_complete_id_list'] = self.file.tell() == 0x4c + id_list_size + 2

    def parse_link_info(self):
        link_info_start_byte = self.file.tell()
        parsed_data = self.info.setdefault('link_info', {})
        validity = parsed_data.setdefault('validity_checks', {})

        # parse header

        link_info_size_bytes = self.file.read(4)
        link_info_size = parse_int_unsigned_little_endian(link_info_size_bytes)
        parsed_data['link_info_size'] = link_info_size

        link_info_header_size_bytes = self.file.read(4)
        link_info_header_size = parse_int_unsigned_little_endian(link_info_header_size_bytes)
        validity['sane_link_info_header_size'] = link_info_header_size in [0x1c, 0x20, 0x24]
        parsed_data['link_info_header_size'] = link_info_header_size

        link_info_flags_bytes = self.file.read(4)
        link_info_flags = parse_binary_flag_list(link_info_flags_bytes)
        validity['only_two_info_flags'] = not any(attr for i, attr in enumerate(link_info_flags) if i >= 2)
        parsed_data['link_info_flags'] = dict(zip(LINK_INFO_FLAGS_NAMES, link_info_flags))

        volume_id_offset_bytes = self.file.read(4)
        volume_id_offset = parse_int_unsigned_little_endian(volume_id_offset_bytes)
        if not link_info_flags[0]:
            validity['null_volume_id'] = volume_id_offset == 0
            volume_id_offset = None
            volume_id_offset_abs = None
        else:
            volume_id_offset_abs = volume_id_offset + link_info_start_byte
        parsed_data['volume_id_offset'] = volume_id_offset
        parsed_data['volume_id_offset_abs'] = volume_id_offset_abs

        local_base_path_offset_bytes = self.file.read(4)
        local_base_path_offset = parse_int_unsigned_little_endian(local_base_path_offset_bytes)
        if not link_info_flags[0]:
            validity['null_local_path'] = local_base_path_offset == 0
            local_base_path_offset = None
            local_base_path_offset_abs = None
        else:
            local_base_path_offset_abs = local_base_path_offset + link_info_start_byte
        parsed_data['local_base_path_offset'] = local_base_path_offset
        parsed_data['local_base_path_offset_abs'] = local_base_path_offset_abs

        common_net_rel_link_bytes = self.file.read(4)
        common_net_rel_link_offset = parse_int_unsigned_little_endian(common_net_rel_link_bytes)
        if not link_info_flags[1]:
            validity['null_net_rel_link'] = common_net_rel_link_offset == 0
            common_net_rel_link_offset = None
            common_net_rel_link_offset_abs = None
        else:
            common_net_rel_link_offset_abs = common_net_rel_link_offset + link_info_start_byte
        parsed_data['common_net_rel_link_offset'] = common_net_rel_link_offset
        parsed_data['common_net_rel_link_offset_abs'] = common_net_rel_link_offset_abs

        common_path_suffix_offset_bytes = self.file.read(4)
        common_path_suffix_offset = parse_int_unsigned_little_endian(common_path_suffix_offset_bytes)
        common_path_suffix_offset_abs = common_path_suffix_offset + link_info_start_byte
        parsed_data['common_path_suffix_offset'] = common_path_suffix_offset
        parsed_data['common_path_suffix_offset_abs'] = common_path_suffix_offset_abs

        if link_info_header_size >= 0x20:
            local_base_path_offset_unicode_bytes = self.file.read(4)
            local_base_path_offset_unicode = parse_int_unsigned_little_endian(local_base_path_offset_unicode_bytes)
            if not link_info_flags[0]:
                validity['null_local_path_unicode'] = local_base_path_offset_unicode == 0
                local_base_path_offset_unicode = None
                local_base_path_unicode_offset_abs = None
            else:
                local_base_path_unicode_offset_abs = local_base_path_offset_unicode + link_info_start_byte
            parsed_data['local_base_path_offset_unicode'] = local_base_path_offset_unicode
            parsed_data['local_base_path_unicode_offset_abs'] = local_base_path_unicode_offset_abs
        else:
            local_base_path_unicode_offset_abs = None

        if link_info_header_size == 0x24:
            common_path_suffix_unicode_bytes = self.file.read(4)
            common_path_suffix_unicode_offset = parse_int_unsigned_little_endian(common_path_suffix_unicode_bytes)
            common_path_suffix_unicode_offset_abs = common_path_suffix_unicode_offset + link_info_start_byte
            parsed_data['common_path_suffix_unicode_offset'] = common_path_suffix_unicode_offset
            parsed_data['common_path_suffix_unicode_offset_abs'] = common_path_suffix_unicode_offset_abs
        else:
            common_path_suffix_unicode_offset_abs = None

        # parse the rest of the link_info structure

        if volume_id_offset_abs is not None:
            validity['volume_id_no_overlap'] = volume_id_offset_abs >= self.file.tell()
            self.file.seek(volume_id_offset_abs)

            volume_id_size_bytes = self.file.read(4)
            volume_id_size = parse_int_unsigned_little_endian(volume_id_size_bytes)
            validity['sane_volume_id_size'] = volume_id_size >= 0x10
            parsed_data['volume_id_size'] = volume_id_size

            drive_type_bytes = self.file.read(4)
            drive_type_key = parse_int_unsigned_little_endian(drive_type_bytes)
            validity['sane_drive_type'] = drive_type_key in DRIVE_TYPES.keys()
            parsed_data['drive_type_key'] = drive_type_key
            parsed_data['drive_type'] = DRIVE_TYPES[drive_type_key]

            drive_serial_number_bytes = self.file.read(4)
            drive_serial_number = parse_int_unsigned_little_endian(drive_serial_number_bytes)
            parsed_data['drive_serial_number'] = drive_serial_number

            volume_label_offset_bytes = self.file.read(4)
            volume_label_offset = parse_int_unsigned_little_endian(volume_label_offset_bytes)
            if volume_label_offset == 0x00000014:
                volume_label_offset_abs = None
            else:
                volume_label_offset_abs = volume_label_offset + volume_id_offset_abs
            parsed_data['volume_label_offset'] = volume_label_offset
            parsed_data['volume_label_offset_abs'] = volume_label_offset_abs

            if volume_id_size >= 0x14:
                volume_label_unicode_offset_bytes = self.file.read(4)
                volume_label_unicode_offset = parse_int_unsigned_little_endian(volume_label_unicode_offset_bytes)
                if volume_label_offset == 0x00000014:
                    volume_label_unicode_offset_abs = volume_label_unicode_offset + volume_id_offset_abs
                else:
                    volume_label_unicode_offset_abs = None
                parsed_data['volume_label_unicode_offset'] = volume_label_unicode_offset
                parsed_data['volume_label_unicode_offset_abs'] = volume_label_unicode_offset_abs
            else:
                volume_label_unicode_offset_abs = None

            if volume_label_offset_abs is not None:
                self.file.seek(volume_label_offset_abs)
                volume_label = self.read_null_terminated_string_ascii()
            else:
                self.file.seek(volume_label_unicode_offset_abs)
                volume_label = self.read_null_terminated_string_utf16()
            parsed_data['volume_label'] = volume_label

            validity['volume_id_within_bounds'] = self.file.tell() <= volume_id_offset_abs + volume_id_size

        if local_base_path_offset_abs is not None:
            validity['local_path_no_overlap'] = local_base_path_offset_abs >= self.file.tell()
            self.file.seek(local_base_path_offset_abs)

            local_base_path = self.read_null_terminated_string_ascii()
            parsed_data['local_base_path'] = local_base_path

        if common_net_rel_link_offset_abs is not None:
            validity['net_rel_link_no_overlap'] = common_net_rel_link_offset_abs >= self.file.tell()
            self.file.seek(common_net_rel_link_offset_abs)

            common_net_rel_link_size_bytes = self.file.read(4)
            common_net_rel_link_size = parse_int_unsigned_little_endian(common_net_rel_link_size_bytes)
            validity['sane_common_network_rel_link_size'] = common_net_rel_link_size >= 0x00000014
            parsed_data['common_network_rel_link_size'] = common_net_rel_link_size

            common_net_rel_link_flags_bytes = self.file.read(4)
            common_net_rel_link_flags = parse_int_unsigned_little_endian(common_net_rel_link_flags_bytes)
            validity['only_two_net_rel_link_flags'] = not any(attr for i, attr in enumerate(link_info_flags) if i >= 2)
            parsed_data['common_net_rel_link_flags'] = dict(zip(NET_REL_LINK_FLAGS_NAMES, common_net_rel_link_flags))

            net_name_offset_bytes = self.file.read(4)
            net_name_offset = parse_int_unsigned_little_endian(net_name_offset_bytes)
            net_name_offset_abs = net_name_offset + common_net_rel_link_offset_abs
            parsed_data['net_name_offset'] = net_name_offset
            parsed_data['net_name_offset_abs'] = net_name_offset_abs

            device_name_offset_bytes = self.file.read(4)
            device_name_offset = parse_int_unsigned_little_endian(device_name_offset_bytes)
            if not common_net_rel_link_flags[0]:
                validity['null_device_name'] = device_name_offset == 0
                device_name_offset = None
                device_name_offset_abs = None
            else:
                device_name_offset_abs = device_name_offset + common_net_rel_link_offset_abs
            parsed_data['device_name_offset'] = device_name_offset
            parsed_data['device_name_offset_abs'] = device_name_offset_abs

            network_provider_type_val_bytes = self.file.read(4)
            network_provider_type_val = parse_int_unsigned_little_endian(network_provider_type_val_bytes)
            if common_net_rel_link_flags[1]:
                validity['valid_network_provider_type_val'] = network_provider_type_val in NETWORK_PROVIDER_TYPES
            else:
                network_provider_type_val = None
            parsed_data['network_provider_type_val'] = network_provider_type_val

            if network_provider_type_val is not None:
                parsed_data['network_provider_type'] = NETWORK_PROVIDER_TYPES[network_provider_type_val]

            if net_name_offset >= 0x18:
                net_name_unicode_offset_bytes = self.file.read(4)
                net_name_unicode_offset = parse_int_unsigned_little_endian(net_name_unicode_offset_bytes)
                net_name_unicode_offset_abs = net_name_unicode_offset + common_net_rel_link_offset_abs
                parsed_data['net_name_unicode_offset'] = net_name_unicode_offset
                parsed_data['net_name_unicode_offset_abs'] = net_name_unicode_offset_abs
            else:
                net_name_unicode_offset = None
                net_name_unicode_offset_abs = None

            if net_name_offset >= 0x1c:
                validity['no_name_means_no_unicode'] = not common_net_rel_link_flags[0]
                device_name_unicode_offset_bytes = self.file.read(4)
                device_name_unicode_offset = parse_int_unsigned_little_endian(device_name_unicode_offset_bytes)
                device_name_unicode_offset_abs = device_name_unicode_offset + common_net_rel_link_offset_abs
                parsed_data['device_name_unicode_offset'] = device_name_unicode_offset
                parsed_data['device_name_unicode_offset_abs'] = device_name_unicode_offset_abs
            else:
                device_name_unicode_offset = None
                device_name_unicode_offset_abs = None

            validity['net_name_no_overlap'] = net_name_offset_abs >= self.file.tell()
            self.file.seek(net_name_offset_abs)
            net_name = self.read_null_terminated_string_ascii()
            parsed_data['net_name'] = net_name

            if device_name_offset_abs is not None:
                validity['device_name_no_overlap'] = device_name_offset_abs >= self.file.tell()
                self.file.seek(device_name_offset_abs)
                device_name = self.read_null_terminated_string_ascii()
                parsed_data['device_name'] = device_name

            if net_name_unicode_offset_abs is not None:
                validity['net_name_unicode_no_overlap'] = net_name_unicode_offset_abs >= self.file.tell()
                self.file.seek(net_name_unicode_offset_abs)
                net_name_unicode = self.read_null_terminated_string_utf16()
                parsed_data['net_name_unicode'] = net_name_unicode

            if device_name_unicode_offset_abs is not None:
                validity['device_name_unicode_no_overlap'] = device_name_unicode_offset_abs >= self.file.tell()
                self.file.seek(device_name_unicode_offset_abs)
                device_name_unicode = self.read_null_terminated_string_utf16()
                parsed_data['device_name_unicode'] = device_name_unicode

            validity['read_full_net'] = common_net_rel_link_offset_abs + common_net_rel_link_size == self.file.tell()

        validity['common_path_suffix_no_overlap'] = common_path_suffix_offset_abs >= self.file.tell()
        self.file.seek(common_path_suffix_offset_abs)
        common_path_suffix = self.read_null_terminated_string_ascii()
        parsed_data['common_path_suffix'] = common_path_suffix

        if local_base_path_unicode_offset_abs is not None:
            validity['local_base_path_unicode_no_overlap'] = local_base_path_unicode_offset_abs >= self.file.tell()
            self.file.seek(local_base_path_unicode_offset_abs)
            local_base_path_unicode = self.read_null_terminated_string_utf16()
            parsed_data['local_base_path_unicode'] = local_base_path_unicode

        if common_path_suffix_unicode_offset_abs is not None:
            validity['common_path_suf_unicode_no_overlap'] = common_path_suffix_unicode_offset_abs >= self.file.tell()
            self.file.seek(common_path_suffix_unicode_offset_abs)
            common_path_suffix_unicode = self.read_null_terminated_string_utf16()
            parsed_data['common_path_suffix_unicode'] = common_path_suffix_unicode

        validity['read_entire_link_info'] = link_info_size + link_info_start_byte == self.file.tell()

    def parse_string_struct(self):
        string_len_bytes = self.file.read(2)
        string_len = parse_int_unsigned_little_endian(string_len_bytes)
        if self.info['ShellLinkHeader']['LinkFlags']['IsUnicode']:
            out_string = b'\xff\xfe' + self.file.read(string_len * 2)
            out_string = out_string.decode('utf16')
        else:
            out_string = self.file.read(string_len)
        return out_string

    def parse_string_data(self):
        parsed_data = self.info.setdefault('StringData', {})
        validity = parsed_data.setdefault('validity_checks', {})

        if self.info['ShellLinkHeader']['LinkFlags']['HasName']:
            parsed_data['name_string'] = self.parse_string_struct()

        if self.info['ShellLinkHeader']['LinkFlags']['HasRelativePath']:
            parsed_data['relative_path'] = self.parse_string_struct()

        if self.info['ShellLinkHeader']['LinkFlags']['HasWorkingDir']:
            parsed_data['working_dir'] = self.parse_string_struct()

        if self.info['ShellLinkHeader']['LinkFlags']['HasArguments']:
            parsed_data['command_line_arguments'] = self.parse_string_struct()

        if self.info['ShellLinkHeader']['LinkFlags']['HasIconLocation']:
            parsed_data['icon_location'] = self.parse_string_struct()

    def parse_console_data(self):
        parsed_data = self.info.setdefault('ExtraData', {})
        validity = parsed_data.setdefault('validity_checks', {})

        fill_attributes_bytes = self.file.read(2)
        fill_attributes_val = parse_int_unsigned_little_endian(fill_attributes_bytes)
        parsed_data['fill_attributes_val'] = fill_attributes_val
        fill_attributes = [fill_info for fill_key, fill_info in FILL_ATTRIBUTES if fill_attributes_val and fill_key]
        parsed_data['fill_attributes'] = fill_attributes

        popup_fill_attributes_bytes = self.file.read(2)
        popup_fill_attributes_val = parse_int_unsigned_little_endian(popup_fill_attributes_bytes)
        parsed_data['popup_fill_attributes_val'] = popup_fill_attributes_val
        fill_attributes = [fill_info for fill_key, fill_info in FILL_ATTRIBUTES if fill_attributes_val and fill_key]
        parsed_data['popup_fill_attributes'] = fill_attributes

        screen_buffer_size_x_bytes = self.file.read(2)
        screen_buffer_size_x = parse_int_signed_little_endian(screen_buffer_size_x_bytes)
        parsed_data['screen_buffer_size_x'] = screen_buffer_size_x

        screen_buffer_size_y_bytes = self.file.read(2)
        screen_buffer_size_y = parse_int_signed_little_endian(screen_buffer_size_y_bytes)
        parsed_data['screen_buffer_size_y'] = screen_buffer_size_y

        window_size_x_bytes = self.file.read(2)
        window_size_x = parse_int_signed_little_endian(window_size_x_bytes)
        parsed_data['window_size_x'] = window_size_x

        window_size_y_bytes = self.file.read(2)
        window_size_y = parse_int_signed_little_endian(window_size_y_bytes)
        parsed_data['window_size_y'] = window_size_y

        window_origin_x_bytes = self.file.read(2)
        window_origin_x = parse_int_signed_little_endian(window_origin_x_bytes)
        parsed_data['window_origin_x'] = window_origin_x

        window_origin_y_bytes = self.file.read(2)
        window_origin_y = parse_int_signed_little_endian(window_origin_y_bytes)
        parsed_data['window_origin_y'] = window_origin_y

        unused_1_bytes = self.file.read(4)
        unused_2_bytes = self.file.read(4)

        font_size_bytes = self.file.read(4)
        font_size = parse_int_unsigned_little_endian(font_size_bytes)
        parsed_data['font_size'] = font_size

        font_family_bytes = self.file.read(4)
        font_family_val = parse_int_unsigned_little_endian(font_family_bytes)
        validity['font_family_exists'] = font_family_val in FONT_FAMILY
        parsed_data['font_family'] = FONT_FAMILY[font_family_val]

        font_weight_bytes = self.file.read(4)
        font_weight_val = parse_int_unsigned_little_endian(font_weight_bytes)
        font_weight = 'BOLD' if font_weight_val >= 700 else 'REGULAR'
        parsed_data['font_weight_val'] = font_weight_val

        font_name_bytes = self.file.read(64)
        font_name = (b'\xfe\xff' + font_name_bytes).decode('utf16')
        parsed_data['font_name'] = font_name
        # idk whats the byte order for this so try both for now
        font_name_alt = (b'\xff\xfe' + font_name_bytes).decode('utf16')
        parsed_data['font_name_alt'] = font_name_alt
        parsed_data['font_name_helptext'] = 'idk whats the byte order for this so try both for now'

        cursor_size_bytes = self.file.read(4)
        cursor_size_val = parse_int_unsigned_little_endian(cursor_size_bytes)
        validity['sane_cursor_size'] = 0 <= cursor_size_val <= 100
        parsed_data['cursor_size_val'] = cursor_size_val
        if cursor_size_val <= 25:
            cursor_size = 'SMALL'
        elif cursor_size_val <= 50:
            cursor_size = 'MEDIUM'
        elif cursor_size_val <= 100:
            cursor_size = 'LARGE'
        else:
            cursor_size = 'UNDEFINED BUT PROBABLY HUGE'
        parsed_data['cursor_size'] = cursor_size

        full_screen_bytes = self.file.read(4)
        full_screen_val = parse_int_unsigned_little_endian(full_screen_bytes)
        full_screen = bool(full_screen_val)
        # whether to full-screen or use the window_size_x/y
        parsed_data['full_screen_val'] = full_screen_val
        parsed_data['full_screen_enabled'] = full_screen

        quick_edit_bytes = self.file.read(4)
        quick_edit_val = parse_int_unsigned_little_endian(quick_edit_bytes)
        quick_edit = bool(quick_edit_val)
        parsed_data['quick_edit_val'] = quick_edit_val
        parsed_data['quick_edit_enabled'] = quick_edit

        insert_mode_bytes = self.file.read(4)
        insert_mode_val = parse_int_unsigned_little_endian(insert_mode_bytes)
        insert_mode = bool(insert_mode_val)
        parsed_data['insert_mode_val'] = insert_mode_val
        parsed_data['insert_mode_enabled'] = insert_mode

        auto_position_bytes = self.file.read(4)
        auto_position_val = parse_int_unsigned_little_endian(auto_position_bytes)
        auto_position = bool(auto_position_val)
        # whether to auto-position or use the window_origin_x/y
        parsed_data['auto_position_val'] = auto_position_val
        parsed_data['auto_position_enabled'] = auto_position

        raise NotImplementedError

        history_buffer_size_bytes = self.file.read(4)
        history_buffer_size = parse_int_unsigned_little_endian(history_buffer_size_bytes)

        num_of_history_buffers_bytes = self.file.read(4)
        num_of_history_buffers = parse_int_unsigned_little_endian(num_of_history_buffers_bytes)

        history_no_dup_bytes = self.file.read(4)
        history_no_dup = parse_int_unsigned_little_endian(history_no_dup_bytes)

        color_table_bytes = self.file.read(64)
        color_table = parse_int_unsigned_little_endian(color_table_bytes)

    def parse_extra_data(self):
        block_size_bytes = self.file.read(4)
        block_size = parse_int_unsigned_little_endian(block_size_bytes)
        block_signature_bytes = self.file.read(4)
        block_signature = parse_int_unsigned_little_endian(block_signature_bytes)

        print(hex(block_signature))
        if block_signature == 0xA0000002:
            self.parse_console_data()

        raise NotImplementedError

    def parse_lnk(self):
        # parse SHELL_LINK_HEADER
        self.parse_header()

        # parse LINK_TARGET_IDLIST
        if self.info['ShellLinkHeader']['LinkFlags']['HasLinkTargetIDList']:
            self.parse_id_list()

        # parse LINK_INFO
        if not self.info['ShellLinkHeader']['LinkFlags']['ForceNoLinkInfo']:
            self.parse_link_info()

        # parse STRING_DATA
        self.parse_string_data()

        # parse *EXTRA_DATA
        self.parse_extra_data()

        # done!
        pprint.pprint(self.info)

        # check read bytes
        print(list(enumerate(i for j in self.file.seen for i in j))[::-1])


if __name__ == '__main__':
    ShellLink(r'C:\Users\avery\Desktop\dir.lnk')
    ShellLink(r'C:\Users\avery\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk')
