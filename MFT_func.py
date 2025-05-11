import csv
import os
import sys
import pytsk3
import binascii
import json
import ctypes
import struct
from datetime import datetime
from optparse import OptionParser


VERSION = "v3.0.1"


SIAttributeSizeXP = 72
SIAttributeSizeNT = 48

class WindowsTime:
    """Convert the Windows time in 100 nanosecond intervals since Jan 1, 1601 to time in seconds since Jan 1, 1970"""

    def __init__(self, low, high, localtz):
        self.low = int(low)
        self.high = int(high)

        if (low == 0) and (high == 0):
            self.dt = 0
            self.dtstr = "Not defined"
            self.unixtime = 0
            return

        self.unixtime = self.get_unix_time()

        try:
            if localtz:
                self.dt = datetime.fromtimestamp(self.unixtime)
            else:
                self.dt = datetime.utcfromtimestamp(self.unixtime)

            self.dtstr = self.dt.isoformat(' ')

        except:
            self.dt = 0
            self.dtstr = "Invalid timestamp"
            self.unixtime = 0

    def get_unix_time(self):
        t = float(self.high) * 2 ** 32 + self.low
        return t * 1e-7 - 11644473600


def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, '\000')
        print("%s%s%s" % (sep.join("%02x" % ord(c) for c in line),
                          sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)

def parse_little_endian_signed_positive(buf):
    ret = 0
    for i, b in enumerate(buf):
        ret += b * (1 << (i * 8))
    return ret


def parse_little_endian_signed_negative(buf):
    ret = 0
    for i, b in enumerate(buf):
        ret += (b ^ 0xFF) * (1 << (i * 8))
    ret += 1

    ret *= -1
    return ret


def parse_little_endian_signed(buf):
    try:
        if not ord(buf[-1:]) & 0b10000000:
            return parse_little_endian_signed_positive(buf)
        else:
            return parse_little_endian_signed_negative(buf)
    except Exception:
        return ''

class MftSession:
    """Class to describe an entire MFT processing session"""

    @staticmethod
    def fmt_excel(date_str):
        return '="{}"'.format(date_str)

    @staticmethod
    def fmt_norm(date_str):
        return date_str


    def __init__(self):
        self.mft = {}
        self.fullmft = {}
        self.folders = {}
        self.debug = False
        self.mftsize = 0

    def mft_options(self):
        parser = OptionParser()
        parser.set_defaults(inmemory=False, debug=False, UseLocalTimezone=False, UseGUI=False)

        parser.add_option("-f", "--file", dest="filename",
                          help="read MFT from FILE", metavar="FILE")

        parser.add_option("-o", "--output", dest="output",
                          help="write results to FILE", metavar="FILE")

        parser.add_option("-l", "--localtz",
                          action="store_true", dest="localtz",
                          help="report times using local timezone")
        
        (self.options, args) = parser.parse_args()
        self.options.filename = "$MFT_COPY"
        self.options.output = "MFT_result.csv"
        self.options.localtz = True
        self.options.date_formatter = MftSession.fmt_norm

    def open_files(self):
        try:
            self.file_mft = open(self.options.filename, 'rb')
        except:
            print("Unable to open file: %s" % self.options.filename)
            sys.exit()

        if self.options.output is not None:
            try:
                self.file_csv = csv.writer(open(self.options.output, 'w', newline=""), dialect=csv.excel, quoting=1)
            except (IOError, TypeError):
                print("Unable to open file: %s" % self.options.output)
                sys.exit()

    def sizecheck(self):
        self.mftsize = int(os.path.getsize(self.options.filename)) / 1024

    def process_mft_file(self):

        self.sizecheck()

        self.build_filepaths()

        # reset the file reading
        self.num_records = 0
        self.file_mft.seek(0)
        raw_record = self.file_mft.read(1024)

        if self.options.output is not None:
            try:
                self.file_csv.writerow(mft_to_csv(None, True, self.options))
            except UnicodeEncodeError:
                pass

        while raw_record != b"":
            record = parse_record(raw_record, self.options)
            if self.options.debug:
                print(record)

            record['filename'] = self.mft[self.num_records]['filename']

            self.do_output(record)

            self.num_records += 1

            if record['ads'] > 0:
                for i in range(0, record['ads']):
                    record_ads = record.copy()
                    record_ads['filename'] = record['filename'] + ':' + record['data_name', i].decode()
                    self.do_output(record_ads)

            raw_record = self.file_mft.read(1024)

    def do_output(self, record):
        if self.options.output is not None:
            try:
                self.file_csv.writerow(mft_to_csv(record, False, self.options))
            except UnicodeEncodeError:
                pass

    def plaso_process_mft_file(self):

        self.build_filepaths()

        self.num_records = 0
        self.file_mft.seek(0)
        raw_record = self.file_mft.read(1024)

        while raw_record != b"":
            record = parse_record(raw_record, self.options)
            if self.options.debug:
                print(record)

            record['filename'] = self.mft[self.num_records]['filename']

            self.fullmft[self.num_records] = record

            self.num_records += 1

            raw_record = self.file_mft.read(1024)

    def build_filepaths(self):
        self.file_mft.seek(0)

        self.num_records = 0

        raw_record = self.file_mft.read(1024)
        while raw_record != b"":
            minirec = {}
            record = parse_record(raw_record, self.options)
            if self.options.debug:
                print(record)

            minirec['filename'] = record['filename']
            minirec['fncnt'] = record['fncnt']
            if record['fncnt'] == 1:
                minirec['par_ref'] = record['fn', 0]['par_ref']
                minirec['name'] = record['fn', 0]['name']
            if record['fncnt'] > 1:
                minirec['par_ref'] = record['fn', 0]['par_ref']
                for i in (0, record['fncnt'] - 1):
                    if record['fn', i]['nspace'] == 0x1 or record['fn', i]['nspace'] == 0x3:
                        minirec['name'] = record['fn', i]['name']
                if minirec.get('name') is None:
                    minirec['name'] = record['fn', record['fncnt'] - 1]['name']

            self.mft[self.num_records] = minirec

            self.num_records += 1

            raw_record = self.file_mft.read(1024)

        self.gen_filepaths()

    def get_folder_path(self, seqnum):
        if self.debug:
            print("Building Folder For Record Number (%d)" % seqnum)

        if seqnum not in self.mft:
            return 'Orphan'

        if (self.mft[seqnum]['filename']) != '':
            return self.mft[seqnum]['filename']

        try:
                self.mft[seqnum]['filename'] = self.mft[seqnum]['name'].decode()
                return self.mft[seqnum]['filename']
        except:
            self.mft[seqnum]['filename'] = 'NoFNRecord'
            return self.mft[seqnum]['filename']

        if (self.mft[seqnum]['par_ref']) == seqnum:
            if self.debug:
                print("Error, self-referential, while trying to determine path for seqnum %s" % seqnum)
            self.mft[seqnum]['filename'] = 'ORPHAN' + self.mft[seqnum]['name'].decode()
            return self.mft[seqnum]['filename']

        parentpath = self.get_folder_path((self.mft[seqnum]['par_ref']))
        self.mft[seqnum]['filename'] = parentpath + self.mft[seqnum]['name'].decode()

        return self.mft[seqnum]['filename']

    def gen_filepaths(self):

        for i in self.mft:
            if (self.mft[i]['filename']) == '':

                if self.mft[i]['fncnt'] > 0:
                    self.get_folder_path(i)
                    if self.debug:
                        print("Filename (with path): %s" % self.mft[i]['filename'])
                else:
                    self.mft[i]['filename'] = 'NoFNRecord'

# mft
def parse_record(raw_record, options):
    record = {
        'filename': '',
        'notes': '',
        'ads': 0,
        'datacnt': 0,
    }

    decode_mft_header(record, raw_record)
    if record['seq_number'] == raw_record[510:512] and record['seq_number'] == raw_record[1022:1024]:
        raw_record = raw_record[:510] + record['seq_attr1'] + raw_record[512:1022] + record['seq_attr2']

    record_number = record['recordnum']

    if options.debug:
        print('-->Record number: %d\n\tMagic: %s Attribute offset: %d Flags: %s Size:%d' % (
            record_number,
            record['magic'],
            record['attr_off'],
            hex(int(record['flags'])),
            record['size'],
        ))

    if record['magic'] == 0x44414142:
        if options.debug:
            print("BAAD MFT Record")
        record['baad'] = True
        return record

    if record['magic'] != 0x454c4946:
        if options.debug:
            print("Corrupt MFT Record")
        record['corrupt'] = True
        return record

    read_ptr = record['attr_off']

    while read_ptr < 1024:

        atr_record = decode_atr_header(raw_record[read_ptr:])
        if atr_record['type'] == 0xffffffff:
            break

        if atr_record['nlen'] > 0:
            record_bytes = raw_record[
                read_ptr + atr_record['name_off']: read_ptr + atr_record['name_off'] + atr_record['nlen'] * 2]
            atr_record['name'] = record_bytes.decode('utf-16').encode('utf-8')
        else:
            atr_record['name'] = ''

        if options.debug:
            print("Attribute type: %x Length: %d Res: %x" % (atr_record['type'], atr_record['len'], atr_record['res']))

        if atr_record['type'] == 0x10:
            if options.debug:
                print("Stardard Information:\n++Type: %s Length: %d Resident: %s Name Len:%d Name Offset: %d" % (
                    hex(int(atr_record['type'])),
                    atr_record['len'],
                    atr_record['res'],
                    atr_record['nlen'],
                    atr_record['name_off'],
                ))
            si_record = decode_si_attribute(raw_record[read_ptr + atr_record['soff']:], options.localtz)
            record['si'] = si_record
            if options.debug:
                print("++CRTime: %s\n++MTime: %s\n++ATime: %s\n++EntryTime: %s" % (
                    si_record['crtime'].dtstr,
                    si_record['mtime'].dtstr,
                    si_record['atime'].dtstr,
                    si_record['ctime'].dtstr,
                ))

        elif atr_record['type'] == 0x20:
            if options.debug:
                print("Attribute list")
            if atr_record['res'] == 0:
                al_record = decode_attribute_list(raw_record[read_ptr + atr_record['soff']:], record)
                record['al'] = al_record
                if options.debug:
                    print("Name: %s" % (al_record['name']))
            else:
                if options.debug:
                    print("Non-resident Attribute List?")
                record['al'] = None

        elif atr_record['type'] == 0x30:
            if options.debug:
                print("File name record")
            fn_record = decode_fn_attribute(raw_record[read_ptr + atr_record['soff']:], options.localtz, record)
            record['fn', record['fncnt']] = fn_record
            if options.debug:
                print("Name: %s (%d)" % (fn_record['name'], record['fncnt']))
            record['fncnt'] += 1
            if fn_record['crtime'] != 0:
                if options.debug:
                    print("\tCRTime: %s MTime: %s ATime: %s EntryTime: %s" % (
                        fn_record['crtime'].dtstr,
                        fn_record['mtime'].dtstr,
                        fn_record['atime'].dtstr,
                        fn_record['ctime'].dtstr,
                    ))

        elif atr_record['type'] == 0x40:
            object_id_record = decode_object_id(raw_record[read_ptr + atr_record['soff']:])
            record['objid'] = object_id_record
            if options.debug:
                print("Object ID")

        elif atr_record['type'] == 0x50:
            record['sd'] = True
            if options.debug:
                print("Security descriptor")

        elif atr_record['type'] == 0x60:
            record['volname'] = True
            if options.debug:
                print("Volume name")

        elif atr_record['type'] == 0x70:
            if options.debug:
                print("Volume info attribute")
            volume_info_record = decode_volume_info(raw_record[read_ptr + atr_record['soff']:], options)
            record['volinfo'] = volume_info_record

        elif atr_record['type'] == 0x80:
            if atr_record['name'] != '':
                record['data_name', record['ads']] = atr_record['name']
                record['ads'] += 1
            if atr_record['res'] == 0:
                data_attribute = decode_data_attribute(raw_record[read_ptr + atr_record['soff']:], atr_record)
            else:
                data_attribute = {
                    'ndataruns': atr_record['ndataruns'],
                    'dataruns': atr_record['dataruns'],
                    'drunerror': atr_record['drunerror'],
                }
            record['data', record['datacnt']] = data_attribute
            record['datacnt'] += 1

            if options.debug:
                print("Data attribute")

        elif atr_record['type'] == 0x90:
            record['indexroot'] = True
            if options.debug:
                print("Index root")

        elif atr_record['type'] == 0xA0:
            record['indexallocation'] = True
            if options.debug:
                print("Index allocation")

        elif atr_record['type'] == 0xB0:
            record['bitmap'] = True
            if options.debug:
                print("Bitmap")

        elif atr_record['type'] == 0xC0:
            record['reparsepoint'] = True
            if options.debug:
                print("Reparse point")

        elif atr_record['type'] == 0xD0:
            record['eainfo'] = True
            if options.debug:
                print("EA Information")

        elif atr_record['type'] == 0xE0:
            record['ea'] = True
            if options.debug:
                print("EA")

        elif atr_record['type'] == 0xF0:
            record['propertyset'] = True
            if options.debug:
                print("Property set")

        elif atr_record['type'] == 0x100:
            record['loggedutility'] = True
            if options.debug:
                print("Logged utility stream")

        else:
            if options.debug:
                print("Found an unknown attribute")

        if atr_record['len'] > 0:
            read_ptr = read_ptr + atr_record['len']
        else:
            if options.debug:
                print("ATRrecord->len < 0, exiting loop")
            break

    return record

def mft_to_csv(record, ret_header, options):
    """Return a MFT record in CSV format"""

    if ret_header:
        csv_string = ['Record Number', 'Good', 'Active', 'Record type',
                      'Sequence Number', 'Parent File Rec. #', 'Parent File Rec. Seq. #',
                      'Filename #1', 'Std Info Creation date', 'Std Info Modification date',
                      'Std Info Access date', 'Std Info Entry date', 'FN Info Creation date',
                      'FN Info Modification date', 'FN Info Access date', 'FN Info Entry date',
                      'Object ID', 'Birth Volume ID', 'Birth Object ID', 'Birth Domain ID',
                      'Filename #2', 'FN Info Creation date', 'FN Info Modify date',
                      'FN Info Access date', 'FN Info Entry date', 'Filename #3', 'FN Info Creation date',
                      'FN Info Modify date', 'FN Info Access date', 'FN Info Entry date', 'Filename #4',
                      'FN Info Creation date', 'FN Info Modify date', 'FN Info Access date',
                      'FN Info Entry date', 'Standard Information', 'Attribute List', 'Filename',
                      'Object ID', 'Volume Name', 'Volume Info', 'Data', 'Index Root',
                      'Index Allocation', 'Bitmap', 'Reparse Point', 'EA Information', 'EA',
                      'Property Set', 'Logged Utility Stream', 'Log/Notes', 'STF FN Shift', 'uSec Zero',
                      'ADS', 'Possible Copy', 'Possible Volume Move']
        return csv_string

    if 'baad' in record:
        csv_string = ["%s" % record['recordnum'], "BAAD MFT Record"]
        return csv_string

    csv_string = [record['recordnum'], decode_mft_magic(record), decode_mft_isactive(record),
                  decode_mft_recordtype(record)]

    if 'corrupt' in record:
        tmp_string = ["%s" % record['recordnum'], "Corrupt", "Corrupt", "Corrupt MFT Record"]
        csv_string.extend(tmp_string)
        return csv_string

    tmp_string = ["%d" % record['seq']]
    csv_string.extend(tmp_string)

    if record['fncnt'] > 0:
        csv_string.extend([str(record['fn', 0]['par_ref']), str(record['fn', 0]['par_seq'])])
    else:
        csv_string.extend(['NoParent', 'NoParent'])

    if record['fncnt'] > 0 and 'si' in record:
        filename_buffer = [
            record['filename'],
            options.date_formatter(record['si']['crtime'].dtstr),
            options.date_formatter(record['si']['mtime'].dtstr),
            options.date_formatter(record['si']['atime'].dtstr),
            options.date_formatter(record['si']['ctime'].dtstr),
            options.date_formatter(record['fn', 0]['crtime'].dtstr),
            options.date_formatter(record['fn', 0]['mtime'].dtstr),
            options.date_formatter(record['fn', 0]['atime'].dtstr),
            options.date_formatter(record['fn', 0]['ctime'].dtstr),
        ]
    elif 'si' in record:
        filename_buffer = [
            'NoFNRecord',
            options.date_formatter(record['si']['crtime'].dtstr),
            options.date_formatter(record['si']['mtime'].dtstr),
            options.date_formatter(record['si']['atime'].dtstr),
            options.date_formatter(record['si']['ctime'].dtstr),
            'NoFNRecord', 'NoFNRecord', 'NoFNRecord', 'NoFNRecord',
        ]

    else:
        filename_buffer = [
            'NoFNRecord',
            'NoSIRecord', 'NoSIRecord', 'NoSIRecord', 'NoSIRecord',
            'NoFNRecord', 'NoFNRecord', 'NoFNRecord', 'NoFNRecord',
        ]

    csv_string.extend(filename_buffer)

    if 'objid' in record:
        objid_buffer = [
            record['objid']['objid'],
            record['objid']['orig_volid'],
            record['objid']['orig_objid'],
            record['objid']['orig_domid'],
        ]
    else:
        objid_buffer = ['', '', '', '']

    csv_string.extend(objid_buffer)

    for i in range(1, min(4, record['fncnt'])):
        filename_buffer = [
            record['fn', i]['name'],
            record['fn', i]['crtime'].dtstr,
            record['fn', i]['mtime'].dtstr,
            record['fn', i]['atime'].dtstr,
            record['fn', i]['ctime'].dtstr,
        ]
        csv_string.extend(filename_buffer)

    if record['fncnt'] < 2:
        tmp_string = ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '']
    elif record['fncnt'] == 2:
        tmp_string = ['', '', '', '', '', '', '', '', '', '']
    elif record['fncnt'] == 3:
        tmp_string = ['', '', '', '', '']
    else:
        tmp_string = []

    csv_string.extend(tmp_string)

    for record_str in ['si', 'al']:
        csv_string.append('True') if record_str in record else csv_string.append('False')

    csv_string.append('True') if record['fncnt'] > 0 else csv_string.append('False')

    for record_str in [
        'objid',
        'volname',
        'volinfo',
        'data',
        'indexroot',
        'indexallocation',
        'bitmap',
        'reparse',
        'eainfo',
        'ea',
        'propertyset',
        'loggedutility',
    ]:
        csv_string.append('True') if record_str in record else csv_string.append('False')

    if 'notes' in record:
        csv_string.append(record['notes'])
    else:
        csv_string.append('None')
        record['notes'] = ''

    if 'stf-fn-shift' in record:
        csv_string.append('Y')
    else:
        csv_string.append('N')

    if 'usec-zero' in record:
        csv_string.append('Y')
    else:
        csv_string.append('N')

    if record['ads'] > 0:
        csv_string.append('Y')
    else:
        csv_string.append('N')

    if 'possible-copy' in record:
        csv_string.append('Y')
    else:
        csv_string.append('N')

    if 'possible-volmove' in record:
        csv_string.append('Y')
    else:
        csv_string.append('N')

    return csv_string

def decode_mft_header(record, raw_record):
    record['magic'] = struct.unpack("<I", raw_record[:4])[0]
    record['upd_off'] = struct.unpack("<H", raw_record[4:6])[0]
    record['upd_cnt'] = struct.unpack("<H", raw_record[6:8])[0]
    record['lsn'] = struct.unpack("<d", raw_record[8:16])[0]
    record['seq'] = struct.unpack("<H", raw_record[16:18])[0]
    record['link'] = struct.unpack("<H", raw_record[18:20])[0]
    record['attr_off'] = struct.unpack("<H", raw_record[20:22])[0]
    record['flags'] = struct.unpack("<H", raw_record[22:24])[0]
    record['size'] = struct.unpack("<I", raw_record[24:28])[0]
    record['alloc_sizef'] = struct.unpack("<I", raw_record[28:32])[0]
    record['base_ref'] = struct.unpack("<Lxx", raw_record[32:38])[0]
    record['base_seq'] = struct.unpack("<H", raw_record[38:40])[0]
    record['next_attrid'] = struct.unpack("<H", raw_record[40:42])[0]
    record['f1'] = raw_record[42:44]
    record['recordnum'] = struct.unpack("<I", raw_record[44:48])[0]
    record['seq_number'] = raw_record[48:50]
    if record['upd_off'] == 42:
        record['seq_attr1'] = raw_record[44:46] 
        record['seq_attr2'] = raw_record[46:58]
    else:
        record['seq_attr1'] = raw_record[50:52]
        record['seq_attr2'] = raw_record[52:54]
    record['fncnt'] = 0
    record['datacnt'] = 0

def decode_mft_magic(record):
    if record['magic'] == 0x454c4946:
        return "Good"
    elif record['magic'] == 0x44414142:
        return 'Bad'
    elif record['magic'] == 0x00000000:
        return 'Zero'
    else:
        return 'Unknown'

def decode_mft_isactive(record):
    if record['flags'] & 0x0001:
        return 'Active'
    else:
        return 'Inactive'

def decode_mft_recordtype(record):
    if int(record['flags']) & 0x0002:
        tmp_buffer = 'Folder'
    else:
        tmp_buffer = 'File'
    if int(record['flags']) & 0x0004:
        tmp_buffer = "%s %s" % (tmp_buffer, '+ Unknown1')
    if int(record['flags']) & 0x0008:
        tmp_buffer = "%s %s" % (tmp_buffer, '+ Unknown2')

    return tmp_buffer

def decode_atr_header(s):
    d = {'type': struct.unpack("<L", s[:4])[0]}
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L", s[4:8])[0]
    d['res'] = struct.unpack("B", s[8:9])[0]
    d['nlen'] = struct.unpack("B", s[9:10])[0]
    d['name_off'] = struct.unpack("<H", s[10:12])[0]
    d['flags'] = struct.unpack("<H", s[12:14])[0]
    d['id'] = struct.unpack("<H", s[14:16])[0]
    if d['res'] == 0:
        d['ssize'] = struct.unpack("<L", s[16:20])[0]
        d['soff'] = struct.unpack("<H", s[20:22])[0]
        d['idxflag'] = struct.unpack("B", s[22:23])[0]
        _ = struct.unpack("B", s[23:24])[0]
    else:
        d['start_vcn'] = struct.unpack("<Q", s[16:24])[0]
        d['last_vcn'] = struct.unpack("<Q", s[24:32])[0]
        d['run_off'] = struct.unpack("<H", s[32:34])[0]
        d['compsize'] = struct.unpack("<H", s[34:36])[0]
        _ = struct.unpack("<I", s[36:40])[0]
        d['allocsize'] = struct.unpack("<Lxxxx", s[40:48])[0]
        d['realsize'] = struct.unpack("<Lxxxx", s[48:56])[0]
        d['streamsize'] = struct.unpack("<Lxxxx", s[56:64])[0]
        (d['ndataruns'], d['dataruns'], d['drunerror']) = unpack_dataruns(s[64:])

    return d

def unpack_dataruns(datarun_str):
    dataruns = []
    numruns = 0
    pos = 0
    prevoffset = 0
    error = ''

    c_uint8 = ctypes.c_uint8

    class LengthBits(ctypes.LittleEndianStructure):
        _fields_ = [
            ("lenlen", c_uint8, 4),
            ("offlen", c_uint8, 4),
        ]

    class Lengths(ctypes.Union):
        _fields_ = [("b", LengthBits),
                    ("asbyte", c_uint8)]

    lengths = Lengths()

    while True:
        lengths.asbyte = struct.unpack("B", datarun_str[pos:pos + 1])[0]
        pos += 1
        if lengths.asbyte == 0x00:
            break

        if lengths.b.lenlen > 6 or lengths.b.lenlen == 0:
            error = "Datarun oddity."
            break

        bit_len = parse_little_endian_signed(datarun_str[pos:pos + lengths.b.lenlen])

        pos += lengths.b.lenlen

        if lengths.b.offlen > 0:
            offset = parse_little_endian_signed(datarun_str[pos:pos + lengths.b.offlen])
            offset = offset + prevoffset
            prevoffset = offset
            pos += lengths.b.offlen
        else:
            offset = 0
            pos += 1

        dataruns.append([bit_len, offset])
        numruns += 1


    return numruns, dataruns, error

def decode_si_attribute(s, localtz):
    d = {
        'crtime': WindowsTime(struct.unpack("<L", s[:4])[0], struct.unpack("<L", s[4:8])[0], localtz),
        'mtime': WindowsTime(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], localtz),
        'ctime': WindowsTime(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], localtz),
        'atime': WindowsTime(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], localtz),
        'dos': struct.unpack("<I", s[32:36])[0], 'maxver': struct.unpack("<I", s[36:40])[0],
        'ver': struct.unpack("<I", s[40:44])[0], 'class_id': struct.unpack("<I", s[44:48])[0],
        'own_id': struct.unpack("<I", s[48:52])[0], 'sec_id': struct.unpack("<I", s[52:56])[0],
        'quota': struct.unpack("<d", s[56:64])[0], 'usn': struct.unpack("<d", s[64:72])[0],
    }

    return d

def decode_fn_attribute(s, localtz, _):

    d = {
        'par_ref': struct.unpack("<Lxx", s[:6])[0], 'par_seq': struct.unpack("<H", s[6:8])[0],
        'crtime': WindowsTime(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], localtz),
        'mtime': WindowsTime(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], localtz),
        'ctime': WindowsTime(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], localtz),
        'atime': WindowsTime(struct.unpack("<L", s[32:36])[0], struct.unpack("<L", s[36:40])[0], localtz),
        'alloc_fsize': struct.unpack("<q", s[40:48])[0], 'real_fsize': struct.unpack("<q", s[48:56])[0],
        'flags': struct.unpack("<d", s[56:64])[0], 'nlen': struct.unpack("B", s[64:65])[0],
        'nspace': struct.unpack("B", s[65:66])[0],
    }

    attr_bytes = s[66:66 + d['nlen'] * 2]
    try:
        d['name'] = attr_bytes.decode('utf-16').encode('utf-8')
    except:
        d['name'] = 'UnableToDecodeFilename'

    return d

def decode_attribute_list(s, _):
    d = {
        'type': struct.unpack("<I", s[:4])[0], 'len': struct.unpack("<H", s[4:6])[0],
        'nlen': struct.unpack("B", s[6:7])[0], 'f1': struct.unpack("B", s[7:8])[0],
        'start_vcn': struct.unpack("<d", s[8:16])[0], 'file_ref': struct.unpack("<Lxx", s[16:22])[0],
        'seq': struct.unpack("<H", s[22:24])[0], 'id': struct.unpack("<H", s[24:26])[0],
    }

    attr_bytes = s[26:26 + d['nlen'] * 2]
    d['name'] = attr_bytes.decode('utf-16').encode('utf-8')

    return d

def decode_volume_info(s, options):
    d = {
        'f1': struct.unpack("<d", s[:8])[0], 'maj_ver': struct.unpack("B", s[8:9])[0],
        'min_ver': struct.unpack("B", s[9:10])[0], 'flags': struct.unpack("<H", s[10:12])[0],
        'f2': struct.unpack("<I", s[12:16])[0],
    }

    if options.debug:
        print("+Volume Info")
        print("++F1%d" % d['f1'])
        print("++Major Version: %d" % d['maj_ver'])
        print("++Minor Version: %d" % d['min_ver'])
        print("++Flags: %d" % d['flags'])
        print("++F2: %d" % d['f2'])

    return d

def decode_data_attribute(s, at_rrecord):
    d = {'data': s[:at_rrecord['ssize']]}

    return d

def decode_object_id(s):
    d = {
        'objid': object_id(s[0:16]),
        'orig_volid': object_id(s[16:32]),
        'orig_objid': object_id(s[32:48]),
        'orig_domid': object_id(s[48:64]),
    }

    return d

def object_id(s):
    if s == 0:
        objstr = 'Undefined'
    else:
        objstr = '-'.join(map(bytes.decode, list(map(binascii.hexlify, (s[0:4][::-1], s[4:6][::-1], \
                                                                   s[6:8][::-1], s[8:10], s[10:])))))

    return objstr

def anomaly_detect(record):
    if record['fncnt'] > 0:
        try:
            if record['si']['crtime'].dt < record['fn', 0]['crtime'].dt:
                record['stf-fn-shift'] = True
        except:
            pass

        try:
            if record['si']['crtime'].dt != 0:
                if record['si']['crtime'].dt.microsecond == 0:
                    record['usec-zero'] = True
        except:
            pass

        try:
            if record['si']['crtime'].dt > record['si']['mtime'].dt:
                record['possible-copy'] = True
        except:
            pass

        try:
            if record['si']['atime'].dt > record['si']['mtime'].dt and record['si']['atime'].dt > record['si']['crtime'].dt:
                record['possible-volmove'] = True
        except:
            pass

def extract_mft(image_path, output_file):
    img_info = pytsk3.Img_Info(image_path)

    fs_info = pytsk3.FS_Info(img_info, offset=0)

    mft_file = fs_info.open_meta(inode=0)

    mft_content = mft_file.read_random(0, mft_file.info.meta.size)

    with open(output_file, 'wb') as output:
        output.write(mft_content)

        
