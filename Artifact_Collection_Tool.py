import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv
import os
import socket
import psutil
import win32evtlog
import win32evtlogutil
import win32gui
import win32con
import win32service
import re
from scapy.all import *
import win32com.client
import hashlib
import psutil
from datetime import datetime
import time
import winreg
import pandas as pd
from datetime import datetime
import codecs
import getpass
import platform
import subprocess
import chardet
import xml.etree.ElementTree as ET
# import evtx
from registry import Registry
import subprocess
from MFT_func import extract_mft, MftSession
from browser_history.browsers import Chrome
from browser_history.browsers import Firefox
from browser_history.browsers import Brave
from browser_history.browsers import Chromium
from browser_history.browsers import Edge
from browser_history.browsers import LibreWolf
from browser_history.browsers import Opera
from browser_history.browsers import OperaGX
from browser_history.browsers import Safari
from browser_history.browsers import Vivaldi
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import pytsk3
from regipy import RegistryHive
from Evtx.Evtx import Evtx  
from Evtx.Views import evtx_file_xml_view
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet
import os
import logging
from logging.handlers import RotatingFileHandler
import getpass
import sys
from tkinter import font as tkfont
import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog
import logging
import sys
from ttkbootstrap import Style
from ttkbootstrap.constants import *
import ttkbootstrap as tb
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def some_function():
    from registry import Registry
    # sử dụng Registry ở đây
    
global canvas
output_directory = ""
status_window = None
trees = {}

# Thiết lập theme và màu sắc
DARK_BG = "#2c3e50"
LIGHT_BG = "#ecf0f1"
ACCENT_COLOR = "#3498db"
TEXT_COLOR = "#2c3e50"
BUTTON_COLOR = "#3498db"
BUTTON_HOVER = "#2980b9"
ENTRY_BG = "#ffffff"
FRAME_BG = "#dfe6e9"

# Hàm chữ ký số mã hóa
def generate_file_hash(file_path):
    """Tạo SHA-256 hash cho file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def verify_file_hash(file_path, expected_hash):
    """Xác minh tính toàn vẹn của file"""
    return generate_file_hash(file_path) == expected_hash

# Hàm mã hóa và ký dữ liệu
def encrypt_and_sign(data, public_key, private_key):
    """Mã hóa và ký dữ liệu"""
    # Mã hóa với public key
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Tạo chữ ký số với private key
    signature = private_key.sign(
        encrypted,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(encrypted), base64.b64encode(signature)


def verify_artifacts_integrity(output_directory):
    """Xác minh tính toàn vẹn của tất cả artifacts"""
    integrity_report = []
    for root, _, files in os.walk(output_directory):
        for file in files:
            if file.endswith('.csv'):
                file_path = os.path.join(root, file)
                try:
                    file_hash = generate_file_hash(file_path)
                    integrity_report.append({
                        'file': file_path,
                        'hash': file_hash,
                        'status': 'Verified'
                    })
                except Exception as e:
                    integrity_report.append({
                        'file': file_path,
                        'error': str(e),
                        'status': 'Failed'
                    })
    
    # Lưu báo cáo
    report_path = os.path.join(output_directory, "integrity_report.json")
    with open(report_path, 'w') as f:
        json.dump(integrity_report, f, indent=2)
    
    return report_path




#Hàm thiết lập đường dẫn tùy chỉnh
#Duyệt thư mục đầu ra
def browse_output_directory():
    global output_directory
    directory = filedialog.askdirectory()
    if directory:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, directory)
        output_directory = directory
# Thiết lập thư mục mặc định
def set_default_output_directory():
    global output_directory
    default_directory = os.getcwd()
    output_entry.delete(0, tk.END)
    output_entry.insert(0, default_directory)
    output_directory = default_directory
# Thực thi và lưu kết quả
def execute_and_save_artifacts():
    for artifact, var in variables.items():
        if var.get():
            func = artifact_functions.get(artifact)
            if func:
                func(output_directory)
# Khởi tạo logger toàn cục
logger = None

def setup_logging(output_directory):
    """Thiết lập hệ thống ghi log và khởi tạo khóa số học (public/private key)"""
    global logger

    # Tạo thư mục logs nếu chưa tồn tại
    log_dir = os.path.join(output_directory, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Định dạng log
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Tạo logger chính
    logger = logging.getLogger('ArtifactCollector')
    logger.setLevel(logging.INFO)

    # Handler ghi log vào file với xoay vòng
    log_file = os.path.join(log_dir, "artifact_collector.log")
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Handler hiển thị log trên console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Thêm các handler vào logger (tránh thêm lại nếu đã tồn tại)
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    logger.info("="*50)
    logger.info("Khởi động chương trình thu thập hiện vật số")
    logger.info(f"Thư mục làm việc: {output_directory}")

    # Tạo key pair cho chữ ký số nếu chưa tồn tại
    public_key_path = os.path.join(log_dir, "public_key.pem")
    private_key_path = os.path.join(log_dir, "private_key.pem")
    
    if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Lưu public key
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            # Lưu private key (có thể mã hóa bằng password nếu cần)
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            logger.info("Đã tạo cặp khóa số học RSA (2048-bit) thành công.")
        except Exception as e:
            logger.error(f"Không thể tạo key pair: {str(e)}")
            raise
    else:
        logger.info("Khóa RSA đã tồn tại, bỏ qua bước tạo mới.")

    return logger

# Hàm ghi log cho các hàm thu thập hiện vật
def log_artifact_action(func):
    """Decorator để ghi log tự động cho các hàm thu thập hiện vật"""
    def wrapper(output_dir, *args, **kwargs):
        func_name = func.__name__
        artifact_name = func_name.replace('_func', '').replace('_', ' ').title()
        
        try:
            logger.info(f"Bắt đầu thu thập: {artifact_name}")
            start_time = time.time()
            
            result = func(output_dir, *args, **kwargs)
            
            elapsed_time = time.time() - start_time
            logger.info(f"Hoàn thành thu thập {artifact_name} trong {elapsed_time:.2f} giây")
            
            # Ghi hash của các file được tạo
            if isinstance(result, str) and os.path.exists(result):
                file_hash = generate_file_hash(result)
                logger.info(f"Hash của file {result}: {file_hash}")
            elif isinstance(result, list):
                for file_path in result:
                    if os.path.exists(file_path):
                        file_hash = generate_file_hash(file_path)
                        logger.info(f"Hash của file {file_path}: {file_hash}")
            
            return result
        except Exception as e:
            logger.error(f"Lỗi khi thu thập {artifact_name}: {str(e)}", exc_info=True)
            raise
    
    return wrapper


# Các hàm thực hiện điều tra số ==========================================================================================================================
# Hàm dump bộ nhớ hệ thống
def memory_dump_func(output_directory):
    return 1
# Xử lý các file Prefetch và xuất kết quả dạng CSV
@log_artifact_action
def prefetch_func(output_directory):
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Prefetch_{case_number}_{current_date}.csv'

    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        csv_writer = csv.writer(file)

        # Write the header line
        header = ["Artifact timestamp", "Filename", "First executed", "Last executed", "Action", "Source"]
        csv_writer.writerow(header)

        prefetch_directory = r"C:\Windows\Prefetch\\"
        prefetch_files = os.listdir(prefetch_directory)

        for pf_file in prefetch_files:
            if pf_file.endswith(".pf"):
                full_path = os.path.join(prefetch_directory, pf_file)
                app_name = pf_file[:-12]
                first_executed = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getctime(full_path)))
                last_executed = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(full_path)))

                first_executed_line = [first_executed, app_name, first_executed, last_executed, "Program first executed", "Prefetch - " + pf_file]
                last_executed_line = [last_executed, app_name, first_executed, last_executed, "Program last executed", "Prefetch - " + pf_file]

                csv_writer.writerow(first_executed_line)
                csv_writer.writerow(last_executed_line)
# Xử lý MFT (Master File Table) của NTFS
class MyImgInfo(pytsk3.Img_Info):
    def __init__(self, device_path):
        # Mở thiết bị như file nhị phân
        self._fd = open(device_path, 'rb')
        # Sử dụng TSK_IMG_TYPE_RAW thay vì TSK_IMG_TYPE_EXTERNAL
        super(MyImgInfo, self).__init__(device_path, type=pytsk3.TSK_IMG_TYPE_RAW)

    def close(self):
        self._fd.close()

    def read(self, offset, size):
        self._fd.seek(offset)
        return self._fd.read(size)

    def get_size(self):
        current = self._fd.tell()
        self._fd.seek(0, os.SEEK_END)
        size = self._fd.tell()
        self._fd.seek(current)
        return size
@log_artifact_action
def NTFS_func(output_directory):
    image_path = r"\\.\C:"  # Đường dẫn ổ đĩa C
    output_file = "$MFT_COPY"

    # Dùng lớp mới để đọc thiết bị
    img_info = MyImgInfo(image_path)

    # Nếu extract_mft cần tham số là Img_Info thay vì đường dẫn, gọi trực tiếp
    # extract_mft(img_info, output_file)  # Uncomment nếu cần

    # Gọi các hàm liên quan đến xử lý MFT
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'MFT_{case_number}_{current_date}.csv'
    output_csv_file = os.path.join(output_directory, filename)

    # Khởi tạo và xử lý MFT
    session = MftSession()
    session.mft_options()
    session.options.output = output_csv_file
    session.open_files()
    session.process_mft_file()

    # Đóng file sau khi xử lý xong
    img_info.close()
# Thu thập thông tin hệ thống và xuất ra file CSV
@log_artifact_action
def sys_info_func(output_directory):
    try:
        case_number = case_ref_entry.get().replace('/', '_')
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'Thong_tin_he_thong_{case_number}_{current_date}.csv'
        with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
            csv_writer = csv.writer(file)
            headers = ['Type', 'Information']
            csv_writer.writerow(headers)

            system_info = {
                'System': platform.system(),
                'Node Name': platform.node(),
                'Release': platform.release(),
                'Version': platform.version(),
                'Architecture': platform.architecture(),
                'Machine': platform.machine(),
                'Processor': platform.processor()
            }
            for key, value in system_info.items():
                csv_writer.writerow([key, value])

            gp_result = subprocess.run(['gpresult', '/r'], capture_output=True, text=True)
            group_policy_info = gp_result.stdout if gp_result.returncode == 0 else f"Error: {gp_result.stderr}"
            csv_writer.writerow(['Group Policy Info', group_policy_info])

            audit_result = subprocess.run(['auditpol', '/get', '/category:*'], capture_output=True, text=True)
            system_audit_info = audit_result.stdout if audit_result.returncode == 0 else f"Error: {audit_result.stderr}"
            csv_writer.writerow(['System Audit Info', system_audit_info])

    except Exception as e:
        print(f"An error occurred while saving system information: {e}")
# Xuất dữ liệu registry và chuyển đổi sang định dạng CSV
@log_artifact_action
def regi_hive(output_directory):
    import os
    import csv
    import subprocess
    from datetime import datetime
    from Registry import Registry

    key_paths = [
        'HKEY_CURRENT_USER',
        r'HKLM\sam',
        r'HKLM\security',
        r'HKLM\software',
        r'HKLM\system',
        r'HKEY_USERS\.DEFAULT',
        'HKEY_CURRENT_CONFIG',
    ]
    extract_files = []

    def recursive_search(key, csv_writer):
        subkeys = key.subkeys()
        if len(subkeys) == 0:
            for v in key.values():
                try:
                    csv_writer.writerow([key.path(), v.name(), v.value()])
                except Registry.RegistryParse.UnknownTypeException:
                    pass
                except UnicodeDecodeError:
                    pass
        else:
            for subkey in subkeys:
                recursive_search(subkey, csv_writer)

    def export_registry_key_to_csv(hive_path, output_csv):
        try:
            reg = Registry.Registry(hive_path)
            key = reg.root()
            with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
                csv_writer = csv.writer(csv_file, dialect=csv.excel, quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerow(['Path', 'Name', 'Value'])
                recursive_search(key, csv_writer)
        except Exception as e:
            print(f"Error exporting registry key to CSV: {e}")

    def extract_registry_file():
        key_path = "HKLM\\SAM"
        output_file = os.path.join(output_directory, "SAM.hiv")
        try:
            result = subprocess.run(f'reg save "{key_path}" "{output_file}" /y',
                                    capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                print(f"[+] Registry saved successfully: {output_file}")
                extract_files.append(output_file)
            else:
                print(f"[!] Error saving registry: {result.stderr}")
        except Exception as e:
            print(f"[!] Exception: {str(e)}")

    extract_registry_file()

    for file in extract_files:
        case_number = case_ref_entry.get().replace('/', '_')  # Nếu không có, cần truyền vào từ bên ngoài
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'Du_lieu_registry_{case_number}_{current_date}.csv'
        export_registry_key_to_csv(file, os.path.join(output_directory, filename))


# Các hàm thu thập nhật ký hệ thống
@log_artifact_action
def event_viewer_log_func(output_directory, case_ref_entry):
    # Đường dẫn file log
    log_file = 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx'

    # Lấy số tham chiếu của case
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Nhat_ky_su_kien_{case_number}_{current_date}.csv'
    output_csv_file = os.path.join(output_directory, filename)

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    with Evtx(log_file) as log:
        title_row = [
            'Provider name', 'Provider guid', 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords',
            'TimeCreated', 'EventRecordID', 'ActivityID', 'RelatedActivityID', 'ProcessID', 'ThreadID', 'Channel',
            'Computer', 'Security'
        ]

        with open(output_csv_file, 'w', newline='', encoding='utf-8-sig') as f:
            csv_writer = csv.writer(f, dialect=csv.excel, quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(title_row)

            for record in log.records():
                csv_record = []
                root = ET.fromstring(record.xml())
                for child in root[0]:
                    if child.attrib.items():
                        for key, value in child.attrib.items():
                            if key == "Qualifiers":
                                csv_record.append(child.text)
                            else:
                                csv_record.append(value)
                    else:
                        csv_record.append(child.text)
                csv_writer.writerow(csv_record)


# Thu thập dữ liệu SRUM (System Resource Usage Monitor) và thông tin mạng/dịch vụ
@log_artifact_action
def srum_host_service_func(output_directory):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'SRUM_HOST_Service_{case_number}_{current_date}.csv'
    output_file = os.path.join(output_directory, filename)
    
    with open(output_file, 'w', newline="", encoding='utf-8') as file:
        writer = csv.writer(file, dialect=csv.excel, quoting=csv.QUOTE_MINIMAL)
        
        try:
            srudb_path = r'C:\Windows\System32\sru\SRUDB.DAT'
            registry_path = r'C:\Windows\System32\config\SOFTWARE'
            cmd = f'srum_dump.exe -i {srudb_path} -r {registry_path} -o temp_srum_report.xls'
            subprocess.run(args=cmd, text=True, stdout=subprocess.DEVNULL)
            if os.path.exists('temp_srum_report.xls'):
                xlsx = pd.read_excel('temp_srum_report.xls')
                for index, row in xlsx.iterrows():
                    writer.writerow(row)
                os.remove('temp_srum_report.xls')
        except Exception as e:
            print(f"Error in SRUM data collection: {e}")

        try:
            host_info = psutil.net_if_addrs()
            family_dict = {2: 'AF_INET', 23: 'AF_INET6', -1: 'AF_LINK'}
            for interface, addresses in host_info.items():
                for address in addresses:
                    writer.writerow([interface, family_dict.get(address.family, 'Unknown'), address.address, address.netmask, address.broadcast])
        except Exception as e:
            print(f"Error retrieving host information: {e}")

        try:
            services_info = psutil.win_service_iter()
            for service in services_info:
                writer.writerow([service.name(), service.display_name(), service.status()])
        except Exception as e:
            print(f"Error retrieving services information: {e}")
# Thu thập và xuất các biến môi trường hệ thống
@log_artifact_action
def enviornment_func(output_directory):
    env_vars = os.environ
    
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Bien_moi_truong_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        csv_writer = csv.writer(file, dialect=csv.excel, quoting=csv.QUOTE_ALL)
        
        csv_writer.writerow(['Key', 'Value'])
        
        for key, value in env_vars.items():
            csv_writer.writerow([key, value])
# Thu thập danh sách các bản vá Windows đã cài đặt
@log_artifact_action
def patch_list_func(output_directory):
    update_session = win32com.client.Dispatch("Microsoft.Update.Session")
    update_searcher = update_session.CreateUpdateSearcher()

    history_count = update_searcher.GetTotalHistoryCount()
    updates = update_searcher.QueryHistory(0, history_count)

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Danh_sach_ban_va_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Title', 'Update ID', 'Version', 'Date'])

        for update in updates:
            title = update.Title

            kb_pattern = r"KB\d+"
            version_pattern = r"\(version\s([\d.]+)\)"

            kb_match = re.search(kb_pattern, title)
            version_match = re.search(version_pattern, title)

            kb_number = kb_match.group(0) if kb_match else "Không có thông tin KB"
            version = version_match.group(1) if version_match else "Không có thông tin phiên bản"

            title_only = title.split(" - ")[0] if " - " in title else title

            writer.writerow([title_only, kb_number, version, str(update.Date)])

# Thu thập thông tin các tiến trình đang chạy trên hệ thống
@log_artifact_action
def process_list_info_func(output_directory):
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Danh_sach_tien_trinh_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Process ID', 'Process name', 'Process path', 'Process creat time', 'Process access time', 'Process modify time', 'Process size', 'hash value(sha-256)'])

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            process_info = proc.info
            file_path = process_info.get("exe")
            if file_path and os.path.isfile(file_path):
                creation_time = os.path.getctime(file_path)
                access_time = os.path.getatime(file_path)
                modification_time = os.path.getmtime(file_path)
                
                file_size = os.path.getsize(file_path)

                hash_md5 = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                hash_value = hash_md5.hexdigest()

                writer.writerow([
                    process_info['pid'],
                    process_info['name'],
                    file_path,
                    datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S'),
                    datetime.fromtimestamp(access_time).strftime('%Y-%m-%d %H:%M:%S'),
                    datetime.fromtimestamp(modification_time).strftime('%Y-%m-%d %H:%M:%S'),
                    file_size,
                    hash_value
                ])
            else:
                process = psutil.Process(process_info['pid'])
                writer.writerow([
                    process.pid,
                    process.name(),
                    'N/A',
                    datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A'
                ])
# Quét các cổng mạng đang mở trên hệ thống
@log_artifact_action
def connection_info_func(output_directory):
    host_name = socket.gethostname()

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_ket_noi_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Port Number'])

        ports = range(1, 65535)
        
        packets = [IP(dst=host_name)/TCP(dport=port, flags="S") for port in ports]
        responses, _ = sr(packets, timeout=1, verbose=0)

        for sent, received in responses:
            if received.haslayer(TCP) and received[TCP].flags == 18:
                writer.writerow([sent[TCP].dport])
# Thu thập thông tin cấu hình IP của các giao diện mạng
@log_artifact_action
def ip_setting_info_func(output_directory):
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_IP_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Interface', 'IP Address', 'Netmask', 'Broadcast Address'])
        
        net_if_stats = psutil.net_if_stats()
        
        for interface, stats in net_if_stats.items():
            if stats.isup:
                addresses = psutil.net_if_addrs().get(interface, [])
                for address in addresses:
                    if address.family == socket.AF_INET:
                        writer.writerow([
                            interface, 
                            address.address, 
                            address.netmask, 
                            address.broadcast
                        ])
# Thu thập bảng ARP của hệ thống
@log_artifact_action
def ARP_info_func(output_directory):
    arp_table = os.popen('arp -a').read()

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_ARP_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Physical Address', 'Type'])

        lines = arp_table.split('\n')
        for line in lines:
            if line.strip() and 'internet address' not in line.lower():
                parts = line.split()
                if len(parts) == 3:
                    type_value = 'static' if parts[2] == 'Tĩnh' else 'dynamic' if parts[2] == 'Động' else parts[2]
                    writer.writerow([parts[0], parts[1], type_value])

# Thu thập thông tin NetBIOS từ hệ thống
@log_artifact_action
def NetBIOS_info_func(output_directory):
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_NetBIOS_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Network Name', 'IP Address', 'NetBIOS name', 'NetBIOS type', 'NetBIOS status'])

        result = os.popen('nbtstat -n').read()
        ethernet_tables = re.split(r'([^\n]*):\nNode', result, flags=re.DOTALL)[1:]
        ip_pattern = r'IpAddress: \[([\d.]+)\] phamvi ID: \[\]'
        netbios_pattern = r'(\S+)\s+([A-Z]+)\s+(\S+)'

        for i in range(0, len(ethernet_tables), 2):
            adapter_name = ethernet_tables[i].strip()
            ethernet_table = ethernet_tables[i + 1]

            ip_address = None  # Gán giá trị mặc định là None
            ip_match = re.search(ip_pattern, ethernet_table, re.DOTALL)
            if ip_match:
                ip_address = ip_match.group(1)

            netbios_matches = re.findall(netbios_pattern, ethernet_table)
            if netbios_matches:
                for match in netbios_matches:
                    name, netbios_type, status = match
                    status = 'registration' if status == 'đã được đăng ký' else 'collision' if status == 'xung đột' else status

                    writer.writerow([adapter_name, ip_address, name, netbios_type, status])
            else:
                writer.writerow([adapter_name, ip_address, None, None, None])

# Thu thập thông tin các cửa sổ đang mở
@log_artifact_action
def open_handle_info_func(output_directory):
    def callback(_hwnd, _result: list):
        title = win32gui.GetWindowText(_hwnd)
        if win32gui.IsWindowEnabled(_hwnd) and win32gui.IsWindowVisible(_hwnd) and title and len(title) > 0:
            _result.append(_hwnd)
        return True

    result = []
    win32gui.EnumWindows(callback, result)

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_cua_so_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Window Number', 'Window Title', 'Window Class', 'Visible'])

        for _hwnd in result:
            writer.writerow([
                _hwnd, 
                win32gui.GetWindowText(_hwnd),
                win32gui.GetClassName(_hwnd),
                win32gui.IsWindowVisible(_hwnd)
            ])
# Thu thập thông tin các tác vụ được lên lịch trong Task Scheduler
@log_artifact_action
def work_schedule_info_func(output_directory):
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_lich_trinh_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(["Task name", "Last run Time", "Next run Time", "Enabled", "Trigger Count", "Action Count"])

        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folders = [scheduler.GetFolder("\\")]

        while folders:
            folder = folders.pop(0)
            folders += list(folder.GetFolders(0))
            tasks = list(folder.GetTasks(0))

            for task in tasks:
                settings = task.Definition.Settings
                triggers = task.Definition.Triggers
                actions = task.Definition.Actions

                writer.writerow([task.Name, task.LastRunTime, task.NextRunTime, task.Enabled, triggers.Count, actions.Count])
# Thu thập thông tin sự kiện đăng nhập hệ thống từ Windows Event Log
@log_artifact_action
def sys_logon_info_func(output_directory):
    server = 'localhost'
    log_type = ['Application', 'System', 'Security', 'Setup', 'Forwarded Events']
    query = 'logon'

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thong_tin_dang_nhap_{case_number}_{current_date}.csv'
    with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Log Type', 'Event ID', 'Source', 'Time Generated', 'Time Written', 'Event Category', 'Event Type'])

        for logtype in log_type:
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            while events:
                for event in events:
                    if query in win32evtlogutil.SafeFormatMessage(event, logtype):
                        writer.writerow([
                            logtype,
                            event.EventID,
                            event.SourceName,
                            event.TimeGenerated,
                            event.TimeWritten,
                            event.EventCategory,
                            event.EventType
                        ])
                events = win32evtlog.ReadEventLog(hand, flags, 0)
# Thu thập thông tin các dịch vụ đã đăng ký trong hệ thống
@log_artifact_action
def regi_service_info_func(output_directory):
    resume = 0
    accessSCM = win32con.GENERIC_READ
    accessSrv = win32service.SC_MANAGER_ALL_ACCESS

    hscm = win32service.OpenSCManager(None, None, accessSCM)

    typeFilter = win32service.SERVICE_WIN32
    stateFilter = win32service.SERVICE_STATE_ALL

    statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Thông tin dịch vụ đã đăng ký_{case_number}_{current_date}.csv'
    output_path = os.path.join(output_directory, filename)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Short Name', 'Description', 'Status'])

        for (short_name, desc, status) in statuses:
            csv_writer.writerow([short_name, desc, status])
# Hàm thu thập hoạt động gần đây (placeholder)

def recent_act_info_func(output_directory):
    return 1
# Thu thập thông tin từ khóa UserAssist trong registry
@log_artifact_action
def userassist_func(output_directory):
    def get_reg_value_userassist(key_path):
        userassist_list = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                userassist = winreg.EnumKey(key, i)
                userassist_key_path = fr"{key_path}\{userassist}\count"
                
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, userassist_key_path) as userassist_key:
                    for j in range(0, winreg.QueryInfoKey(userassist_key)[1]):
                        userassist_key_name = winreg.EnumValue(userassist_key, j)
                        try:
                            decrypted_userassist = codecs.decode(userassist_key_name[0], 'rot_13')
                            userassist_list.append(decrypted_userassist)
                        except:
                            userassist_list.append(userassist_key_name[0])
                            continue
        return userassist_list

    def csv_writer(files):
        case_number = case_ref_entry.get().replace('/', '_')
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'UserAssist_{case_number}_{current_date}.csv'
        csv_file_path = f"{output_directory}/{filename}.csv"
        with open(csv_file_path, 'w', newline="") as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['File Name'])
            for file_name in files:
                csv_writer.writerow([file_name])

    userassist_list = get_reg_value_userassist(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    csv_writer(userassist_list)
# Thu thập các chương trình tự động chạy từ registry
@log_artifact_action
def autorun_func(output_directory):
    auto_run_list = [
        r'Software\Microsoft\Windows\CurrentVersion\Run', 
        r'Software\Microsoft\Windows\CurrentVersion\RunOnce'
    ]
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'AutoRun_{case_number}_{current_date}.csv'

    with open(os.path.join(output_directory, filename), 'w', newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Process Name', 'Process Path', 'Status'])

        for key_path in auto_run_list:
            for hkey in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hkey, key_path) as key:
                        for j in range(winreg.QueryInfoKey(key)[1]):
                            auto_run_info = winreg.EnumValue(key, j)
                            csv_writer.writerow([auto_run_info[0], auto_run_info[1], auto_run_info[2]])
                except Exception as e:
                    print(f"[-] An error occurred: {e}")

def registry_func(output_directory):
    return 1
# Thu thập lịch sử trình duyệt từ các trình duyệt phổ biến
@log_artifact_action
def browser_info_func(output_directory):
    browsers = ['Chrome', 'Firefox', 'Brave', 'Chromium', 'Edge', 'LibreWolf', 'Opera', 'OperaGX', 'Safari', 'Vivaldi']

    try:
        case_number = case_ref_entry.get().replace('/', '_')
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'Lich_su_trinh_duyet_{case_number}_{current_date}.csv'
        with open(os.path.join(output_directory, filename), 'w', newline='', encoding='utf-8') as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['Time Stamp', 'Browser', 'URL Link', 'Explain'])

            for browser in browsers:
                try:
                    if browser == 'Chrome':
                        f = Chrome()
                    elif browser == 'Firefox':
                        f = Firefox()
                    elif browser == 'Brave':
                        f = Brave()
                    elif browser == 'Chromium':
                        f = Chromium()
                    elif browser == 'Edge':
                        f = Edge()
                    elif browser == 'LibreWolf':
                        f = LibreWolf()
                    elif browser == 'Opera':
                        f = Opera()
                    elif browser == 'OperaGX':
                        f = OperaGX()
                    elif browser == 'Safari':
                        f = Safari()
                    elif browser == 'Vivaldi':
                        f = Vivaldi()
                    else:
                        return

                    outputs = f.fetch_history()
                    his = outputs.histories

                    for i in his:
                        csv_writer.writerow([i[0], browser, i[1], i[2]])

                except Exception as e:
                    print(f"[-] Lỗi khi phân tích lịch sử  Browser History({browser}) : {e}")

    except Exception as e:
        print(f"[-] Lỗi khi tạo file lịch sử trình duyệt: {e}")


def bin_func(output_directory):
    def get_reg_value_sid(user_folder_path, key_path):
        print(f"[DEBUG] Tìm SID cho user folder: {user_folder_path}")
        user_folder_name = os.path.basename(user_folder_path).lower()

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(key, i)
                    sid_key_path = fr"{key_path}\{sid}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_key_path) as sid_key:
                        profile_path, _ = winreg.QueryValueEx(sid_key, "ProfileImagePath")
                        print(f"[DEBUG] Đã tìm thấy ProfileImagePath: {profile_path} cho SID: {sid}")
                        if os.path.basename(profile_path).lower() == user_folder_name:
                            print(f"[DEBUG] Khớp với folder user -> Trả về SID: {sid}")
                            return sid
                    i += 1
                except Exception as e:
                    print(f"[DEBUG] Kết thúc vòng lặp hoặc lỗi: {e}")
                    break
        print("[-] Không tìm thấy SID phù hợp.")
        return None

    def analyze_deleted_file(file, file_path):
        origin_file = f"$R{file[2:]}"
        origin_file_path = f"{file_path}\\{origin_file}"
        deleted_file_path = f"{file_path}\\{file}"

        try:
            with open(deleted_file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding'] if result['encoding'] is not None else 'utf-8'

                content = raw_data.decode(encoding)
                creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getctime(deleted_file_path)))
                modified_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(deleted_file_path)))
                access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getatime(deleted_file_path)))

                file_size = str(os.path.getsize(origin_file_path)) if os.path.exists(origin_file_path) else 'Không tìm thấy file gốc'
                return [deleted_file_path, creation_time, access_time, modified_time, file_size]
        except UnicodeDecodeError as e:
            print(f"[-] Lỗi mã hóa: {e}")
            return None
        except Exception as e:
            print(f"[-] Lỗi khác: {e}")
            return None

    user_profile_path = os.path.expanduser("~")  # Sử dụng thư mục user thật
    print(f"[DEBUG] Đường dẫn user profile: {user_profile_path}")

    recycle_path = 'C:\\$Recycle.Bin\\'
    sid = get_reg_value_sid(user_profile_path, r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    if sid is None:
        print("[-] Không lấy được SID. Thoát.")
        return

    personal_recycle_path = os.path.join(recycle_path, sid)
    print(f"[DEBUG] Đường dẫn thùng rác cá nhân: {personal_recycle_path}")

    if os.path.exists(personal_recycle_path):
        print(f"[DEBUG] Tồn tại thư mục: {personal_recycle_path}")
        recycle_files = os.listdir(personal_recycle_path)
        print(f"[DEBUG] Số file trong thùng rác: {len(recycle_files)}")

        case_number = "TESTCASE_001".replace('/', '_')
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'Thung_rac_{case_number}_{current_date}.csv'

        output_file_path = os.path.join(output_directory, filename)
        print(f"[DEBUG] Đường dẫn file CSV xuất: {output_file_path}")

        with open(output_file_path, 'w', newline="", encoding='utf-8') as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['Deleted FilePath', 'Creation Time', 'Access Time', 'Modified Time', 'File Size'])

            for deleted_file in recycle_files:
                if deleted_file.lower() == "desktop.ini":
                    continue
                print(f"[DEBUG] Phân tích file: {deleted_file}")
                file_info = analyze_deleted_file(deleted_file, personal_recycle_path)
                if file_info:
                    csv_writer.writerow(file_info)
    else:
        print(f"[-] Không tìm thấy thư mục: {personal_recycle_path}")

# Hàm xuất log PowerShell từ Event Viewer thành file CSV
@log_artifact_action
def powershell_log_func(output_directory):
    server=''
    logtype='Windows PowerShell'
    handle = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = 0

    try:
        case_number = case_ref_entry.get().replace('/', '_')
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'Nhật ký PowerShell_{case_number}_{current_date}.csv'
        with open(os.path.join(output_directory, filename), 'w', newline='') as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['Event Category', 'Generated Time', 'Source Name', 'Event ID', 'Event Type', 'Message'])

            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break

                for event in events:
                    if event.EventCategory is None:
                        continue
                    else:
                        csv_writer.writerow([event.EventCategory, event.TimeGenerated, event.SourceName, event.EventID, event.EventType, event.StringInserts])
                        total += 1

    finally:
        win32evtlog.CloseEventLog(handle)

    return total
@log_artifact_action
def lnk_files_func(output_directory):
    user = getpass.getuser()
    lnk_file_path = f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Recent"

    if os.path.exists(lnk_file_path):
        lnk_file_list = os.listdir(lnk_file_path)
        filename, createtime_list, modifiedtime_list, accesstime_list = [], [], [], []

        for file in lnk_file_list:
            full_path = os.path.join(lnk_file_path, file)
            createtime_list.append(datetime.fromtimestamp(os.path.getctime(full_path)))
            modifiedtime_list.append(datetime.fromtimestamp(os.path.getmtime(full_path)))
            accesstime_list.append(datetime.fromtimestamp(os.path.getatime(full_path)))
            filename.append(file)

        df = pd.DataFrame({
            'FileName': filename,
            'CreatedTime': createtime_list,
            'ModifiedTime': modifiedtime_list,
            'Accesstime': accesstime_list
        })
        case_number = case_ref_entry.get().replace('/', '_')
        current_date = datetime.now().strftime('%Y-%m-%d')
        filename = f'Tệp LNK_{case_number}_{current_date}.csv'
        output_file = os.path.join(output_directory, filename)
        df.to_csv(output_file)
    else:
        print("[-] Đường dẫn đến file LNK không hợp lệ")


# == Các hàm thu thập hiện vật (artifact) ==========================================================================================================================
@log_artifact_action
def environment_func(output_directory):
    # Ví dụ ghi biến môi trường vào file
    import os
    import csv
    from datetime import datetime

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'BienMoiTruong_{case_number}_{current_date}.csv'
    output_file = os.path.join(output_directory, filename)

    env_vars = os.environ

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Tên biến", "Giá trị"])
        for key, value in env_vars.items():
            writer.writerow([key, value])

data = {
    "Biến môi trường": environment_func,  
}
@log_artifact_action
def arp_info_func(output_directory):
    # Tạo thư mục nếu chưa tồn tại
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # Lấy mã vụ việc và ngày hiện tại
    case_number = case_ref_entry.get().replace('/', '_')
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'Bảng_ARP_{case_number}_{current_date}.csv'
    output_file = os.path.join(output_directory, filename)

    # Lấy thông tin ARP
    arp_info = os.popen('arp -a').read()

    # Ghi vào file CSV theo định dạng bảng
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "MAC Address", "Type"])  # Tiêu đề

        for line in arp_info.strip().split('\n'):
            # Bỏ qua dòng tiêu đề hoặc dòng trống
            if line.strip() == '' or line.startswith('Interface:') or line.startswith('Internet'):
                continue
            parts = line.split()
            if len(parts) == 3:
                writer.writerow(parts)

def netbios_info_func():
   
    pass

data = {
    "Thông tin NetBIOS": netbios_info_func,  
}
artifact_functions = {
    "Bản ghi nhớ (Memory Dump)": memory_dump_func,
    "Thông tin Prefetch": prefetch_func,
    "Hiện vật hệ thống tệp NTFS": NTFS_func,
    "Thông tin hệ thống": sys_info_func,
    "Dữ liệu Registry Hive": regi_hive,
    "Nhật ký Event Viewer": lambda out: event_viewer_log_func(out, case_ref_entry),
    "SRUM, Hosts và Dịch vụ": srum_host_service_func,
    "Biến môi trường": environment_func,
    "Danh sách bản vá (Patch List)": patch_list_func,
    "Thông tin tiến trình đang chạy": process_list_info_func,
    "Thông tin kết nối (cổng đang mở)": connection_info_func,
    "Cấu hình địa chỉ IP": ip_setting_info_func,
    "Bảng ARP": arp_info_func,
    "Thông tin NetBIOS": NetBIOS_info_func,
    "Danh sách Handle đang mở": open_handle_info_func,
    "Lịch trình tác vụ (Task Scheduler)": work_schedule_info_func,
    "Lịch sử đăng nhập hệ thống": sys_logon_info_func,
    "Dịch vụ đã đăng ký": regi_service_info_func,
    "Hoạt động gần đây": recent_act_info_func,
    "Trình theo dõi sử dụng ứng dụng (UserAssist)": userassist_func,
    "Ứng dụng khởi động cùng hệ thống (Autorun)": autorun_func,
    "Thông tin Registry": registry_func,
    "Lịch sử trình duyệt web": browser_info_func,
    "Thùng rác (Recycle Bin)": bin_func,
    "Nhật ký PowerShell": powershell_log_func,
    "Các tệp LNK gần đây": lnk_files_func
}



# == Cửa sổ trạng thái tiến trình  ============================================================================================================================
def open_status_window():
    global status_window
    status_window = tk.Toplevel(app)
    status_window.title("Hoàn tất")
    status_window.geometry("300x100")
    status_window.resizable(False, False)
    complete_label = tk.Label(status_window, text="Tất cả tác vụ đã hoàn tất.", font=("Arial", 12))
    complete_label.pack(pady=10)

    def on_exit():
        app.quit()

   
    def show_results():
        for widget in app.winfo_children():
            widget.destroy()

        # Frame chính
        main_frame = tb.Frame(app, bootstyle="light")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Header frame
        header_frame = tb.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 10))

        tb.Label(header_frame, text="📄 Chọn file kết quả:", font=("Segoe UI", 10), bootstyle="primary").pack(side='left', padx=(0, 10))

        csv_files = sorted([file for file in os.listdir(output_directory) if file.endswith(".csv")])
        selected_file_var = tk.StringVar()

        # Combobox chọn file
        file_combobox = tb.Combobox(
            header_frame,
            textvariable=selected_file_var,
            values=csv_files,
            state='readonly',
            width=40,
            font=('Segoe UI', 10),
            bootstyle="info"
        )
        file_combobox.pack(side='left', fill='x', expand=True, padx=(0, 10))
     
        # Nút refresh
        refresh_icon = tk.PhotoImage(data="""R0lGODlhEAAQAPIAAP///wAAAMLCwkJCQgAAAGJiYoKCgpKSkiH+C05FVFNDQVBFMi4wAwEAAAAh
    +QQJBAAAACwAAAAAEAAQAAADMwi63P4wyklrE2MIOggZnAdOmGYJRbExwroUmcG2LmDEwnHQLVsY
    Od2mGkzXBoNwKZ5jG4UACH5BAkEAAAALAAAAAAQABAAAAMyCLrc/jDKSWsTY4Q6CBmcB06YZglF
    sTHCuhSZwbbObBwJwR5FQaHglBwjzSM4jAIAOw==""")
        refresh_btn = tb.Button(
            header_frame,
            image=refresh_icon,
            command=lambda: [selected_file_var.set(''), file_combobox['values']],
            bootstyle="warning",
            width=3
        )
        refresh_btn.image = refresh_icon
        refresh_btn.pack(side='left')

        # Frame chứa nội dung
        content_frame = tb.Frame(main_frame)
        content_frame.pack(fill='both', expand=True)

        scrollable_frame = create_scrollable_frame(content_frame)
        scrollable_frame.pack(fill='both', expand=True)

        # Footer frame
        footer_frame = tb.Frame(main_frame)
        footer_frame.pack(fill='x', pady=(10, 0))

        # Nút quay lại
        back_btn = tb.Button(
            footer_frame,
            text="🔙 Quay lại",
            command=restart_app,
            bootstyle="danger outline"
        )
        back_btn.pack(side='right')

        # Nút xuất báo cáo
        export_btn = tb.Button(
            footer_frame,
            text="📤 Xuất báo cáo",
            command=export_report,
            bootstyle="success outline"
        )
        export_btn.pack(side='right', padx=(0, 10))

        def on_file_selected(event=None):
            selected_file = selected_file_var.get()
            if not selected_file:
                return

            file_path = os.path.join(output_directory, selected_file)
            if not os.path.exists(file_path):
                messagebox.showerror("Lỗi", f"Không tìm thấy file: {selected_file}")
                return

            for widget in scrollable_frame.winfo_children():
                widget.destroy()

            try:
                data = read_csv(file_path)
                show_csv_in_treeview(scrollable_frame, data, selected_file)

                # Làm nổi bật combobox khi chọn
                file_combobox.configure(bootstyle="info")

            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể đọc file: {str(e)}")

        file_combobox.bind('<<ComboboxSelected>>', on_file_selected)

        if csv_files:
            selected_file_var.set(csv_files[0])
            app.after(100, on_file_selected)

    def restart_app():
        """Khởi động lại ứng dụng"""
        python = sys.executable
        os.execl(python, python, *sys.argv)

    def export_report():
        """Xuất báo cáo tổng hợp"""
        # Thêm chức năng xuất báo cáo ở đây
        messagebox.showinfo("Thông báo", "Chức năng xuất báo cáo đang được phát triển")


    # Nút thoát
    exit_button = tk.Button(status_window, text="Thoát", command=on_exit)
    exit_button.pack(side="left", padx=10, pady=10)

    # Nút xem kết quả
    result_button = tk.Button(status_window, text="Xem kết quả", command=show_results)
    result_button.pack(side="right", padx=10, pady=10)

    status_window.withdraw()

    return lambda message: status_label.config(text=message)



# Hàm đọc dữ liệu từ tệp CSV
def read_csv(file_path):
    import csv

    encodings_to_try = ['utf-8-sig', 'utf-8', 'latin1', 'windows-1252']
    data = []

    for enc in encodings_to_try:
        try:
            with open(file_path, newline='', encoding=enc) as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    data.append(row)
            break  # Đọc thành công thì thoát vòng lặp
        except UnicodeDecodeError:
            continue  # Thử mã hóa tiếp theo nếu lỗi

    return data





def show_csv_in_treeview(parent, data, title):
    if not data:
        return

    frame = tb.Frame(parent)
    frame.pack(expand=True, fill='both')

    # Nhãn tiêu đề
    title_label = tb.Label(frame, text=title, bootstyle="inverse-primary")
    title_label.pack(side="top", fill="x")

    tree_frame = tb.Frame(frame)
    tree_frame.pack(expand=True, fill='both')

    # Tạo style tùy chỉnh cho Treeview
    style = tb.Style()
    style.configure("Left.Treeview.Heading", anchor="w")  # Căn trái cho tiêu đề
    
    tree = tb.Treeview(tree_frame, columns=data[0], show="headings", bootstyle="info")
    tree.pack(side="left", expand=True, fill='both')

    # Thanh cuộn dọc
    scrollbar = tb.Scrollbar(tree_frame, orient="vertical", command=tree.yview, bootstyle="round")
    scrollbar.pack(side="right", fill='y')
    tree.configure(yscrollcommand=scrollbar.set)
    
    # Cài đặt tiêu đề và cột - SỬA ĐỔI Ở ĐÂY
    for col in data[0]:
        tree.column(col, width=92, anchor="w")  # Dữ liệu căn trái
        tree.heading(col, text=col, anchor="w")  # Tiêu đề căn trái

    # Chèn dữ liệu vào TreeView
    for row in data[1:]:
        tree.insert("", "end", values=row)

    # Khung tìm kiếm
    search_frame = tb.Frame(frame)
    search_frame.pack(side="top", fill="x", pady=5)

    headers = ['Tất cả'] + data[0]
    header_combobox = tb.Combobox(search_frame, values=headers, state="readonly", bootstyle="info")
    header_combobox.pack(side="left", padx=5)
    header_combobox.current(0)

    search_entry = tb.Entry(search_frame)
    search_entry.pack(side="left", padx=5)

    def on_search():
        query = search_entry.get().lower()
        selected_header = header_combobox.get()

        for item in tree.get_children():
            tree.item(item, tags=("normal",))

        matching_items = []
        non_matching_items = []

        if selected_header == "Tất cả":
            for item in tree.get_children():
                if query in " ".join(map(str, tree.item(item, 'values'))).lower():
                    matching_items.append(item)
                else:
                    non_matching_items.append(item)
        else:
            col_index = data[0].index(selected_header)
            for item in tree.get_children():
                if query in str(tree.item(item, 'values')[col_index]).lower():
                    matching_items.append(item)
                else:
                    non_matching_items.append(item)

        # Làm nổi bật các dòng tìm được
        for item in matching_items + non_matching_items:
            tree.move(item, '', 'end')

        for item in matching_items:
            tree.item(item, tags=("found",))

        tree.tag_configure('found', background='yellow')
        tree.tag_configure('normal', background='white')

    search_button = tb.Button(search_frame, text="Tìm kiếm", command=on_search, bootstyle="primary")
    search_button.pack(side="left", padx=5)

def on_frame_configure(event, canvas=None):
    if not canvas:
        canvas = event.widget
    canvas.configure(scrollregion=canvas.bbox("all"))


def create_scrollable_frame(parent):
    canvas = tk.Canvas(parent)
    canvas.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")
    canvas.configure(yscrollcommand=scrollbar.set)

    scrollable_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')

    def on_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    scrollable_frame.bind("<Configure>", on_configure)

    return scrollable_frame





def execute_and_save_artifacts():
    global logger, status_window
    try:
        setup_logging(output_entry.get())
        update_status = open_status_window()
        selected_artifacts = [a for a, var in variables.items() if var.get()]
        
        logger.info(f"Bắt đầu thu thập {len(selected_artifacts)} hiện vật được chọn")

        collected_files = []
        
        for artifact in selected_artifacts:
            func = artifact_functions.get(artifact)
            if func:
                try:
                    update_status(f"Bắt đầu thu thập: {artifact}")
                    logger.info(f"Bắt đầu xử lý hiện vật: {artifact}")
                    
                    result = func(output_entry.get())
                    if result:
                        if isinstance(result, str):
                            collected_files.append(result)
                        elif isinstance(result, list):
                            collected_files.extend(result)
                    
                    update_status(f"Hoàn tất thu thập: {artifact}")
                    logger.info(f"Hoàn thành xử lý hiện vật: {artifact}")
                except Exception as e:
                    logger.error(f"Lỗi khi xử lý hiện vật {artifact}: {str(e)}", exc_info=True)
                    update_status(f"❌ Lỗi khi thu thập: {artifact}")
        
        # Xác minh tính toàn vẹn
        update_status("🔍 Đang xác minh tính toàn vẹn dữ liệu...")
        integrity_report = verify_artifacts_integrity(output_entry.get())
        logger.info(f"Báo cáo tính toàn vẹn: {integrity_report}")
        
        logger.info("Đã hoàn thành tất cả tác vụ thu thập")
        update_status("✅ Tất cả tác vụ đã hoàn thành.")
        status_window.deiconify()

    except Exception as e:
        logger.critical(f"Lỗi nghiêm trọng trong quá trình thực thi: {str(e)}", exc_info=True)
        update_status("❌ Đã xảy ra lỗi nghiêm trọng!")
        
        error_popup = tk.Toplevel(app)
        error_popup.title("Lỗi")
        error_popup.geometry("400x150")
        error_popup.resizable(False, False)
        tb.Label(error_popup, text="Đã xảy ra lỗi nghiêm trọng!", 
                font=("Segoe UI", 12, "bold"), bootstyle="danger").pack(pady=(20, 10))
        tb.Label(error_popup, text=str(e), font=("Segoe UI", 10), 
                wraplength=380, bootstyle="secondary").pack(pady=(0, 10))
        tb.Button(error_popup, text="Đóng", bootstyle="danger-outline", 
                command=error_popup.destroy).pack()
if __name__ == "__main__":
    try:
        app = tb.Window(themename="cosmo")  # Hoặc 'cosmo', 'flatly', 'darkly',...
        app.title('🛠️ Công cụ thu thập Artifacts trên hệ điều hành Windows')
        app.geometry("1800x720")
        app.resizable(False, False)
        
        # Nhóm nhập mã vụ việc
        case_frame = tb.LabelFrame(app, text="🔍 Thông tin vụ việc", padding=10, bootstyle="primary")
        case_frame.pack(fill='x', padx=20, pady=10)

        tb.Label(case_frame, text="Mã vụ việc / Tham chiếu:", bootstyle="primary").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        case_ref_entry = tb.Entry(case_frame, width=80)
        case_ref_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=2, sticky='w')

        # Nhóm hiện vật thu thập
        artifact_frame = tb.LabelFrame(app, text="📦 Chọn các hiện vật cần thu thập", padding=10, bootstyle="info")
        artifact_frame.pack(fill='x', padx=20, pady=10)

        checkbuttons = {}
        variables = {}
        options = [
            "Thông tin Prefetch", "Hiện vật hệ thống tệp NTFS", "Thông tin hệ thống", "Dữ liệu Registry Hive",
            "Nhật ký Event Viewer", "SRUM, Hosts và dịch vụ", "Biến môi trường", "Danh sách bản vá (Patch List)",
            "Danh sách tiến trình đang chạy", "Thông tin kết nối (cổng đang mở)", "Cấu hình địa chỉ IP", "Bảng ARP",
            "Thông tin NetBIOS", "Danh sách Handle đang mở", "Lịch trình tác vụ (Task Scheduler)",
            "Lịch sử đăng nhập hệ thống", "Dịch vụ đã đăng ký", "Trình theo dõi sử dụng ứng dụng (UserAssist)",
            "Ứng dụng khởi động cùng hệ thống (Autorun)", "Lịch sử trình duyệt web", "Thùng rác (Recycle Bin)",
            "Nhật ký PowerShell", "Tệp LNK gần đây"
        ]

        for i, option in enumerate(options):
            variables[option] = tk.BooleanVar()
            checkbuttons[option] = tb.Checkbutton(artifact_frame, text=option, variable=variables[option], bootstyle="round-toggle")
            checkbuttons[option].grid(row=i // 4, column=i % 4, padx=5, pady=4, sticky='w')

        # Nhóm thư mục xuất
        output_frame = tb.LabelFrame(app, text="📁 Thư mục lưu kết quả", padding=10, bootstyle="success")
        output_frame.pack(fill='x', padx=20, pady=10)

        output_entry = tb.Entry(output_frame, width=80)
        output_entry.pack(side="left", padx=5, pady=5, fill='x', expand=True)
        browse_button = tb.Button(output_frame, text="Duyệt...", bootstyle="secondary", command=browse_output_directory)
        browse_button.pack(side="left", padx=5, pady=5)

        set_default_output_directory()
        # Nút bắt đầu
        start_button = tb.Button(app, text="🚀 Bắt đầu thu thập", bootstyle="success outline", command=execute_and_save_artifacts)
        start_button.pack(pady=20, ipadx=10, ipady=5)
        
        # Nhãn trạng thái
        status_label = tb.Label(app, text="", font=("Segoe UI", 11), bootstyle="success")
        status_label.pack()

        app.mainloop()

    except Exception as e:
        print(f"Lỗi khởi chạy ứng dụng: {str(e)}")
        sys.exit(1)

