import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv
import os
import tkinter

global canvas

# == 아티팩트 함수 ==========================================================================================================================
def memory_dump_func():
    file_name = 'memory_dump.csv'

    with open(file_name, 'r') as file:
        reader = csv.reader(file)
        return list(reader)

def prefetch_func():
    file_name = 'prefetch.csv'

    with open(file_name, 'r') as file:
        reader = csv.reader(file)
        return list(reader)

def NTFS_func():
    return ["항목1", "항목2", "항목3"]


def sys_info_func():
    return []

def regi_hive():
    return ["1232"]

def event_viewer_log_func():
    return 1

def enviornment_func():
    return 1

def patch_list_func():
    return 1

def process_list_info_func():
    return 1

def connection_info_func():
    return 1

def ip_setting_info_func():
    return 1

def ARP_info_func():
    return 1

def NetBIOS_info_func():
    return 1

def open_handle_info_func():
    return 1

def work_schedule_info_func():
    return 1

def sys_logon_info_func():
    return 1

def regi_service_info_func():
    return 1

def recent_act_info_func():
    return 1

def userassist_func():
    return 1

def autorun_func():
    return 1

def registry_func():
    return 1

def browser_info_func():
    return 1

def bin_func():
    return 1

def powershell_log_func():
    return 1

def lnk_files_func():
    return 1



# == 아티팩트 함수 ==========================================================================================================================
artifact_functions = {
    "Bản ghi nhớ (Memory Dump)": memory_dump_func,
    "Thông tin Prefetch": prefetch_func,
    "Hiện vật hệ thống tệp NTFS": NTFS_func,
    "Thông tin hệ thống": sys_info_func,
    "Dữ liệu Registry Hive": regi_hive,
    "Nhật ký Event Viewer": event_viewer_log_func,
    "Biến môi trường": enviornment_func,
    "Danh sách bản vá (Patch List)": patch_list_func,
    "Danh sách tiến trình đang chạy": process_list_info_func,
    "Thông tin kết nối (cổng đang mở)": connection_info_func,
    "Cấu hình địa chỉ IP": ip_setting_info_func,
    "Bảng ARP": ARP_info_func,
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

# Chức năng tìm kiếm theo từng hiện vật (artifact)
def search_in_treeview(tree, query, header_name, header_map, search_results):
    search_results.clear()

    if header_name == 'Tất cả':
        search_columns = range(len(tree['columns']))
    else:
        search_columns = [header_map[header_name]]

    for item in tree.get_children():
        if any(query.lower() in str(tree.item(item, 'values')[col]).lower() for col in search_columns):
            tree.item(item, tags=('found',))
            search_results.append(item)
        else:
            tree.item(item, tags=('not_found',))



def navigate_search_results(tree, search_results, direction):
    if not search_results:
        return

    current_item = tree.focus()
    next_item = None

    if direction == "up":
        previous_items = [item for item in search_results if tree.index(item) < tree.index(current_item)]
        if previous_items:
            next_item = previous_items[-1]

    elif direction == "down":
        next_items = [item for item in search_results if tree.index(item) > tree.index(current_item)]
        if next_items:
            next_item = next_items[0]

    if next_item:
        tree.selection_set(next_item)
        tree.focus(next_item)
        tree.see(next_item)  



# Chức năng bật/tắt (toggle) danh sách kết quả
def toggle_items(frame):
    frame.pack_forget() if frame.winfo_viewable() else frame.pack(side='top', fill='x', padx=5, pady=5)

# Hiển thị khung kết quả
def create_result_frame(parent, title, items):
    frame = tk.Frame(parent, relief='solid', borderwidth=2, background='white')
    frame.pack(side='top', fill='x', padx=5, pady=5)

    title_frame = tk.Frame(frame, background='#D6D5CB')
    title_frame.pack(side='top', fill='x')
    title_label = tk.Label(title_frame, text=title, font=('Arial', 10), background='#D6D5CB', anchor='w')
    title_label.pack(side='left', padx=5, pady=5)

    items_frame = tk.Frame(frame, background='white')
    items_frame.pack(side='top', fill='x', padx=5, pady=5)

    if not isinstance(items, list):
        items = [items]

    if len(items) > 0 and all(isinstance(item, list) for item in items):
        search_results = []
        header_map = {name: index for index, name in enumerate(items[0])}
        search_frame = tk.Frame(frame)
        search_frame.pack(side='top', fill='x', padx=5, pady=5)

        header_options = ['Tất cả'] + items[0]
        header_combobox = ttk.Combobox(search_frame, values=header_options, state="readonly")
        header_combobox.current(0)
        header_combobox.pack(side='left', padx=5, pady=5)

        # Ô tìm kiếm và nút tìm kiếm
        search_entry = tk.Entry(search_frame)
        search_entry.pack(side='left', padx=5, pady=5)
        search_button = tk.Button(search_frame, text="Tìm kiếm", command=lambda: search_in_treeview(tree, search_entry.get(), header_combobox.get(), header_map))
        search_button.pack(side='left', padx=5, pady=5)

        up_button = tk.Button(search_frame, text="Lên", command=lambda: navigate_search_results(tree, search_results, "up"))
        up_button.pack(side='left', padx=5, pady=5)

        down_button = tk.Button(search_frame, text="Xuống", command=lambda: navigate_search_results(tree, search_results, "down"))
        down_button.pack(side='left', padx=5, pady=5)

        # Thêm nút lọc
        filter_button = tk.Button(search_frame, text="Lọc", command=lambda: show_filter_window(items[0], tree))
        filter_button.pack(side='left', padx=5, pady=5)

        # Thêm nút khởi tạo lại (reset)
        reset_button = tk.Button(search_frame, text="Khởi tạo lại", command=lambda: reset_treeview(tree))
        reset_button.pack(side='left', padx=5, pady=5)

        search_button.config(command=lambda: search_in_treeview(tree, search_entry.get(), header_combobox.get(), header_map, search_results))


        # Tạo và cấu hình widget Treeview
        tree = ttk.Treeview(items_frame, columns=[str(i) for i in range(len(items[0]))], show='headings')
        tree.pack(side='left', fill='both', expand=True)

        for i, title in enumerate(items[0]):
            tree.heading(str(i), text=title)
            tree.column(str(i), width=100, minwidth=50, anchor=tk.W)

        for row in items[1:]:
            tree.insert('', 'end', values=row)

        scrollbar = ttk.Scrollbar(items_frame, orient='vertical', command=tree.yview)
        scrollbar.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar.set)

        tree.tag_configure('found', background='yellow')
        tree.tag_configure('not_found', background='white')

    else:
        for item in items:
            item_label = tk.Label(items_frame, text=item, background='white')
            item_label.pack(side='top', anchor='w', padx=5, pady=2)

    title_frame.bind("<Button-1>", lambda e: toggle_items(items_frame))
    title_label.bind("<Button-1>", lambda e: toggle_items(items_frame))

    return frame



# Tạo và cấu hình cửa sổ lọc
def show_filter_window(headers, tree):
    filter_window = tk.Toplevel(app)
    filter_window.title("Cấu hình bộ lọc")
    filter_window.geometry("330x400")
    filter_window.resizable(False, False)

    filter_frame = tk.Frame(filter_window)
    filter_frame.pack(fill='both', expand=True, padx=5, pady=5)

    button_frame = tk.Frame(filter_window)
    button_frame.pack(side='top', pady=5)

    # Nút thêm điều kiện
    add_condition_button = tk.Button(filter_window, text="Thêm điều kiện", command=lambda: add_filter_condition(filter_frame, headers, tree))
    add_condition_button.pack(side='top', pady=5)

    # Nút áp dụng lọc
    apply_button = tk.Button(button_frame, text="Áp dụng", command=lambda: apply_filters(tree, headers, filter_window))
    apply_button.pack(side='left', padx=5)

    add_filter_condition(filter_frame, headers, tree)


filter_conditions = []
def add_filter_condition(filter_frame, headers, tree):
    condition_frame = tk.Frame(filter_frame)
    condition_frame.pack(fill='x', padx=5, pady=5)

    # Combobox để chọn cột (header)
    header_options = ["Tất cả"] + headers
    header_combobox = ttk.Combobox(condition_frame, values=header_options, state="readonly", width=10)
    header_combobox.pack(side='left', padx=5)
    header_combobox.current(0)

    # Trường nhập nội dung lọc
    filter_entry = ttk.Entry(condition_frame, width=20)
    filter_entry.pack(side='left', padx=5)
    

    # Nút xoá điều kiện
    def delete_condition():
        condition_frame.destroy()

    delete_button = tk.Button(condition_frame, text="X", command=delete_condition)
    delete_button.pack(side='right', padx=5)

    # Lưu điều kiện lọc
    condition = {
        "header_combobox": header_combobox,
        "filter_entry": filter_entry,
    }
    filter_conditions.append(condition)



def apply_filters(tree, headers, filter_window):
    matching_items = []
    non_matching_items = []

    for item in tree.get_children():
        item_values = tree.item(item, 'values')
        match = True

        for condition in filter_conditions:
            try:
                header = condition["header_combobox"].get()
                value = condition["filter_entry"].get().lower()

                header_index = headers.index(header) if header != "Tất cả" else None

                if header_index is not None:
                    if value not in item_values[header_index].lower():
                        match = False
                        break
                else:
                    if not any(value in str(v).lower() for v in item_values):
                        match = False
                        break
            except tkinter.TclError:
                continue

        if match:
            matching_items.append((item, tree.item(item)))
        else:
            non_matching_items.append((item, tree.item(item)))

    # Xoá tất cả các mục trong TreeView
    tree.delete(*tree.get_children())

    # Các mục khớp với điều kiện lọc
    for item, values in matching_items:
        tree.insert('', 'end', iid=item, values=values['values'], tags=('matched',))

    # Các mục không khớp với điều kiện lọc
    for item, values in non_matching_items:
        tree.insert('', 'end', iid=item, values=values['values'], tags=('not_matched',))

    # Cài đặt màu nền
    tree.tag_configure('matched', background='white')
    tree.tag_configure('not_matched', background='lightgray')

    filter_window.destroy()



def reset_treeview(tree):
    for item in tree.get_children():
        tree.item(item, tags=('default',))

    tree.tag_configure('default', background='white')

# Kết nối cuộn chuột với khung kết quả
def on_mousewheel(event):
    global canvas
    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

def move_to_frame():
    selected_artifact = selected_combobox.get()
    if selected_artifact in artifact_frames:
        y_position = artifact_frames[selected_artifact]
        
        scrollregion = canvas.cget("scrollregion").split()
        if scrollregion:
            scrollregion_height = int(scrollregion[3])

            relative_position = y_position / scrollregion_height

            canvas.yview_moveto(relative_position)



def start_capture():
    global case_ref_label, case_ref_entry, options_frame, output_label, output_entry, browse_button, start_button, artifact_label, canvas, fixed_frame, selected_combobox, artifact_frames
    # Ẩn các widget hiện tại
    case_label.grid_forget()
    case_ref_entry.grid_forget()
    options_frame.grid_forget()
    output_label.grid_forget()
    output_entry.grid_forget()
    browse_button.grid_forget()
    start_button.grid_forget()
    artifact_label.grid_forget()



    case_ref = case_ref_entry.get()

    fixed_frame = tk.Frame(app, background='#f0f0f0')
    fixed_frame.grid(row=0, column=0, columnspan=3, sticky='ew')

    move_button = ttk.Button(fixed_frame, text="Di chuyển", command=move_to_frame)
    move_button.grid(row=0, column=1, padx=5, pady=5)

    # Danh sách checkbox
    selected_options = [option for option in options if variables[option].get()]
    
    # Combobox lựa chọn
    selected_combobox = ttk.Combobox(fixed_frame, values=selected_options, state="readonly")
    selected_combobox.grid(row=0, column=0, padx=5, pady=5)

    canvas = tk.Canvas(app, borderwidth=0, background="#ffffff", height=550, width=780)
    scrollbar = tk.Scrollbar(app, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.grid(row=3, column=1, sticky='ns')
    canvas.grid(row=2, column=0, sticky="nsew")
    canvas.bind_all("<MouseWheel>", on_mousewheel)


    result_container = tk.Frame(canvas, background='white')
    canvas.create_window((0, 0), window=result_container, anchor="nw")
    result_container.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))


    case_ref_label = tk.Label(result_container, text="Tham chiếu Case: {}".format(case_ref), font=('Arial', 12), background='white', anchor='w', width=85)
    case_ref_label.pack(side='top', fill='x', padx=5, pady=5)


    artifact_frames = {}
    y_position = 0
    for option in options:
        if variables[option].get() and option in artifact_functions:
            function = artifact_functions[option]
            result_items = function()
            frame = create_result_frame(result_container, option, result_items)
            frame.pack(side='top', fill='x', padx=5, pady=5)

            app.update_idletasks()

            frame_height = frame.winfo_height()
            artifact_frames[option] = y_position
            y_position += frame_height





# == Trang bắt đầu ==================================================================================================================================


# Hàm tìm vị trí lưu tệp
def browse_output_directory():
    directory = filedialog.askdirectory()
    if directory:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, directory)


# Cấu trúc cửa sổ UI / Phong cách
app = tk.Tk()
app.title('Công cụ thu thập dữ liệu')
app.geometry("800x600")
app.resizable(False, False)
app['bg'] = '#f0f0f0'
style = ttk.Style()
style.theme_use('clam')



#  Phần tham chiếu hồ sơ vụ việc
case_label = ttk.Label(app, text="Mã hồ sơ / Tham chiếu:", background='#f0f0f0')
case_label.grid(row=0, column=0, padx=5, pady=10)
case_ref_entry = ttk.Entry(app)
case_ref_entry.grid(row=0, column=1, padx=5, pady=10, columnspan=2, sticky='ew')


# Phần tùy chọn thu thập dữ liệu
artifact_label = ttk.Label(app, text="Chọn các dấu vết cần thu thập", background='#f0f0f0', font=('Arial', 10))
artifact_label.grid(row=1, column=0, columnspan=1, padx=5, pady=(50, 1))
options_frame = ttk.Frame(app, relief='solid', borderwidth=2)
options_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=1, sticky='ew')


# Hàm chọn tất cả
def select_all():
    for option in options:
        variables[option].set(select_all_var.get())

# Khởi tạo biến và checkbox cho từng tùy chọn
checkbuttons = {}
variables = {}
options = [
    "Bản ghi nhớ (Memory Dump)",
    "Prefetch", 
    "Hiện vật NTFS", 
    "Thông tin hệ thống",
    "Tệp Registry Hive",
    "Nhật ký Event Viewer",
    "SRUM, Hosts và dịch vụ",
    "Biến môi trường",
    "Danh sách bản vá",
    "Danh sách tiến trình đang chạy",
    "Thông tin kết nối (cổng đang mở)",
    "Thông tin cấu hình IP",
    "Thông tin ARP",
    "Thông tin NetBIOS",
    "Thông tin Handle đang mở",
    "Thông tin tác vụ định kỳ",
    "Thông tin đăng nhập hệ thống",
    "Thông tin dịch vụ đã đăng ký",
    "Thông tin hoạt động gần đây",
    "UserAssist",
    "AutoRun",
    "Registry",
    "Lịch sử trình duyệt",
    "Thùng rác",
    "Nhật ký PowerShell",
    "Tệp LNK gần đây"
]
for i, option in enumerate(options):
    variables[option] = tk.BooleanVar()
    checkbuttons[option] = ttk.Checkbutton(options_frame, text=option, variable=variables[option])
    checkbuttons[option].grid(row=i // 5, column=i % 5, padx=3, pady=2, sticky='w')

# Thiết lập độ rộng cột trong khung
for i in range(5):
    options_frame.grid_columnconfigure(i, weight=1)

# Chức năng chọn tất cả
select_all_var = tk.BooleanVar()
select_all_checkbox = ttk.Checkbutton(options_frame, text="Chọn tất cả", variable=select_all_var, command=select_all)
select_all_checkbox.grid(row=100, column=4, padx=3, pady=2, sticky='e')



# Cài đặt vị trí lưu kết quả
output_label = ttk.Label(app, text="Vị trí lưu đầu ra:", background='#f0f0f0')
output_label.grid(row=1000, column=0, padx=5, pady=100, sticky='e')
output_entry = ttk.Entry(app)
output_entry.grid(row=1000, column=1, padx=5, pady=100, sticky='ew')
browse_button = ttk.Button(app, text="Duyệt", command=browse_output_directory)
browse_button.grid(row=1000, column=2, padx=(5, 30), pady=100)



# Nút bắt đầu thu thập
start_button = ttk.Button(app, text="Bắt đầu thu thập", command=start_capture)
start_button.grid(row=1001, column=0, columnspan=3, padx=5, pady=20)



result_label = tk.Label(app, justify=tk.LEFT, anchor='w')
result_label.grid(row=1002, column=0, columnspan=3, padx=5, pady=20)


app.grid_rowconfigure(1, weight=1)
app.grid_columnconfigure(1, weight=1)
app.mainloop()
