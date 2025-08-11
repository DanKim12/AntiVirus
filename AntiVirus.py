#installing a library in python
import os
import requests
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import messagebox

#constants
api_key = "69b7cf63cc753825e4e243e3d0195af6c6b38a7ec44337166d34e606fa59761a" #switch with your api key
scan_url = "https://www.virustotal.com/vtapi/v2/file/scan"
report_url = "https://www.virustotal.com/vtapi/v2/file/report"


def Exists(path):
    return os.path.exists(path)

def scan_file(file_path):
    scan_id = upload_file(file_path)
    is_virus = get_report(scan_id)
    if is_virus:
        print("Found a virus: ", file_path)
    else:
        print(file_path, " is not a virus")
    return is_virus


def get_report(scan_id):
    print("Getting Report for scan_id", scan_id)
    params = {'apikey': api_key, "resource": scan_id}
    response = requests.get(report_url, params=params)
    if not response:
        raise Exception("Unexpected error")
    
    if response.status_code == 200:
        result = response.json()
        if "positives" in result:
            return result["positives"] > 0
        else:
            print("Warning: 'positives' key not found in the report response.")
            return False
    elif response.status_code == 204:
        raise Exception("Rate limit exceeded: Too many requests. Please try later.")
    elif response.status_code == 400:
        raise Exception("Bad request: The request was invalid or malformed.")
    elif response.status_code == 401:
        raise Exception("Unauthorized: API key is invalid or missing.")
    elif response.status_code == 403:
        raise Exception("Forbidden: Access denied to the resource.")
    elif response.status_code == 404:
        raise Exception("Not Found: The requested resource does not exist.")
    elif response.status_code == 500:
        raise Exception("Internal Server Error: Server encountered an error.")
    else:
        raise Exception(f"Unexpected HTTP status code: {response.status_code}")


def upload_file(file_path):
    print("scanning file: ", file_path)
    params = {'apikey': api_key}
    files = {'file': (file_path, open(file_path, 'rb'))}
    rsp = requests.post(scan_url, files=files, params=params)
    rsp = rsp.json()
    return rsp["scan_id"]


def scan_folder(folder_path):
    print("scanning folder", folder_path)
    for file in os.listdir(folder_path): #listdir-creates a list of files(paths) in folder
        FilePath = os.path.join(folder_path, file) #full path

        if os.path.isdir(FilePath):
            scan_folder(FilePath)
        else:
            scan_file(FilePath)


#--------------------------------------------------------------------------------------------------

#GUI SECTION
# Create main window
my_status = None

# Create main window
root = tk.Tk()
root.title("Antivirus Scanner")
root.geometry("600x600")
root.configure(bg="#1E2D3B")

# Center window on screen
root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width - width) // 2
y = (screen_height - height) // 2
root.geometry(f"{width}x{height}+{x}+{y}")

# Title label
title_label = tk.Label(
    root,
    text="Antivirus Scanner",
    font=("Segoe UI", 28, "bold"),
    fg="#00FF7F",
    bg="#1E2D3B",
)
title_label.pack(pady=40)

# Buttons frame
button_frame = tk.Frame(root, bg="#1E2D3B")
button_frame.pack(pady=20)

style = ttk.Style()
style.theme_use('clam')

style.configure(
    "Custom.TButton",
    font=("Segoe UI", 18, "bold"),
    foreground="#FFFFFF",
    background="#008080",
    padding=15,
    borderwidth=0,
    focusthickness=3,
    focuscolor='none',
)
style.map(
    "Custom.TButton",
    background=[('active', '#00CED1'), ('!active', '#008080')],
)

custom_scan_btn = ttk.Button(
    button_frame, text="Custom Scan", style="Custom.TButton", width=20
)
custom_scan_btn.grid(row=0, column=0, padx=30, pady=20)

smart_scan_btn = ttk.Button(
    button_frame, text="Smart Scan(Not available at the moment)", style="Custom.TButton", width=20
)
smart_scan_btn.grid(row=1, column=0, padx=30, pady=20)

# Search frame
search_frame = tk.Frame(root, bg="#223344")
search_frame.pack(fill='x', padx=40, pady=10)
search_frame.pack_forget()

status_label = tk.Label(root, text="", fg="red", bg="#1E2D3B", font=("Segoe UI", 12, "bold"))
status_label.pack(pady=5)
status_label.pack_forget()

search_var = tk.StringVar()

search_entry = tk.Entry(
    search_frame,
    textvariable=search_var,
    font=("Segoe UI", 14),
    fg="#FFFFFF",
    bg="#334455",
    relief="flat",
    insertbackground="#FFFFFF",
)
search_entry.pack(side='left', fill='x', expand=True, ipady=6, padx=(10, 0))

def open_file_dialog():
    global my_status
    choice = messagebox.askquestion(
        "Select scan target",
        "Do you want to scan a folder? (Yes = folder, No = file)"
    )
    if choice == 'yes':
        path = filedialog.askdirectory(title="Select folder to scan")
        my_status = 0
    else:
        path = filedialog.askopenfilename(title="Select file to scan")
        my_status = 1
    if path:
        search_var.set(path)

search_btn = tk.Button(
    search_frame,
    text="🔍",
    font=("Segoe UI", 18),
    fg="#00FF7F",
    bg="#1E2D3B",
    relief="flat",
    activebackground="#00CED1",
    activeforeground="#003300",
    command=open_file_dialog,
    width=4,
)
search_btn.pack(side='left', padx=10, pady=6)

# Start Scan button
start_scan_btn = ttk.Button(
    root,
    text="Start Scan",
    style="Custom.TButton",
    width=20,
    command=None
)
start_scan_btn.pack(pady=20)
start_scan_btn.pack_forget()


def start_scan():
    path = search_var.get()
    if not Exists(path):
        status_label.config(text="Path does not exist")
        status_label.pack()
        return
    status_label.pack_forget()

    if my_status == 0:
        scan_folder(path)
    else:
        scan_file(path)

start_scan_btn.config(command=start_scan)


def on_search_var_change(*args):
    if search_var.get().strip():
        start_scan_btn.pack(pady=20)
    else:
        start_scan_btn.pack_forget()
        status_label.pack_forget()

search_var.trace_add("write", on_search_var_change)

def on_custom_scan_click():
    if search_frame.winfo_ismapped():
        search_frame.pack_forget()
        start_scan_btn.pack_forget()
        status_label.pack_forget()
    else:
        search_frame.pack(fill='x', padx=40, pady=10)

custom_scan_btn.config(command=on_custom_scan_click)

root.mainloop()