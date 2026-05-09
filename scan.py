import socket
import threading
import ipaddress
import csv
import json
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor

# =========================
# COMMON PORT SERVICES
# =========================
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

# =========================
# GLOBAL VARIABLES
# =========================
scan_running = False
open_ports_data = []

# =========================
# PORT SCANNING FUNCTION
# =========================
def scan_ports():

    global scan_running
    global open_ports_data

    target = entry_ip.get().strip()

    # Validate IP
    try:
        ipaddress.ip_address(target)
    except ValueError:
        messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
        return

    # Validate Ports
    try:
        start_port = int(entry_start.get())
        end_port = int(entry_end.get())

        if start_port < 1 or end_port > 65535:
            raise ValueError

        if start_port > end_port:
            messagebox.showerror(
                "Port Error",
                "Start Port cannot be greater than End Port."
            )
            return

    except:
        messagebox.showerror(
            "Invalid Ports",
            "Please enter valid port numbers (1-65535)."
        )
        return

    # Clear old results
    result_box.delete(*result_box.get_children())
    open_ports_data.clear()

    progress['value'] = 0
    status_label.config(text="Scanning...", fg="yellow")

    total_ports = end_port - start_port + 1
    scanned_ports = 0

    scan_running = True

    # =========================
    # SCAN SINGLE PORT
    # =========================
    def scan(port):

        nonlocal scanned_ports

        if not scan_running:
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)

            result = s.connect_ex((target, port))

            if result == 0:

                service = services.get(port, "Unknown")

                banner = ""

                # Banner grabbing
                try:
                    s.send(b"HELLO\r\n")
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "No Banner"

                s.close()

                data = {
                    "Port": port,
                    "Status": "OPEN",
                    "Service": service,
                    "Banner": banner
                }

                open_ports_data.append(data)

                # Safe GUI update
                root.after(
                    0,
                    lambda d=data: result_box.insert(
                        "",
                        "end",
                        values=(
                            d["Port"],
                            d["Status"],
                            d["Service"],
                            d["Banner"]
                        )
                    )
                )

        except:
            pass

        scanned_ports += 1

        percent = (scanned_ports / total_ports) * 100

        root.after(
            0,
            lambda: progress.config(value=percent)
        )

    # =========================
    # RUN SCAN
    # =========================
    def run():

        global scan_running

        start_time = datetime.now()

        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan, range(start_port, end_port + 1))

        end_time = datetime.now()
        duration = end_time - start_time

        scan_running = False

        root.after(
            0,
            lambda: status_label.config(
                text=f"Scan Complete | Time: {duration}",
                fg="#00ff99"
            )
        )

        root.after(
            0,
            lambda: messagebox.showinfo(
                "Scan Finished",
                f"Scanning completed for {target}"
            )
        )

    threading.Thread(target=run, daemon=True).start()

# =========================
# STOP SCAN
# =========================
def stop_scan():

    global scan_running

    scan_running = False

    status_label.config(
        text="Scan Stopped",
        fg="red"
    )

# =========================
# SAVE RESULTS
# =========================
def save_results():

    if not open_ports_data:
        messagebox.showwarning(
            "No Results",
            "No scan results available to save."
        )
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[
            ("Text File", "*.txt"),
            ("CSV File", "*.csv"),
            ("JSON File", "*.json")
        ]
    )

    if not file_path:
        return

    try:

        # TXT
        if file_path.endswith(".txt"):

            with open(file_path, "w") as file:

                for item in open_ports_data:
                    file.write(
                        f"Port {item['Port']} | "
                        f"{item['Status']} | "
                        f"{item['Service']} | "
                        f"{item['Banner']}\n"
                    )

        # CSV
        elif file_path.endswith(".csv"):

            with open(file_path, "w", newline="") as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "Port",
                        "Status",
                        "Service",
                        "Banner"
                    ]
                )

                writer.writeheader()
                writer.writerows(open_ports_data)

        # JSON
        elif file_path.endswith(".json"):

            with open(file_path, "w") as file:
                json.dump(open_ports_data, file, indent=4)

        messagebox.showinfo(
            "Saved",
            "Results saved successfully!"
        )

    except Exception as e:

        messagebox.showerror(
            "Save Error",
            str(e)
        )

# =========================
# RESOLVE HOSTNAME
# =========================
def resolve_hostname():

    target = entry_ip.get().strip()

    try:
        hostname = socket.gethostbyaddr(target)[0]

        messagebox.showinfo(
            "Hostname",
            f"Hostname:\n{hostname}"
        )

    except:
        messagebox.showerror(
            "Error",
            "Could not resolve hostname."
        )

# =========================
# GUI SETUP
# =========================
root = Tk()

root.title("Advanced Network Scanner")
root.geometry("900x600")
root.configure(bg="#1e1e1e")

# =========================
# STYLE
# =========================
style = ttk.Style()

style.theme_use("default")

style.configure(
    "Treeview",
    background="#2d2d2d",
    foreground="white",
    fieldbackground="#2d2d2d",
    rowheight=28
)

style.configure(
    "Treeview.Heading",
    font=("Arial", 10, "bold")
)

# =========================
# TITLE
# =========================
title = Label(
    root,
    text="ADVANCED NETWORK SCANNER",
    font=("Arial", 18, "bold"),
    bg="#1e1e1e",
    fg="#00ff99"
)

title.pack(pady=15)

# =========================
# INPUT FRAME
# =========================
input_frame = Frame(root, bg="#1e1e1e")
input_frame.pack(pady=10)

# IP
Label(
    input_frame,
    text="Target IP:",
    bg="#1e1e1e",
    fg="white",
    font=("Arial", 10)
).grid(row=0, column=0, padx=10, pady=5)

entry_ip = Entry(
    input_frame,
    width=20,
    font=("Arial", 11)
)

entry_ip.grid(row=0, column=1)

# Start Port
Label(
    input_frame,
    text="Start Port:",
    bg="#1e1e1e",
    fg="white",
    font=("Arial", 10)
).grid(row=0, column=2, padx=10)

entry_start = Entry(
    input_frame,
    width=10,
    font=("Arial", 11)
)

entry_start.grid(row=0, column=3)

# End Port
Label(
    input_frame,
    text="End Port:",
    bg="#1e1e1e",
    fg="white",
    font=("Arial", 10)
).grid(row=0, column=4, padx=10)

entry_end = Entry(
    input_frame,
    width=10,
    font=("Arial", 11)
)

entry_end.grid(row=0, column=5)

# =========================
# BUTTON FRAME
# =========================
button_frame = Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)

scan_btn = Button(
    button_frame,
    text="Start Scan",
    command=scan_ports,
    bg="#4CAF50",
    fg="white",
    width=15,
    font=("Arial", 10, "bold")
)

scan_btn.grid(row=0, column=0, padx=10)

stop_btn = Button(
    button_frame,
    text="Stop Scan",
    command=stop_scan,
    bg="#f44336",
    fg="white",
    width=15,
    font=("Arial", 10, "bold")
)

stop_btn.grid(row=0, column=1, padx=10)

save_btn = Button(
    button_frame,
    text="Save Results",
    command=save_results,
    bg="#2196F3",
    fg="white",
    width=15,
    font=("Arial", 10, "bold")
)

save_btn.grid(row=0, column=2, padx=10)

resolve_btn = Button(
    button_frame,
    text="Resolve Hostname",
    command=resolve_hostname,
    bg="#9C27B0",
    fg="white",
    width=18,
    font=("Arial", 10, "bold")
)

resolve_btn.grid(row=0, column=3, padx=10)

# =========================
# PROGRESS BAR
# =========================
progress = ttk.Progressbar(
    root,
    length=700,
    mode="determinate"
)

progress.pack(pady=15)

# =========================
# STATUS LABEL
# =========================
status_label = Label(
    root,
    text="Ready",
    bg="#1e1e1e",
    fg="white",
    font=("Arial", 10, "bold")
)

status_label.pack()

# =========================
# RESULT TABLE
# =========================
columns = (
    "Port",
    "Status",
    "Service",
    "Banner"
)

result_box = ttk.Treeview(
    root,
    columns=columns,
    show="headings",
    height=18
)

for col in columns:

    result_box.heading(col, text=col)

    result_box.column(
        col,
        anchor=CENTER,
        width=180
    )

result_box.pack(
    pady=20,
    padx=20,
    fill=BOTH,
    expand=True
)

# =========================
# START GUI
# =========================
root.mainloop()