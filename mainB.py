import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading
import socket
import queue
import ipaddress

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("端口扫描工具")

        self.ip_label = tk.Label(root, text="目标IP段（例如：192.168.0.0/16）：")
        self.ip_label.pack()

        self.ip_entry = tk.Entry(root)
        self.ip_entry.pack()

        self.port_label = tk.Label(root, text="目标端口（例如：80）：")
        self.port_label.pack()

        self.port_entry = tk.Entry(root)
        self.port_entry.pack()

        self.scan_button = tk.Button(root, text="开始扫描", command=self.start_scan)
        self.scan_button.pack()

        self.cancel_button = tk.Button(root, text="取消扫描", command=self.cancel_scan)
        self.cancel_button.pack()
        self.cancel_button["state"] = "disabled"

        self.progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate")
        self.progress_bar.pack()

        self.queue = queue.Queue()
        self.threads = []

    def start_scan(self):
        target_ip_range = self.ip_entry.get()
        target_port = int(self.port_entry.get())

        if not target_ip_range or not target_port:
            messagebox.showerror("错误", "请输入目标IP段和端口")
            return

        try:
            ip_network = ipaddress.ip_network(target_ip_range)
        except ValueError:
            messagebox.showerror("错误", "无效的IP段格式")
            return

        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = ip_network.num_addresses

        self.threads = []
        for ip in ip_network:
            thread = threading.Thread(target=self.scan_thread, args=(str(ip), target_port))
            self.threads.append(thread)
            thread.start()

        self.scan_button["state"] = "disabled"
        self.cancel_button["state"] = "normal"

        self.check_progress()

    def scan_thread(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                self.queue.put(ip)
        except:
            pass
        finally:
            sock.close()

    def check_progress(self):
        finished_threads = sum(1 for thread in self.threads if not thread.is_alive())
        self.progress_bar["value"] = finished_threads

        if finished_threads < self.progress_bar["maximum"]:
            self.root.after(100, self.check_progress)
        else:
            self.show_results()
            self.scan_button["state"] = "normal"
            self.cancel_button["state"] = "disabled"

    def cancel_scan(self):
        for thread in self.threads:
            thread.join()
        self.threads = []
        self.scan_button["state"] = "normal"
        self.cancel_button["state"] = "disabled"

    def show_results(self):
        result_window = tk.Toplevel(self.root)
        result_window.title("扫描结果")

        results = []
        while not self.queue.empty():
            results.append(self.queue.get())

        results_text = tk.Text(result_window)
        results_text.pack()

        for ip in results:
            results_text.insert(tk.END, f"开放端口：{ip}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
