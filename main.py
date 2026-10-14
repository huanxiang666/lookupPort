#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端口扫描工具 — GUI + CLI 双模式。

特性:
- 线程池并发（默认 100），不会把系统拖垮
- 真正的取消（threading.Event + 取消待处理任务）
- 输入校验前置，非法输入弹窗提示，不崩
- 支持 CIDR 网段（192.168.1.0/24）或起始 IP 前缀（192.168.1.）
- 结果按 IP 数字序排序
"""
import argparse
import ipaddress
import queue
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 100
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                8888, 9200, 25565, 27017]


def parse_targets(ip_input: str):
    """解析目标为 IP 列表。支持 '192.168.1.' 前缀或 '192.168.1.0/24' CIDR 或单 IP。"""
    ip_input = ip_input.strip()
    if not ip_input:
        raise ValueError("目标不能为空")
    if "/" in ip_input:  # CIDR
        net = ipaddress.ip_network(ip_input, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if not hosts:
            hosts = [str(net.network_address)]
        return hosts
    if ip_input.endswith("."):  # 前缀 192.168.1.
        base = ip_input
        parts = base[:-1].split(".")
        if len(parts) != 3:
            raise ValueError("IP 前缀格式错误，例如 192.168.1.")
        for p in parts:
            if not p.isdigit() or not (0 <= int(p) <= 255):
                raise ValueError("IP 前缀格式错误，例如 192.168.1.")
        return [f"{base}{i}" for i in range(1, 255)]
    ipaddress.ip_address(ip_input)  # 单 IP 校验
    return [ip_input]


def scan_port(ip: str, port: int, timeout: float, cancel: threading.Event,
              results: "queue.Queue"):
    """扫单个 (ip, port)，开放则入队。可被 cancel 中断。"""
    if cancel.is_set():
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                results.put((ip, port))
    except OSError:
        pass  # 网络不可达/被重置等，视为未开放


def run_scan(ips, port, timeout=DEFAULT_TIMEOUT, workers=DEFAULT_WORKERS,
             cancel=None, progress_cb=None):
    """线程池扫描。progress_cb(done, total) 回报进度。返回排序后的 [(ip,port),...]。"""
    if cancel is None:
        cancel = threading.Event()
    results: "queue.Queue" = queue.Queue()
    total = len(ips)
    done = 0
    lock = threading.Lock()

    def task(ip):
        nonlocal done
        if cancel.is_set():
            return
        scan_port(ip, port, timeout, cancel, results)
        with lock:
            done += 1
            if progress_cb:
                progress_cb(done, total)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(task, ip) for ip in ips]
        for f in futures:
            if cancel.is_set():
                f.cancel()
    out = []
    while not results.empty():
        out.append(results.get())
    out.sort(key=lambda x: tuple(int(p) for p in x[0].split(".")))
    return out


# ------------------------- CLI -------------------------

def cli_main(argv=None):
    ap = argparse.ArgumentParser(description="端口扫描工具（命令行）")
    ap.add_argument("target", help="目标：单IP / 192.168.1. 前缀 / 192.168.1.0/24 网段")
    ap.add_argument("-p", "--port", type=int, default=None,
                    help="单个端口（默认扫描常用端口列表）")
    ap.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="超时秒数")
    ap.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="并发线程数")
    args = ap.parse_args(argv)

    try:
        ips = parse_targets(args.target)
    except ValueError as e:
        print(f"[错误] {e}")
        return 2

    ports = [args.port] if args.port else COMMON_PORTS
    print(f"目标 {len(ips)} 个 IP × {len(ports)} 个端口，超时 {args.timeout}s，并发 {args.workers}")

    open_found = []
    try:
        for port in ports:
            open_found.extend(run_scan(ips, port, args.timeout, args.workers))
    except KeyboardInterrupt:
        print("\n已中断")

    if not open_found:
        print("未发现开放端口")
        return 0
    cur_ip = None
    for ip, port in open_found:
        if ip != cur_ip:
            print(f"\n{ip}:")
            cur_ip = ip
        print(f"  端口 {port} 开放")
    return 0


# ------------------------- GUI -------------------------

def gui_main():
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext

    class App:
        def __init__(self, root):
            self.root = root
            root.title("端口扫描工具")
            root.geometry("560x460")
            self.cancel = threading.Event()

            frm = ttk.Frame(root, padding=10)
            frm.pack(fill="x")

            ttk.Label(frm, text="目标(单IP / 192.168.1. / 192.168.1.0/24):").grid(row=0, column=0, sticky="w")
            self.ip_entry = ttk.Entry(frm, width=30)
            self.ip_entry.grid(row=0, column=1, sticky="w")
            self.ip_entry.insert(0, "192.168.1.")

            ttk.Label(frm, text="端口(留空=常用端口):").grid(row=1, column=0, sticky="w")
            self.port_entry = ttk.Entry(frm, width=12)
            self.port_entry.grid(row=1, column=1, sticky="w")

            ttk.Label(frm, text="超时(s):").grid(row=2, column=0, sticky="w")
            self.timeout_entry = ttk.Entry(frm, width=12)
            self.timeout_entry.grid(row=2, column=1, sticky="w")
            self.timeout_entry.insert(0, "1.0")

            self.start_btn = ttk.Button(frm, text="开始扫描", command=self.start)
            self.start_btn.grid(row=3, column=0, pady=8)
            self.cancel_btn = ttk.Button(frm, text="取消", command=self.stop, state="disabled")
            self.cancel_btn.grid(row=3, column=1, sticky="w", pady=8)

            self.progress = ttk.Progressbar(root, mode="determinate")
            self.progress.pack(fill="x", padx=10)

            self.out = scrolledtext.ScrolledText(root, height=15)
            self.out.pack(fill="both", expand=True, padx=10, pady=10)

        def log(self, msg):
            self.out.insert("end", msg + "\n")
            self.out.see("end")

        def start(self):
            try:
                ips = parse_targets(self.ip_entry.get())
            except ValueError as e:
                messagebox.showerror("输入错误", str(e))
                return
            port_txt = self.port_entry.get().strip()
            if port_txt:
                try:
                    port = int(port_txt)
                    if not (1 <= port <= 65535):
                        raise ValueError
                    ports = [port]
                except ValueError:
                    messagebox.showerror("输入错误", "端口必须是 1-65535 的整数")
                    return
            else:
                ports = COMMON_PORTS
            try:
                timeout = float(self.timeout_entry.get())
                if timeout <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror("输入错误", "超时必须是正数")
                return

            self.cancel.clear()
            self.start_btn["state"] = "disabled"
            self.cancel_btn["state"] = "normal"
            self.out.delete("1.0", "end")
            self.log(f"开始：{len(ips)} IP × {len(ports)} 端口")
            threading.Thread(target=self._worker, args=(ips, ports, timeout), daemon=True).start()

        def _worker(self, ips, ports, timeout):
            for port in ports:
                if self.cancel.is_set():
                    break
                self.root.after(0, self.log, f"--- 扫描端口 {port} ---")
                self.progress["maximum"] = len(ips)
                self.progress["value"] = 0

                def cb(done, total):
                    self.root.after(0, lambda d=done: self.progress.config(value=d))

                res = run_scan(ips, port, timeout, DEFAULT_WORKERS, self.cancel, cb)
                for ip, p in res:
                    self.root.after(0, self.log, f"  {ip}:{p} 开放")
            self.root.after(0, self._finish)

        def _finish(self):
            self.start_btn["state"] = "normal"
            self.cancel_btn["state"] = "disabled"
            self.log("已取消" if self.cancel.is_set() else "扫描完成")

        def stop(self):
            self.cancel.set()
            self.log("正在取消…")

    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(cli_main())
    else:
        gui_main()
