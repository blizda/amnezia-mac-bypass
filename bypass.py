import socket
import subprocess
import threading
import time
import signal
import sys
import requests
import resource
import shutil
import concurrent.futures
import select
from datetime import datetime
from dnslib import DNSRecord

# --- НАСТРОЙКИ ---
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 53

DOH_URL = "https://1.1.1.1/dns-query"
PUBLIC_DNS_POOL = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]

ROUTE_TTL = 3600 * 12
GW_CHECK_INTERVAL = 3
GC_INTERVAL = 300
MAX_ROUTES = 500

DIRECT_DOMAINS = (
    ".ru.", ".vk.com.", ".vk.me.", "yandex.cloud.", "boosty.to.", "reddit.com."
)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ И БЛОКИРОВКИ ---
state_lock = threading.Lock()
routed_ips = {}
current_gateway = None
current_service_name = "Wi-Fi"
current_dev = "en0"
current_fallback_dns = ["8.8.8.8"]

doh_session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
doh_session.mount("https://", adapter)

# --- БЕЗОПАСНЫЙ ПОИСК СИСТЕМНЫХ УТИЛИТ ---
def get_cmd(name, default_path):
    return shutil.which(name) or default_path

CMD_NETWORKSETUP = get_cmd("networksetup", "/usr/sbin/networksetup")
CMD_DSCACHEUTIL = get_cmd("dscacheutil", "/usr/bin/dscacheutil")
CMD_KILLALL = get_cmd("killall", "/usr/bin/killall")
CMD_ROUTE = get_cmd("route", "/sbin/route")
CMD_IPCONFIG = get_cmd("ipconfig", "/usr/sbin/ipconfig")

def log(msg, is_error=False):
    timestamp = datetime.now().strftime("%H:%M:%S")
    out = sys.stderr if is_error else sys.stdout
    print(f"[{timestamp}] {msg}", file=out, flush=True)

try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
except Exception as e:
    log(f"[-] Ошибка установки лимитов FD: {e}", True)

# --- СЕТЕВЫЕ ФУНКЦИИ ---
def get_physical_network_info():
    for dev in ["en0", "en1", "en2", "en3", "en4", "en5"]:
        try:
            res_route = subprocess.run([CMD_ROUTE, "-n", "get", "default", "-ifscope", dev],
                                       capture_output=True, text=True, timeout=2)
            gw = None
            for line in res_route.stdout.splitlines():
                if "gateway:" in line:
                    gw = line.split(":")[1].strip()
                    break

            if not gw:
                res_dhcp = subprocess.run([CMD_IPCONFIG, "getpacket", dev],
                                          capture_output=True, text=True, timeout=2)
                for line in res_dhcp.stdout.splitlines():
                    if "router" in line:
                        parts = line.split("{")
                        if len(parts) > 1:
                            gw = parts[1].replace("}", "").strip()
                        break

            if gw:
                res_net = subprocess.run([CMD_NETWORKSETUP, "-listallhardwareports"],
                                         capture_output=True, text=True, timeout=2)
                lines = res_net.stdout.splitlines()
                name = "Wi-Fi"
                for i, line in enumerate(lines):
                    if f"Device: {dev}" in line and i > 0:
                        if "Hardware Port:" in lines[i - 1]:
                            name = lines[i - 1].split(":")[1].strip()
                return dev, name, gw
        except Exception:
            continue
    return "en0", "Wi-Fi", None

def get_system_dns(service_name):
    try:
        res = subprocess.run([CMD_NETWORKSETUP, "-getdnsservers", service_name],
                             capture_output=True, text=True, timeout=5)
        servers = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if line and "There aren't any DNS Servers" not in line and line != LISTEN_IP:
                servers.append(line)
        return servers if servers else ["8.8.8.8"]
    except Exception:
        return ["8.8.8.8"]

def get_vpn_route_state():
    try:
        res = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, timeout=5)
        vpn_lines = [line for line in res.stdout.splitlines() if any(v in line for v in ["utun", "tun", "tap", "ipsec", "ppp", "wg"])]
        return "\n".join(vpn_lines)
    except Exception:
        return ""

def flush_dns_cache():
    try:
        subprocess.run([CMD_DSCACHEUTIL, "-flushcache"], capture_output=True, timeout=5)
        subprocess.run([CMD_KILLALL, "-HUP", "mDNSResponder"], capture_output=True, timeout=5)
    except Exception:
        pass

def flush_os_routes():
    with state_lock:
        ips_to_delete = list(routed_ips.keys())
        routed_ips.clear()

    if not ips_to_delete:
        return

    log(f"[*] Очистка {len(ips_to_delete)} системных маршрутов...")
    for ip in ips_to_delete:
        try:
            subprocess.run([CMD_ROUTE, "-q", "delete", "-host", ip], capture_output=True, timeout=2)
        except Exception:
            pass

def set_system_dns(dns_server, service_name):
    try:
        subprocess.run([CMD_NETWORKSETUP, "-setdnsservers", service_name, dns_server], capture_output=True, timeout=5)
        if dns_server == "Empty":
            log(f"[*] Системный DNS: DHCP (Интерфейс: {service_name})")
        else:
            log(f"[*] Системный DNS: Установлен {dns_server} (Интерфейс: {service_name})")
    except Exception as e:
        log(f"[-] Ошибка networksetup: {e}", True)

def query_fastest_udp(data, ips, timeout=1.0):
    if not ips:
        return None

    sockets = []
    try:
        for ip in ips:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # ИСПРАВЛЕНИЕ: Сразу добавляем в список, чтобы finally гарантированно закрыл сокет
                sockets.append(sock)
                sock.setblocking(False)
                sock.sendto(data, (ip, 53))
            except Exception:
                pass

        if not sockets:
            return None

        start_time = time.time()
        while sockets:
            remain = timeout - (time.time() - start_time)
            if remain <= 0:
                break

            ready_to_read, _, _ = select.select(sockets, [], [], remain)
            if not ready_to_read:
                break

            for sock in ready_to_read:
                try:
                    resp_data, _ = sock.recvfrom(4096)
                    if resp_data:
                        return resp_data
                except Exception:
                    pass

                if sock in sockets:
                    sockets.remove(sock)
                    try:
                        sock.close()
                    except Exception:
                        pass
    finally:
        # Теперь все сокеты точно дойдут до этого блока очистки
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    return None

# --- WORKERS (ФОНОВЫЕ ПОТОКИ) ---
def gateway_watcher():
    global current_gateway, current_service_name, current_dev, current_fallback_dns
    was_disconnected = False
    current_vpn_state = get_vpn_route_state()

    while True:
        try:
            new_dev, new_service, new_gw = get_physical_network_info()
            if not new_gw:
                if not was_disconnected:
                    log("[-] Потеряна сеть. Ожидание...")
                    flush_os_routes()
                was_disconnected = True
            else:
                need_reconfigure = False

                with state_lock:
                    if new_gw != current_gateway or new_service != current_service_name or was_disconnected:
                        need_reconfigure = True
                        current_gateway = new_gw
                        current_service_name = new_service
                        current_dev = new_dev
                        current_fallback_dns = get_system_dns(current_service_name)

                if need_reconfigure:
                    flush_os_routes()
                    log(f"[+] Сеть активна. Адаптер: {new_service} ({new_dev}) | Шлюз: {new_gw}")
                    was_disconnected = False
                    set_system_dns(LISTEN_IP, new_service)
                    flush_dns_cache()
                else:
                    check_res = subprocess.run([CMD_NETWORKSETUP, "-getdnsservers", new_service],
                                               capture_output=True, text=True, timeout=5)
                    if LISTEN_IP not in check_res.stdout:
                        log(f"[*] Система сбросила DNS. Возвращаем {LISTEN_IP} на {new_service}...")
                        set_system_dns(LISTEN_IP, new_service)
                        flush_dns_cache()

            new_vpn_state = get_vpn_route_state()
            if new_vpn_state != current_vpn_state:
                log("[*] Изменение VPN-маршрутов. Сброс кэша маршрутов!")
                flush_os_routes()
                with state_lock:
                    srv = current_service_name
                set_system_dns(LISTEN_IP, srv)
                flush_dns_cache()
                current_vpn_state = new_vpn_state

        except Exception:
            pass

        time.sleep(GW_CHECK_INTERVAL)

def sleep_detector():
    last_wall = time.time()
    last_mono = time.monotonic()

    while True:
        time.sleep(5)
        now_wall = time.time()
        now_mono = time.monotonic()

        wall_delta = now_wall - last_wall
        mono_delta = now_mono - last_mono

        if (wall_delta - mono_delta) > 5.0:
            log(f"[*] ДЕТЕКТОР СНА: Выход из спящего режима (спали ~{int(wall_delta)}с). Обновление маршрутов...")
            flush_os_routes()

        last_wall = now_wall
        last_mono = now_mono

def route_garbage_collector():
    while True:
        time.sleep(GC_INTERVAL)
        now = time.time()

        with state_lock:
            expired_ips = [ip for ip, ts in routed_ips.items() if now - ts > ROUTE_TTL]
            for ip in expired_ips:
                del routed_ips[ip]

        for ip in expired_ips:
            try:
                subprocess.run([CMD_ROUTE, "-q", "delete", "-host", ip], capture_output=True, timeout=2)
                log(f"[-] Маршрут удален по TTL: {ip}")
            except Exception:
                pass

def cleanup_and_exit(signum, frame):
    log("\n[*] Завершение работы. Очистка DNS и маршрутов...")
    with state_lock:
        srv = current_service_name
    set_system_dns("Empty", srv)
    flush_os_routes()
    sys.exit(0)

# --- ОБРАБОТКА DNS ---
def handle_request(data, addr, main_sock):
    try:
        record = DNSRecord.parse(data)
        qname = str(record.q.qname).lower()
        qtype = record.q.qtype
        is_direct = qname.endswith(DIRECT_DOMAINS)

        if is_direct and qtype == 28:
            reply = record.reply()
            main_sock.sendto(reply.pack(), addr)
            return

        with state_lock:
            local_gw = current_gateway
            local_dev = current_dev
            isp_dns = current_fallback_dns[0] if current_fallback_dns else None

        resp_data = None

        if is_direct:
            if not local_gw:
                return

            query_ips = PUBLIC_DNS_POOL.copy()
            if local_gw: query_ips.append(local_gw)
            if isp_dns and isp_dns not in query_ips: query_ips.append(isp_dns)

            resp_data = query_fastest_udp(data, query_ips, timeout=1.5)

        else:
            headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
            try:
                with doh_session.post(DOH_URL, data=data, headers=headers, timeout=1.5, verify=True) as resp:
                    if resp.status_code == 200:
                        resp_data = resp.content
            except Exception:
                pass

            if not resp_data:
                resp_data = query_fastest_udp(data, PUBLIC_DNS_POOL, timeout=1.5)

        if not resp_data:
            return

        resp_record = DNSRecord.parse(resp_data)

        if is_direct and local_gw:
            for rr in resp_record.rr:
                if rr.rtype == 1:
                    ip = str(rr.rdata)
                    need_to_route = False
                    need_flush = False

                    with state_lock:
                        if len(routed_ips) >= MAX_ROUTES:
                            need_flush = True

                    if need_flush:
                        log("[!] Превышен лимит маршрутов. Полный сброс.")
                        flush_os_routes()

                    with state_lock:
                        if ip not in routed_ips:
                            routed_ips[ip] = time.time()
                            need_to_route = True
                        else:
                            routed_ips[ip] = time.time()

                    if need_to_route:
                        # ИСПРАВЛЕНИЕ: Добавлены таймауты, чтобы защитить пул потоков от зависания
                        try:
                            subprocess.run([CMD_ROUTE, "-q", "delete", "-host", ip], capture_output=True, timeout=2)
                            cmd = [CMD_ROUTE, "-q", "add", "-host", ip, local_gw, "-ifp", local_dev]
                            res = subprocess.run(cmd, capture_output=True, timeout=3)

                            if res.returncode == 0:
                                log(f"[+] Маршрут: {qname} -> {ip} via {local_gw} (dev {local_dev})")
                            else:
                                err = res.stderr.decode('utf-8', errors='ignore').strip()
                                log(f"[-] Ошибка добавления {ip}: {err}", True)
                        except subprocess.TimeoutExpired:
                            log(f"[-] Ошибка: ОС слишком долго добавляла маршрут для {ip}", True)
                        except Exception as e:
                            log(f"[-] Ошибка вызова route для {ip}: {e}", True)

        main_sock.sendto(resp_data, addr)

    except Exception as e:
        # Убрал вывод ошибки в консоль на каждый битый пакет (иначе спамит в лог),
        # оставляем только для отладки, если нужно
        pass

# --- ТОЧКА ВХОДА ---
if __name__ == "__main__":
    signal.signal(signal.SIGTERM, cleanup_and_exit)
    signal.signal(signal.SIGINT, cleanup_and_exit)

    log("[*] Запуск DNS Route Injector Pro v4 (Stable + Leak Free)")

    current_dev, current_service_name, current_gateway = get_physical_network_info()
    if not current_gateway:
        log("[-] Ожидание сети...")
    else:
        current_fallback_dns = get_system_dns(current_service_name)
        log(f"[*] Адаптер: {current_service_name} ({current_dev}) | Шлюз: {current_gateway}")
        set_system_dns(LISTEN_IP, current_service_name)

    threading.Thread(target=gateway_watcher, daemon=True).start()
    threading.Thread(target=route_garbage_collector, daemon=True).start()
    threading.Thread(target=sleep_detector, daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((LISTEN_IP, LISTEN_PORT))
        log(f"[*] Слушаю {LISTEN_IP}:{LISTEN_PORT}")
    except Exception as e:
        log(f"[!] Ошибка бинда порта: {e}", True)
        sys.exit(1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                executor.submit(handle_request, data, addr, sock)
            except Exception as e:
                time.sleep(0.1)
