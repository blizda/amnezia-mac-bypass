import socket
import subprocess
import threading
import time
import signal
import sys
import requests
import resource
from dnslib import DNSRecord

try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
except Exception:
    pass

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 53
WIFI_INTERFACE_NAME = "Wi-Fi"

DOH_URL = "https://1.1.1.1/dns-query"
doh_session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
doh_session.mount("https://", adapter)

ROUTE_TTL = 3600 * 12
GW_CHECK_INTERVAL = 3
GC_INTERVAL = 300

state_lock = threading.Lock()
routed_ips = {}
current_gateway = None

CMD_IPCONFIG = "/usr/sbin/ipconfig"
CMD_NETWORKSETUP = "/usr/sbin/networksetup"
CMD_DSCACHEUTIL = "/usr/bin/dscacheutil"
CMD_KILLALL = "/usr/bin/killall"
CMD_ROUTE = "/sbin/route"

DIRECT_DOMAINS = (
    ".ru.", ".vk.com.", ".vk.me.", "yandex.cloud."
)

def log(msg):
    print(msg, flush=True)

def get_physical_gateway():
    try:
        cmd = f"{CMD_IPCONFIG} getpacket en0 | grep router | awk '{{print $3}}' | tr -d '{{}}'"
        gw = subprocess.check_output(cmd, shell=True, timeout=5, stderr=subprocess.DEVNULL).decode().strip()
        return gw if gw else None
    except Exception:
        return None

def get_vpn_route_state():
    """Получает слепок таблицы маршрутизации для VPN-интерфейсов (Amnezia, Tunnelblick и др.)"""
    try:
        cmd = "netstat -rn -f inet | grep -E 'utun|tun|tap|ipsec|ppp|wg'"
        return subprocess.check_output(cmd, shell=True, timeout=5, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""

def flush_dns_cache():
    try:
        subprocess.run([CMD_DSCACHEUTIL, "-flushcache"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([CMD_KILLALL, "-HUP", "mDNSResponder"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def set_system_dns(dns_server):
    try:
        subprocess.run([CMD_NETWORKSETUP, "-setdnsservers", WIFI_INTERFACE_NAME, dns_server],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if dns_server == "Empty":
            log("[*] Системный DNS: DHCP")
        else:
            log(f"[*] Системный DNS: Установлен {dns_server}")
    except Exception as e:
        log(f"[-] Ошибка networksetup: {e}")

def gateway_watcher():
    global current_gateway
    was_disconnected = False
    current_vpn_state = get_vpn_route_state()

    while True:
        try:
            # 1. Проверка физического шлюза (Wi-Fi)
            new_gw = get_physical_gateway()
            if not new_gw:
                if not was_disconnected:
                    log("[-] Потеряна сеть. Ожидание...")
                    with state_lock:
                        routed_ips.clear()
                was_disconnected = True
            else:
                if new_gw != current_gateway or was_disconnected:
                    with state_lock:
                        log(f"[+] Сеть активна. Шлюз: {new_gw}")
                        current_gateway = new_gw
                        routed_ips.clear()
                        was_disconnected = False
                    set_system_dns(LISTEN_IP)
                    flush_dns_cache()
                else:
                    check_cmd = [CMD_NETWORKSETUP, "-getdnsservers", WIFI_INTERFACE_NAME]
                    check_dns = subprocess.check_output(check_cmd, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
                    if LISTEN_IP not in check_dns:
                        log("[*] Система сбросила DNS. Возвращаем 127.0.0.1...")
                        with state_lock:
                            routed_ips.clear()
                        set_system_dns(LISTEN_IP)
                        flush_dns_cache()

            # 2. ДЕТЕКТОР VPN (Таблица маршрутизации)
            new_vpn_state = get_vpn_route_state()
            if new_vpn_state != current_vpn_state:
                log("[*] Изменение VPN-маршрутов (Amnezia/Tunnelblick). Сброс кэша маршрутов!")
                with state_lock:
                    routed_ips.clear()
                set_system_dns(LISTEN_IP)
                flush_dns_cache()
                current_vpn_state = new_vpn_state

        except Exception:
            pass
        time.sleep(GW_CHECK_INTERVAL)

def sleep_detector():
    """Безупречное обнаружение выхода из спящего режима через time.monotonic"""
    global current_gateway

    last_wall = time.time()
    last_mono = time.monotonic()

    while True:
        time.sleep(2)

        now_wall = time.time()
        now_mono = time.monotonic()

        wall_delta = now_wall - last_wall
        mono_delta = now_mono - last_mono

        if (wall_delta - mono_delta) > 5.0:
            log(f"[*] ДЕТЕКТОР СНА: Выход из спящего режима (спали ~{int(wall_delta)}с). Обновление!")
            with state_lock:
                routed_ips.clear()
                cg = get_physical_gateway()
                if cg:
                    current_gateway = cg

        last_wall = now_wall
        last_mono = now_mono

def route_garbage_collector():
    while True:
        time.sleep(GC_INTERVAL)
        now = time.time()
        with state_lock:
            expired_ips = [ip for ip, ts in routed_ips.items() if now - ts > ROUTE_TTL]
            for ip in expired_ips:
                try:
                    subprocess.run([CMD_ROUTE, "-q", "delete", "-host", ip],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                except Exception:
                    pass
                del routed_ips[ip]
                log(f"[-] Маршрут удален: {ip}")

def cleanup_and_exit(signum, frame):
    log("\n[*] Завершение работы. Очистка DNS и маршрутов...")
    set_system_dns("Empty")
    with state_lock:
        for ip in routed_ips.keys():
            try:
                subprocess.run([CMD_ROUTE, "-q", "delete", "-host", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass
    sys.exit(0)

signal.signal(signal.SIGTERM, cleanup_and_exit)
signal.signal(signal.SIGINT, cleanup_and_exit)

def handle_request(data, addr, main_sock):
    global current_gateway

    try:
        record = DNSRecord.parse(data)
        qname = str(record.q.qname).lower()
        qtype = record.q.qtype
        is_ru = qname.endswith(DIRECT_DOMAINS)

        if is_ru and qtype == 28:
            reply = record.reply()
            main_sock.sendto(reply.pack(), addr)
            return

        if is_ru:
            local_gw = current_gateway
            if not local_gw:
                local_gw = get_physical_gateway()
                if local_gw:
                    with state_lock:
                        current_gateway = local_gw

            if not local_gw:
                return

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up_sock:
                    up_sock.settimeout(2.0)
                    up_sock.sendto(data, (local_gw, 53))
                    resp_data, _ = up_sock.recvfrom(4096)
            except socket.timeout:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up_sock:
                    up_sock.settimeout(2.0)
                    up_sock.sendto(data, ("8.8.8.8", 53))
                    resp_data, _ = up_sock.recvfrom(4096)
        else:
            headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
            try:
                with doh_session.post(DOH_URL, data=data, headers=headers, timeout=1.5, verify=True) as resp:
                    if resp.status_code == 200:
                        resp_data = resp.content
                    else:
                        raise Exception(f"HTTP {resp.status_code}")
            except Exception:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up_sock:
                    up_sock.settimeout(2.0)
                    up_sock.sendto(data, ("8.8.8.8", 53))
                    resp_data, _ = up_sock.recvfrom(4096)

        resp_record = DNSRecord.parse(resp_data)

        if is_ru:
            for rr in resp_record.rr:
                if rr.rtype == 1:
                    ip = str(rr.rdata)
                    need_to_route = False

                    if local_gw:
                        with state_lock:
                            if len(routed_ips) > 5000:
                                routed_ips.clear()
                            if ip not in routed_ips:
                                routed_ips[ip] = time.time()
                                need_to_route = True
                            else:
                                routed_ips[ip] = time.time()

                        if need_to_route:
                            subprocess.run([CMD_ROUTE, "-q", "add", "-host", ip, local_gw],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                            log(f"[+] Маршрут: {qname} -> {ip} via {local_gw}")

        main_sock.sendto(resp_data, addr)

    except Exception as e:
        log(f"[-] Ошибка в handle_request: {e}")

if __name__ == "__main__":
    log("[*] Запуск DNS Route Injector (VPN & Sleep Detector)")
    current_gateway = get_physical_gateway()
    if not current_gateway:
        log("[-] Ожидание сети...")
    else:
        log(f"[*] Шлюз: {current_gateway}")
        set_system_dns(LISTEN_IP)

    threading.Thread(target=gateway_watcher, daemon=True).start()
    threading.Thread(target=route_garbage_collector, daemon=True).start()
    threading.Thread(target=sleep_detector, daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((LISTEN_IP, LISTEN_PORT))
        log(f"[*] Слушаю {LISTEN_IP}:{LISTEN_PORT}")
    except Exception as e:
        log(f"[!] Ошибка бинда: {e}")
        sys.exit(1)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=handle_request, args=(data, addr, sock), daemon=True).start()
        except Exception:
            time.sleep(1)
