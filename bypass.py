import socket
import subprocess
import threading
import time
import signal
import sys
import requests
import resource
import shutil
import select
import queue
import logging
import concurrent.futures
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict
from datetime import datetime
from dnslib import DNSRecord

# --- НАСТРОЙКИ ---
@dataclass
class Config:
    LISTEN_IP: str = "127.0.0.1"
    LISTEN_PORT: int = 53
    DOH_URL: str = "https://1.1.1.1/dns-query"
    PUBLIC_DNS_POOL: List[str] = ("1.1.1.1", "9.9.9.9", "8.8.8.8")
    ROUTE_TTL: int = 3600 * 12
    GW_CHECK_INTERVAL: int = 3
    GC_INTERVAL: int = 300
    MAX_ROUTES: int = 3000
    DIRECT_DOMAINS: Tuple[str, ...] = (
        ".ru.", ".vk.com.", ".vk.me.", "yandex.cloud.", "boosty.to.", "reddit.com."
    )
    MAX_WORKERS: int = 50

# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("DNSProxy")

def set_limits():
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
    except Exception as e:
        logger.error(f"[-] Ошибка установки лимитов FD: {e}")

# --- СИСТЕМНЫЕ УТИЛИТЫ ---
class SystemNetwork:
    CMD_NETWORKSETUP = shutil.which("networksetup") or "/usr/sbin/networksetup"
    CMD_DSCACHEUTIL = shutil.which("dscacheutil") or "/usr/bin/dscacheutil"
    CMD_KILLALL = shutil.which("killall") or "/usr/bin/killall"
    CMD_ROUTE = shutil.which("route") or "/sbin/route"
    CMD_IPCONFIG = shutil.which("ipconfig") or "/usr/sbin/ipconfig"

    @classmethod
    def get_physical_network_info(cls) -> Tuple[str, str, Optional[str]]:
        for dev in ["en0", "en1", "en2", "en3", "en4", "en5"]:
            try:
                res_route = subprocess.run([cls.CMD_ROUTE, "-n", "get", "default", "-ifscope", dev],
                                           capture_output=True, text=True, timeout=2)
                gw = None
                for line in res_route.stdout.splitlines():
                    if "gateway:" in line:
                        gw = line.split(":")[1].strip()
                        break

                if not gw:
                    res_dhcp = subprocess.run([cls.CMD_IPCONFIG, "getpacket", dev],
                                              capture_output=True, text=True, timeout=2)
                    for line in res_dhcp.stdout.splitlines():
                        if "router" in line:
                            parts = line.split("{")
                            if len(parts) > 1:
                                gw = parts[1].replace("}", "").strip()
                            break

                if gw:
                    res_net = subprocess.run([cls.CMD_NETWORKSETUP, "-listallhardwareports"],
                                             capture_output=True, text=True, timeout=2)
                    lines = res_net.stdout.splitlines()
                    name = "Wi-Fi"
                    for i, line in enumerate(lines):
                        if f"Device: {dev}" in line and i > 0 and "Hardware Port:" in lines[i - 1]:
                            name = lines[i - 1].split(":")[1].strip()
                    return dev, name, gw
            except Exception:
                continue
        return "en0", "Wi-Fi", None

    @classmethod
    def get_system_dns(cls, service_name: str) -> List[str]:
        try:
            res = subprocess.run([cls.CMD_NETWORKSETUP, "-getdnsservers", service_name],
                                 capture_output=True, text=True, timeout=5)
            servers = [line.strip() for line in res.stdout.splitlines() 
                       if line.strip() and "There aren't any DNS Servers" not in line and line.strip() != Config.LISTEN_IP]
            return servers if servers else ["8.8.8.8"]
        except Exception:
            return ["8.8.8.8"]

    @classmethod
    def get_vpn_route_state(cls) -> str:
        try:
            res = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, timeout=5)
            return "\n".join([line for line in res.stdout.splitlines() 
                              if any(v in line for v in ["utun", "tun", "tap", "ipsec", "ppp", "wg"])])
        except Exception:
            return ""

    @classmethod
    def flush_dns_cache(cls):
        try:
            subprocess.run([cls.CMD_DSCACHEUTIL, "-flushcache"], capture_output=True, timeout=5)
            subprocess.run([cls.CMD_KILLALL, "-HUP", "mDNSResponder"], capture_output=True, timeout=5)
        except Exception:
            pass

    @classmethod
    def set_system_dns(cls, dns_server: str, service_name: str):
        try:
            subprocess.run([cls.CMD_NETWORKSETUP, "-setdnsservers", service_name, dns_server], capture_output=True, timeout=5)
            if dns_server == "Empty":
                logger.info(f"[*] Системный DNS: DHCP (Интерфейс: {service_name})")
            else:
                logger.info(f"[*] Системный DNS: Установлен {dns_server} (Интерфейс: {service_name})")
        except Exception as e:
            logger.error(f"[-] Ошибка networksetup: {e}")

# --- УПРАВЛЕНИЕ МАРШРУТАМИ ---
class RouteManager:
    def __init__(self):
        self.routed_ips: Dict[str, float] = {}
        self.lock = threading.Lock()
        self.task_queue = queue.PriorityQueue()
        
        # Запуск воркера маршрутов
        threading.Thread(target=self._executor_worker, daemon=True).start()

    def add_route(self, ip: str, gw: str, dev: str, qname: str) -> threading.Event:
        ready_event = threading.Event()
        with self.lock:
            self.routed_ips[ip] = time.time()
        self.task_queue.put((1, 'add', ip, gw, dev, qname, ready_event))
        return ready_event

    def queue_delete_route(self, ip: str):
        self.task_queue.put((2, 'delete', ip))

    def check_and_clean_limits(self):
        with self.lock:
            if len(self.routed_ips) < Config.MAX_ROUTES:
                return
            
            logger.warning(f"[!] Превышен лимит маршрутов ({Config.MAX_ROUTES}). Удаляем 50 самых старых.")
            sorted_ips = sorted(self.routed_ips.items(), key=lambda item: item[1])
            ips_to_remove = [old_ip for old_ip, _ in sorted_ips[:50]]
            for old_ip in ips_to_remove:
                del self.routed_ips[old_ip]

        for old_ip in ips_to_remove:
            self.queue_delete_route(old_ip)

    def flush_all_routes(self):
        with self.lock:
            ips_to_delete = list(self.routed_ips.keys())
            self.routed_ips.clear()

        if ips_to_delete:
            logger.info(f"[*] Ставим в очередь очистку {len(ips_to_delete)} системных маршрутов (Приоритет: Низкий)...")
            for ip in ips_to_delete:
                self.queue_delete_route(ip)

    def garbage_collect(self):
        now = time.time()
        with self.lock:
            expired_ips = [ip for ip, ts in self.routed_ips.items() if now - ts > Config.ROUTE_TTL]
            for ip in expired_ips:
                del self.routed_ips[ip]

        for ip in expired_ips:
            self.queue_delete_route(ip)
            logger.info(f"[-] Отправлено на удаление по TTL: {ip}")

    def _executor_worker(self):
        """Фоновый поток для выполнения вызовов route ОС"""
        while True:
            task = self.task_queue.get()
            action = task[1]
            try:
                if action == 'add':
                    _, _, ip, local_gw, local_dev, qname, ready_event = task
                    subprocess.run([SystemNetwork.CMD_ROUTE, "-q", "delete", "-host", ip], capture_output=True, timeout=2)
                    res = subprocess.run([SystemNetwork.CMD_ROUTE, "-q", "add", "-host", ip, local_gw, "-ifp", local_dev], capture_output=True, timeout=3)
                    
                    if res.returncode == 0:
                        logger.info(f"[+] Маршрут добавлен: {qname} -> {ip} via {local_gw} (dev {local_dev})")
                    else:
                        err = res.stderr.decode('utf-8', errors='ignore').strip()
                        logger.error(f"[-] Ошибка добавления {ip}: {err}")
                    
                    if ready_event:
                        ready_event.set()
                        
                elif action == 'delete':
                    _, _, ip = task
                    subprocess.run([SystemNetwork.CMD_ROUTE, "-q", "delete", "-host", ip], capture_output=True, timeout=2)
            except Exception as e:
                logger.error(f"[-] Ошибка в route_executor_worker: {e}")
            finally:
                self.task_queue.task_done()

# --- ЯДРО ПРОКСИ ---
class DNSProxy:
    def __init__(self):
        self.cfg = Config()
        self.route_mgr = RouteManager()
        self.state_lock = threading.Lock()
        
        self.current_gateway: Optional[str] = None
        self.current_service_name: str = "Wi-Fi"
        self.current_dev: str = "en0"
        self.current_fallback_dns: List[str] = ["8.8.8.8"]
        
        # DoH Circuit Breaker
        self.doh_fails: int = 0
        self.doh_disabled_until: float = 0.0
        self.doh_session = self._init_session()

        self._running = True

    @staticmethod
    def _init_session() -> requests.Session:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount("https://", adapter)
        return session

    def query_fastest_udp(self, data: bytes, ips: List[str], timeout: float = 1.0) -> Optional[bytes]:
        if not ips: return None
        sockets = []
        try:
            for ip in ips:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sockets.append(sock)
                    sock.setblocking(False)
                    sock.sendto(data, (ip, 53))
                except Exception:
                    pass

            if not sockets: return None
            start_time = time.monotonic()
            
            while sockets:
                remain = timeout - (time.monotonic() - start_time)
                if remain <= 0: break

                ready_to_read, _, _ = select.select(sockets, [], [], remain)
                if not ready_to_read: break

                for sock in ready_to_read:
                    try:
                        resp_data, _ = sock.recvfrom(4096)
                        if resp_data: return resp_data
                    except Exception:
                        pass
                    if sock in sockets:
                        sockets.remove(sock)
                        try: sock.close()
                        except Exception: pass
        finally:
            for sock in sockets:
                try: sock.close()
                except Exception: pass
        return None

    def handle_request(self, data: bytes, addr: Tuple[str, int], main_sock: socket.socket):
        try:
            record = DNSRecord.parse(data)
            qname = str(record.q.qname).lower()
            qtype = record.q.qtype
            is_direct = qname.endswith(self.cfg.DIRECT_DOMAINS)

            # Гасим IPv6 
            if is_direct and qtype == 28:
                reply = record.reply()
                reply.header.rcode = 3
                main_sock.sendto(reply.pack(), addr)
                return

            with self.state_lock:
                local_gw = self.current_gateway
                local_dev = self.current_dev
                isp_dns = self.current_fallback_dns[0] if self.current_fallback_dns else None
                do_doh = time.time() > self.doh_disabled_until

            resp_data = None

            if is_direct:
                if not local_gw: return
                query_ips = list(self.cfg.PUBLIC_DNS_POOL)
                if local_gw: query_ips.append(local_gw)
                if isp_dns and isp_dns not in query_ips: query_ips.append(isp_dns)
                resp_data = self.query_fastest_udp(data, query_ips, timeout=1.5)
            else:
                if do_doh:
                    headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
                    try:
                        with self.doh_session.post(self.cfg.DOH_URL, data=data, headers=headers, timeout=1.0) as resp:
                            if resp.status_code == 200:
                                resp_data = resp.content
                                with self.state_lock: self.doh_fails = 0
                    except Exception:
                        with self.state_lock:
                            self.doh_fails += 1
                            if self.doh_fails >= 3:
                                self.doh_disabled_until = time.time() + 60
                                self.doh_fails = 0
                                logger.warning("[!] DoH сервер недоступен. Переход на резервный UDP на 60 сек!")

                if not resp_data:
                    resp_data = self.query_fastest_udp(data, list(self.cfg.PUBLIC_DNS_POOL), timeout=1.0)

            if not resp_data: return
            resp_record = DNSRecord.parse(resp_data)

            if is_direct and local_gw:
                for rr in resp_record.rr:
                    if rr.rtype == 1:
                        ip = str(rr.rdata)
                        self.route_mgr.check_and_clean_limits()

                        need_to_route = False
                        with self.route_mgr.lock:
                            if ip not in self.route_mgr.routed_ips:
                                need_to_route = True
                            else:
                                self.route_mgr.routed_ips[ip] = time.time()

                        if need_to_route:
                            ready_event = self.route_mgr.add_route(ip, local_gw, local_dev, qname)
                            ready_event.wait(timeout=0.5)

            main_sock.sendto(resp_data, addr)
        except Exception:
            pass

    def start_watchers(self):
        threading.Thread(target=self._gateway_watcher, daemon=True).start()
        threading.Thread(target=self._sleep_detector, daemon=True).start()
        threading.Thread(target=self._gc_worker, daemon=True).start()

    def _gc_worker(self):
        while self._running:
            time.sleep(self.cfg.GC_INTERVAL)
            self.route_mgr.garbage_collect()

    def _sleep_detector(self):
        last_wall, last_mono = time.time(), time.monotonic()
        while self._running:
            time.sleep(5)
            now_wall, now_mono = time.time(), time.monotonic()
            if ((now_wall - last_wall) - (now_mono - last_mono)) > 5.0:
                logger.info(f"[*] ДЕТЕКТОР СНА: Выход из спящего режима. Сброс DNS...")
                SystemNetwork.flush_dns_cache()
            last_wall, last_mono = now_wall, now_mono

    def _gateway_watcher(self):
        was_disconnected = False
        current_vpn_state = SystemNetwork.get_vpn_route_state()

        while self._running:
            try:
                new_dev, new_service, new_gw = SystemNetwork.get_physical_network_info()
                if not new_gw:
                    if not was_disconnected:
                        logger.warning("[-] Потеряна сеть. Ожидание...")
                        self.route_mgr.flush_all_routes()
                    was_disconnected = True
                else:
                    need_reconfigure = False
                    with self.state_lock:
                        if new_gw != self.current_gateway or new_service != self.current_service_name or was_disconnected:
                            need_reconfigure = True
                            self.current_gateway = new_gw
                            self.current_service_name = new_service
                            self.current_dev = new_dev
                            self.current_fallback_dns = SystemNetwork.get_system_dns(self.current_service_name)

                    if need_reconfigure:
                        self.route_mgr.flush_all_routes()
                        logger.info(f"[+] Сеть активна. Адаптер: {new_service} ({new_dev}) | Шлюз: {new_gw}")
                        was_disconnected = False
                        SystemNetwork.set_system_dns(self.cfg.LISTEN_IP, new_service)
                        SystemNetwork.flush_dns_cache()
                    else:
                        check_res = subprocess.run([SystemNetwork.CMD_NETWORKSETUP, "-getdnsservers", new_service],
                                                   capture_output=True, text=True, timeout=5)
                        if self.cfg.LISTEN_IP not in check_res.stdout:
                            logger.info(f"[*] Система сбросила DNS. Возвращаем {self.cfg.LISTEN_IP} на {new_service}...")
                            SystemNetwork.set_system_dns(self.cfg.LISTEN_IP, new_service)
                            SystemNetwork.flush_dns_cache()

                new_vpn_state = SystemNetwork.get_vpn_route_state()
                if new_vpn_state != current_vpn_state:
                    logger.info("[*] Изменение VPN-маршрутов. Сброс кэша маршрутов!")
                    self.route_mgr.flush_all_routes()
                    with self.state_lock: srv = self.current_service_name
                    SystemNetwork.set_system_dns(self.cfg.LISTEN_IP, srv)
                    SystemNetwork.flush_dns_cache()
                    current_vpn_state = new_vpn_state

            except Exception:
                pass
            time.sleep(self.cfg.GW_CHECK_INTERVAL)

    def shutdown(self):
        logger.info("\n[*] Завершение работы. Очистка DNS и маршрутов...")
        self._running = False
        with self.state_lock: srv = self.current_service_name
        SystemNetwork.set_system_dns("Empty", srv)
        self.route_mgr.flush_all_routes()
        sys.exit(0)

# --- ТОЧКА ВХОДА ---
if __name__ == "__main__":
    set_limits()
    proxy = DNSProxy()

    def handle_exit(sig, frame):
        proxy.shutdown()

    signal.signal(signal.SIGTERM, handle_exit)
    signal.signal(signal.SIGINT, handle_exit)

    logger.info(f"[*] Запуск DNS Route Injector Pro v7.0 (OOP Refactored) - Limit: {proxy.cfg.MAX_ROUTES}")

    dev, srv, gw = SystemNetwork.get_physical_network_info()
    if not gw:
        logger.warning("[-] Ожидание сети...")
    else:
        with proxy.state_lock:
            proxy.current_gateway = gw
            proxy.current_service_name = srv
            proxy.current_dev = dev
            proxy.current_fallback_dns = SystemNetwork.get_system_dns(srv)
        logger.info(f"[*] Адаптер: {srv} ({dev}) | Шлюз: {gw}")
        SystemNetwork.set_system_dns(proxy.cfg.LISTEN_IP, srv)

    proxy.start_watchers()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)

    try:
        sock.bind((proxy.cfg.LISTEN_IP, proxy.cfg.LISTEN_PORT))
        logger.info(f"[*] Слушаю {proxy.cfg.LISTEN_IP}:{proxy.cfg.LISTEN_PORT}")
    except Exception as e:
        logger.error(f"[!] Ошибка бинда порта: {e}")
        sys.exit(1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=proxy.cfg.MAX_WORKERS) as executor:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if executor._work_queue.qsize() > 40:
                    logger.warning("[!] ВНИМАНИЕ: Очередь пула потоков перегружена! Возможны задержки DNS.")
                executor.submit(proxy.handle_request, data, addr, sock)
            except OSError as e:
                logger.error(f"[-] Системная ошибка сокета: {e}")
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"[-] Критическая ошибка в главном цикле: {e}")
                time.sleep(1)
