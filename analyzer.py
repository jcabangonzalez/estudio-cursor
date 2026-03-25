print("Script started")
import re
import json
from collections import Counter

log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+|-)'
)

def parse_line(line: str):
    match = log_pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])
    return data

from collections import Counter

def detect_suspicious_ips(ip_counter, threshold=100):
    suspicious = {}

    for ip, count in ip_counter.items():
        if count >= threshold:
            suspicious[ip] = count

    return suspicious

def detect_scanners(ip_counter, scan_threshold=20):
    scanners = {}

    for ip, count in ip_counter.items():
        if count >= scan_threshold:
            scanners[ip] = count

    return scanners

def detect_bursts(burst_counter, threshold=50):
    bursts = {}
    for clave, count in burst_counter.items():
        if count >= threshold:
            # Convertimos la tupla (ip, minuto) en un solo texto "ip | minuto"
            texto_clave = f"{clave[0]} | {clave[1]}"
            bursts[texto_clave] = count
    return bursts
 
def analyze_file(filepath: str, login_url: str = "/login"):
    ips = Counter()
    burst_counter = Counter() # <-- Asegúrate de que esta línea esté al inicio de esta función
    login_attempts = Counter()
    errors_4xx = 0
    errors_5xx = 0
    total_requests = 0
    parsed_lines = 0


    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                parsed = parse_line(line)
                if not parsed:
                    continue

                parsed_lines += 1
                total_requests += 1
                ips[parsed["ip"]] += 1
                t = parsed["datetime"].split(':')
                minuto_clave = f"{t[0]}:{t[1]}:{t[2]}"
                burst_counter[(parsed["ip"], minuto_clave)] += 1
                if parsed["method"] == "POST" and parsed["url"] == login_url:
                    login_attempts[parsed["ip"]] += 1

                
                if 400 <= parsed["status"] < 500:
                    errors_4xx += 1
                elif 500 <= parsed["status"] < 600:
                    errors_5xx += 1

        suspicious_ips = detect_suspicious_ips(ips)
        scanners = detect_scanners(ips)
        burst_attacks = detect_bursts(burst_counter, threshold=2)
        print("\nSuspicious IPs:")

        for ip, count in suspicious_ips.items():
            print(f"{ip} -> {count} requests")

    except FileNotFoundError:
        return {"error": "not_found", "filepath": filepath}
    except PermissionError:
        return {"error": "permission", "filepath": filepath}
    except Exception as e:
        return {"error": f"unexpected: {e}", "filepath": filepath}

    return {
        "error": None,
        "filepath": filepath,
        "total_requests": total_requests,
        "parsed_lines": parsed_lines,
        "errors_4xx": errors_4xx,
        "errors_5xx": errors_5xx,
        "ips": ips,
        "login_attempts": login_attempts,
        "scanners": scanners,
        "bursts": burst_attacks  # <--- ¡No olvides añadir esto!
    }
    