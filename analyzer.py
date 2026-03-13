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
 

def analyze_file(filepath: str, login_url: str = "/login"):
    ips = Counter()
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

                if parsed["method"] == "POST" and parsed["url"] == login_url:
                    login_attempts[parsed["ip"]] += 1

                
                if 400 <= parsed["status"] < 500:
                    errors_4xx += 1
                elif 500 <= parsed["status"] < 600:
                    errors_5xx += 1

        suspicious_ips = detect_suspicious_ips(ips)
        scanners = detect_scanners(ips)
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
        "scanners": scanners
    }

def print_report(results, top: int = 10, bf_threshold: int = 3):
    print("Printing report...")
    if results.get("error"):
        print("Error found")
        err = results["error"]
        path = results.get("filepath")
        if err == "not_found":
            print(f"Error: archivo no encontrado: {path}")
        elif err == "permission":
            print(f"Error: sin permisos para leer: {path}")
        else:
            print(f"Error: {err}")
        return
def save_json_report(results, top=10, bf_threshold=3, output_file="report.json"):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, default=str)

    print(f"\nJSON report saved to: {output_file}")

   
   
    
if __name__ == "__main__":
    import sys

    print("Running analyzer...")

    if len(sys.argv) < 2:
        print("Uso: python3 analyzer.py <logfile>")
        sys.exit(1)

    filepath = sys.argv[1]

    results = analyze_file(filepath)

    print(results)

    print_report(results)
    
    save_json_report(results)
    
    