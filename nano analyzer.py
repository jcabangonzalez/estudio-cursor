import re
from collections import Counter, defaultdict
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<prototcol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+)'
)

def parse_line(line):
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        data["status"] = int(data["status"])
        data["size"] = int(data["size"])
        # minuto: "21/Feb/2026:15:32"
        data["minute"] = data["datetime"][:17]
        return data
    return None


# Umbrales (ajústalos luego)
MAX_REQ_PER_IP = 20          # total requests por IP en el archivo
MAX_REQ_PER_MINUTE = 10      # requests por IP en el mismo minuto

ips_total = Counter()
ips_per_minute = defaultdict(Counter)
login_attempts = Counter()

errors_4xx = 0
errors_5xx = 0
total_requests = 0


with open("access.log", "r") as file:
    for line in file:
        parsed = parse_line(line)
        if not parsed:
            continue

        total_requests += 1
        ip = parsed["ip"]
        minute = parsed["minute"]

        ips_total[ip] += 1
        ips_per_minute[minute][ip] += 1
        if parsed["method"] == "POST" and parsed["url"] == "/login":
    login_attempts[ip] += 1
        login_attempts = Counter()
        if parsed["method"] == "POST" and parsed["url"] == "/login":
    login_attempts[ip] += 1
        elif 500 <= parsed["status"] < 600:
            errors_5xx += 1


print("Total Requests:", total_requests)
print("Errores 4xx:", errors_4xx)
print("Errores 5xx:", errors_5xx)

print("\nTop IPs:")
for ip, count in ips_total.most_common():
    print(ip, count)

print("\nIPs que exceden MAX_REQ_PER_IP =", MAX_REQ_PER_IP)
flagged_total = [(ip, c) for ip, c in ips_total.items() if c > MAX_REQ_PER_IP]
if not flagged_total:
    print("Ninguna")
else:
    for ip, c in sorted(flagged_total, key=lambda x: x[1], reverse=True):
        print(ip, c)

print("\nBurst por minuto (MAX_REQ_PER_MINUTE =", MAX_REQ_PER_MINUTE, ")")
found_burst = False
for minute, counter in ips_per_minute.items():
    for ip, c in counter.items():
        if c > MAX_REQ_PER_MINUTE:
            found_burst = True
            print(minute, ip, c)
if not found_burst: