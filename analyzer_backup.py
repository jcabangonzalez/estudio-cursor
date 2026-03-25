import re
from collections import Counter, defaultdict

log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+)'
)

def parse_line(line):
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        data["status"] = int(data["status"])
        data["size"] = int(data["size"])
        return data
    return None


ips = Counter()
errors_4xx = 0
errors_5xx = 0
total_requests = 0
login_attempts = Counter()

with open("access.log", "r") as file:
    for line in file:
        parsed = parse_line(line)
        if parsed:
            total_requests += 1
            ips[parsed["ip"]] += 1
            if parsed["method"] == "POST" and parsed["url"] == "/login":
                login_attempts[parsed["ip"]] += 1
            if 400 <= parsed["status"] < 500:
                errors_4xx += 1
            elif 500 <= parsed["status"] < 600:
                errors_5xx += 1


print("Total Requests:", total_requests)
print("Errores 4xx:", errors_4xx)
print("Errores 5xx:", errors_5xx)

print("\nTop IPs:")
for ip, count in ips.most_common():
    print(ip, count)
    
print("\nIntentos de login (POST /login) por IP:")
if not login_attempts:
    print("Ninguno")
else:
    for ip, c in login_attempts.most_common():
        print(ip, c)

print("\nPosible brute force (>3 intentos):")
flag = False
for ip, c in login_attempts.items():
    if c > 3:
        flag = True
        print(ip, c)
if not flag:
    print("Ninguno")