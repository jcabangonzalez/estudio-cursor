import re

lines = [
    '192.168.1.10 - - [21/Feb/2026:10:10:10] "GET /login HTTP/1.1" 200 532',
    '10.0.0.5 - - [21/Feb/2026:10:11:10] "POST /admin HTTP/1.1" 403 210',
    '192.168.1.10 - - [21/Feb/2026:10:12:10] "GET /dashboard HTTP/1.1" 200 800'
]

pattern = r"\d+\.\d+\.\d+\.\d+"

ip_list = []

for line in lines:
    match = re.search(pattern, line)
    if match:
        ip_list.append(match.group(0))

print(ip_list)
from collections import Counter

counter = Counter(ip_list)

print(counter.most_common(2))