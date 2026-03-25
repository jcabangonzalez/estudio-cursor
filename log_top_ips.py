import re
from collections import Counter

LOG_FILE = "security_log.txt"
PATTERN = r"\d+\.\d+\.\d+\.\d+"

def extract_ips(path: str) -> list[str]:
    ips = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.search(PATTERN, line)
            if m:
                ips.append(m.group(0))
    return ips

def main():
    ips = extract_ips(LOG_FILE)
    counter = Counter(ips)

    print(f"Total líneas con IP: {len(ips)}")
    print("Top 10 IPs:")
    for ip, count in counter.most_common(10):
        print(ip, count)

if __name__ == "__main__":
    main()