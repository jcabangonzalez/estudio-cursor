import argparse
from analyzer import analyze_file, print_report

def build_parser():
    p = argparse.ArgumentParser(description="Apache Log Analyzer CLI")
    p.add_argument("logfile", help="Ruta del access log")
    p.add_argument("--top", type=int, default=10, help="Top N IPs (default: 10)")
    p.add_argument("--login-url", default="/login", help="URL de login (default: /login)")
    p.add_argument("--bf-threshold", type=int, default=3, help="Umbral brute force (default: 3)")
    return p

def main():
    args = build_parser().parse_args()
    results = analyze_file(args.logfile, login_url=args.login_url)
    print_report(results, top=args.top, bf_threshold=args.bf_threshold)

if __name__ == "__main__":
    main()