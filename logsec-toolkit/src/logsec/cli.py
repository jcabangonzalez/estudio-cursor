import argparse

from logsec.apache_analyzer import analyze_file as analyze_apache_file, print_report as print_apache_report
from logsec.juice_analyzer import analyze_juice_logs, print_juice_report


def build_parser():
    p = argparse.ArgumentParser(description="LogSec Toolkit (Apache + Juice Shop log detection)")
    sub = p.add_subparsers(dest="command", required=True)

    # Apache
    ap = sub.add_parser("apache", help="Analyze Apache/Nginx access logs")
    ap.add_argument("logfile", help="Path to access.log")
    ap.add_argument("--top", type=int, default=10, help="Top N IPs (default: 10)")
    ap.add_argument("--login-url", default="/login", help="Login URL to track (default: /login)")
    ap.add_argument("--bf-threshold", type=int, default=3, help="Brute-force threshold (default: 3)")

    # Juice Shop (docker logs)
    js = sub.add_parser("juice", help="Analyze OWASP Juice Shop docker logs")
    js.add_argument("logfile", help="Path to juice_shop_docker.log")
    js.add_argument("--top", type=int, default=10, help="Top N (default: 10)")

    return p


def main():
    args = build_parser().parse_args()

    if args.command == "apache":
        results = analyze_apache_file(args.logfile, login_url=args.login_url)
        print_apache_report(results, top=args.top, bf_threshold=args.bf_threshold)
        return

    if args.command == "juice":
        results = analyze_juice_logs(args.logfile)
        print_juice_report(results, top=args.top)
        return


if __name__ == "__main__":
    main()