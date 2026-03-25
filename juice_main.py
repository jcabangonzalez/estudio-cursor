import argparse
from juice_analyzer import analyze_juice_logs, print_juice_report

def build_parser():
    p = argparse.ArgumentParser(description="Juice Shop Docker Log Analyzer")
    p.add_argument("logfile", help="Ruta del archivo juice_shop_docker.log")
    p.add_argument("--top", type=int, default=10, help="Top N (default: 10)")
    return p

def main():
    args = build_parser().parse_args()
    results = analyze_juice_logs(args.logfile)
    if results["solved_challenges"]:
    print("\nALERT: Security challenge exploitation detected in lab.")

if __name__ == "__main__":
    main()