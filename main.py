import argparse
import json
from core.downgrade import downgrade_ssh
from core.banner import grab_banner
from core.enumerate import enumerate_ssh

def main():
    results = []

    parser = argparse.ArgumentParser(description="SSH Downgrade Testing Tool")
    parser.add_argument("-i", "--ip", required=True)
    parser.add_argument("-u", "--user", default="root")
    parser.add_argument("--enum", action="store_true")
    parser.add_argument("--downgrade", action="store_true")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    result = {}

    if args.enum:
        print("Enumerating SSL...")
        results["enumeration"] = enumerate_ssh(args.ip)

    if args.downgrade:
        print("Attempting downgrade....")
        results["downgrade"] = downgrade_ssh(args.user, args.ip)

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"[*] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save results: {e}")
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()