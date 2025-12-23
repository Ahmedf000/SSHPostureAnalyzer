import argparse
import json
from core.downgrade import downgrade_ssh
from core.banner import grab_banner
from core.enumerate import enumerate_ssh
import re

def main():

    parser = argparse.ArgumentParser(description="SSH Downgrade Testing Tool")
    parser.add_argument("-i", "--ip", required=True)
    parser.add_argument("-s", "--sock", action="store_true",
                    help="Grab SSH banner using raw socket")
    parser.add_argument("-u", "--user", default="root")
    parser.add_argument("-e","--enum", action="store_true")
    parser.add_argument("-d","--downgrade", action="store_true")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    result = {}

    downgrade_possible = False
    if args.sock:
        print(f"Starting connection with {args.ip} ")
        try:
            banner = grab_banner(args.ip, port=22, timeout=5)
            if banner is None:
                print("failed to obtain SSh banner")
                exit(1)

            elif not isinstance(banner,(bytes, bytearray)):
                print("Banner is not a string")
                exit(1)

            elif len(banner) < 20:
                print("Banner is suspicisouly short")
                exit(1)

            decoded_banner = banner.decode(errors="ignore")
            logic_banner = decoded_banner.lower().strip("\r\n")

            if not logic_banner.startswith("ssh-"):
                print("Non-SSH service or malformed banner")
                exit(1)

            banner_parts = logic_banner.split("-", 2)
            if len(banner_parts) < 3:
                print("Malformed SSH banner format")
                exit(1)

            proto_version = banner_parts[1]

            if proto_version == "1.99":
                print("SSH-1.99 detected")
                print("High-risk downgrade candidate")
                downgrade_possible = True

            elif proto_version.startswith("1."):
                print("SSH-1.x detected")
                downgrade_possible = False

            elif proto_version == "2.0":
                print("SSH-2.0 detected")
                print("Modern SSH — downgrade depends on enabled algorithms")
                downgrade_possible = False

            else:
                print(f"Unknown SSH protocol version: {proto_version}")
                exit(1)

            result["banner"] = {
                "raw": decoded_banner.strip(),
                "protocol_version": proto_version,
                "Downgrade_possibility": downgrade_possible,
            }

        except Exception as e:
            print(f"ERROR: {e}")


    if args.downgrade:
        if downgrade_possible:
            print("Starting SSH protocol downgrade...")
        else:
            print("Downgrade not possible on this target.")
            exit(1)
    else:
        print("Downgrade flag not set — analysis only")


    if args.enum:
        print("Enumerating SSH...")
        result["enumeration"] = enumerate_ssh(args.ip)



    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[*] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save results: {e}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()