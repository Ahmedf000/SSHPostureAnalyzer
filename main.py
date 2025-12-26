import argparse
import json
from core.downgrade import downgrade_ssh
from core.banner import grab_banner
from core.enumerate import *
import os

def main():
    print("""
            __        ____ ____  _   _ 
            \\ \\      / ___/ ___|| | | |
             \\ \\    \\___ \\___ \\| |_| |
             / /      ___) |__) |  _  |     
            /_/____  |____/____/|_| |_|
             |_____| 
                              
    """)
    
    parser = argparse.ArgumentParser(description="SSH Downgrade, enumeration Testing Tool")
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


    if args.enum:
        print(f"Initializing enumeration phase with: {args.ip} ")
        enumeration_phase = enumerate_ssh(args.ip, port=22, timeout=10)
        try:
            print("The enumeration phase and all target information saved as follows")

            import json
            from datetime import datetime

            report = {
                "enumeration_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Target_IP": args.ip,
                "All_findings_from_remote_target": {
                        "banner": {
                            "raw": None,
                            "protocol_version": None,
                            "software": None,
                            "comments": None
                        },

                        "key_exchange": {
                            "server_offered": [],
                            "client_offered": [],
                            "negotiated": None,
                            "vulnerable_algorithms": [],
                            "detailed_analysis": []
                        },

                        "encryption": {
                            "server_offered": [],
                            "client_offered": [],
                            "client_to_server": None,
                            "server_to_client": None,
                            "vulnerable_algorithms": [],
                            "detailed_analysis": []
                        },

                        "mac": {
                            "server_offered": [],
                            "client_offered": [],
                            "client_to_server": None,
                            "server_to_client": None,
                            "vulnerable_algorithms": [],
                            "detailed_analysis": [],
                            "note": None
                        },

                        "host_key": {
                            "algorithm": None,
                            "key_type": None,
                            "bits": None,
                            "fingerprint_md5": None,
                            "fingerprint_sha256": None,
                            "detailed_analysis": None
                        },

                        "compression": {
                            "server_offered": [],
                            "client_offered": [],
                            "client_to_server": None,
                            "server_to_client": None
                        },

                        "security_assessment": {
                            "overall_risk": None,
                            "downgrade_possible": False,
                            "weak_algorithms_count": 0,
                            "recommendations": []
                        },

                        "connection_info": {
                            "status": None,
                            "error": None,
                            "connection_time_ms": None
                            }
                        }
                }

            os.makedirs("reports", exist_ok=True)
            report_path = os.path.join("reports", "enumeration_phase.json")
            with open(report_path, "w", encoding="utf_8") as enum_json_file:
                json.dump(report, enum_json_file, indent=3)
            print(f"All enumeration findings saved to {report_path}")
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






    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"Results saved to {args.output}")
        except Exception as e:
            print(f"Failed to save results: {e}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()