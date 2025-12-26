import argparse
import json
import os
from datetime import datetime
from core.banner import grab_banner
from core.enumerate import enumerate_ssh
from core.downgrade import downgrade_ssh, attempt_downgrade_attacks


def main():
    print("""
                                                                                                                                                                                                                                                                                                                     
           ,%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@S:           
         ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:         
        ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@S%%%S#@@@@@@@@@@@@@@@@@#%%%S#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.           .#@@@@@@@@*.            #@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*    ,S###SS;. .#@@@@@@?    ,%###S%;.  #@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*   ,@@@@@@@@@@@@@@@@@@?   ,@@@@@@@@@@@@@@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@;.?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:   *@@@@@@@@@@@@@@@@@@;   +@@@@@@@@@@@@@@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@;    ,*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+    ?@@@@@@@@@@@@@@@@@?    *@@@@@@@@@@@@@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@+.    .*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;     :#@@@@@@@@@@@@@@@;     :#@@@@@@@@@@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@%.    .+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,      ,?@@@@@@@@@@@@@@:      ,?@@@@@@@@@@@@@,   .::::::::::::::.   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@*,.   .+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%,       *@@@@@@@@@@@@@%,      .+@@@@@@@@@@,                      +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@S.     :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;      .@@@@@@@@@@@@@@@;      .#@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@+.    .?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.    %@@@@@@@@@@@@@@@@+     ?@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@#+.    ,*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.   ,@@@@@@@@@@@@@@@@@@.   ,@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@:.    ,%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*   .@@@@@@@@@@@@@@@@@@*   .@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@S;.    :?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.   *@@@@@@@@@@@@@@@@@@.   +@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@+    .,S@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,  ,?@@@@@@#,    +@@@@@,  ,?@@@@@@@,    +@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@; :S@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,             .*@@@@@@@,             .*@@@@@@@@@,   +@@@@@@@@@@@@@@:   +@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@S?*++*?S@@@@@@@@@@@@@@@S?*++*?S@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%        
        ?@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@S                    .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%        
        :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@S....................,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;        
         :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;         
           :S@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#;           
                                                            SSH Security Assessment Tool v1.0.0                                                                                                                                
    """)

    parser = argparse.ArgumentParser(description="SSH Security Assessment & Downgrade Testing Tool")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--user", default="root", help="Username for downgrade testing")
    parser.add_argument("-s", "--sock", action="store_true", help="Grab SSH banner using raw socket")
    parser.add_argument("-e", "--enum", action="store_true", help="Perform SSH enumeration")
    parser.add_argument("-d", "--downgrade", action="store_true", help="Attempt intelligent downgrade attacks")
    parser.add_argument("--auto", action="store_true", help="Auto mode: enumerate + downgrade")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args()



    result = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": {
            "ip": args.ip,
            "port": args.port
        }
    }



    if args.auto:
        args.sock = True
        args.enum = True
        args.downgrade = True




    if args.sock:
        print(f"Grabbing SSH banner from {args.ip}:{args.port}")
        try:
            banner = grab_banner(args.ip, port=args.port, timeout=5)


            if not banner:
                print("Failed to obtain SSH banner")
                result["banner_check"] = {"status": "failed", "error": "No banner received"}
            else:
                print(f"Banner received: {banner}")


                if not banner.startswith("SSH-"):
                    print("Non-SSH service or malformed banner")
                    result["banner_check"] = {"status": "failed", "error": "Invalid SSH banner"}
                else:
                    banner_parts = banner.split("-", 2)
                    if len(banner_parts) >= 2:
                        proto_version = banner_parts[1]

                        downgrade_possible = False
                        risk_level = "UNKNOWN"

                        if proto_version == "1.99":
                            print("SSH-1.99 detected - HIGH RISK (supports SSH-1 and SSH-2)")
                            downgrade_possible = True
                            risk_level = "HIGH"
                        elif proto_version.startswith("1."):
                            print("SSH-1.x detected - CRITICAL RISK (fundamentally insecure)")
                            downgrade_possible = True
                            risk_level = "CRITICAL"
                        elif proto_version == "2.0":
                            print("SSH-2.0 detected (modern, but check algorithms)")
                            risk_level = "LOW"



                        result["banner_check"] = {
                            "status": "success",
                            "raw": banner,
                            "protocol_version": proto_version,
                            "downgrade_risk": risk_level,
                            "downgrade_possible": downgrade_possible
                        }

        except Exception as e:
            print(f"[!] Error grabbing banner: {e}")
            result["banner_check"] = {"status": "error", "error": str(e)}





    if args.enum:
        print(f"Starting SSH enumeration on {args.ip}:{args.port}")

        try:
            enumeration_data = enumerate_ssh(args.ip, port=args.port, timeout=10)
            result["enumeration"] = enumeration_data

            print("\n" + "=" * 60)
            print("ENUMERATION RESULTS")
            print("=" * 60)

            if enumeration_data["connection_info"]["status"] == "success":
                print(f"Connection successful ({enumeration_data['connection_info']['connection_time_ms']}ms)")
                print(f"Banner: {enumeration_data['banner']['raw']}")
                print(f"Server Software: {enumeration_data['banner']['software']}")


                print(f"Key Exchange Algorithms: {len(enumeration_data['key_exchange']['server_offered'])} offered")
                if enumeration_data['key_exchange']['vulnerable_algorithms']:
                    print(f"Vulnerable: {', '.join(enumeration_data['key_exchange']['vulnerable_algorithms'])}")


                print(f"Encryption Algorithms: {len(enumeration_data['encryption']['server_offered'])} offered")
                if enumeration_data['encryption']['vulnerable_algorithms']:
                    print(f"Vulnerable: {', '.join(enumeration_data['encryption']['vulnerable_algorithms'])}")


                print(f"MAC Algorithms: {len(enumeration_data['mac']['server_offered'])} offered")
                if enumeration_data['mac']['vulnerable_algorithms']:
                    print(f"Vulnerable: {', '.join(enumeration_data['mac']['vulnerable_algorithms'])}")


                print(f"Host Key: {enumeration_data['host_key']['algorithm']} ({enumeration_data['host_key']['bits']} bits)")
                print(f"    MD5: {enumeration_data['host_key']['fingerprint_md5']}")
                print(f"    SHA256: {enumeration_data['host_key']['fingerprint_sha256']}")



                print(f"Security Assessment:")
                print(f"    Overall Risk: {enumeration_data['security_assessment']['overall_risk']}")
                print(f"    Weak Algorithms: {enumeration_data['security_assessment']['weak_algorithms_count']}")
                print(f"    Downgrade Possible: {enumeration_data['security_assessment']['downgrade_possible']}")



                if enumeration_data['security_assessment']['recommendations']:
                    print(f"Recommendations:")
                    for rec in enumeration_data['security_assessment']['recommendations']:
                        print(f"    - {rec}")

            else:
                print(f"Enumeration failed: {enumeration_data['connection_info']['error']}")

        except Exception as e:
            print(f"Enumeration error: {e}")
            result["enumeration"] = {"error": str(e)}



    if args.downgrade:
        if "enumeration" not in result or result["enumeration"].get("connection_info", {}).get("status") != "success":
            print("Cannot perform downgrade attacks without successful enumeration")
            print("Run with -e flag first or use --auto for combined scan")
        else:
            try:
                downgrade_results = attempt_downgrade_attacks(
                    ip=args.ip,
                    user=args.user,
                    enumeration_data=result["enumeration"]
                )
                result["downgrade_attacks"] = downgrade_results

            except Exception as e:
                print(f"Downgrade attack error: {e}")
                result["downgrade_attacks"] = {"error": str(e)}


    if args.output:
        try:
            os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)

            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            print(f"Results saved to {args.output}")

        except Exception as e:
            print(f"Failed to save results: {e}")
    else:
        print("\n" + "=" * 60)
        print("FULL RESULTS (JSON)")
        print("=" * 60)
        print(json.dumps(result, indent=2))

    print("Scan complete")


if __name__ == "__main__":
    main()