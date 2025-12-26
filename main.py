import argparse
import json
import os
import sys
from datetime import datetime
from core.banner import grab_banner
from core.enumerate import enumerate_ssh
from core.colors import Colors, red, green, yellow, blue, cyan, bold
from core.downgrade import downgrade_ssh, attempt_downgrade_attacks


def main():
    print("""
                                                                                                                                    
         ;%%%%%%%%%?.      :SSSSSSSS#S,    ?###;     S###,                              ?##:         ?S%,  ;%%;         
       *%?%%?++*%SS+     +S%S#%*+*%##S     ####     .####                              ?S#,         ,S%*  .%%?          
      *?%%,             +%%S:        .    ;###?     ?###;                             ?S#,          ?%%.  +%%:          
      ???%,             %%%S;             SSS#,     #S##          /**####/            ?SS,       %%%%%%%%%%%%%%?%//     
      +????%?;          +%%%%%S+.        .#SSS######S##?         /#S##%/             ?SS.       ////?%%,..+%%;////       
       .+%%????%?.        ;%S%%%%%S,     *SSSSSSSSSSSS#,        /;####/             ?%S.           /S%+  .%??            
            :?%??%:           ,?%%%S;    S%SS     .#SSS                           ?%S.            ?%%.  +%%:            
              :??%+             ,%%%%   :S%S*     *%SS;                          ?%S.         %%%%%%%%%%?????%:         
    ;.        ;??%:   ;,        :%%%+   ?%%S.     S%S#         +%%%%.           ?%S.             ?%%.  ;%%:             
   .????+:::*%??%;    ??%?*;::*S%%%*   .S%%%     :S%%?         S%%S?           ?%%.             ,%%+  .%??              
   ,+??????????;     .+?%%%%%%%%%+     +%%S;     ?%SS,        ,SSSS,          ?%%               ??%.  +%%:              
                                                                             ?%%                                        
                            
                                    SECURITY ASSESSMENT TOOL V1.0.0                                                                               
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
        print(f"\n{cyan('[*]')} Grabbing SSH banner from {args.ip}:{args.port}")
        try:
            banner = grab_banner(args.ip, port=args.port, timeout=5)


            if not banner:
                print(red("[!] Failed to obtain SSH banner"))
                result["banner_check"] = {"status": "failed", "error": "No banner received"}
            else:
                print(green(f"[+] Banner received: {banner}"))


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
                            print(yellow("[!] SSH-1.99 detected - HIGH RISK"))
                            downgrade_possible = True
                            risk_level = "HIGH"
                        elif proto_version.startswith("1."):
                            print(red("[!] SSH-1.x detected - CRITICAL RISK"))
                            downgrade_possible = True
                            risk_level = "CRITICAL"
                        elif proto_version == "2.0":
                            print(green("[+] SSH-2.0 detected (modern)"))
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
        print(f"\n{cyan('[*]')} Starting SSH enumeration on {args.ip}:{args.port}")

        try:
            enumeration_data = enumerate_ssh(args.ip, port=args.port, timeout=10)
            result["enumeration"] = enumeration_data

            print("\n" + "=" * 60)
            print("ENUMERATION RESULTS")
            print("=" * 60)

            if enumeration_data["connection_info"]["status"] == "success":
                print(green(f"[+] Connection successful ({enumeration_data['connection_info']['connection_time_ms']}ms)"))
                print(f"Banner: {enumeration_data['banner']['raw']}")
                print(f"Server Software: {enumeration_data['banner']['software']}")

                risk = enumeration_data['security_assessment']['overall_risk']
                if risk == "CRITICAL":
                    risk_colored = red(bold(risk))
                elif risk == "HIGH":
                    risk_colored = red(risk)
                elif risk == "MEDIUM":
                    risk_colored = yellow(risk)
                else:
                    risk_colored = green(risk)

                print(f"\n{cyan('[*]')} Security Assessment:")
                print(f"    Overall Risk: {risk_colored}")


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
        if "enumeration" in result and result["enumeration"].get("connection_info", {}).get("status") == "success":
            print("\n[*] Using enumeration data for targeted attacks")
            try:
                downgrade_results = attempt_downgrade_attacks(
                    ip=args.ip,
                    user=args.user,
                    enumeration_data=result["enumeration"]
                )
                result["downgrade_attacks"] = downgrade_results
            except Exception as e:
                print(f"[!] Downgrade attack error: {e}")
                result["downgrade_attacks"] = {"error": str(e)}

        else:
            print("\n[*] No enumeration data found - running enumeration first...")
            try:
                enumeration_data = enumerate_ssh(args.ip, port=args.port, timeout=10)
                result["enumeration"] = enumeration_data

                if enumeration_data["connection_info"]["status"] == "success":
                    print("[+] Enumeration complete, starting downgrade attacks...")
                    downgrade_results = attempt_downgrade_attacks(
                        ip=args.ip,
                        user=args.user,
                        enumeration_data=enumeration_data
                    )
                    result["downgrade_attacks"] = downgrade_results
                else:
                    print(f"[!] Enumeration failed: {enumeration_data['connection_info']['error']}")
                    result["downgrade_attacks"] = {"error": "Enumeration failed"}

            except Exception as e:
                print(f"[!] Error during auto-enumeration: {e}")
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

    if "downgrade_attacks" in result:
        attacks = result["downgrade_attacks"]
        print(f"\n{bold('=' * 60)}")
        print(f"{bold('FINAL ASSESSMENT')}")
        print(f"{bold('=' * 60)}")

        if "enumeration" in result:
            weak_count = result["enumeration"]["security_assessment"]["weak_algorithms_count"]
            risk = result["enumeration"]["security_assessment"]["overall_risk"]

            if risk == "CRITICAL":
                print(f"Risk Level: {red(bold(risk))} ({weak_count} weak algorithms found)")
            elif risk == "HIGH":
                print(f"Risk Level: {red(risk)} ({weak_count} weak algorithms found)")
            elif risk == "MEDIUM":
                print(f"Risk Level: {yellow(risk)} ({weak_count} weak algorithms found)")
            else:
                print(f"Risk Level: {green(risk)} ({weak_count} weak algorithms found)")

        if attacks.get("successful_attacks", 0) > 0:
            print(
                f"\n{red(bold('⚠ VULNERABLE:'))} {attacks['successful_attacks']}/{attacks['attacks_attempted']} downgrade attacks succeeded")
            print(f"{red('Action Required:')} Disable weak algorithms immediately")
        else:
            print(f"\n{green(bold('✓ SECURE:'))} {attacks['attacks_attempted']} downgrade attacks failed")
            print(f"{green('Status:')} Server properly rejects weak algorithms")

    print(f"\n{cyan('[*]')} Scan complete")

    print("Scan complete")


if __name__ == "__main__":
    main()