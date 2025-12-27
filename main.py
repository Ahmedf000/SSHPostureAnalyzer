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
                    print(red("[!] Non-SSH service or malformed banner"))
                    result["banner_check"] = {"status": "failed", "error": "Invalid SSH banner"}
                else:
                    banner_parts = banner.split("-", 2)
                    if len(banner_parts) >= 2:
                        proto_version = banner_parts[1]
                        downgrade_possible = False
                        risk_level = "UNKNOWN"

                        if proto_version == "1.99":
                            print(yellow("[!] SSH-1.99 detected - HIGH RISK (supports SSH-1 and SSH-2)"))
                            downgrade_possible = True
                            risk_level = "HIGH"
                        elif proto_version.startswith("1."):
                            print(red("[!] SSH-1.x detected - CRITICAL RISK (fundamentally insecure)"))
                            downgrade_possible = True
                            risk_level = "CRITICAL"
                        elif proto_version == "2.0":
                            print(green("[+] SSH-2.0 detected (modern, check algorithms)"))
                            risk_level = "LOW"

                        result["banner_check"] = {
                            "status": "success",
                            "raw": banner,
                            "protocol_version": proto_version,
                            "downgrade_risk": risk_level,
                            "downgrade_possible": downgrade_possible
                        }

        except Exception as e:
            print(red(f"[!] Error grabbing banner: {e}"))
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
                print(
                    green(f"[+] Connection successful ({enumeration_data['connection_info']['connection_time_ms']}ms)"))
                print(f"[+] Banner: {enumeration_data['banner']['raw']}")
                print(f"[+] Server Software: {enumeration_data['banner']['software']}")

                print(
                    f"\n{cyan('[*]')} Key Exchange Algorithms: {len(enumeration_data['key_exchange']['server_offered'])} offered")
                if enumeration_data['key_exchange']['vulnerable_algorithms']:
                    vulns = ', '.join(enumeration_data['key_exchange']['vulnerable_algorithms'])
                    print(f"    {yellow('[!]')} Vulnerable: {vulns}")

                print(
                    f"\n{cyan('[*]')} Encryption Algorithms: {len(enumeration_data['encryption']['server_offered'])} offered")
                if enumeration_data['encryption']['vulnerable_algorithms']:
                    vulns = ', '.join(enumeration_data['encryption']['vulnerable_algorithms'])
                    print(f"    {yellow('[!]')} Vulnerable: {vulns}")

                print(f"\n{cyan('[*]')} MAC Algorithms: {len(enumeration_data['mac']['server_offered'])} offered")
                if enumeration_data['mac']['vulnerable_algorithms']:
                    vulns = ', '.join(enumeration_data['mac']['vulnerable_algorithms'])
                    print(f"    {yellow('[!]')} Vulnerable: {vulns}")

                print(
                    f"\n{cyan('[*]')} Host Key: {enumeration_data['host_key']['algorithm']} ({enumeration_data['host_key']['bits']} bits)")
                print(f"    MD5: {enumeration_data['host_key']['fingerprint_md5']}")
                print(f"    SHA256: {enumeration_data['host_key']['fingerprint_sha256']}")

                risk = enumeration_data['security_assessment']['overall_risk']
                weak_count = enumeration_data['security_assessment']['weak_algorithms_count']
                downgrade_possible = enumeration_data['security_assessment']['downgrade_possible']

                if risk == "CRITICAL":
                    risk_colored = red(bold(risk))
                elif risk == "HIGH":
                    risk_colored = red(risk)
                elif risk == "MEDIUM":
                    risk_colored = yellow(risk)
                elif risk == "LOW":
                    risk_colored = green(risk)
                else:
                    risk_colored = risk

                print(f"\n{cyan('[*]')} Security Assessment:")
                print(f"    Overall Risk: {risk_colored}")
                print(f"    Weak Algorithms: {weak_count}")
                print(f"    Downgrade Possible: {downgrade_possible}")

                if enumeration_data['security_assessment']['recommendations']:
                    print(f"\n{cyan('[*]')} Recommendations:")
                    for rec in enumeration_data['security_assessment']['recommendations']:
                        print(f"    - {rec}")

            else:
                print(red(f"[!] Enumeration failed: {enumeration_data['connection_info']['error']}"))

        except Exception as e:
            print(red(f"[!] Enumeration error: {e}"))
            result["enumeration"] = {"error": str(e)}

    if args.downgrade:
        enumeration_data = None

        if "enumeration" in result and result["enumeration"].get("connection_info", {}).get("status") == "success":
            print(f"\n{cyan('[*]')} Using existing enumeration data for targeted attacks")
            enumeration_data = result["enumeration"]
        else:
            print(f"\n{cyan('[*]')} Running enumeration for downgrade attack planning...")
            try:
                enumeration_data = enumerate_ssh(args.ip, port=args.port, timeout=10)
                result["enumeration"] = enumeration_data

                if enumeration_data["connection_info"]["status"] != "success":
                    print(red(f"[!] Enumeration failed: {enumeration_data['connection_info']['error']}"))
                    result["downgrade_attacks"] = {
                        "error": "Enumeration failed",
                        "attacks_attempted": 0,
                        "successful_attacks": 0,
                        "attack_details": []
                    }
                    enumeration_data = None
            except Exception as e:
                print(red(f"[!] Enumeration error: {e}"))
                result["downgrade_attacks"] = {
                    "error": str(e),
                    "attacks_attempted": 0,
                    "successful_attacks": 0,
                    "attack_details": []
                }
                enumeration_data = None

        if enumeration_data and enumeration_data["connection_info"]["status"] == "success":
            try:
                downgrade_results = attempt_downgrade_attacks(
                    ip=args.ip,
                    user=args.user,
                    enumeration_data=enumeration_data
                )
                result["downgrade_attacks"] = downgrade_results
            except Exception as e:
                print(red(f"[!] Downgrade attack error: {e}"))
                result["downgrade_attacks"] = {
                    "error": str(e),
                    "attacks_attempted": 0,
                    "successful_attacks": 0,
                    "attack_details": []
                }

    if args.output:
        try:
            output_dir = os.path.dirname(args.output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            print(f"\n{green('[+]')} Results saved to {args.output}")

        except Exception as e:
            print(red(f"[!] Failed to save results: {e}"))
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

        if "enumeration" in result and "security_assessment" in result["enumeration"]:
            security = result["enumeration"]["security_assessment"]
            weak_count = security.get("weak_algorithms_count", 0)
            risk = security.get("overall_risk", "UNKNOWN")

            if risk == "CRITICAL":
                risk_display = red(bold(risk))
            elif risk == "HIGH":
                risk_display = red(risk)
            elif risk == "MEDIUM":
                risk_display = yellow(risk)
            elif risk == "LOW":
                risk_display = green(risk)
            else:
                risk_display = risk

            print(f"Risk Level: {risk_display} ({weak_count} weak algorithms found)")

        if "error" in attacks:
            print(f"\n{red('[!]')} Downgrade testing error: {attacks['error']}")
        else:
            attacks_attempted = attacks.get("attacks_attempted", 0)
            successful_attacks = attacks.get("successful_attacks", 0)

            if attacks_attempted == 0:
                print(f"\n{green(bold('SECURE:'))} No weak algorithms found to test")
                print(f"{green('Status:')} Server configuration is properly hardened")
            elif successful_attacks > 0:
                print(
                    f"\n{red(bold('VULNERABLE:'))} {successful_attacks}/{attacks_attempted} downgrade attacks succeeded")
                print(f"{red('Action Required:')} Disable weak algorithms immediately")
            else:
                print(f"\n{green(bold('SECURE:'))} All {attacks_attempted} downgrade attacks failed")
                print(f"{green('Status:')} Server properly rejects weak algorithms")

    print(f"\n{cyan('[*]')} Scan complete")


if __name__ == "__main__":
    main()