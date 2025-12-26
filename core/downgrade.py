import subprocess
from core.colors import Colors, red, green, yellow, blue, cyan, bold
import sys


def downgrade_ssh(user, ip, port=22, kex=None, hostkey=None, pubkey=None, cipher=None, mac=None):
    command = ["ssh", "-p", str(port), f"{user}@{ip}"]

    if kex:
        command.extend(["-oKexAlgorithms=+" + kex])
    if hostkey:
        command.extend(["-oHostKeyAlgorithms=+" + hostkey])
    if pubkey:
        command.extend(["-oPubkeyAcceptedAlgorithms=+" + pubkey])
    if cipher:
        command.extend(["-oCiphers=" + cipher])
    if mac:
        command.extend(["-oMACs=" + mac])

    command.extend([
        "-oBatchMode=yes",
        "-oConnectTimeout=5",
        "-oStrictHostKeyChecking=no",
        "-oUserKnownHostsFile=/dev/null",
        "exit"
    ])




    try:
        print(f"Testing downgrade attack...")
        print(f"Command: {' '.join(command)}")

        result = subprocess.run(
            command,
            capture_output=True,
            timeout=10,
            text=True
        )

        response = {
            "success": False,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "attempted_algorithms": {
                "kex": kex,
                "hostkey": hostkey,
                "pubkey": pubkey,
                "cipher": cipher,
                "mac": mac
            }
        }

        # Update downgrade.py success messages
        if "no matching" in result.stderr.lower():
            response["success"] = False
            response["reason"] = "Server rejected weak algorithms (SECURE)"
            print(green("[+] Server does NOT accept these weak algorithms - SECURE"))
        elif result.returncode == 0:
            response["success"] = True
            response["reason"] = "Connection succeeded with weak algorithms (VULNERABLE)"
            print(red("[!] WARNING: Server accepted weak algorithms - VULNERABLE!"))
        elif "permission denied" in result.stderr.lower():
            response["success"] = True
            response["reason"] = "Algorithms accepted but authentication failed (VULNERABLE)"
            print(yellow("[!] WARNING: Server accepted weak algorithms (auth failed) - VULNERABLE!"))
        else:
            response["success"] = False
            response["reason"] = f"Connection failed: {result.stderr[:100]}"
            print(f"Connection failed: {result.stderr[:100]}")

        return response




    except subprocess.TimeoutExpired:
        print("[!] Connection timeout")
        return {
            "success": False,
            "returncode": -1,
            "reason": "Connection timeout",
            "attempted_algorithms": {"kex": kex, "hostkey": hostkey, "cipher": cipher, "mac": mac}
        }
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return {
            "success": False,
            "returncode": -1,
            "reason": str(e),
            "attempted_algorithms": {"kex": kex, "hostkey": hostkey, "cipher": cipher, "mac": mac}
        }





def attempt_downgrade_attacks(ip, user, enumeration_data):

    print("\n" + "=" * 60)
    print("DOWNGRADE ATTACK PHASE")
    print("=" * 60)

    results = {
        "attacks_attempted": 0,
        "successful_attacks": 0,
        "attack_details": []
    }


    vulnerable_kex = enumeration_data.get("key_exchange", {}).get("vulnerable_algorithms", [])
    vulnerable_ciphers = enumeration_data.get("encryption", {}).get("vulnerable_algorithms", [])
    vulnerable_macs = enumeration_data.get("mac", {}).get("vulnerable_algorithms", [])



    if not (vulnerable_kex or vulnerable_ciphers or vulnerable_macs):
        print("No weak algorithms found - server appears secure")
        return results

    print(f"{cyan('[*]')} Found vulnerable algorithms:")
    if vulnerable_kex:
        print(f"    KEX: {yellow(', '.join(vulnerable_kex))}")
    if vulnerable_ciphers:
        print(f"    Ciphers: {yellow(', '.join(vulnerable_ciphers))}")
    if vulnerable_macs:
        print(f"    MACs: {yellow(', '.join(vulnerable_macs))}")




    attack_combinations = []

    if vulnerable_kex and vulnerable_ciphers and vulnerable_macs:
        print("Testing CRITICAL severity attack (KEX + Cipher + MAC)...")
        attack = {
            "severity": "CRITICAL",
            "kex": vulnerable_kex[0] if vulnerable_kex else None,
            "cipher": vulnerable_ciphers[0] if vulnerable_ciphers else None,
            "mac": vulnerable_macs[0] if vulnerable_macs else None,
            "hostkey": "ssh-rsa"
        }
        attack_combinations.append(attack)

    elif vulnerable_kex and vulnerable_ciphers:
        print("Testing HIGH severity attack (KEX + Cipher)...")
        attack = {
            "severity": "HIGH",
            "kex": vulnerable_kex[0],
            "cipher": vulnerable_ciphers[0],
            "hostkey": "ssh-rsa"
        }
        attack_combinations.append(attack)

    elif vulnerable_kex or vulnerable_ciphers:
        print("Testing MEDIUM severity attack (KEX or Cipher)...")
        attack = {
            "severity": "MEDIUM",
            "kex": vulnerable_kex[0] if vulnerable_kex else None,
            "cipher": vulnerable_ciphers[0] if vulnerable_ciphers else None
        }
        attack_combinations.append(attack)

    elif vulnerable_macs:
        print("Testing LOW severity attack (MAC only)...")
        attack = {
            "severity": "LOW",
            "mac": vulnerable_macs[0]
        }
        attack_combinations.append(attack)




    for attack in attack_combinations:
        results["attacks_attempted"] += 1

        result = downgrade_ssh(
            user=user,
            ip=ip,
            kex=attack.get("kex"),
            hostkey=attack.get("hostkey"),
            cipher=attack.get("cipher"),
            mac=attack.get("mac")
        )

        result["severity"] = attack["severity"]
        results["attack_details"].append(result)

        if result["success"]:
            results["successful_attacks"] += 1




    print("\n" + "=" * 60)
    print(f"ATTACK SUMMARY: {results['successful_attacks']}/{results['attacks_attempted']} attacks succeeded")
    print("=" * 60)

    return results