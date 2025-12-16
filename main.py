import argparse
import json
import paramiko

def collect_ssh_info(ip, port=22):

    ssh_info = {
        "banner",
        "kex",
        "ciphers",
        "host_key",
        "auth_methods",
    }

    transport = None
    try:
        print(f"[*] Starting SSH connection to {ip}:{port}...")
        transport = paramiko.Transport((ip, port))
        transport.start_client()
        print(f"[*] SSH connection to {ip}:{port} established.")
        ssh_info["banner"] = transport.remote_version
        security = transport.get_security_options()
        ssh_info["kex"] = security.kex
        ssh_info["ciphers"] = {
            "client_to_server": security.ciphers,
            "server_to_client": security.ciphers
        }
        ssh_info["host_key"] = transport.get_remote_server_key().get_name()


    except paramiko.ssh_exception.SSHException as e:
        print(f"[!] SSH negotiation failed: {e}")
        ssh_info["error"] = f"SSH negotiation failed: {e}"

    except paramiko.ssh_exception.AuthenticationException:
        print("[!] Authentication failed (pre-auth)")
        ssh_info["error"] = "Authentication failed"

    finally:
        if transport:
            transport.close()

    return ssh_info

def main():
    results = []

    args = argparse.ArgumentParser()
    args.add_argument("-i", "--ip", required=True, help="ip address for the SSH conenction")
    args.add_argument("-o", "--output",  help="output file to save the SSH banner to json file reports_and_analysis.json")
    arg = args.parse_args()

    IP = arg.ip


    host_results = collect_ssh_info(IP)
    results.append(host_results)

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