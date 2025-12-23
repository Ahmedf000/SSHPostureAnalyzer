import paramiko

def enumerate_ssh(ip, port=22):
    ssh_info = {
        "banner": None,

        "kex": {
            "Kex": [],
            "chosen": None
        },

        "ciphers": {
            "supported": [],
            "client-to-server": None,
            "Server-to-client": None
        },

        "macs": {
            "supported": [],
            "client-to-server": None,
            "Server-to-client": None
        },

        "host_key": None
    }

    transport = None
    try:
        print(f"Starting SSH connection to {ip}:{port}...")
        transport = paramiko.Transport((ip, port))
        transport.start_client()
        print(f"SSH connection to {ip}:{port} established.")
        ssh_info["banner"] = transport.remote_version
        security = transport.get_security_options()
        ssh_info["kex"] = list(security.kex)
        ssh_info["ciphers"] = list(security.ciphers)
        ssh_info["MAC"] = list(security.MAC)
        ssh_info["host_key"] = transport.get_remote_server_key().get_name()


    except paramiko.ssh_exception.SSHException as e:
        print(f"SSH negotiation failed: {e}")
        ssh_info["error"] = f"SSH negotiation failed: {e}"

    except paramiko.ssh_exception.AuthenticationException:
        print("Authentication failed (pre-auth)")
        ssh_info["error"] = "Authentication failed"

    finally:
        if transport:
            transport.close()

    return ssh_info

