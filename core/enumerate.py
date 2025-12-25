import paramiko
import socket

def enumerate_ssh(ip, port=22, timeout=10):
    ssh_info = {
        "target": {
            "ip": ip,
            "port": port
        },
        "banner": {
          "raw": None,
          "protocol_version": None,
            "software": None,
            "comments": None
        },

        "kex_exchange": {
            "server_offered": [],
            "client_offered": [],
            "negotiated": None,
            "vulnerable_algorithms": []
        },

        "encryption": {
            "server_offered": [],
            "client_offered": [],
            "client_to_server": None,
            "server_to_client": None,
            "vulnerable_algorithms": []
        },

        "mac": {
            "server_offered": [],
            "client_offered": [],
            "client-to-server": None,
            "Server-to-client": None,
            "vulnerable_algorithms": [],
            "note": None
        },

        "host_key": {
            "algorithm": None,
            "key_type": None,
            "bits": None,
            "fingerprint_md5": None,
            "fingerprint_sha256": None
        },

        #compression shrinks the data BEFORE encrypting it - cus encrypted data cannot be compressed
        #better for bandwith usage
        "compression": {
            "server_offered": [],
            "client_offered": [],
            "client_to_server": None,
            "server_to_client": None
        },

        "security_assessment": {
            "overall_risk": None,
            "downgrade_possibility": None,
            "weak_algorithm_count": 0,
            "recommendation": []
        },

        "connection_info": {
            "status": None,
            "error": None,
            "connection_time_ms": None
        }

    }



    transport = None
    start_time = None

    try:
        import time
        start_time = time.time()

        print(f"Starting SSH connection to {ip}:{port}...")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        transport = paramiko.Transport(s)
        security_options = transport.get_security_options()



        #client default capabilities
        ssh_info["key_exchange"]["client_offered"] = list(security_options.kex)
        ssh_info["encryption"]["client_offered"] = list(security_options.ciphers)
        ssh_info["mac"]["client_offered"] = list(security_options.digests)
        ssh_info["compression"]["client_offered"] = list(security_options.compression)


        print("Starting SSH connection...")
        transport.start_client(timeout=timeout)

        if start_time:
            start_up_timing = ( time.time() - start_time ) * 1000 #note: turn to ms
            ssh_info["connection_info"]["connection_time_ms"] = round(start_up_timing)

        print("SSH connection established")
        ssh_info["connection_info"]["status"] = "success"

        raw_banner = transport.remote_version
        ssh_info["banner"]["raw"] = raw_banner

        if raw_banner:
            """
                banners initially conclude 
                    1-protocol
                    2-version
                    3-software & comments
            """
            banner_parts = raw_banner.split("-",2)
            if len(banner_parts) == 2:
                if not banner_parts[0].startswith("SSH"):
                    return "Non supported banner, SSH not existing"

                if banner_parts[0].startswith("SSH"):
                    ssh_info["banner"]["protocol_version"] = banner_parts[1]
                    split_software_comment = banner_parts[2].split(" ")
                    ssh_info["banner"]["software"] = split_software_comment[0]

            else:
                if not banner_parts[0].startswith("SSH"):
                    return "Non supported banner, SSH not existing"

                ssh_info["banner"]["software"] = banner_parts[1]
                software_comment = banner_parts[2].split(" ",1)
                ssh_info["banner"]["software"] = software_comment[0]
                if len(software_comment) > 1:
                    ssh_info["banner"]["comment"] = software_comment[1]


        #moving to the algorithm information

        security_features = transport.get_security_options()

        ssh_info["kex_exchange"]["server_offered"] = list(security_features.kex)
        ssh_info["encryption"]["server_offered"] = list(security_features.ciphers)
        ssh_info["mac"]["server_offered"] = list(security_features.digests)
        ssh_info["compression"]["server_offered"] = list(security_features.compression)

         #negotiated algo

        try:
            if hasattr(transport, 'kex_engine') and transport.kex_engine:
                ssh_info["key_exchange"]["negotiated"] = transport.kex_engine.name

            if hasattr(transport, 'local_cipher'):
                ssh_info["encryption"]["client_to_server"] = transport.local_cipher
            if hasattr(transport, 'remote_cipher'):
                ssh_info["encryption"]["server_to_client"] = transport.remote_cipher

            if hasattr(transport, 'local_mac'):
                ssh_info["mac"]["client_to_server"] = transport.local_mac
            if hasattr(transport, 'remote_mac'):
                ssh_info["mac"]["server_to_client"] = transport.remote_version

            if hasattr(transport, 'local_compression'):
                ssh_info["compression"]["client_to_server"] = transport.local_compression
            if hasattr(transport, 'remote_compression'):
                ssh_info["compression"]["server_to_client"] = transport.remote_compression

        except AttributeError as e:
            print(f"WARNING: Could not access negotiated algorithms: {e}")






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

