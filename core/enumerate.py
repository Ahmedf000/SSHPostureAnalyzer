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

        ssh_info["key_exchange"]["client_offered"] = list(security_options.kex)
        ssh_info["encryption"]["client_offered"] = list(security_options.ciphers)
        ssh_info["mac"]["client_offered"] = list(security_options.digests)
        ssh_info["compression"]["client_offered"] = list(security_options.compression)

        print("Starting SSH handshake...")
        transport.start_client(timeout=timeout)
        if start_time:
            connection_time = (time.time() - start_time) * 1000
            ssh_info["connection_info"]["connection_time_ms"] = round(connection_time, 2)
        print("SSH connection established")
        ssh_info["connection_info"]["status"] = "success"

        raw_banner = transport.remote_version
        ssh_info["banner"]["raw"] = raw_banner
        if raw_banner:
            banner_parts = raw_banner.split("-", 2)
            if len(banner_parts) >= 2:
                ssh_info["banner"]["protocol_version"] = banner_parts[1]
            if len(banner_parts) >= 3:
                software_and_comments = banner_parts[2].split(" ", 1)
                ssh_info["banner"]["software"] = software_and_comments[0]
                if len(software_and_comments) > 1:
                    ssh_info["banner"]["comments"] = software_and_comments[1]

        security = transport.get_security_options()
        ssh_info["key_exchange"]["server_offered"] = list(security.kex)
        ssh_info["encryption"]["server_offered"] = list(security.ciphers)
        ssh_info["mac"]["server_offered"] = list(security.digests)
        ssh_info["compression"]["server_offered"] = list(security.compression)

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
                ssh_info["mac"]["server_to_client"] = transport.remote_mac

            if hasattr(transport, 'local_compression'):
                ssh_info["compression"]["client_to_server"] = transport.local_compression
            if hasattr(transport, 'remote_compression'):
                ssh_info["compression"]["server_to_client"] = transport.remote_compression

        except AttributeError as e:
            print(f"WARNING: Could not access negotiated algorithms: {e}")

        try:
            host_key = transport.get_remote_server_key()
            ssh_info["host_key"]["algorithm"] = host_key.get_name()

            key_type = type(host_key).__name__
            ssh_info["host_key"]["key_type"] = key_type

            if hasattr(host_key, 'get_bits'):
                ssh_info["host_key"]["bits"] = host_key.get_bits()
            elif hasattr(host_key, 'size'):
                ssh_info["host_key"]["bits"] = host_key.size

            import hashlib
            import base64

            key_bytes = host_key.asbytes()
            md5_hash = hashlib.md5(key_bytes).hexdigest()
            md5_fingerprint = ":".join(md5_hash[i:i + 2] for i in range(0, len(md5_hash), 2))
            ssh_info["host_key"]["fingerprint_md5"] = md5_fingerprint

            sha256_hash = hashlib.sha256(key_bytes).digest()
            sha256_fingerprint = base64.b64encode(sha256_hash).decode('ascii').rstrip('=')
            ssh_info["host_key"]["fingerprint_sha256"] = f"SHA256:{sha256_fingerprint}"

        except Exception as e:
            print(f"Warning: Could not extract host key info: {e}")

        ssh_info = assess_security(ssh_info)
        AEAD_CIPHERS = ['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com']
        if (ssh_info["encryption"]["client_to_server"] in AEAD_CIPHERS or
                ssh_info["encryption"]["server_to_client"] in AEAD_CIPHERS):
            ssh_info["mac"]["note"] = "AEAD cipher in use - MAC is integrated"




    except socket.timeout:
        ssh_info["connection_info"]["status"] = "failed"
        ssh_info["connection_info"]["error"] = "Connection timeout"
        print(f"Connection timeout after {timeout} seconds")
    except socket.error as e:
        ssh_info["connection_info"]["status"] = "failed"
        ssh_info["connection_info"]["error"] = f"Socket error: {str(e)}"
        print(f"Socket error: {e}")
    except paramiko.SSHException as e:
        ssh_info["connection_info"]["status"] = "failed"
        ssh_info["connection_info"]["error"] = f"SSH error: {str(e)}"
        print(f"SSH negotiation failed: {e}")
    except Exception as e:
        ssh_info["connection_info"]["status"] = "failed"
        ssh_info["connection_info"]["error"] = f"Unexpected error: {str(e)}"
        print(f"Unexpected error: {e}")

    finally:
        if transport:
            transport.close()
            print("Connection closed")
    return ssh_info


def assess_security(ssh_info):
    weak_kex = [
        'diffie-hellman-group1-sha1',
        'diffie-hellman-group14-sha1',
        'diffie-hellman-group-exchange-sha1',
        'rsa1024-sha1',
    ]
    weak_ciphers = [
        '3des-cbc',
        'aes128-cbc',
        'aes192-cbc',
        'aes256-cbc',
        'arcfour',
        'arcfour128',
        'arcfour256',
        'blowfish-cbc',
        'cast128-cbc',
        'idea-cbc'
    ]
    weak_macs = [
        'hmac-md5',
        'hmac-md5-96',
        'hmac-sha1-96',
        'hmac-ripemd160',
        'hmac-sha1',
    ]
    weak_host_keys = [
        'ssh-dss',
        'ssh-rsa',
    ]

    for kex_algo in ssh_info["key_exchange"]["server_offered"]:
        classification = classify_algorithm(kex_algo, "kex")
        ssh_info["key_exchange"]["detailed_analysis"].append(classification)

    for cipher_algo in ssh_info["encryption"]["server_offered"]:
        classification = classify_algorithm(cipher_algo, "cipher")
        ssh_info["encryption"]["detailed_analysis"].append(classification)

    for mac_algo in ssh_info["mac"]["server_offered"]:
        classification = classify_algorithm(mac_algo, "mac")
        ssh_info["mac"]["detailed_analysis"].append(classification)

    if ssh_info["host_key"]["algorithm"]:
        ssh_info["host_key"]["detailed_analysis"] = classify_algorithm(
            ssh_info["host_key"]["algorithm"],
            "host_key"
        )

    vulnerable_kex = [
        algo["name"]
        for algo in ssh_info["key_exchange"]["detailed_analysis"]
        if algo["status"] in ["vulnerable", "weak"]
    ]
    vulnerable_ciphers = [
        algo["name"]
        for algo in ssh_info["encryption"]["detailed_analysis"]
        if algo["status"] in ["vulnerable", "weak"]
    ]
    vulnerable_macs = [
        algo["name"]
        for algo in ssh_info["mac"]["detailed_analysis"]
        if algo["status"] in ["vulnerable", "weak"]
    ]

    ssh_info["key_exchange"]["vulnerable_algorithms"] = vulnerable_kex
    ssh_info["encryption"]["vulnerable_algorithms"] = vulnerable_ciphers
    ssh_info["mac"]["vulnerable_algorithms"] = vulnerable_macs

    weak_count = len(vulnerable_kex) + len(vulnerable_ciphers) + len(vulnerable_macs)
    ssh_info["security_assessment"]["weak_algorithms_count"] = weak_count
    if weak_count > 0:
        ssh_info["security_assessment"]["downgrade_possible"] = True

    protocol_version = ssh_info["banner"]["protocol_version"]
    if protocol_version == "1.99":
        ssh_info["security_assessment"]["downgrade_possible"] = True
        ssh_info["security_assessment"]["recommendations"].append(
            "Protocol version 1.99 detected - supports both SSH-1 and SSH-2 (downgrade risk)"
        )
    elif protocol_version and protocol_version.startswith("1."):
        ssh_info["security_assessment"]["downgrade_possible"] = True
        ssh_info["security_assessment"]["recommendations"].append(
            "SSH-1 protocol detected - fundamentally insecure, upgrade to SSH-2 immediately"
        )

    if ssh_info["host_key"].get("detailed_analysis"):
        host_analysis = ssh_info["host_key"]["detailed_analysis"]
        if host_analysis["status"] in ["vulnerable", "weak"]:
            ssh_info["security_assessment"]["recommendations"].append(
                f"Weak host key: {host_analysis['recommendation']}"
            )

    if vulnerable_kex:
        ssh_info["security_assessment"]["recommendations"].append(
            f"Disable weak KEX algorithms: {', '.join(vulnerable_kex)}"
        )
    if vulnerable_ciphers:
        ssh_info["security_assessment"]["recommendations"].append(
            f"Disable weak ciphers: {', '.join(vulnerable_ciphers)}"
        )
    if vulnerable_macs:
        ssh_info["security_assessment"]["recommendations"].append(
            f"Disable weak MACs: {', '.join(vulnerable_macs)}"
        )

    if weak_count == 0 and protocol_version == "2.0":
        ssh_info["security_assessment"]["overall_risk"] = "LOW"
    elif weak_count <= 3:
        ssh_info["security_assessment"]["overall_risk"] = "MEDIUM"
    elif weak_count <= 6:
        ssh_info["security_assessment"]["overall_risk"] = "HIGH"
    else:
        ssh_info["security_assessment"]["overall_risk"] = "CRITICAL"

    return ssh_info


def classify_algorithm(algorithm_name, category):
    classification = {
        "name": algorithm_name,
        "category": category,
        "status": "unknown",
        "risk_level": "unknown",
        "reason": "",
        "cve_references": [],
        "recommendation": ""
    }

    if category == "kex":
        if algorithm_name in ['diffie-hellman-group1-sha1']:
            classification["status"] = "vulnerable"
            classification["risk_level"] = "critical"
            classification["reason"] = "1024-bit group vulnerable to Logjam attack, uses SHA-1"
            classification["cve_references"] = ["CVE-2015-4000"]
            classification["recommendation"] = "Replace with curve25519-sha256 or ecdh-sha2-nistp256"

        elif algorithm_name in ['diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']:
            classification["status"] = "weak"
            classification["risk_level"] = "high"
            classification["reason"] = "Uses SHA-1 which has known collision attacks"
            classification["recommendation"] = "Upgrade to SHA-256 variant"

        elif algorithm_name in ['curve25519-sha256', 'curve25519-sha256@libssh.org']:
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "Modern elliptic curve, excellent performance and security"

        elif algorithm_name.startswith('ecdh-sha2-'):
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "NIST elliptic curve with SHA-2"






    elif category == "cipher":
        if algorithm_name in ['3des-cbc', 'blowfish-cbc']:
            classification["status"] = "vulnerable"
            classification["risk_level"] = "high"
            classification["reason"] = "64-bit block size vulnerable to Sweet32 attack"
            classification["cve_references"] = ["CVE-2016-2183"]
            classification["recommendation"] = "Replace with aes256-gcm or chacha20-poly1305"

        elif algorithm_name.startswith('arcfour'):
            classification["status"] = "vulnerable"
            classification["risk_level"] = "critical"
            classification["reason"] = "RC4 stream cipher is completely broken"
            classification["recommendation"] = "Disable immediately"

        elif 'cbc' in algorithm_name:
            classification["status"] = "weak"
            classification["risk_level"] = "medium"
            classification["reason"] = "CBC mode vulnerable to padding oracle attacks"
            classification["recommendation"] = "Use CTR or GCM mode instead"

        elif algorithm_name in ['chacha20-poly1305@openssh.com']:
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "Modern AEAD cipher, excellent performance"

        elif 'gcm' in algorithm_name:
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "AEAD mode provides encryption and authentication"

        elif 'ctr' in algorithm_name:
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "Counter mode is secure (but consider AEAD for authentication)"






    elif category == "mac":
        if 'md5' in algorithm_name:
            classification["status"] = "vulnerable"
            classification["risk_level"] = "critical"
            classification["reason"] = "MD5 has practical collision attacks"
            classification["recommendation"] = "Replace with hmac-sha2-256 or hmac-sha2-512"

        elif algorithm_name.endswith('-96'):
            classification["status"] = "weak"
            classification["risk_level"] = "medium"
            classification["reason"] = "Truncated MAC reduces security margin"
            classification["recommendation"] = "Use full-length MAC variant"

        elif 'sha1' in algorithm_name and 'sha2' not in algorithm_name:
            classification["status"] = "weak"
            classification["risk_level"] = "medium"
            classification["reason"] = "SHA-1 has known collision attacks"
            classification["recommendation"] = "Upgrade to hmac-sha2-256"

        elif 'sha2' in algorithm_name:
            if 'etm' in algorithm_name:
                classification["status"] = "secure"
                classification["risk_level"] = "low"
                classification["reason"] = "SHA-2 with Encrypt-then-MAC (best practice)"
            else:
                classification["status"] = "secure"
                classification["risk_level"] = "low"
                classification["reason"] = "SHA-2 is currently secure"





    elif category == "host_key":
        if algorithm_name == 'ssh-dss':
            classification["status"] = "vulnerable"
            classification["risk_level"] = "critical"
            classification["reason"] = "DSA is cryptographically broken"
            classification["recommendation"] = "Replace with ed25519 or rsa (4096-bit)"

        elif algorithm_name == 'ssh-rsa':
            classification["status"] = "weak"
            classification["risk_level"] = "medium"
            classification["reason"] = "RSA with SHA-1 signatures being phased out"
            classification["recommendation"] = "Prefer ed25519 or rsa-sha2-256/512"

        elif algorithm_name.startswith('ssh-ed25519'):
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "Modern Edwards curve, excellent security"

        elif algorithm_name.startswith('rsa-sha2-'):
            classification["status"] = "secure"
            classification["risk_level"] = "low"
            classification["reason"] = "RSA with SHA-2 signatures"

    return classification