import subprocess

def downgrade_ssh(user, IP_ADDRESS, port=22,kex="diffie-hellman-group1-sha1",
                  hostkey="ssh-rsa",
                  pubkey="ssh-rsa",
                  cipher="aes128-cbc"):

    COMMAND = [
        "ssh",
        "-p", str(port),
        f"{user}@{IP_ADDRESS}",
        f"_oKexAlgorithms=+{kex}",
        f"-oHostkeyAlgorithms=+{hostkey}",
        f"-oPubKeyAcceptedAlgorithms=+{pubkey}",
        "-c", cipher,
        "-oBatchMode=yes",
    ]

    print("Running:", " ".join(COMMAND))

    cmd_turn = subprocess.run(COMMAND, shell=True, capture_output=True, timeout=10)

    return {
        "returncode": cmd_turn.returncode,
        "stdout": cmd_turn.stdout.strip(),
        "stderr": cmd_turn.stderr.strip()
    }

