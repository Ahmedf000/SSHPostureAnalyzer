import subprocess

def downgrade_ssh(user, IP_ADDRESS, port=22,kex, hostkey, pubkey, cipher):


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

    try:
        print("Initiating downgrade process.....")
        print("Running:", " ".join(COMMAND))

        cmd_turn = subprocess.run(COMMAND, shell=True, capture_output=True, timeout=10)

        target_cmd_response= {
            "returncode": cmd_turn.returncode,
            "stdout": cmd_turn.stdout.strip(),
            "stderr": cmd_turn.stderr.strip()
        }

        for response in target_cmd_response.items():
            print(f"The return code is {response['returncode']}")
            if response == "stdout":
                print(f"The target stdout CMD response: {response}")
                exit(1)
            elif response == "stderr":
                print(f"The target stderr CMD response: {response}")
            else:
                print("Unknown response")


    except subprocess.TimeoutExpired as e:
        print(f"Timeout ran out: {str(e)}")
        exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {str(e)}")
        exit(1)
    except Exception as e:
        print(f"Error Occured: {str(e)}")

