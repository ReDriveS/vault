
import json
import os
import sys
import urllib.error
import urllib.request

VAULT_ADDR = os.environ["VAULT_ADDR"].rstrip("/")
KEYS_FILE = "/vault-keys/keys.json"


def vault_request(path, payload=None):
    data = None
    headers = {}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        VAULT_ADDR + path,
        data=data,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )

    with urllib.request.urlopen(
        request,
        timeout=10,
    ) as response:
        return json.load(response)


def vault_is_sealed():
    status = vault_request("/v1/sys/seal-status")

    if not isinstance(status.get("sealed"), bool):
        raise ValueError("Invalid Vault seal status")

    return status["sealed"]


def main():
    if not vault_is_sealed():
        print("Vault is already unsealed.", flush=True)
        return

    print("Vault is sealed. Attempting unseal.", flush=True)

    with open(KEYS_FILE, encoding="utf-8") as file:
        keys = json.load(file)["keys"]

    if (
        not isinstance(keys, list)
        or not keys
        or not all(isinstance(key, str) and key for key in keys)
    ):
        raise ValueError("Unseal keys are missing or invalid.")

    for key in keys:
        result = vault_request(
            "/v1/sys/unseal",
            {"key": key},
        )

        if not isinstance(result.get("sealed"), bool):
            raise ValueError("Invalid unseal response")

        if not result["sealed"]:
            break

    if not vault_is_sealed():
        print("Vault successfully unsealed.", flush=True)
        return

    print(
        "Vault remains sealed after submitting keys.",
        flush=True,
    )
    sys.exit(1)


if __name__ == "__main__":
    try:
        main()

    except urllib.error.HTTPError as error:
        print(
            f"Vault HTTP error: {error.code}",
            flush=True,
        )
        sys.exit(1)

    except Exception as error:
        print(
            f"Unseal attempt failed: {type(error).__name__}",
            flush=True,
        )
        sys.exit(1)
