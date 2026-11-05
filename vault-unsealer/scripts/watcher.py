
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VAULT_ADDR = os.environ["VAULT_ADDR"].rstrip("/")
NAMESPACE = os.environ["POD_NAMESPACE"]

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL") or "10")
RETRY_INTERVAL = int(os.getenv("RETRY_INTERVAL") or "90")
SUCCESS_TTL = int(os.getenv("SUCCESS_TTL") or "30")
FAILED_TTL = int(os.getenv("FAILED_TTL") or "3600")

JOB_IMAGE = os.getenv("JOB_IMAGE", "python:3.13-slim")
KEYS_SECRET_NAME = os.environ["KEYS_SECRET_NAME"]
SCRIPT_CONFIGMAP = os.environ["UNSEAL_SCRIPT_CONFIGMAP"]

API = "https://kubernetes.default.svc"
BASE = f"/apis/batch/v1/namespaces/{NAMESPACE}"

TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

CONTEXT = ssl.create_default_context(cafile=CA_FILE)

JOB_LABEL = "app.kubernetes.io/component=vault-unseal-attempt"

last_attempt = 0.0


def k8s_request(method, path, payload=None):
    with open(TOKEN_FILE, encoding="utf-8") as file:
        token = file.read().strip()

    data = (
        json.dumps(payload).encode("utf-8")
        if payload is not None
        else None
    )

    content_type = (
        "application/merge-patch+json"
        if method == "PATCH"
        else "application/json"
    )

    request = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
        },
    )

    with urllib.request.urlopen(
        request,
        context=CONTEXT,
        timeout=10,
    ) as response:
        return json.load(response)


def vault_is_sealed():
    with urllib.request.urlopen(
        VAULT_ADDR + "/v1/sys/seal-status",
        timeout=5,
    ) as response:
        status = json.load(response)

    if not isinstance(status.get("sealed"), bool):
        raise ValueError("Invalid Vault seal status")

    return status["sealed"]


def list_unseal_jobs():
    selector = urllib.parse.quote(JOB_LABEL, safe="")

    result = k8s_request(
        "GET",
        f"{BASE}/jobs?labelSelector={selector}",
    )

    return result.get("items", [])


def job_condition(job, condition_type):
    return any(
        condition.get("type") == condition_type
        and condition.get("status") == "True"
        for condition in job.get("status", {}).get("conditions", [])
    )


def seconds_since_created(job):
    created = job["metadata"]["creationTimestamp"]

    created_at = datetime.fromisoformat(
        created.replace("Z", "+00:00")
    )

    return (
        datetime.now(timezone.utc) - created_at
    ).total_seconds()


def cleanup_successful_jobs(jobs):
    for job in jobs:
        if not job_condition(job, "Complete"):
            continue

        name = job["metadata"]["name"]

        current_ttl = job.get("spec", {}).get(
            "ttlSecondsAfterFinished"
        )

        if current_ttl == SUCCESS_TTL:
            continue

        k8s_request(
            "PATCH",
            f"{BASE}/jobs/{name}",
            {
                "spec": {
                    "ttlSecondsAfterFinished": SUCCESS_TTL
                }
            },
        )

        print(
            f"Successful Job {name}: TTL set to {SUCCESS_TTL}s.",
            flush=True,
        )


def create_unseal_job():
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "generateName": "vault-unseal-attempt-",
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/component":
                    "vault-unseal-attempt"
            },
        },
        "spec": {
            "backoffLimit": 2,
            "activeDeadlineSeconds": 60,
            "ttlSecondsAfterFinished": FAILED_TTL,
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component":
                            "vault-unseal-attempt"
                    }
                },
                "spec": {
                    "serviceAccountName": "vault-unsealer",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": {
                            "type": "RuntimeDefault"
                        },
                    },
                    "containers": [
                        {
                            "name": "unsealer",
                            "image": JOB_IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "command": [
                                "python",
                                "/app/unseal.py"
                            ],
                            "env": [
                                {
                                    "name": "VAULT_ADDR",
                                    "value": VAULT_ADDR
                                }
                            ],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {
                                    "drop": ["ALL"]
                                },
                            },
                            "resources": {
                                "requests": {
                                    "cpu": "25m",
                                    "memory": "32Mi"
                                },
                                "limits": {
                                    "cpu": "200m",
                                    "memory": "128Mi"
                                },
                            },
                            "volumeMounts": [
                                {
                                    "name": "script",
                                    "mountPath": "/app",
                                    "readOnly": True
                                },
                                {
                                    "name": "unseal-keys",
                                    "mountPath": "/vault-keys",
                                    "readOnly": True
                                },
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "script",
                            "configMap": {
                                "name": SCRIPT_CONFIGMAP,
                                "defaultMode": 292
                            },
                        },
                        {
                            "name": "unseal-keys",
                            "secret": {
                                "secretName": KEYS_SECRET_NAME,
                                "defaultMode": 288
                            },
                        },
                    ],
                },
            },
        },
    }

    result = k8s_request(
        "POST",
        f"{BASE}/jobs",
        job,
    )

    print(
        f"Created unseal Job: {result['metadata']['name']}",
        flush=True,
    )


def check_vault():
    global last_attempt

    jobs = list_unseal_jobs()

    cleanup_successful_jobs(jobs)

    if not vault_is_sealed():
        return

    print("Vault is sealed.", flush=True)

    # Prevent overlapping unseal Jobs.
    for job in jobs:
        if not (
            job_condition(job, "Complete")
            or job_condition(job, "Failed")
        ):
            print(
                "An unseal Job is already pending or running.",
                flush=True,
            )
            return

    # Respect retry delay within this watcher process.
    if time.monotonic() - last_attempt < RETRY_INTERVAL:
        return

    # Respect recently created Jobs still in Kubernetes.
    if jobs:
        latest = max(
            jobs,
            key=lambda item: item["metadata"]["creationTimestamp"],
        )

        if seconds_since_created(latest) < RETRY_INTERVAL:
            return

    print("Creating unseal Job.", flush=True)

    last_attempt = time.monotonic()
    create_unseal_job()


def main():
    print("Vault watcher started.", flush=True)

    while True:
        try:
            check_vault()

        except urllib.error.HTTPError as error:
            print(
                f"Watcher HTTP error: {error.code}",
                flush=True,
            )

        except Exception as error:
            print(
                f"Watcher error: {type(error).__name__}",
                flush=True,
            )

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
