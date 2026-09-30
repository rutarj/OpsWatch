"""Bridge from the C1 serverless project: CloudWatch alarm -> SNS -> OpsWatch incident.

Security: anyone on the internet can POST to a webhook. Before trusting a message,
we verify the SNS signature using AWS's signing certificate, and only accept
certificates served from an sns.<region>.amazonaws.com host over HTTPS.
"""
import base64
import json
import re
from functools import lru_cache
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

CERT_HOST = re.compile(r"^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$")
SIGNED_KEYS = {
    "Notification": ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"],
    "SubscriptionConfirmation": ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"],
    "UnsubscribeConfirmation": ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"],
}


class SNSVerificationError(Exception):
    pass


def validate_cert_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not CERT_HOST.match(parsed.hostname or "") or not parsed.path.endswith(".pem"):
        raise SNSVerificationError(f"untrusted SigningCertURL: {url}")


def string_to_sign(message: dict) -> bytes:
    keys = SIGNED_KEYS.get(message.get("Type", ""))
    if keys is None:
        raise SNSVerificationError(f"unknown message type {message.get('Type')!r}")
    parts = []
    for key in keys:
        if key in message and message[key] is not None:  # Subject is optional in notifications
            parts.append(f"{key}\n{message[key]}\n")
    return "".join(parts).encode()


@lru_cache(maxsize=16)
def _fetch_cert(url: str) -> bytes:
    response = httpx.get(url, timeout=5.0)
    response.raise_for_status()
    return response.content


def verify_signature(message: dict, fetch_cert=_fetch_cert) -> None:
    validate_cert_url(message.get("SigningCertURL", ""))
    version = message.get("SignatureVersion")
    algorithm = {"1": hashes.SHA1(), "2": hashes.SHA256()}.get(version)
    if algorithm is None:
        raise SNSVerificationError(f"unsupported SignatureVersion {version!r}")
    cert = x509.load_pem_x509_certificate(fetch_cert(message["SigningCertURL"]))
    try:
        cert.public_key().verify(base64.b64decode(message["Signature"]), string_to_sign(message),
                                 padding.PKCS1v15(), algorithm)
    except Exception as exc:
        raise SNSVerificationError("signature does not match") from exc


def parse_alarm(message: dict) -> dict:
    """Turn a CloudWatch alarm notification into incident fields."""
    alarm = json.loads(message["Message"])
    trigger = alarm.get("Trigger", {}) or {}
    return {
        "alarm_name": alarm.get("AlarmName", "unknown-alarm"),
        "state": alarm.get("NewStateValue", "UNKNOWN"),
        "reason": alarm.get("NewStateReason", ""),
        "region": alarm.get("Region", ""),
        "metric": f"{trigger.get('Namespace', '')}/{trigger.get('MetricName', '')}".strip("/"),
        "changed_at": alarm.get("StateChangeTime", ""),
        "description": alarm.get("AlarmDescription") or "",
    }
