import base64
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from opswatch.api import create_app
from opswatch.integrations import sns

KEY = {"X-API-Key": "test-key"}
CERT_URL = "https://sns.ca-central-1.amazonaws.com/SimpleNotificationService-test.pem"


@pytest.fixture(scope="module")
def signing():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.com")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM)


def signed(key, message: dict, version="2") -> dict:
    message = {**message, "SignatureVersion": version, "SigningCertURL": CERT_URL}
    algo = hashes.SHA256() if version == "2" else hashes.SHA1()
    sig = key.sign(sns.string_to_sign(message), padding.PKCS1v15(), algo)
    return {**message, "Signature": base64.b64encode(sig).decode()}


def alarm_message(name="order-recon-dev-dlq-not-empty", state="ALARM"):
    return {"Type": "Notification", "MessageId": "m-1", "TopicArn": "arn:aws:sns:ca-central-1:1:alerts",
            "Subject": f"{state}: {name}", "Timestamp": "2026-09-29T14:02:00.000Z",
            "Message": json.dumps({"AlarmName": name, "NewStateValue": state, "Region": "ca-central-1",
                                   "NewStateReason": "Threshold Crossed", "StateChangeTime": "2026-09-29T14:02:00Z",
                                   "Trigger": {"Namespace": "AWS/SQS",
                                               "MetricName": "ApproximateNumberOfMessagesVisible"}})}


@pytest.fixture
def client(ops, signing):
    _, pem = signing
    return TestClient(create_app(ops, verify_sns=lambda m: sns.verify_signature(m, fetch_cert=lambda url: pem)))


# ---------------- SNS verification ----------------
@pytest.mark.parametrize("url", [
    "http://sns.ca-central-1.amazonaws.com/x.pem",           # not https
    "https://sns.ca-central-1.amazonaws.com.evil.com/x.pem",  # lookalike host
    "https://evil.com/sns.amazonaws.com/x.pem",
    "https://sns.ca-central-1.amazonaws.com/x.txt",           # not a .pem
])
def test_untrusted_cert_urls_rejected(url):
    with pytest.raises(sns.SNSVerificationError):
        sns.validate_cert_url(url)


@pytest.mark.parametrize("version", ["1", "2"])
def test_valid_signature_accepted(signing, version):
    key, pem = signing
    sns.verify_signature(signed(key, alarm_message(), version), fetch_cert=lambda url: pem)


def test_tampered_message_rejected(signing):
    key, pem = signing
    msg = signed(key, alarm_message())
    msg["Message"] = msg["Message"].replace("ALARM", "OK")
    with pytest.raises(sns.SNSVerificationError, match="does not match"):
        sns.verify_signature(msg, fetch_cert=lambda url: pem)


# ---------------- webhook (C1 bridge) ----------------
def test_webhook_rejects_unsigned(client):
    assert client.post("/webhooks/sns", json=alarm_message()).status_code == 403


def test_alarm_opens_incident_once_then_proposes_resolution(client, ops, signing):
    key, _ = signing
    first = client.post("/webhooks/sns", json=signed(key, alarm_message())).json()
    assert first["action"] == "created" and first["priority"] == "P2"
    ticket = ops.store.get_ticket(first["ticket_id"])
    assert ticket["category"] == "cloud_ops" and ticket["assignment_group"] == "Cloud Operations"
    assert "KB0016" in ops.store.work_notes(ticket["id"])[0]["note"]

    again = client.post("/webhooks/sns", json=signed(key, alarm_message())).json()
    assert again == {"action": "noted_existing", "ticket_id": ticket["id"]}

    ok = client.post("/webhooks/sns", json=signed(key, alarm_message(state="OK"))).json()
    assert ok["action"] == "proposed_resolution" and ok["proposal_status"] == "pending"


def test_subscription_confirmation_is_not_auto_confirmed(client, signing):
    key, _ = signing
    msg = signed(key, {"Type": "SubscriptionConfirmation", "MessageId": "c-1", "Token": "t",
                       "TopicArn": "arn:aws:sns:ca-central-1:1:alerts", "Message": "confirm",
                       "SubscribeURL": "https://sns.ca-central-1.amazonaws.com/?Action=ConfirmSubscription",
                       "Timestamp": "2026-09-29T14:00:00.000Z"})
    assert client.post("/webhooks/sns", json=msg).json()["action"] == "subscription_pending"


# ---------------- REST API ----------------
def test_health_and_console_are_public(client):
    assert client.get("/health").json() == {"status": "ok"}
    page = client.get("/").text
    assert "Sign-off queue" in page and "innerHTML" not in page  # XSS-safe rendering


def test_api_requires_key(client):
    assert client.get("/api/tickets").status_code == 401
    assert client.get("/api/tickets", headers={"X-API-Key": "wrong"}).status_code == 401


def test_create_ticket_returns_triage_suggestion(client):
    r = client.post("/api/tickets", headers=KEY, json={"short_description": "Projector not turning on in A2104",
                                                       "description": "Lecture starts in 10 minutes. Urgent.",
                                                       "caller": "Prof Lee"})
    assert r.status_code == 201 and r.json()["triage_suggestion"]["category"] == "av_classroom"


def test_approval_flow_over_http(client, ops):
    t = ops.store.list_tickets(limit=1)[0]
    r = ops.propose(ticket_id=t["id"], action="add_work_note", payload={"note": "Called the user."},
                    rationale="follow-up", actor="agent:mcp")
    assert [a["id"] for a in client.get("/api/approvals", headers=KEY).json()] == [r.action_id]
    bad = client.post(f"/api/approvals/{r.action_id}/approve", headers=KEY, json={"approver": "agent:mcp"})
    assert bad.status_code == 409
    good = client.post(f"/api/approvals/{r.action_id}/approve", headers=KEY, json={"approver": "rutarj"})
    assert good.json()["status"] == "executed"
    assert client.get("/api/audit/verify", headers=KEY).json()["ok"] is True
    assert client.get("/api/metrics", headers=KEY).json()["actions_by_status"] == {"executed": 1}


def test_reject_over_http(client, ops):
    t = ops.store.list_tickets(limit=1)[0]
    r = ops.propose(ticket_id=t["id"], action="add_work_note", payload={"note": "x"}, rationale="y",
                    actor="agent:mcp")
    res = client.post(f"/api/approvals/{r.action_id}/reject", headers=KEY,
                      json={"approver": "rutarj", "reason": "not needed"})
    assert res.json()["status"] == "rejected"


def test_apply_triage_requires_approver(client, ops):
    t = ops.store.list_tickets(limit=1)[0]
    assert client.post(f"/api/tickets/{t['id']}/apply-triage", headers=KEY,
                       json={"approver": "stranger"}).status_code == 403
    ok = client.post(f"/api/tickets/{t['id']}/apply-triage", headers=KEY, json={"approver": "rutarj"})
    assert ok.json()["state"] == "in_progress" and ok.json()["category"]


def test_missing_server_key_is_503(ops):
    from dataclasses import replace
    ops.settings = replace(ops.settings, api_key=None)
    assert TestClient(create_app(ops)).get("/api/tickets", headers=KEY).status_code == 503
