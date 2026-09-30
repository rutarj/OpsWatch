"""REST API + approval console. This is the HUMAN side of OpsWatch.

The MCP server lets an AI propose; this API is where people review, approve or
reject. Endpoints that change data require an API key (X-API-Key). In production
the approver's identity would come from SSO, not a request body.
"""
import hmac
import json
from importlib import resources

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from opswatch import audit
from opswatch.actions import ActionError
from opswatch.app import OpsWatch
from opswatch.integrations.alarm_handler import handle_alarm
from opswatch.integrations.sns import SNSVerificationError, parse_alarm, verify_signature


class NewTicket(BaseModel):
    short_description: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=3, max_length=5000)
    caller: str = Field(min_length=1, max_length=100)
    source: str = Field(default="portal", pattern="^(portal|email|phone)$")


class Decision(BaseModel):
    approver: str = Field(min_length=1, max_length=60)
    reason: str = Field(default="", max_length=500)


class ApplyTriage(BaseModel):
    approver: str = Field(min_length=1, max_length=60)


def create_app(ops: OpsWatch, verify_sns=verify_signature) -> FastAPI:
    app = FastAPI(title="OpsWatch", version="1.0.0",
                  description="AI-assisted service desk triage with human approval gates.")

    def require_key(x_api_key: str | None = Header(default=None)):
        expected = ops.settings.api_key
        if not expected:
            raise HTTPException(503, "OPSWATCH_API_KEY is not set on the server")
        # compare_digest avoids leaking the key through response timing
        if not x_api_key or not hmac.compare_digest(x_api_key, expected):
            raise HTTPException(401, "missing or wrong X-API-Key")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def console():
        return resources.files("opswatch.web").joinpath("console.html").read_text()

    @app.get("/api/tickets", dependencies=[Depends(require_key)])
    def list_tickets(state: str | None = None, category: str | None = None, q: str | None = None, limit: int = 50):
        return ops.store.list_tickets(state=state, category=category, query=q, limit=limit)

    @app.get("/api/tickets/{ticket_id}", dependencies=[Depends(require_key)])
    def get_ticket(ticket_id: str):
        ticket = ops.store.get_ticket(ticket_id)
        if ticket is None:
            raise HTTPException(404, "ticket not found")
        return {**ticket, "work_notes": ops.store.work_notes(ticket_id),
                "proposals": ops.store.list_actions(ticket_id=ticket_id)}

    @app.post("/api/tickets", status_code=201, dependencies=[Depends(require_key)])
    def create_ticket(body: NewTicket):
        ticket = ops.store.create_ticket(body.short_description, body.description, body.caller,
                                         actor=f"caller:{body.caller}", source=body.source)
        return {"ticket": ticket, "triage_suggestion": ops.triage(ticket["id"]).to_dict()}

    @app.post("/api/tickets/{ticket_id}/triage", dependencies=[Depends(require_key)])
    def triage(ticket_id: str):
        try:
            return ops.triage(ticket_id).to_dict()
        except KeyError:
            raise HTTPException(404, "ticket not found") from None

    @app.post("/api/tickets/{ticket_id}/apply-triage", dependencies=[Depends(require_key)])
    def apply_triage(ticket_id: str, body: ApplyTriage):
        """A human accepts the AI suggestion directly. Logged under the human's name."""
        if body.approver not in ops.policy.approvers:
            raise HTTPException(403, f"'{body.approver}' is not an approver")
        try:
            s = ops.triage(ticket_id)
        except KeyError:
            raise HTTPException(404, "ticket not found") from None
        return ops.store.update_ticket(ticket_id, {"category": s.category, "priority": s.priority,
                                                   "assignment_group": s.assignment_group,
                                                   "state": "in_progress"}, actor=body.approver)

    @app.get("/api/approvals", dependencies=[Depends(require_key)])
    def approvals(status: str | None = "pending", limit: int = 50):
        return ops.store.list_actions(status=status or None, limit=limit)

    @app.post("/api/approvals/{action_id}/approve", dependencies=[Depends(require_key)])
    def approve(action_id: int, body: Decision):
        try:
            return ops.approve(action_id, body.approver)
        except ActionError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/api/approvals/{action_id}/reject", dependencies=[Depends(require_key)])
    def reject(action_id: int, body: Decision):
        try:
            return ops.reject(action_id, body.approver, body.reason or "no reason given")
        except ActionError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/audit", dependencies=[Depends(require_key)])
    def audit_log(limit: int = 100):
        rows = ops.store.conn.execute(
            "SELECT seq, ts, actor, event, ticket_id, details, hash FROM audit_log ORDER BY seq DESC LIMIT ?",
            (min(limit, 500),)).fetchall()
        return [{**dict(r), "details": json.loads(r["details"])} for r in rows]

    @app.get("/api/audit/verify", dependencies=[Depends(require_key)])
    def audit_verify():
        return audit.verify(ops.store.conn)

    @app.get("/api/metrics", dependencies=[Depends(require_key)])
    def metrics():
        return ops.store.metrics()

    @app.post("/webhooks/sns")
    async def sns_webhook(request: Request):
        """No API key here: SNS can't send one. Trust comes from the SNS signature instead."""
        try:
            message = json.loads(await request.body())
        except json.JSONDecodeError:
            raise HTTPException(400, "body must be JSON") from None
        if ops.settings.sns_verify_signatures:
            try:
                verify_sns(message)
            except (SNSVerificationError, KeyError) as exc:
                raise HTTPException(403, f"SNS signature check failed: {exc}") from None
        kind = message.get("Type")
        if kind == "SubscriptionConfirmation":
            # Not auto-confirmed on purpose: a human opens SubscribeURL once, from the logs.
            return {"action": "subscription_pending", "subscribe_url": message.get("SubscribeURL")}
        if kind != "Notification":
            return {"action": "ignored", "type": kind}
        try:
            alarm = parse_alarm(message)
        except (json.JSONDecodeError, KeyError):
            raise HTTPException(400, "Message is not a CloudWatch alarm") from None
        return handle_alarm(ops, alarm)

    return app


def build_default_app() -> FastAPI:
    ops = OpsWatch.create()
    ops.seed_open_tickets()
    return create_app(ops)
