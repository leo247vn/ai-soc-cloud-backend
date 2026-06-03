import os
from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from google.cloud import firestore


APP_VERSION = "phase4-agent-decisions"
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "").strip()
FIRESTORE_COLLECTION = os.getenv("FIRESTORE_COLLECTION", "incidents")
DECISIONS_COLLECTION = os.getenv("DECISIONS_COLLECTION", "decisions")
AUDIT_COLLECTION = os.getenv("AUDIT_COLLECTION", "audit_logs")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
GEMINI_ENABLED = os.getenv("GEMINI_ENABLED", "false").lower() in {"1", "true", "yes", "y"}
VERTEX_AI_PROJECT = os.getenv("VERTEX_AI_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
VERTEX_AI_LOCATION = os.getenv("VERTEX_AI_LOCATION", "global")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
LAB_CONTEXT = {
    "wazuh_ip": os.getenv("LAB_WAZUH_IP", "172.16.10.28"),
    "wazuh_bridge_path": os.getenv("LAB_BRIDGE_PATH", "/home/leonuc/wazuh-bridge-agent"),
    "pfsense_lan_ip": os.getenv("LAB_PFSENSE_LAN_IP", "172.16.11.220"),
    "pfsense_ssh_port": os.getenv("LAB_PFSENSE_SSH_PORT", "2222"),
    "pfsense_block_table": os.getenv("LAB_PFSENSE_BLOCK_TABLE", "ai_soc_block"),
    "cloud_run_url": os.getenv(
        "LAB_CLOUD_RUN_URL",
        "https://ai-soc-backend-4dsqwutw7q-as.a.run.app/",
    ),
    "firestore_incidents": os.getenv("FIRESTORE_COLLECTION", "incidents"),
    "firestore_decisions": os.getenv("DECISIONS_COLLECTION", "decisions"),
    "firestore_audit_logs": os.getenv("AUDIT_COLLECTION", "audit_logs"),
}
PROTECTED_IP_RANGES = [
    ip_network(item.strip())
    for item in os.getenv(
        "PROTECTED_IP_RANGES",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16",
    ).split(",")
    if item.strip()
]
ALLOWED_DECISION_ACTIONS = {"block_ip", "unblock_ip", "ignore", "whitelist"}

app = FastAPI(title="AI SOC Cloud Backend", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
db = firestore.Client()


def require_token(authorization: str | None) -> None:
    if not INGEST_TOKEN:
        return
    expected = f"Bearer {INGEST_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid ingest token")


def require_admin(authorization: str | None) -> None:
    if not ADMIN_TOKEN:
        return
    expected = f"Bearer {ADMIN_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid admin token")


def to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    return value


def incident_from_doc(document: Any) -> dict[str, Any]:
    data = document.to_dict() or {}
    data["document_id"] = document.id
    return to_jsonable(data)


def decision_from_doc(document: Any) -> dict[str, Any]:
    data = document.to_dict() or {}
    data["decision_id"] = document.id
    return to_jsonable(data)


def nested_get(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_audit_log(
    event_type: str,
    actor: str,
    target_type: str,
    target_id: str,
    detail: dict[str, Any],
) -> None:
    db.collection(AUDIT_COLLECTION).document(str(uuid4())).set(
        {
            "event_type": event_type,
            "actor": actor,
            "target_type": target_type,
            "target_id": target_id,
            "detail": detail,
            "created_at": utc_now(),
        }
    )


def validate_target_ip(target_ip: str, allow_protected: bool = False) -> dict[str, Any]:
    try:
        parsed = ip_address(target_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid target_ip: {target_ip}") from exc

    matched_range = None
    for protected_range in PROTECTED_IP_RANGES:
        if parsed in protected_range:
            matched_range = str(protected_range)
            break

    if matched_range and not allow_protected:
        raise HTTPException(
            status_code=400,
            detail=(
                f"target_ip {target_ip} is in protected range {matched_range}; "
                "decision was not created"
            ),
        )

    return {
        "ip": str(parsed),
        "version": parsed.version,
        "is_private": parsed.is_private,
        "is_global": parsed.is_global,
        "protected_range": matched_range,
    }


def validate_decision_action(action: str) -> str:
    normalized = action.strip().lower()
    if normalized not in ALLOWED_DECISION_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"action must be one of: {sorted(ALLOWED_DECISION_ACTIONS)}",
        )
    return normalized


def validate_pending_decision(decision_id: str) -> dict[str, Any]:
    document = db.collection(DECISIONS_COLLECTION).document(decision_id).get()
    if not document.exists:
        raise HTTPException(status_code=404, detail="decision not found")
    decision = decision_from_doc(document)
    if decision.get("status") != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"decision is not pending; current status={decision.get('status')}",
        )
    return decision


def fetch_recent_incidents(limit: int = 20) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 100))
    query = (
        db.collection(FIRESTORE_COLLECTION)
        .order_by("cloud_received_at", direction=firestore.Query.DESCENDING)
        .limit(safe_limit)
    )
    return [incident_from_doc(document) for document in query.stream()]


def summarize_incidents(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = Counter(str(item.get("status") or "unknown") for item in incidents)
    by_asset_type = Counter(str(nested_get(item, "asset.type", "unknown")) for item in incidents)
    by_scenario = Counter(str(item.get("scenario") or "unmapped") for item in incidents)
    by_rule_level = Counter(str(nested_get(item, "rule.level", "unknown")) for item in incidents)

    source_ips = [
        str(nested_get(item, "network.source_ip"))
        for item in incidents
        if nested_get(item, "network.source_ip")
    ]
    top_source_ips = [
        {"source_ip": source_ip, "count": count}
        for source_ip, count in Counter(source_ips).most_common(10)
    ]

    high_value = []
    for item in incidents:
        level = nested_get(item, "rule.level", 0)
        try:
            level_int = int(level)
        except (TypeError, ValueError):
            level_int = 0
        if level_int >= 10:
            high_value.append(
                {
                    "document_id": item.get("document_id"),
                    "event_id": item.get("event_id"),
                    "timestamp": item.get("timestamp"),
                    "rule_id": nested_get(item, "rule.id"),
                    "rule_level": level_int,
                    "description": nested_get(item, "rule.description"),
                    "source_ip": nested_get(item, "network.source_ip"),
                    "asset_type": nested_get(item, "asset.type"),
                    "scenario": item.get("scenario"),
                }
            )

    return {
        "sample_size": len(incidents),
        "by_status": dict(by_status),
        "by_asset_type": dict(by_asset_type),
        "by_scenario": dict(by_scenario),
        "by_rule_level": dict(by_rule_level),
        "top_source_ips": top_source_ips,
        "high_value_incidents": high_value[:10],
        "latest_cloud_received_at": incidents[0].get("cloud_received_at") if incidents else None,
    }


def compact_for_prompt(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compacted = []
    for item in incidents:
        compacted.append(
            {
                "document_id": item.get("document_id"),
                "event_id": item.get("event_id"),
                "timestamp": item.get("timestamp"),
                "cloud_received_at": item.get("cloud_received_at"),
                "status": item.get("status"),
                "rule_id": nested_get(item, "rule.id"),
                "rule_level": nested_get(item, "rule.level"),
                "rule_description": nested_get(item, "rule.description"),
                "scenario": item.get("scenario"),
                "scenario_name": item.get("scenario_name"),
                "attack_type": item.get("attack_type"),
                "asset_type": nested_get(item, "asset.type"),
                "asset_name": nested_get(item, "asset.agent_name"),
                "decoder": nested_get(item, "asset.decoder"),
                "source_ip": nested_get(item, "network.source_ip"),
                "destination_ip": nested_get(item, "network.destination_ip"),
                "destination_port": nested_get(item, "network.destination_port"),
                "suggested_action": item.get("suggested_action"),
            }
        )
    return compacted


def heuristic_chat_answer(message: str, incidents: list[dict[str, Any]]) -> str:
    direct_answer = direct_lab_answer(message)
    if direct_answer:
        return direct_answer

    summary = summarize_incidents(incidents)
    top_ips = summary["top_source_ips"][:5]
    high_value = summary["high_value_incidents"][:5]

    lines = [
        f"Da xem {summary['sample_size']} incident moi nhat trong Firestore.",
        f"Asset type noi bat: {summary['by_asset_type']}.",
        f"Scenario: {summary['by_scenario']}.",
    ]

    if top_ips:
        ip_text = ", ".join(f"{item['source_ip']} ({item['count']})" for item in top_ips)
        lines.append(f"Top source IP: {ip_text}.")

    if high_value:
        lines.append("Incident muc uu tien cao:")
        for item in high_value:
            lines.append(
                "- "
                f"rule={item.get('rule_id')} level={item.get('rule_level')} "
                f"src={item.get('source_ip')} asset={item.get('asset_type')} "
                f"desc={item.get('description')}"
            )
    else:
        lines.append("Chua thay incident level >= 10 trong mau dang xem.")

    lowered = message.lower()
    if "block" in lowered or "chan" in lowered or "chặn" in lowered:
        lines.append(
            "Khuyen nghi Phase 2: chi de xuat action, chua tu dong block. "
            "Sang Phase 3 moi tao decision can admin approve."
        )

    return "\n".join(lines)


def direct_lab_answer(message: str) -> str | None:
    lowered = message.lower()
    asks_ip = "ip" in lowered or "địa chỉ" in lowered or "dia chi" in lowered

    if "pfsense" in lowered and asks_ip:
        return (
            f"IP LAN của pfSense trong lab là {LAB_CONTEXT['pfsense_lan_ip']}.\n"
            f"SSH pfSense dùng port {LAB_CONTEXT['pfsense_ssh_port']}.\n"
            f"Table block đang dùng là {LAB_CONTEXT['pfsense_block_table']}."
        )

    if "wazuh" in lowered and asks_ip:
        return (
            f"IP máy Wazuh/Bridge Agent trong lab là {LAB_CONTEXT['wazuh_ip']}.\n"
            f"Bridge Agent path: {LAB_CONTEXT['wazuh_bridge_path']}."
        )

    if "cloud run" in lowered or "backend" in lowered:
        if asks_ip or "url" in lowered or "endpoint" in lowered:
            return f"Cloud Run backend URL hiện tại là {LAB_CONTEXT['cloud_run_url']}."

    if "collection" in lowered or "firestore" in lowered:
        return (
            "Firestore đang dùng các collection chính:\n"
            f"- incidents: {LAB_CONTEXT['firestore_incidents']}\n"
            f"- decisions: {LAB_CONTEXT['firestore_decisions']}\n"
            f"- audit_logs: {LAB_CONTEXT['firestore_audit_logs']}"
        )

    return None


def build_gemini_prompt(message: str, incidents: list[dict[str, Any]]) -> str:
    compacted = compact_for_prompt(incidents)
    return (
        "Ban la AI SOC assistant cho lab Wazuh + pfSense. "
        "Tra loi dung y cau hoi cua admin. "
        "Neu admin hoi thong tin ha tang/cau hinh, tra loi truc tiep bang Lab context. "
        "Neu admin hoi dieu tra/canh bao/log, hay phan tich incident va dua risk, evidence, suggested action, confidence. "
        "Khong noi da thuc thi firewall action tru khi du lieu noi ro decision da executed.\n\n"
        f"Lab context:\n{LAB_CONTEXT}\n\n"
        f"Cau hoi cua admin:\n{message}\n\n"
        "Du lieu incident moi nhat tu Firestore dang o dang JSON compact:\n"
        f"{compacted}"
    )


def ask_gemini(message: str, incidents: list[dict[str, Any]]) -> str:
    if not VERTEX_AI_PROJECT:
        raise RuntimeError("VERTEX_AI_PROJECT or GOOGLE_CLOUD_PROJECT is required")

    from google import genai
    from google.genai import types

    client = genai.Client(
        vertexai=True,
        project=VERTEX_AI_PROJECT,
        location=VERTEX_AI_LOCATION,
    )
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=build_gemini_prompt(message, incidents),
        config=types.GenerateContentConfig(
            temperature=0.2,
            max_output_tokens=900,
        ),
    )
    return response.text or ""


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok", "service": "ai-soc-backend", "version": APP_VERSION}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": APP_VERSION}


@app.post("/")
@app.post("/ingest-alert")
async def ingest_alert(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    body = await request.json()
    incident = body.get("incident")
    if not isinstance(incident, dict):
        raise HTTPException(status_code=400, detail="body must contain incident object")

    now = datetime.now(timezone.utc)
    event_id = str(incident.get("event_id") or uuid4())
    site_id = str(incident.get("site_id") or "unknown-site")
    document_id = f"{site_id}_{event_id}".replace("/", "_").replace(":", "_")

    document = {
        **incident,
        "status": "new",
        "cloud_received_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    db.collection(FIRESTORE_COLLECTION).document(document_id).set(document, merge=True)

    return {
        "ok": True,
        "collection": FIRESTORE_COLLECTION,
        "document_id": document_id,
    }


@app.get("/incidents")
def list_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
    scenario: str | None = Query(default=None),
) -> dict[str, Any]:
    incidents = fetch_recent_incidents(limit=limit * 3 if (status or scenario) else limit)
    if status:
        incidents = [item for item in incidents if item.get("status") == status]
    if scenario:
        incidents = [item for item in incidents if item.get("scenario") == scenario]
    incidents = incidents[:limit]
    return {"items": incidents, "count": len(incidents)}


@app.get("/incidents/{document_id}")
def get_incident(document_id: str) -> dict[str, Any]:
    document = db.collection(FIRESTORE_COLLECTION).document(document_id).get()
    if not document.exists:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident_from_doc(document)


@app.get("/stats")
def stats(limit: int = Query(default=100, ge=1, le=300)) -> dict[str, Any]:
    incidents = fetch_recent_incidents(limit=limit)
    return summarize_incidents(incidents)


@app.post("/chat")
async def chat(request: Request) -> dict[str, Any]:
    body = await request.json()
    message = str(body.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    limit = body.get("limit", 30)
    try:
        limit_int = int(limit)
    except (TypeError, ValueError):
        limit_int = 30
    limit_int = max(1, min(limit_int, 60))

    incidents = fetch_recent_incidents(limit=limit_int)
    summary = summarize_incidents(incidents)
    use_gemini = bool(body.get("use_gemini", True)) and GEMINI_ENABLED

    source = "heuristic"
    error = None
    direct_answer = direct_lab_answer(message)
    if direct_answer:
        return {
            "answer": direct_answer,
            "source": "lab_context",
            "gemini_enabled": GEMINI_ENABLED,
            "gemini_error": None,
            "summary": summary,
            "incidents_used": len(incidents),
        }

    if use_gemini:
        try:
            answer = ask_gemini(message, incidents)
            source = "gemini"
        except Exception as exc:
            answer = heuristic_chat_answer(message, incidents)
            error = str(exc)
    else:
        answer = heuristic_chat_answer(message, incidents)

    return {
        "answer": answer,
        "source": source,
        "gemini_enabled": GEMINI_ENABLED,
        "gemini_error": error,
        "summary": summary,
        "incidents_used": len(incidents),
    }


@app.get("/decisions")
def list_decisions(
    limit: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
) -> dict[str, Any]:
    query = (
        db.collection(DECISIONS_COLLECTION)
        .order_by("created_at", direction=firestore.Query.DESCENDING)
        .limit(limit * 3 if status else limit)
    )
    decisions = [decision_from_doc(document) for document in query.stream()]
    if status:
        decisions = [item for item in decisions if item.get("status") == status]
    decisions = decisions[:limit]
    return {"items": decisions, "count": len(decisions)}


@app.get("/decisions/{decision_id}")
def get_decision(decision_id: str) -> dict[str, Any]:
    document = db.collection(DECISIONS_COLLECTION).document(decision_id).get()
    if not document.exists:
        raise HTTPException(status_code=404, detail="decision not found")
    return decision_from_doc(document)


@app.post("/decisions")
async def create_decision(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin(authorization)
    body = await request.json()

    action = validate_decision_action(str(body.get("action") or ""))
    target_ip = str(body.get("target_ip") or "").strip()
    if not target_ip and action in {"block_ip", "unblock_ip", "whitelist"}:
        raise HTTPException(status_code=400, detail="target_ip is required for this action")

    ip_info = None
    if target_ip:
        ip_info = validate_target_ip(
            target_ip,
            allow_protected=bool(body.get("allow_protected", False)),
        )

    ttl_minutes = body.get("ttl_minutes", 60)
    try:
        ttl_minutes_int = int(ttl_minutes)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="ttl_minutes must be an integer") from exc
    if ttl_minutes_int < 1 or ttl_minutes_int > 1440:
        raise HTTPException(status_code=400, detail="ttl_minutes must be between 1 and 1440")

    now = utc_now()
    decision_id = str(uuid4())
    incident_id = str(body.get("incident_document_id") or body.get("incident_id") or "").strip()
    created_by = str(body.get("created_by") or "soc-operator").strip()
    document = {
        "decision_id": decision_id,
        "incident_document_id": incident_id or None,
        "action": action,
        "target_ip": ip_info["ip"] if ip_info else None,
        "target_ip_info": ip_info,
        "target_type": str(body.get("target_type") or "ip"),
        "ttl_minutes": ttl_minutes_int,
        "reason": str(body.get("reason") or "").strip(),
        "status": "pending",
        "execution_status": "not_started",
        "created_by": created_by,
        "created_at": now,
        "updated_at": now,
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "comment": None,
        "phase": "phase3_approval_only",
    }
    db.collection(DECISIONS_COLLECTION).document(decision_id).set(document)
    add_audit_log(
        event_type="decision_created",
        actor=created_by,
        target_type="decision",
        target_id=decision_id,
        detail={
            "action": action,
            "target_ip": document["target_ip"],
            "incident_document_id": incident_id or None,
        },
    )
    return {"ok": True, "decision": document}


@app.post("/decisions/{decision_id}/approve")
async def approve_decision(
    decision_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin(authorization)
    decision = validate_pending_decision(decision_id)
    body = await request.json()
    actor = str(body.get("approved_by") or body.get("actor") or "soc-admin").strip()
    comment = str(body.get("comment") or "").strip()
    now = utc_now()
    update = {
        "status": "approved",
        "approved_by": actor,
        "approved_at": now,
        "comment": comment or None,
        "updated_at": now,
    }
    db.collection(DECISIONS_COLLECTION).document(decision_id).set(update, merge=True)
    add_audit_log(
        event_type="decision_approved",
        actor=actor,
        target_type="decision",
        target_id=decision_id,
        detail={
            "action": decision.get("action"),
            "target_ip": decision.get("target_ip"),
            "comment": comment,
        },
    )
    return {"ok": True, "decision_id": decision_id, "status": "approved"}


@app.post("/decisions/{decision_id}/reject")
async def reject_decision(
    decision_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin(authorization)
    decision = validate_pending_decision(decision_id)
    body = await request.json()
    actor = str(body.get("rejected_by") or body.get("actor") or "soc-admin").strip()
    comment = str(body.get("comment") or "").strip()
    now = utc_now()
    update = {
        "status": "rejected",
        "rejected_by": actor,
        "rejected_at": now,
        "comment": comment or None,
        "updated_at": now,
    }
    db.collection(DECISIONS_COLLECTION).document(decision_id).set(update, merge=True)
    add_audit_log(
        event_type="decision_rejected",
        actor=actor,
        target_type="decision",
        target_id=decision_id,
        detail={
            "action": decision.get("action"),
            "target_ip": decision.get("target_ip"),
            "comment": comment,
        },
    )
    return {"ok": True, "decision_id": decision_id, "status": "rejected"}


@app.get("/agent/decisions")
def list_agent_decisions(
    limit: int = Query(default=10, ge=1, le=50),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    query = (
        db.collection(DECISIONS_COLLECTION)
        .order_by("approved_at", direction=firestore.Query.DESCENDING)
        .limit(limit * 5)
    )
    decisions = []
    for document in query.stream():
        decision = decision_from_doc(document)
        if decision.get("status") != "approved":
            continue
        if decision.get("execution_status") not in {"not_started", "retry"}:
            continue
        decisions.append(decision)
        if len(decisions) >= limit:
            break
    return {"items": decisions, "count": len(decisions)}


@app.post("/agent/decisions/{decision_id}/result")
async def report_agent_decision_result(
    decision_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    document_ref = db.collection(DECISIONS_COLLECTION).document(decision_id)
    document = document_ref.get()
    if not document.exists:
        raise HTTPException(status_code=404, detail="decision not found")

    body = await request.json()
    execution_status = str(body.get("execution_status") or "").strip().lower()
    if execution_status not in {"executed", "failed", "skipped", "retry"}:
        raise HTTPException(
            status_code=400,
            detail="execution_status must be executed, failed, skipped, or retry",
        )

    actor = str(body.get("executed_by") or body.get("agent_id") or "bridge-agent").strip()
    now = utc_now()
    update = {
        "execution_status": execution_status,
        "execution_result": body.get("execution_result"),
        "executed_by": actor,
        "executed_at": now if execution_status in {"executed", "skipped"} else None,
        "last_execution_attempt_at": now,
        "updated_at": now,
    }
    document_ref.set(update, merge=True)
    add_audit_log(
        event_type="decision_execution_reported",
        actor=actor,
        target_type="decision",
        target_id=decision_id,
        detail={
            "execution_status": execution_status,
            "execution_result": body.get("execution_result"),
        },
    )
    return {"ok": True, "decision_id": decision_id, "execution_status": execution_status}
