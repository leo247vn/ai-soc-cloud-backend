import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query, Request
from google.cloud import firestore


APP_VERSION = "phase2-chatbot"
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "").strip()
FIRESTORE_COLLECTION = os.getenv("FIRESTORE_COLLECTION", "incidents")
GEMINI_ENABLED = os.getenv("GEMINI_ENABLED", "false").lower() in {"1", "true", "yes", "y"}
VERTEX_AI_PROJECT = os.getenv("VERTEX_AI_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
VERTEX_AI_LOCATION = os.getenv("VERTEX_AI_LOCATION", "global")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")

app = FastAPI(title="AI SOC Cloud Backend", version=APP_VERSION)
db = firestore.Client()


def require_token(authorization: str | None) -> None:
    if not INGEST_TOKEN:
        return
    expected = f"Bearer {INGEST_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid ingest token")


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


def nested_get(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


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


def build_gemini_prompt(message: str, incidents: list[dict[str, Any]]) -> str:
    compacted = compact_for_prompt(incidents)
    return (
        "Ban la AI SOC assistant cho lab Wazuh + pfSense. "
        "Chi dua ra phan tich va khuyen nghi, khong bao da thuc thi firewall action. "
        "Tra loi bang tieng Viet ngan gon, co risk, evidence, suggested action, confidence.\n\n"
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
