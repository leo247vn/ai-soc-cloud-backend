# Phase 3 Note - Approval Workflow

Ngay tao: 2026-06-03.

Phase 3 muc tieu: tao workflow de admin duyet action do AI de xuat. Phase nay chua SSH vao pfSense va chua block that.

## 1. Dieu kien dau vao

Phase 1 da xong:

```text
Wazuh -> Bridge Agent -> Cloud Run -> Firestore incidents
```

Phase 2 da xong:

```text
Firestore incidents -> /chat -> Gemini analysis
```

Phase 3 them:

```text
incidents -> decisions pending -> admin approve/reject -> audit_logs
```

## 2. Collection moi

```text
decisions
audit_logs
```

Decision mau:

```json
{
  "action": "block_ip",
  "target_ip": "43.152.112.101",
  "ttl_minutes": 60,
  "reason": "Gemini suggested suspicious destination",
  "status": "pending",
  "execution_status": "not_started",
  "phase": "phase3_approval_only"
}
```

Trang thai hop le:

```text
pending
approved
rejected
```

## 3. Endpoint Phase 3

```text
GET  /decisions
GET  /decisions/{decision_id}
POST /decisions
POST /decisions/{decision_id}/approve
POST /decisions/{decision_id}/reject
```

Mutating endpoints co the bao ve bang:

```text
ADMIN_TOKEN=<long-random-token>
```

Neu set `ADMIN_TOKEN`, request can header:

```text
Authorization: Bearer <ADMIN_TOKEN>
```

## 4. Guardrails

Mac dinh khong cho tao decision block/whitelist/unblock voi IP trong cac range:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16
```

Ly do: tranh block nham LAN, Wazuh, pfSense, gateway, server noi bo.

## 5. Deploy Phase 3

Trong Cloud Shell:

```bash
cd ~/cloud-backend
git pull
```

Deploy:

```bash
TOKEN=YOUR_EXISTING_INGEST_TOKEN

gcloud run deploy ai-soc-backend \
  --source . \
  --region asia-southeast1 \
  --allow-unauthenticated \
  --set-env-vars INGEST_TOKEN=$TOKEN,FIRESTORE_COLLECTION=incidents,DECISIONS_COLLECTION=decisions,AUDIT_COLLECTION=audit_logs,GEMINI_ENABLED=true,VERTEX_AI_PROJECT=neon-webbing-496403-t3,VERTEX_AI_LOCATION=global,GEMINI_MODEL=gemini-2.5-flash-lite
```

## 6. Test

Lay URL:

```bash
SERVICE_URL="$(gcloud run services describe ai-soc-backend --region asia-southeast1 --format='value(status.url)')"
```

Tao decision pending:

```bash
curl -X POST "$SERVICE_URL/decisions" \
  -H "Content-Type: application/json" \
  -d '{"action":"block_ip","target_ip":"43.152.112.101","ttl_minutes":60,"reason":"Gemini suggested suspicious destination","created_by":"admin"}'
```

List decisions:

```bash
curl "$SERVICE_URL/decisions?limit=10"
```

Approve:

```bash
DECISION_ID=PASTE_DECISION_ID

curl -X POST "$SERVICE_URL/decisions/$DECISION_ID/approve" \
  -H "Content-Type: application/json" \
  -d '{"approved_by":"admin","comment":"Approved for lab demo"}'
```

Reject:

```bash
DECISION_ID=PASTE_DECISION_ID

curl -X POST "$SERVICE_URL/decisions/$DECISION_ID/reject" \
  -H "Content-Type: application/json" \
  -d '{"rejected_by":"admin","comment":"Not enough confidence"}'
```

Kiem tra Firestore:

```text
Firestore -> decisions
Firestore -> audit_logs
```

## 7. Ket qua Phase 3

Ket thuc Phase 3 khi:

```text
1. Tao duoc decision pending
2. Approve/reject cap nhat status dung
3. audit_logs co event decision_created, decision_approved hoac decision_rejected
```

Phase 4 se de Bridge Agent poll `decisions` status `approved` va thuc thi pfSense.

