# AI SOC Cloud Backend

Cloud Run backend for the AI SOC Wazuh pipeline.

Current scope:

```text
Phase 1: ingest Wazuh incidents into Firestore
Phase 2: read incidents and answer chatbot questions
```

## Endpoints

```text
GET  /
GET  /healthz
POST /
POST /ingest-alert
GET  /incidents
GET  /incidents/{document_id}
GET  /stats
POST /chat
```

`POST /` and `POST /ingest-alert` both accept Bridge Agent payloads:

```json
{
  "incident": {
    "event_id": "174...",
    "site_id": "lab-onprem",
    "rule": {
      "id": "200500",
      "level": 10
    }
  }
}
```

`POST /chat` accepts:

```json
{
  "message": "1 gio gan day co gi bat thuong?",
  "limit": 30,
  "use_gemini": true
}
```

If `GEMINI_ENABLED=false`, `/chat` returns a rule-based summary from Firestore data. If `GEMINI_ENABLED=true`, it calls Gemini on Vertex AI and falls back to the rule-based answer if Gemini fails.

## Environment

Required for ingest security:

```text
INGEST_TOKEN=<same-token-as-bridge-agent>
FIRESTORE_COLLECTION=incidents
```

Required only when enabling Gemini:

```text
GEMINI_ENABLED=true
VERTEX_AI_PROJECT=neon-webbing-496403-t3
VERTEX_AI_LOCATION=asia-southeast1
GEMINI_MODEL=gemini-2.0-flash-lite-001
```

## Deploy

Enable services:

```bash
gcloud services enable run.googleapis.com firestore.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com aiplatform.googleapis.com
```

Deploy:

```bash
TOKEN=YOUR_EXISTING_INGEST_TOKEN

gcloud run deploy ai-soc-backend \
  --source . \
  --region asia-southeast1 \
  --allow-unauthenticated \
  --set-env-vars INGEST_TOKEN=$TOKEN,FIRESTORE_COLLECTION=incidents,GEMINI_ENABLED=true,VERTEX_AI_PROJECT=neon-webbing-496403-t3,VERTEX_AI_LOCATION=asia-southeast1,GEMINI_MODEL=gemini-2.0-flash-lite-001
```

Get service URL:

```bash
SERVICE_URL="$(gcloud run services describe ai-soc-backend --region asia-southeast1 --format='value(status.url)')"
echo "$SERVICE_URL"
```

Current known good URL:

```text
https://ai-soc-backend-4dsqwutw7q-as.a.run.app/
```

## Test

Health:

```bash
curl "$SERVICE_URL/"
```

List incidents:

```bash
curl "$SERVICE_URL/incidents?limit=5"
```

Stats:

```bash
curl "$SERVICE_URL/stats?limit=50"
```

Chat:

```bash
curl -X POST "$SERVICE_URL/chat" \
  -H "Content-Type: application/json" \
  -d '{"message":"1 gio gan day co gi bat thuong? Co IP nao nen block khong?","limit":30,"use_gemini":true}'
```

Expected response:

```json
{
  "answer": "...",
  "source": "gemini",
  "gemini_enabled": true,
  "summary": {
    "sample_size": 30
  }
}
```

If `source` is `heuristic` and `gemini_error` is not null, Firestore is working but Gemini/Vertex AI needs configuration or quota adjustment.
