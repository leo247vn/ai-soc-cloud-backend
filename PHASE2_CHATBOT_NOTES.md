# Phase 2 Note - AI Chatbot tren Firestore incidents

Ngay tao: 2026-06-03.

Phase 2 muc tieu: bien du lieu `incidents` trong Firestore thanh chatbot SOC co the hoi dap ve alert moi nhat, risk, evidence va action de xuat.

## 1. Dieu kien dau vao

Phase 1 da xong:

```text
Wazuh -> Bridge Agent -> Cloud Run -> Firestore
```

Firestore da co:

```text
Database: (default)
Collection: incidents
Document prefix: lab-onprem_
```

Cloud Run URL dung:

```text
https://ai-soc-backend-4dsqwutw7q-as.a.run.app/
```

## 2. Endpoint Phase 2

Backend co them:

```text
GET  /incidents
GET  /incidents/{document_id}
GET  /stats
POST /chat
```

Phase 1 van giu:

```text
POST /
POST /ingest-alert
```

## 3. Che do chatbot

Co 2 che do:

```text
GEMINI_ENABLED=false
```

Backend tra loi bang heuristic summary tu Firestore. Che do nay dung de test nhanh, khong ton Vertex AI.

```text
GEMINI_ENABLED=true
```

Backend lay incidents tu Firestore, compact context, goi Gemini tren Vertex AI, roi tra loi bang tieng Viet. Neu Gemini loi, backend fallback ve heuristic summary.

## 4. Deploy Phase 2

Trong Cloud Shell, vao thu muc backend:

```bash
cd ~/cloud-backend
```

Neu chua co source Phase 2 tren Cloud Shell, can cap nhat cac file:

```text
main.py
requirements.txt
Dockerfile
```

Enable Vertex AI service:

```bash
gcloud services enable aiplatform.googleapis.com
```

Deploy voi Gemini:

```bash
TOKEN=YOUR_EXISTING_INGEST_TOKEN

gcloud run deploy ai-soc-backend \
  --source . \
  --region asia-southeast1 \
  --allow-unauthenticated \
  --set-env-vars INGEST_TOKEN=$TOKEN,FIRESTORE_COLLECTION=incidents,GEMINI_ENABLED=true,VERTEX_AI_PROJECT=neon-webbing-496403-t3,VERTEX_AI_LOCATION=global,GEMINI_MODEL=gemini-2.5-flash-lite
```

Neu muon test khong dung Gemini:

```bash
gcloud run deploy ai-soc-backend \
  --source . \
  --region asia-southeast1 \
  --allow-unauthenticated \
  --set-env-vars INGEST_TOKEN=$TOKEN,FIRESTORE_COLLECTION=incidents,GEMINI_ENABLED=false
```

## 5. Test endpoint

Lay URL:

```bash
SERVICE_URL="$(gcloud run services describe ai-soc-backend --region asia-southeast1 --format='value(status.url)')"
echo "$SERVICE_URL"
```

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

Ket qua can xem:

```text
source=gemini      -> Gemini da chay
source=heuristic   -> dang fallback hoac GEMINI_ENABLED=false
gemini_error=null  -> khong co loi Gemini
incidents_used > 0 -> da doc duoc Firestore incidents
```

Neu gap loi 404 `Publisher Model ... was not found`, kiem tra lai `GEMINI_MODEL` va `VERTEX_AI_LOCATION`. Nen dung:

```text
VERTEX_AI_LOCATION=global
GEMINI_MODEL=gemini-2.5-flash-lite
```

## 6. Ghi chu bao mat va scope

- Phase 2 chi phan tich va de xuat.
- Khong tu dong block IP.
- Block/Ignore/Approve se lam o Phase 3.
- Bridge Agent SSH vao pfSense se lam o Phase 4.
- Khong dua `INGEST_TOKEN` vao slide/public repo.
