# 📥 Replit Backend: Zone Notes Download Endpoint

**Мета**: Додати endpoint для завантаження консолідованого `.md` файлу зони з MinIO.

---

## Контекст

Кожна зона має консолідований файл `notes-all.md` у MinIO за шляхом:
```
/zones/<zoneId>/notes-all.md
```

MinIO бакет `mcpstorage` приватний, тому фронтенд не може завантажити файл напряму. Потрібен проксі-endpoint на бекенді.

---

## Що потрібно зробити

### 1. Новий endpoint: `GET /v1/zones/{zone_id}/download`

**Авторизація**: Bearer token (`SERVICE_TOKEN`) — прийде від Cloudflare Worker.

**Логіка**:
1. Отримати `zone_id` з URL path
2. Завантажити файл з MinIO: `s3.get_object(Bucket="mcpstorage", Key=f"zones/{zone_id}/notes-all.md")`
3. Повернути файл як `StreamingResponse` з headers:
   - `Content-Type: text/markdown; charset=utf-8`
   - `Content-Disposition: attachment; filename="notes-all.md"`

**Приклад коду (FastAPI)**:
```python
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
import io

router = APIRouter()

@router.get("/v1/zones/{zone_id}/download")
async def download_zone_notes(zone_id: str, auth=Depends(verify_service_token)):
    """Download consolidated notes-all.md for a zone from MinIO."""
    key = f"zones/{zone_id}/notes-all.md"
    
    try:
        response = s3_client.get_object(Bucket="mcpstorage", Key=key)
        content = response["Body"].read()
    except s3_client.exceptions.NoSuchKey:
        raise HTTPException(status_code=404, detail=f"Notes file not found for zone {zone_id}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download: {str(e)}")
    
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="notes-all.md"',
        }
    )
```

### 2. MinIO конфігурація

Використовуй існуючий `s3_client` (boto3) з наявними credentials:
- **Endpoint**: `https://apiminio.exodus.pp.ua`
- **Bucket**: `mcpstorage`

---

## Також потрібно: Cloudflare Worker route

⚠️ **Це буде зроблено окремо у Cloudflare Worker.**

Cloudflare Worker повинен проксувати `GET /zones/{zoneId}/download` до Replit backend `GET /v1/zones/{zone_id}/download` з `SERVICE_TOKEN`.

---

## Перевірка

```bash
# Тест через curl (з токеном)
curl -H "Authorization: Bearer $SERVICE_TOKEN" \
  https://<replit-backend>/v1/zones/099cdc98/download \
  -o test-notes.md

# Перевірити що файл містить markdown контент
head test-notes.md
```

---

## Що НЕ потрібно робити

- ❌ Не змінювати існуючі endpoints
- ❌ Не додавати нові залежності (boto3/s3 вже є)
- ❌ Не робити публічним MinIO бакет
