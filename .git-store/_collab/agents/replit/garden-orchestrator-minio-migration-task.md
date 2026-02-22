# 🚀 Replit Agent Task: Migrate Garden-Orchestrator from Cloudflare KV to MinIO

**Мета**: Замінити Cloudflare KV storage на MinIO для зменшення витрат та уникнення лімітів безкоштовного плану CF.

**Дата створення**: 2026-01-17
**Пріоритет**: HIGH
**Статус**: TODO

---

## 📋 КОНТЕКСТ ПРОБЛЕМИ

### Поточний стан
- **Cloudflare Worker** `garden-orchestrator` використовує **KV storage** для:
  - Черги завдань (`queue:pending`)
  - Збереження завдань (`task:{id}`)
  - Реєстрації воркерів (`worker:{id}`)
  - Історії завершених завдань (`completed:{id}`)
- **Проблема**: Вичерпано денний ліміт KV put() операцій (Free tier: 1000 writes/day)
- **Причина**: Часті polling-запити від RPi Worker + багато write операцій на кожну дію

### Поточна архітектура
```
┌─────────────────────┐
│  RPi Worker         │
│  (Python, polling)  │
└──────────┬──────────┘
           │ HTTP (кожні 5-30 сек)
           ▼
┌─────────────────────┐
│ Cloudflare Worker   │  → Cloudflare KV (ЛІМІТ!)
│ garden-orchestrator │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Lovable Frontend   │
│  (task creation)    │
└─────────────────────┘
```

### Цільова архітектура
```
┌─────────────────────┐
│  RPi Worker         │
│  (Python, polling)  │
└──────────┬──────────┘
           │ HTTP (кожні 30-60 сек)
           ▼
┌─────────────────────┐
│ Replit FastAPI      │  → MinIO Storage (NO LIMITS!)
│ garden-orchestrator │     + In-memory cache
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Lovable Frontend   │
│  (task creation)    │
└─────────────────────┘
```

---

## 🎯 ЗАДАЧІ

### Phase 1: MinIO Storage Service

#### 1.1 Створити MinIO клієнт

Файл: `src/services/minio_storage.py`

```python
"""
MinIO Storage Service for Garden Orchestrator
Replaces Cloudflare KV with S3-compatible object storage
"""

import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from minio import Minio
from minio.error import S3Error
from io import BytesIO
import asyncio
from functools import lru_cache


class MinioStorageService:
    """
    S3-compatible storage using MinIO for task queue management.
    Replaces Cloudflare KV to avoid rate limits.
    """
    
    def __init__(self):
        self.client = Minio(
            os.getenv("MINIO_ENDPOINT", "localhost:9000"),
            access_key=os.getenv("MINIO_ACCESS_KEY", ""),
            secret_key=os.getenv("MINIO_SECRET_KEY", ""),
            secure=os.getenv("MINIO_SECURE", "true").lower() == "true"
        )
        self.bucket = os.getenv("MINIO_BUCKET", "garden-orchestrator")
        
        # In-memory cache to reduce S3 calls
        self._cache: Dict[str, tuple] = {}  # key -> (value, expires_at)
        self._cache_ttl = 10  # seconds
        
        self._ensure_bucket()
    
    def _ensure_bucket(self):
        """Create bucket if not exists"""
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except S3Error as e:
            print(f"MinIO bucket error: {e}")
    
    # ==================== CACHE LAYER ====================
    
    def _cache_get(self, key: str) -> Optional[Any]:
        """Get from cache if not expired"""
        if key in self._cache:
            value, expires_at = self._cache[key]
            if datetime.utcnow() < expires_at:
                return value
            del self._cache[key]
        return None
    
    def _cache_set(self, key: str, value: Any, ttl: int = None):
        """Set cache with TTL"""
        ttl = ttl or self._cache_ttl
        self._cache[key] = (value, datetime.utcnow() + timedelta(seconds=ttl))
    
    def _cache_delete(self, key: str):
        """Remove from cache"""
        self._cache.pop(key, None)
    
    # ==================== STORAGE OPERATIONS ====================
    
    def put(self, key: str, data: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """
        Store JSON data in MinIO.
        
        Args:
            key: Storage key (e.g., "task:abc123")
            data: Dictionary to store
            ttl: Time-to-live in seconds (stored as metadata, cleanup handled separately)
        """
        try:
            json_bytes = json.dumps(data).encode('utf-8')
            stream = BytesIO(json_bytes)
            
            metadata = {
                "created_at": datetime.utcnow().isoformat(),
            }
            if ttl:
                metadata["expires_at"] = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
            
            self.client.put_object(
                self.bucket,
                key,
                stream,
                len(json_bytes),
                content_type="application/json",
                metadata=metadata
            )
            
            # Update cache
            self._cache_set(key, data)
            return True
            
        except S3Error as e:
            print(f"MinIO put error: {e}")
            return False
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve JSON data from MinIO.
        Uses cache to reduce S3 operations.
        """
        # Check cache first
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        
        try:
            response = self.client.get_object(self.bucket, key)
            data = json.loads(response.read().decode('utf-8'))
            response.close()
            response.release_conn()
            
            # Cache the result
            self._cache_set(key, data)
            return data
            
        except S3Error as e:
            if e.code != "NoSuchKey":
                print(f"MinIO get error: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete object from MinIO"""
        try:
            self.client.remove_object(self.bucket, key)
            self._cache_delete(key)
            return True
        except S3Error as e:
            print(f"MinIO delete error: {e}")
            return False
    
    def list_keys(self, prefix: str) -> List[str]:
        """List all keys with prefix"""
        try:
            objects = self.client.list_objects(self.bucket, prefix=prefix)
            return [obj.object_name for obj in objects]
        except S3Error as e:
            print(f"MinIO list error: {e}")
            return []
    
    # ==================== BATCH OPERATIONS ====================
    
    def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple objects at once (with caching)"""
        result = {}
        keys_to_fetch = []
        
        # Check cache first
        for key in keys:
            cached = self._cache_get(key)
            if cached is not None:
                result[key] = cached
            else:
                keys_to_fetch.append(key)
        
        # Fetch remaining from MinIO
        for key in keys_to_fetch:
            data = self.get(key)
            if data:
                result[key] = data
        
        return result
    
    # ==================== CLEANUP ====================
    
    async def cleanup_expired(self):
        """Remove expired objects (run periodically)"""
        now = datetime.utcnow()
        try:
            for prefix in ["completed:", "worker:"]:
                objects = self.client.list_objects(self.bucket, prefix=prefix)
                for obj in objects:
                    stat = self.client.stat_object(self.bucket, obj.object_name)
                    expires_at = stat.metadata.get("x-amz-meta-expires_at")
                    if expires_at:
                        expire_time = datetime.fromisoformat(expires_at)
                        if now > expire_time:
                            self.delete(obj.object_name)
        except S3Error as e:
            print(f"Cleanup error: {e}")


# Singleton instance
@lru_cache(maxsize=1)
def get_minio_storage() -> MinioStorageService:
    return MinioStorageService()
```

#### 1.2 Оновити Task Queue для MinIO

Файл: `src/services/task_queue_minio.py`

```python
"""
Task Queue Service using MinIO storage
Replaces in-memory queue with persistent MinIO-backed storage
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from src.services.minio_storage import get_minio_storage


class TaskQueueMinio:
    """
    Persistent task queue backed by MinIO storage.
    Optimized to minimize storage operations.
    """
    
    QUEUE_KEY = "queue:pending"
    
    def __init__(self):
        self.storage = get_minio_storage()
        # In-memory queue cache (primary source, synced to MinIO)
        self._queue_cache: Optional[List[Dict]] = None
        self._queue_dirty = False
    
    # ==================== QUEUE OPERATIONS ====================
    
    def _load_queue(self) -> List[Dict]:
        """Load queue from storage (with caching)"""
        if self._queue_cache is not None:
            return self._queue_cache
        
        data = self.storage.get(self.QUEUE_KEY)
        self._queue_cache = data if data else []
        return self._queue_cache
    
    def _save_queue(self):
        """Save queue to storage (batched)"""
        if self._queue_cache is not None:
            self.storage.put(self.QUEUE_KEY, self._queue_cache)
            self._queue_dirty = False
    
    def _mark_dirty(self):
        """Mark queue as needing sync"""
        self._queue_dirty = True
    
    def sync(self):
        """Sync queue to storage if dirty"""
        if self._queue_dirty:
            self._save_queue()
    
    # ==================== TASK OPERATIONS ====================
    
    def create_task(self, task_data: Dict[str, Any]) -> str:
        """Create a new task"""
        task_id = str(uuid.uuid4())
        
        task = {
            "id": task_id,
            "role": task_data.get("role", "archivist"),
            "task_type": task_data.get("task_type"),
            "input_data": task_data.get("input_data", {}),
            "priority": task_data.get("priority", 5),
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "project_id": task_data.get("project_id", "default"),
            "context_enabled": task_data.get("context_enabled", True),
            "context_limit": task_data.get("context_limit", 10),
        }
        
        # Save task
        self.storage.put(f"task:{task_id}", task)
        
        # Add to queue (with metadata for filtering)
        queue = self._load_queue()
        queue.append({
            "id": task_id,
            "priority": task["priority"],
            "created_at": task["created_at"],
            "role": task["role"],
            "status": "pending"
        })
        
        # Sort by priority (desc) then created_at (asc)
        queue.sort(key=lambda x: (-x["priority"], x["created_at"]))
        self._queue_cache = queue
        self._save_queue()  # Immediate save for new tasks
        
        return task_id
    
    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task by ID"""
        return self.storage.get(f"task:{task_id}")
    
    def get_next_task(self, worker_id: str, roles: List[str] = None) -> Optional[Dict[str, Any]]:
        """Get and assign next pending task for worker"""
        queue = self._load_queue()
        
        for i, item in enumerate(queue):
            if item.get("status") != "pending":
                continue
            if roles and item.get("role") not in roles:
                continue
            
            # Get full task
            task = self.get_task(item["id"])
            if not task or task.get("status") != "pending":
                continue
            
            # Assign task
            task["status"] = "processing"
            task["assigned_to"] = worker_id
            task["assigned_at"] = datetime.utcnow().isoformat()
            task["updated_at"] = datetime.utcnow().isoformat()
            self.storage.put(f"task:{item['id']}", task)
            
            # Remove from queue
            queue.pop(i)
            self._queue_cache = queue
            self._save_queue()
            
            return task
        
        return None
    
    def complete_task(self, task_id: str, result: Any, status: str = "completed", 
                      observation_id: str = None) -> bool:
        """Mark task as completed"""
        task = self.get_task(task_id)
        if not task:
            return False
        
        task["status"] = status
        task["result"] = result
        task["completed_at"] = datetime.utcnow().isoformat()
        task["updated_at"] = datetime.utcnow().isoformat()
        if observation_id:
            task["observation_id"] = observation_id
        
        # Save task
        self.storage.put(f"task:{task_id}", task)
        
        # Save to completed history (with TTL metadata)
        self.storage.put(f"completed:{task_id}", task, ttl=86400 * 7)  # 7 days
        
        return True
    
    def list_pending_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List pending tasks (queue metadata only, no full task fetch)"""
        queue = self._load_queue()
        return queue[:limit]
    
    def list_tasks_full(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List pending tasks with full data"""
        queue = self._load_queue()
        task_ids = [f"task:{item['id']}" for item in queue[:limit]]
        tasks_data = self.storage.get_many(task_ids)
        return [tasks_data.get(f"task:{item['id']}") for item in queue[:limit] 
                if tasks_data.get(f"task:{item['id']}")]
    
    # ==================== WORKER OPERATIONS ====================
    
    def register_worker(self, worker_id: str, capabilities: List[str] = None) -> bool:
        """Register a worker"""
        worker = {
            "worker_id": worker_id,
            "capabilities": capabilities or [],
            "registered_at": datetime.utcnow().isoformat(),
            "last_heartbeat": datetime.utcnow().isoformat(),
            "status": "active",
        }
        return self.storage.put(f"worker:{worker_id}", worker, ttl=600)  # 10 min TTL
    
    def worker_heartbeat(self, worker_id: str) -> bool:
        """Update worker heartbeat"""
        worker = self.storage.get(f"worker:{worker_id}")
        if worker:
            worker["last_heartbeat"] = datetime.utcnow().isoformat()
            return self.storage.put(f"worker:{worker_id}", worker, ttl=600)
        return False
    
    def list_workers(self) -> List[Dict[str, Any]]:
        """List active workers"""
        worker_keys = self.storage.list_keys("worker:")
        workers_data = self.storage.get_many(worker_keys)
        return list(workers_data.values())
    
    # ==================== STATS ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        queue = self._load_queue()
        workers = self.list_workers()
        
        return {
            "pending_tasks": len(queue),
            "active_workers": len(workers),
            "version": "3.0-minio",
            "storage": "minio",
            "claude_mem_enabled": True,
        }


# Singleton
_task_queue_instance: Optional[TaskQueueMinio] = None

def get_task_queue() -> TaskQueueMinio:
    global _task_queue_instance
    if _task_queue_instance is None:
        _task_queue_instance = TaskQueueMinio()
    return _task_queue_instance
```

### Phase 2: Оновити FastAPI endpoints

#### 2.1 Новий main.py з MinIO

Файл: `src/main_minio.py`

```python
"""
Garden AI Orchestrator - FastAPI with MinIO Storage
Replaces Cloudflare Worker to avoid KV limits
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
import asyncio

from src.services.task_queue_minio import get_task_queue


# ==================== MODELS ====================

class TaskCreate(BaseModel):
    role: str = "archivist"
    task_type: str
    input_data: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 5
    project_id: str = "default"
    context_enabled: bool = True
    context_limit: int = 10

class TaskComplete(BaseModel):
    task_id: str
    result: Any = None
    status: str = "completed"
    observation_id: Optional[str] = None

class WorkerRegister(BaseModel):
    worker_id: str
    capabilities: List[str] = Field(default_factory=list)

class WorkerHeartbeat(BaseModel):
    worker_id: str


# ==================== APP ====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: periodic cleanup task
    async def cleanup_loop():
        while True:
            await asyncio.sleep(3600)  # Every hour
            await get_task_queue().storage.cleanup_expired()
    
    task = asyncio.create_task(cleanup_loop())
    yield
    task.cancel()


app = FastAPI(
    title="Garden AI Orchestrator",
    version="3.0-minio",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== ENDPOINTS ====================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "garden-orchestrator",
        "version": "3.0-minio",
        "storage": "minio"
    }


@app.get("/stats")
async def stats():
    return get_task_queue().get_stats()


# ---- Task endpoints ----

@app.post("/tasks")
async def create_task(task: TaskCreate):
    task_id = get_task_queue().create_task(task.model_dump())
    return {"task_id": task_id, "status": "created"}


@app.get("/tasks/{task_id}")
async def get_task(task_id: str):
    task = get_task_queue().get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    return task


@app.get("/tasks")
async def list_tasks():
    tasks = get_task_queue().list_tasks_full()
    return {"tasks": tasks}


# ---- Polling endpoints (for RPi) ----

@app.post("/poll/register")
async def register_worker(data: WorkerRegister):
    get_task_queue().register_worker(data.worker_id, data.capabilities)
    return {"status": "registered", "worker_id": data.worker_id}


@app.post("/poll/heartbeat")
async def worker_heartbeat(data: WorkerHeartbeat):
    success = get_task_queue().worker_heartbeat(data.worker_id)
    return {"status": "ok" if success else "not_found"}


@app.get("/poll/next")
async def get_next_task(worker_id: str, roles: str = ""):
    roles_list = [r.strip() for r in roles.split(",") if r.strip()] if roles else None
    task = get_task_queue().get_next_task(worker_id, roles_list)
    
    if task:
        return {"task": task}
    return {
        "task": None, 
        "message": "No tasks available",
        "retry_after": 30  # Hint for client to wait
    }


@app.post("/poll/complete")
async def complete_task(data: TaskComplete):
    success = get_task_queue().complete_task(
        data.task_id, 
        data.result, 
        data.status,
        data.observation_id
    )
    if not success:
        raise HTTPException(404, "Task not found")
    return {"status": "completed", "task_id": data.task_id}


@app.get("/poll/workers")
async def list_workers():
    workers = get_task_queue().list_workers()
    return {"workers": workers}


# ==================== RUN ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
```

### Phase 3: Конфігурація

#### 3.1 Environment variables

Файл: `.env.example` (оновити)

```bash
# MinIO Configuration (S3-compatible)
MINIO_ENDPOINT=https://apiminio.exodus.pp.ua
MINIO_ACCESS_KEY=your_access_key
MINIO_SECRET_KEY=your_secret_key
MINIO_SECURE=true
MINIO_BUCKET=garden-orchestrator

# Alternative: Use existing MinIO from your infrastructure
# MINIO_ENDPOINT=minio.exodus.pp.ua

# Claude-Mem (unchanged)
CLAUDE_MEM_ENABLED=true
CLAUDE_MEM_DB_PATH=~/.claude-mem/claude-mem.db
CLAUDE_MEM_CONTEXT_LIMIT=10

# FastAPI
PORT=5000
HOST=0.0.0.0
```

#### 3.2 Оновити requirements.txt

```txt
fastapi>=0.100.0
uvicorn>=0.23.0
pydantic>=2.0.0
pydantic-settings>=2.0.0
httpx>=0.24.0
numpy>=1.24.0
python-multipart>=0.0.6
minio>=7.2.0
```

---

## 🔧 ОПТИМІЗАЦІЇ (ВАЖЛИВО!)

### 1. Зменшення операцій запису

| Операція | Було (CF KV) | Стало (MinIO + cache) |
|----------|--------------|----------------------|
| Create task | 2 writes (task + queue) | 2 writes (batched) |
| Get next task | 2 writes + N reads | 1 read (cached queue) + 2 writes |
| Heartbeat | 1 write кожні 5 сек | 1 write кожні 30-60 сек |
| List tasks | N reads | 1 read (cached) |

### 2. RPi Worker polling

**Оновити** `worker.py` на RPi:

```python
# Було
POLL_INTERVAL = 5  # секунд

# Стало
POLL_INTERVAL = 30  # секунд (або 60 якщо немає активних завдань)
POLL_INTERVAL_IDLE = 60  # якщо немає завдань
```

### 3. In-memory cache

- Queue кешується в пам'яті, синхронізується з MinIO лише при змінах
- Завдання кешуються на 10 секунд
- Workers кешуються на 30 секунд

---

## 📊 ПОРІВНЯННЯ

| Метрика | Cloudflare KV (Free) | MinIO (Self-hosted) |
|---------|---------------------|---------------------|
| Write limit | 1000/day | ∞ (unlimited) |
| Read limit | 100,000/day | ∞ (unlimited) |
| Storage | 1GB | Your disk |
| Latency | ~50ms (edge) | ~10ms (local) |
| Cost | Free → $5+/mo | Free (self-hosted) |

---

## ✅ CHECKLIST

### Phase 1: Storage
- [ ] Встановити `minio` package
- [ ] Створити `src/services/minio_storage.py`
- [ ] Налаштувати MinIO bucket `garden-orchestrator`
- [ ] Протестувати CRUD операції

### Phase 2: Task Queue
- [ ] Створити `src/services/task_queue_minio.py`
- [ ] Імплементувати кешування черги
- [ ] Протестувати create/get/complete flow

### Phase 3: API
- [ ] Оновити `src/main.py` або створити `src/main_minio.py`
- [ ] Додати CORS middleware
- [ ] Протестувати всі endpoints

### Phase 4: Migration
- [ ] Зупинити Cloudflare Worker
- [ ] Оновити RPi Worker URL на Replit
- [ ] Оновити Lovable Frontend URL
- [ ] Протестувати end-to-end

### Phase 5: Cleanup
- [ ] Видалити стару логіку CF KV
- [ ] Оновити документацію
- [ ] Моніторинг MinIO usage

---

## 🚀 КОМАНДИ ТЕСТУВАННЯ

```bash
# Health check
curl http://localhost:5000/health

# Stats
curl http://localhost:5000/stats

# Create task
curl -X POST http://localhost:5000/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "role": "archivist",
    "task_type": "summarize",
    "input_data": {"text": "Test task"},
    "project_id": "test"
  }'

# Get next task (as worker)
curl "http://localhost:5000/poll/next?worker_id=test-worker&roles=archivist"

# Complete task
curl -X POST http://localhost:5000/poll/complete \
  -H "Content-Type: application/json" \
  -d '{"task_id": "YOUR_TASK_ID", "result": {"output": "Done"}}'
```

---

## 📝 NOTES

- MinIO має бути доступний з Replit (публічний endpoint або VPN)
- Якщо MinIO на exodus.pp.ua, переконайся що порт 9000 відкритий
- Альтернатива: використати Supabase Storage або R2 (Cloudflare S3-compatible)
- При переході - зроби backup поточних завдань з CF KV

---

**Автор**: Lovable AI Agent
**Для**: Replit Agent
**Проєкт**: Garden-Agent-Service
