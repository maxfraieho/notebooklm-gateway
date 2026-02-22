# 🚀 Replit Agent Task: Migrate Garden MCP Server to FastAPI + MinIO

## 📋 Мета

Перенести **garden-mcp-server** з Cloudflare Worker + KV на **FastAPI** + **MinIO** (S3-compatible storage).

Це розблокує створення Access Zones та посилань, бо KV ліміти більше не діють.

---

## 🏗️ Поточна архітектура (Cloudflare Worker)

```
┌─────────────────────────────────────────────────────────────┐
│  garden-mcp-server.maxfraieho.workers.dev                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  Cloudflare Worker (index.js ~1600 lines)               ││
│  │  ├── /health                                            ││
│  │  ├── /auth/* (setup, login, status, refresh)            ││
│  │  ├── /zones/* (create, list, validate, delete)          ││
│  │  ├── /comments/:slug (GET, POST)                        ││
│  │  ├── /annotations/:slug (GET, POST)                     ││
│  │  └── /mcp/:zoneId (JSON-RPC + SSE transport)            ││
│  └─────────────────────────────────────────────────────────┘│
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────┐    ┌──────────────┐                      │
│  │ Cloudflare KV│    │    MinIO     │                      │
│  │ (sessions,   │    │ (note content│                      │
│  │  zones, auth)│    │  backup)     │                      │
│  └──────────────┘    └──────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Цільова архітектура (Replit FastAPI)

```
┌─────────────────────────────────────────────────────────────┐
│  Replit FastAPI Service                                     │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  main.py (FastAPI + SSE support)                        ││
│  │  ├── /health                                            ││
│  │  ├── /auth/* (setup, login, status, refresh)            ││
│  │  ├── /zones/* (create, list, validate, delete)          ││
│  │  ├── /comments/:slug (GET, POST)                        ││
│  │  ├── /annotations/:slug (GET, POST)                     ││
│  │  └── /mcp/:zoneId (JSON-RPC + SSE transport)            ││
│  └─────────────────────────────────────────────────────────┘│
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐
│  │                      MinIO                               │
│  │  Bucket: garden-mcp                                      │
│  │  ├── auth/config.json (owner_initialized, password_hash) │
│  │  ├── sessions/{session_id}.json                          │
│  │  ├── zones/index.json (list of zone IDs)                 │
│  │  ├── zones/{zone_id}.json (zone data)                    │
│  │  ├── zones/{zone_id}/notes.jsonl (zone notes content)    │
│  │  ├── comments/{slug_encoded}.json                        │
│  │  └── annotations/{slug_encoded}.json                     │
│  └──────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 MinIO Configuration

```bash
# MinIO Server
MINIO_ENDPOINT=https://apiminio.exodus.pp.ua
MINIO_ACCESS_KEY=<your_access_key>
MINIO_SECRET_KEY=<your_secret_key>
MINIO_BUCKET=garden-mcp
MINIO_SECURE=true

# JWT Secret (same as Cloudflare Worker)
JWT_SECRET=<your_jwt_secret>
```

---

## 📁 Project Structure

```
garden-mcp-server/
├── main.py                    # FastAPI app with all endpoints
├── services/
│   ├── minio_storage.py       # MinIO S3 operations with caching
│   ├── auth_service.py        # Owner authentication
│   ├── zones_service.py       # Access zones management
│   ├── comments_service.py    # Comments CRUD
│   ├── annotations_service.py # Annotations CRUD
│   └── mcp_service.py         # MCP JSON-RPC + SSE
├── models/
│   ├── auth.py                # Auth models
│   ├── zones.py               # Zone models
│   ├── comments.py            # Comment models
│   ├── annotations.py         # Annotation models
│   └── mcp.py                 # MCP protocol models
├── utils/
│   ├── jwt_utils.py           # JWT generation/verification
│   └── helpers.py             # Common helpers
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🔧 Phase 1: Core Infrastructure

### 1.1 MinIO Storage Service

**File: `services/minio_storage.py`**

```python
"""
MinIO Storage Service with in-memory caching
Replaces Cloudflare KV functionality
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Any, List, Dict
from minio import Minio
from minio.error import S3Error
import os
from functools import lru_cache
import asyncio

class MinioStorageService:
    def __init__(self):
        endpoint = os.getenv("MINIO_ENDPOINT", "").replace("https://", "").replace("http://", "")
        self.client = Minio(
            endpoint,
            access_key=os.getenv("MINIO_ACCESS_KEY"),
            secret_key=os.getenv("MINIO_SECRET_KEY"),
            secure=os.getenv("MINIO_SECURE", "true").lower() == "true"
        )
        self.bucket = os.getenv("MINIO_BUCKET", "garden-mcp")
        self._cache: Dict[str, tuple[Any, datetime]] = {}
        self._cache_ttl = timedelta(minutes=5)
        self._ensure_bucket()
    
    def _ensure_bucket(self):
        """Create bucket if not exists"""
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except S3Error as e:
            print(f"[MinIO] Bucket error: {e}")
    
    def _cache_key(self, path: str) -> str:
        return f"{self.bucket}:{path}"
    
    def _is_cache_valid(self, key: str) -> bool:
        if key not in self._cache:
            return False
        _, cached_at = self._cache[key]
        return datetime.now() - cached_at < self._cache_ttl
    
    async def get(self, path: str, default: Any = None) -> Any:
        """Get JSON object from MinIO with caching"""
        cache_key = self._cache_key(path)
        
        # Check cache first
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key][0]
        
        try:
            response = self.client.get_object(self.bucket, path)
            data = json.loads(response.read().decode('utf-8'))
            response.close()
            response.release_conn()
            
            # Update cache
            self._cache[cache_key] = (data, datetime.now())
            return data
        except S3Error as e:
            if e.code == "NoSuchKey":
                return default
            raise
    
    async def put(self, path: str, data: Any, content_type: str = "application/json"):
        """Store JSON object in MinIO"""
        content = json.dumps(data, ensure_ascii=False, indent=2)
        content_bytes = content.encode('utf-8')
        
        from io import BytesIO
        self.client.put_object(
            self.bucket,
            path,
            BytesIO(content_bytes),
            len(content_bytes),
            content_type=content_type
        )
        
        # Invalidate cache
        cache_key = self._cache_key(path)
        if cache_key in self._cache:
            del self._cache[cache_key]
    
    async def delete(self, path: str):
        """Delete object from MinIO"""
        try:
            self.client.remove_object(self.bucket, path)
            
            # Invalidate cache
            cache_key = self._cache_key(path)
            if cache_key in self._cache:
                del self._cache[cache_key]
        except S3Error as e:
            if e.code != "NoSuchKey":
                raise
    
    async def list_objects(self, prefix: str) -> List[str]:
        """List objects with prefix"""
        objects = self.client.list_objects(self.bucket, prefix=prefix)
        return [obj.object_name for obj in objects]
    
    async def exists(self, path: str) -> bool:
        """Check if object exists"""
        try:
            self.client.stat_object(self.bucket, path)
            return True
        except S3Error:
            return False

# Singleton instance
_storage: Optional[MinioStorageService] = None

def get_storage() -> MinioStorageService:
    global _storage
    if _storage is None:
        _storage = MinioStorageService()
    return _storage
```

### 1.2 JWT Utilities

**File: `utils/jwt_utils.py`**

```python
"""
JWT utilities - compatible with Cloudflare Worker implementation
"""

import hmac
import hashlib
import base64
import json
import time
import os
from typing import Optional, Dict, Any

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
DEFAULT_TTL_MS = 86400000  # 24 hours

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def generate_jwt(payload: Dict[str, Any], ttl_ms: int = DEFAULT_TTL_MS) -> str:
    """Generate JWT token compatible with Cloudflare Worker"""
    now = int(time.time() * 1000)  # milliseconds
    
    full_payload = {
        **payload,
        "iat": now,
        "exp": now + ttl_ms
    }
    
    header = {"alg": "HS256", "typ": "JWT"}
    
    header_b64 = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(full_payload).encode('utf-8'))
    
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        JWT_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token and return payload if valid"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            JWT_SECRET.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        actual_sig = base64url_decode(signature_b64)
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        
        # Decode payload
        payload = json.loads(base64url_decode(payload_b64).decode('utf-8'))
        
        # Check expiration (milliseconds)
        now = int(time.time() * 1000)
        if payload.get("exp", 0) < now:
            return None
        
        return payload
    except Exception:
        return None

def hash_password(password: str) -> str:
    """Hash password with secret (compatible with Worker)"""
    data = (password + JWT_SECRET).encode('utf-8')
    return hashlib.sha256(data).hexdigest()
```

---

## 🔧 Phase 2: Auth Service

**File: `services/auth_service.py`**

```python
"""
Owner Authentication Service
Endpoints: /auth/status, /auth/setup, /auth/login, /auth/refresh
"""

from typing import Optional, Dict, Any
from services.minio_storage import get_storage
from utils.jwt_utils import generate_jwt, verify_jwt, hash_password

AUTH_CONFIG_PATH = "auth/config.json"

class AuthService:
    def __init__(self):
        self.storage = get_storage()
    
    async def get_status(self) -> Dict[str, Any]:
        """Check if owner is initialized"""
        config = await self.storage.get(AUTH_CONFIG_PATH, {})
        return {
            "success": True,
            "initialized": config.get("initialized", False)
        }
    
    async def setup(self, password: str) -> Dict[str, Any]:
        """Initial owner setup (one-time)"""
        config = await self.storage.get(AUTH_CONFIG_PATH, {})
        
        if config.get("initialized"):
            return {"success": False, "error": "Already initialized"}
        
        password_hash = hash_password(password)
        
        await self.storage.put(AUTH_CONFIG_PATH, {
            "initialized": True,
            "password_hash": password_hash
        })
        
        token = generate_jwt({"sub": "owner"})
        
        return {
            "success": True,
            "token": token
        }
    
    async def login(self, password: str) -> Dict[str, Any]:
        """Owner login"""
        config = await self.storage.get(AUTH_CONFIG_PATH, {})
        
        if not config.get("initialized"):
            return {"success": False, "error": "Not initialized"}
        
        password_hash = hash_password(password)
        
        if password_hash != config.get("password_hash"):
            return {"success": False, "error": "Invalid password"}
        
        token = generate_jwt({"sub": "owner"})
        
        return {
            "success": True,
            "token": token
        }
    
    async def refresh(self, token: str) -> Dict[str, Any]:
        """Refresh JWT token"""
        payload = verify_jwt(token)
        
        if not payload or payload.get("sub") != "owner":
            return {"success": False, "error": "Invalid token"}
        
        new_token = generate_jwt({"sub": "owner"})
        
        return {
            "success": True,
            "token": new_token
        }
    
    async def verify_owner(self, auth_header: Optional[str]) -> bool:
        """Verify owner from Authorization header"""
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        
        token = auth_header[7:]
        payload = verify_jwt(token)
        
        return payload is not None and payload.get("sub") == "owner"

# Singleton
_auth_service: Optional[AuthService] = None

def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
```

---

## 🔧 Phase 3: Zones Service

**File: `services/zones_service.py`**

```python
"""
Access Zones Service
Endpoints: /zones/create, /zones/list, /zones/validate/:id, DELETE /zones/:id
"""

import uuid
import secrets
import time
from typing import Optional, Dict, Any, List
from services.minio_storage import get_storage

ZONES_INDEX_PATH = "zones/index.json"

def generate_access_code() -> str:
    """Generate readable access code like ZONE-XXXX-YYYY"""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # No confusing chars
    part1 = ''.join(secrets.choice(chars) for _ in range(4))
    part2 = ''.join(secrets.choice(chars) for _ in range(4))
    return f"ZONE-{part1}-{part2}"

class ZonesService:
    def __init__(self):
        self.storage = get_storage()
    
    async def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new access zone"""
        zone_id = f"zone_{uuid.uuid4().hex[:12]}"
        access_code = generate_access_code()
        now = int(time.time() * 1000)
        ttl_minutes = data.get("ttlMinutes", 60)
        expires_at = now + (ttl_minutes * 60 * 1000)
        
        zone = {
            "id": zone_id,
            "name": data.get("name", "Unnamed Zone"),
            "description": data.get("description", ""),
            "allowedPaths": data.get("allowedPaths", []),
            "accessType": data.get("accessType", "both"),
            "accessCode": access_code,
            "createdAt": now,
            "expiresAt": expires_at,
            "noteCount": len(data.get("notes", []))
        }
        
        # Save zone data
        await self.storage.put(f"zones/{zone_id}.json", zone)
        
        # Save zone notes if provided
        if data.get("notes"):
            notes_content = "\n".join([
                f'{{"slug":"{n["slug"]}","title":"{n["title"]}","content":{repr(n["content"])},"tags":{n["tags"]}}}'
                for n in data["notes"]
            ])
            await self.storage.put(
                f"zones/{zone_id}/notes.jsonl", 
                notes_content,
                content_type="application/jsonl"
            )
        
        # Update index
        index = await self.storage.get(ZONES_INDEX_PATH, [])
        index.append(zone_id)
        await self.storage.put(ZONES_INDEX_PATH, index)
        
        return {
            "success": True,
            "zoneId": zone_id,
            "accessCode": access_code,
            "expiresAt": expires_at
        }
    
    async def list(self) -> Dict[str, Any]:
        """List all zones"""
        index = await self.storage.get(ZONES_INDEX_PATH, [])
        zones = []
        now = int(time.time() * 1000)
        
        for zone_id in index:
            zone = await self.storage.get(f"zones/{zone_id}.json")
            if zone:
                # Skip expired zones
                if zone.get("expiresAt", 0) > now:
                    zones.append(zone)
        
        return {"success": True, "zones": zones}
    
    async def validate(self, zone_id: str, code: Optional[str] = None) -> Dict[str, Any]:
        """Validate zone access"""
        zone = await self.storage.get(f"zones/{zone_id}.json")
        
        if not zone:
            return {"success": False, "error": "Zone not found", "status": 404}
        
        now = int(time.time() * 1000)
        
        if zone.get("expiresAt", 0) < now:
            return {"success": False, "error": "Zone expired", "expired": True, "status": 410}
        
        # Check access code for web access
        if zone.get("accessType") in ["web", "both"]:
            if code and code != zone.get("accessCode"):
                return {"success": False, "error": "Invalid access code", "status": 403}
        
        return {
            "success": True,
            "valid": True,
            "zone": {
                "id": zone["id"],
                "name": zone["name"],
                "description": zone.get("description", ""),
                "allowedPaths": zone.get("allowedPaths", []),
                "accessType": zone.get("accessType"),
                "expiresAt": zone.get("expiresAt"),
                "noteCount": zone.get("noteCount", 0)
            }
        }
    
    async def delete(self, zone_id: str) -> Dict[str, Any]:
        """Delete/revoke zone"""
        zone = await self.storage.get(f"zones/{zone_id}.json")
        
        if not zone:
            return {"success": False, "error": "Zone not found"}
        
        # Delete zone data
        await self.storage.delete(f"zones/{zone_id}.json")
        await self.storage.delete(f"zones/{zone_id}/notes.jsonl")
        
        # Update index
        index = await self.storage.get(ZONES_INDEX_PATH, [])
        index = [z for z in index if z != zone_id]
        await self.storage.put(ZONES_INDEX_PATH, index)
        
        return {"success": True}
    
    async def get_zone_notes(self, zone_id: str) -> List[Dict[str, Any]]:
        """Get notes for a zone (for MCP)"""
        import json
        content = await self.storage.get(f"zones/{zone_id}/notes.jsonl", "")
        if not content:
            return []
        
        notes = []
        for line in content.strip().split("\n"):
            if line:
                try:
                    notes.append(json.loads(line))
                except:
                    pass
        return notes

# Singleton
_zones_service: Optional[ZonesService] = None

def get_zones_service() -> ZonesService:
    global _zones_service
    if _zones_service is None:
        _zones_service = ZonesService()
    return _zones_service
```

---

## 🔧 Phase 4: Comments & Annotations Services

**File: `services/comments_service.py`**

```python
"""
Comments Service
Endpoints: GET/POST /comments/:slug
"""

import uuid
import time
import urllib.parse
from typing import Optional, Dict, Any, List
from services.minio_storage import get_storage

class CommentsService:
    def __init__(self):
        self.storage = get_storage()
    
    def _path(self, slug: str) -> str:
        encoded = urllib.parse.quote(slug, safe='')
        return f"comments/{encoded}.json"
    
    async def get(self, slug: str, is_owner: bool = False) -> Dict[str, Any]:
        """Get comments for article"""
        data = await self.storage.get(self._path(slug), {"comments": []})
        comments = data.get("comments", [])
        
        # Filter pending comments for non-owners
        if not is_owner:
            comments = [c for c in comments if c.get("status") != "pending"]
        
        return {"success": True, "comments": comments}
    
    async def create(
        self, 
        slug: str, 
        content: str, 
        is_owner: bool = False,
        parent_id: Optional[str] = None,
        author_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create new comment"""
        data = await self.storage.get(self._path(slug), {"comments": []})
        comments = data.get("comments", [])
        
        comment = {
            "id": f"comment_{uuid.uuid4().hex[:12]}",
            "slug": slug,
            "content": content,
            "authorName": author_name or ("Garden Owner" if is_owner else "Anonymous"),
            "isOwner": is_owner,
            "parentId": parent_id,
            "status": "approved" if is_owner else "pending",
            "createdAt": int(time.time() * 1000)
        }
        
        comments.append(comment)
        await self.storage.put(self._path(slug), {"comments": comments})
        
        return {"success": True, "comment": comment}
    
    async def update_status(
        self, 
        slug: str, 
        comment_id: str, 
        status: str
    ) -> Dict[str, Any]:
        """Update comment status (approve/reject)"""
        data = await self.storage.get(self._path(slug), {"comments": []})
        comments = data.get("comments", [])
        
        for comment in comments:
            if comment["id"] == comment_id:
                comment["status"] = status
                break
        
        await self.storage.put(self._path(slug), {"comments": comments})
        
        return {"success": True}

# Singleton
_comments_service: Optional[CommentsService] = None

def get_comments_service() -> CommentsService:
    global _comments_service
    if _comments_service is None:
        _comments_service = CommentsService()
    return _comments_service
```

**File: `services/annotations_service.py`**

```python
"""
Annotations Service
Endpoints: GET/POST /annotations/:slug
"""

import uuid
import time
import urllib.parse
from typing import Optional, Dict, Any, List
from services.minio_storage import get_storage

class AnnotationsService:
    def __init__(self):
        self.storage = get_storage()
    
    def _path(self, slug: str) -> str:
        encoded = urllib.parse.quote(slug, safe='')
        return f"annotations/{encoded}.json"
    
    async def get(self, slug: str, is_owner: bool = False) -> Dict[str, Any]:
        """Get annotations for article"""
        data = await self.storage.get(self._path(slug), {"annotations": [], "comments": []})
        annotations = data.get("annotations", [])
        comments = data.get("comments", [])
        
        # Filter pending for non-owners
        if not is_owner:
            annotations = [a for a in annotations if a.get("status") != "pending"]
            comments = [c for c in comments if c.get("status") != "pending"]
        
        return {"success": True, "annotations": annotations, "comments": comments}
    
    async def create(
        self, 
        slug: str, 
        highlighted_text: str,
        start_offset: int,
        end_offset: int,
        paragraph_index: int,
        comment_content: str,
        is_owner: bool = False,
        author_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create annotation with linked comment"""
        data = await self.storage.get(self._path(slug), {"annotations": [], "comments": []})
        annotations = data.get("annotations", [])
        comments = data.get("comments", [])
        
        annotation_id = f"ann_{uuid.uuid4().hex[:12]}"
        comment_id = f"comment_{uuid.uuid4().hex[:12]}"
        now = int(time.time() * 1000)
        
        annotation = {
            "id": annotation_id,
            "slug": slug,
            "highlightedText": highlighted_text,
            "startOffset": start_offset,
            "endOffset": end_offset,
            "paragraphIndex": paragraph_index,
            "linkedCommentId": comment_id,
            "status": "approved" if is_owner else "pending",
            "createdAt": now
        }
        
        comment = {
            "id": comment_id,
            "annotationId": annotation_id,
            "slug": slug,
            "content": comment_content,
            "authorName": author_name or ("Garden Owner" if is_owner else "Anonymous"),
            "isOwner": is_owner,
            "status": "approved" if is_owner else "pending",
            "createdAt": now
        }
        
        annotations.append(annotation)
        comments.append(comment)
        
        await self.storage.put(self._path(slug), {
            "annotations": annotations,
            "comments": comments
        })
        
        return {"success": True, "annotation": annotation, "comment": comment}

# Singleton
_annotations_service: Optional[AnnotationsService] = None

def get_annotations_service() -> AnnotationsService:
    global _annotations_service
    if _annotations_service is None:
        _annotations_service = AnnotationsService()
    return _annotations_service
```

---

## 🔧 Phase 5: MCP Service (JSON-RPC + SSE)

**File: `services/mcp_service.py`**

```python
"""
MCP Protocol Service
Implements JSON-RPC 2.0 over SSE transport
Endpoint: /mcp/:zoneId
"""

import json
import asyncio
from typing import Optional, Dict, Any, List, AsyncGenerator
from services.zones_service import get_zones_service

class MCPService:
    def __init__(self):
        self.zones = get_zones_service()
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Return available MCP tools"""
        return [
            {
                "name": "search_notes",
                "description": "Search notes by title, content, or tags",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "limit": {"type": "number", "description": "Max results"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "get_note",
                "description": "Get a specific note by slug",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "slug": {"type": "string", "description": "Note slug/path"}
                    },
                    "required": ["slug"]
                }
            },
            {
                "name": "list_notes",
                "description": "List all available notes",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "folder": {"type": "string"},
                        "limit": {"type": "number"}
                    }
                }
            },
            {
                "name": "get_tags",
                "description": "Get all tags with note counts",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    
    async def handle_tool_call(
        self, 
        tool_name: str, 
        arguments: Dict[str, Any],
        notes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute MCP tool"""
        
        if tool_name == "search_notes":
            query = arguments.get("query", "").lower()
            filter_tags = arguments.get("tags", [])
            limit = arguments.get("limit", 10)
            
            results = []
            for note in notes:
                matches_query = (
                    query in note.get("title", "").lower() or
                    query in note.get("content", "").lower()
                )
                matches_tags = (
                    not filter_tags or
                    any(tag in note.get("tags", []) for tag in filter_tags)
                )
                if matches_query and matches_tags:
                    results.append({
                        "slug": note["slug"],
                        "title": note["title"],
                        "tags": note.get("tags", []),
                        "preview": note.get("content", "")[:200]
                    })
                    if len(results) >= limit:
                        break
            
            return {"content": [{"type": "text", "text": json.dumps(results, indent=2)}]}
        
        elif tool_name == "get_note":
            slug = arguments.get("slug", "")
            note = next(
                (n for n in notes if n["slug"] == slug or n["slug"].endswith(f"/{slug}")),
                None
            )
            if not note:
                return {"content": [{"type": "text", "text": f"Note not found: {slug}"}]}
            return {"content": [{"type": "text", "text": json.dumps(note, indent=2)}]}
        
        elif tool_name == "list_notes":
            folder = arguments.get("folder", "")
            limit = arguments.get("limit", 50)
            
            results = [
                {"slug": n["slug"], "title": n["title"], "tags": n.get("tags", [])}
                for n in notes
                if not folder or n["slug"].startswith(folder)
            ][:limit]
            
            return {"content": [{"type": "text", "text": json.dumps(results, indent=2)}]}
        
        elif tool_name == "get_tags":
            tag_counts = {}
            for note in notes:
                for tag in note.get("tags", []):
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            return {"content": [{"type": "text", "text": json.dumps(tag_counts, indent=2)}]}
        
        return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}]}
    
    def create_jsonrpc_response(self, id: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": id or 0, "result": result}
    
    def create_jsonrpc_error(self, id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": id or 0, "error": {"code": code, "message": message}}
    
    async def handle_jsonrpc(
        self, 
        request: Dict[str, Any],
        zone_id: str
    ) -> Dict[str, Any]:
        """Handle MCP JSON-RPC request"""
        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")
        
        # Validate zone
        zone_result = await self.zones.validate(zone_id)
        if not zone_result.get("success"):
            return self.create_jsonrpc_error(req_id, -32001, "Invalid zone")
        
        # Get zone notes
        notes = await self.zones.get_zone_notes(zone_id)
        
        if method == "initialize":
            return self.create_jsonrpc_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False}
                },
                "serverInfo": {
                    "name": "garden-mcp-server",
                    "version": "3.0.0"
                }
            })
        
        elif method == "tools/list":
            return self.create_jsonrpc_response(req_id, {"tools": self.get_tools()})
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            result = await self.handle_tool_call(tool_name, arguments, notes)
            return self.create_jsonrpc_response(req_id, result)
        
        elif method == "resources/list":
            resources = [
                {
                    "uri": f"note:///{note['slug']}",
                    "name": note["title"],
                    "mimeType": "text/markdown"
                }
                for note in notes
            ]
            return self.create_jsonrpc_response(req_id, {"resources": resources})
        
        elif method == "resources/read":
            uri = params.get("uri", "")
            slug = uri.replace("note:///", "")
            note = next((n for n in notes if n["slug"] == slug), None)
            
            if not note:
                return self.create_jsonrpc_response(req_id, {"contents": []})
            
            return self.create_jsonrpc_response(req_id, {
                "contents": [{
                    "uri": uri,
                    "mimeType": "text/markdown",
                    "text": note.get("content", "")
                }]
            })
        
        return self.create_jsonrpc_error(req_id, -32601, f"Method not found: {method}")

# Singleton
_mcp_service: Optional[MCPService] = None

def get_mcp_service() -> MCPService:
    global _mcp_service
    if _mcp_service is None:
        _mcp_service = MCPService()
    return _mcp_service
```

---

## 🔧 Phase 6: FastAPI Main Application

**File: `main.py`**

```python
"""
Garden MCP Server - FastAPI Implementation
Replaces Cloudflare Worker with MinIO storage
"""

from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
import os

from services.auth_service import get_auth_service
from services.zones_service import get_zones_service
from services.comments_service import get_comments_service
from services.annotations_service import get_annotations_service
from services.mcp_service import get_mcp_service
from services.minio_storage import get_storage

app = FastAPI(title="Garden MCP Server", version="3.0.0")

# CORS - allow all origins for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# Health Check
# ============================================

@app.get("/health")
async def health():
    storage = get_storage()
    minio_ok = False
    try:
        await storage.exists("health-check")
        minio_ok = True
    except:
        pass
    
    return {
        "status": "ok",
        "version": "3.0.0",
        "minio_connected": minio_ok,
        "features": ["rest-api", "mcp-jsonrpc", "sse-transport", "minio-storage"],
        "runtime": "fastapi-replit"
    }

# ============================================
# Auth Endpoints
# ============================================

class AuthSetupRequest(BaseModel):
    password: str

class AuthLoginRequest(BaseModel):
    password: str

@app.post("/auth/status")
async def auth_status():
    auth = get_auth_service()
    return await auth.get_status()

@app.post("/auth/setup")
async def auth_setup(req: AuthSetupRequest):
    auth = get_auth_service()
    result = await auth.setup(req.password)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@app.post("/auth/login")
async def auth_login(req: AuthLoginRequest):
    auth = get_auth_service()
    result = await auth.login(req.password)
    if not result.get("success"):
        raise HTTPException(status_code=401, detail=result.get("error"))
    return result

@app.post("/auth/refresh")
async def auth_refresh(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    
    auth = get_auth_service()
    result = await auth.refresh(authorization[7:])
    if not result.get("success"):
        raise HTTPException(status_code=401, detail=result.get("error"))
    return result

# ============================================
# Zones Endpoints
# ============================================

class ZoneCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    allowedPaths: List[str] = []
    accessType: str = "both"
    ttlMinutes: int = 60
    notes: Optional[List[Dict[str, Any]]] = None

@app.post("/zones/create")
async def zones_create(req: ZoneCreateRequest, authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    if not await auth.verify_owner(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    zones = get_zones_service()
    return await zones.create(req.dict())

@app.get("/zones/list")
async def zones_list(authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    if not await auth.verify_owner(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    zones = get_zones_service()
    return await zones.list()

@app.get("/zones/validate/{zone_id}")
async def zones_validate(zone_id: str, code: Optional[str] = None):
    zones = get_zones_service()
    result = await zones.validate(zone_id, code)
    
    status = result.pop("status", 200)
    if status != 200:
        raise HTTPException(status_code=status, detail=result.get("error"))
    
    return result

@app.delete("/zones/{zone_id}")
async def zones_delete(zone_id: str, authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    if not await auth.verify_owner(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    zones = get_zones_service()
    result = await zones.delete(zone_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result

# ============================================
# Comments Endpoints
# ============================================

class CommentCreateRequest(BaseModel):
    content: str
    parentId: Optional[str] = None
    authorName: Optional[str] = None

@app.get("/comments/{slug:path}")
async def comments_get(slug: str, authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    is_owner = await auth.verify_owner(authorization)
    
    comments = get_comments_service()
    return await comments.get(slug, is_owner)

@app.post("/comments/{slug:path}")
async def comments_create(slug: str, req: CommentCreateRequest, authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    is_owner = await auth.verify_owner(authorization)
    
    comments = get_comments_service()
    return await comments.create(
        slug=slug,
        content=req.content,
        is_owner=is_owner,
        parent_id=req.parentId,
        author_name=req.authorName
    )

# ============================================
# Annotations Endpoints
# ============================================

class AnnotationCreateRequest(BaseModel):
    highlightedText: str
    startOffset: int
    endOffset: int
    paragraphIndex: int
    commentContent: str
    authorName: Optional[str] = None

@app.get("/annotations/{slug:path}")
async def annotations_get(slug: str, authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    is_owner = await auth.verify_owner(authorization)
    
    annotations = get_annotations_service()
    return await annotations.get(slug, is_owner)

@app.post("/annotations/{slug:path}")
async def annotations_create(slug: str, req: AnnotationCreateRequest, authorization: Optional[str] = Header(None)):
    auth = get_auth_service()
    is_owner = await auth.verify_owner(authorization)
    
    annotations = get_annotations_service()
    return await annotations.create(
        slug=slug,
        highlighted_text=req.highlightedText,
        start_offset=req.startOffset,
        end_offset=req.endOffset,
        paragraph_index=req.paragraphIndex,
        comment_content=req.commentContent,
        is_owner=is_owner,
        author_name=req.authorName
    )

# ============================================
# MCP Endpoints (JSON-RPC over HTTP + SSE)
# ============================================

@app.post("/mcp/{zone_id}")
async def mcp_jsonrpc(zone_id: str, request: Request):
    """Handle MCP JSON-RPC requests"""
    mcp = get_mcp_service()
    
    try:
        body = await request.json()
    except:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32700, "message": "Parse error"}},
            status_code=400
        )
    
    result = await mcp.handle_jsonrpc(body, zone_id)
    return JSONResponse(result)

@app.get("/mcp/{zone_id}/sse")
async def mcp_sse(zone_id: str):
    """SSE endpoint for MCP transport"""
    mcp = get_mcp_service()
    zones = get_zones_service()
    
    # Validate zone
    zone_result = await zones.validate(zone_id)
    if not zone_result.get("success"):
        raise HTTPException(status_code=404, detail="Zone not found")
    
    async def event_generator():
        # Send initial connection event
        yield f"event: open\ndata: {json.dumps({'type': 'open'})}\n\n"
        
        # Keep connection alive
        while True:
            await asyncio.sleep(30)
            yield f"event: ping\ndata: {json.dumps({'type': 'ping'})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# ============================================
# Run
# ============================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
```

---

## 📦 Requirements

**File: `requirements.txt`**

```
fastapi>=0.109.0
uvicorn>=0.27.0
minio>=7.2.0
python-dotenv>=1.0.0
pydantic>=2.5.0
```

---

## 🔧 Environment Configuration

**File: `.env.example`**

```bash
# MinIO Configuration
MINIO_ENDPOINT=apiminio.exodus.pp.ua
MINIO_ACCESS_KEY=your_access_key
MINIO_SECRET_KEY=your_secret_key
MINIO_BUCKET=garden-mcp
MINIO_SECURE=true

# JWT Secret (MUST match the one used in Cloudflare Worker for token compatibility)
JWT_SECRET=your_jwt_secret_here

# Server
PORT=8000
```

---

## ✅ Checklist

### Phase 1: Setup
- [ ] Create new Replit project (Python)
- [ ] Add files: main.py, services/*, utils/*, models/*
- [ ] Install dependencies from requirements.txt
- [ ] Configure .env with MinIO and JWT_SECRET

### Phase 2: Testing
- [ ] Test /health endpoint
- [ ] Test /auth/status, /auth/setup, /auth/login
- [ ] Test /zones/create, /zones/list, /zones/validate/:id
- [ ] Test /comments/:slug GET/POST
- [ ] Test /annotations/:slug GET/POST
- [ ] Test /mcp/:zoneId JSON-RPC

### Phase 3: Integration
- [ ] Update frontend VITE_MCP_GATEWAY_URL to new Replit URL
- [ ] Test full flow: login → create zone → validate → access notes

### Phase 4: Migration
- [ ] Copy JWT_SECRET from Cloudflare Worker secrets
- [ ] Migrate owner password (or ask user to re-setup)
- [ ] Verify existing tokens still work

---

## 🧪 Test Commands

```bash
# Health check
curl https://<replit-url>/health

# Auth status
curl -X POST https://<replit-url>/auth/status

# Login (after setup)
curl -X POST https://<replit-url>/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password":"your-password"}'

# Create zone (with token)
curl -X POST https://<replit-url>/zones/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"name":"Test Zone","ttlMinutes":60,"allowedPaths":["/"]}'

# List zones
curl https://<replit-url>/zones/list \
  -H "Authorization: Bearer <token>"

# Validate zone
curl "https://<replit-url>/zones/validate/zone_abc123?code=ZONE-XXXX-YYYY"

# MCP JSON-RPC
curl -X POST https://<replit-url>/mcp/zone_abc123 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

---

## 📝 Notes

1. **JWT Compatibility**: Use the SAME JWT_SECRET from Cloudflare Worker so existing tokens work
2. **MinIO Bucket**: Create `garden-mcp` bucket before first run
3. **Replit Sleep**: Free Replit will sleep after inactivity — first request may be slow
4. **Future Migration**: This same code can run on Oracle server with cloudflared tunnel

---

## 🔗 Frontend Update

After deployment, update in Lovable project:

```typescript
// src/hooks/useAccessZones.ts, useOwnerAuth.tsx, useComments.ts, useAnnotations.ts
// Change:
const MCP_GATEWAY_URL = import.meta.env.VITE_MCP_GATEWAY_URL || 'https://<new-replit-url>';
```

Or set environment variable:
```
VITE_MCP_GATEWAY_URL=https://<replit-url>
```
