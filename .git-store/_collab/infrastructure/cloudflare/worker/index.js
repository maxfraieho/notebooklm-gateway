// ============================================
// Garden MCP Worker v3.0 - Vanilla Cloudflare Workers
// NO EXTERNAL DEPENDENCIES - Pure ES2022 JavaScript
// ============================================

// ============================================
// Helper Functions
// ============================================

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Id, X-Zone-Id, X-Zone-Code, X-Correlation-Id',
      ...extraHeaders
    }
  });
}

function corsResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Id, X-Zone-Id, X-Zone-Code, X-Correlation-Id',
      'Access-Control-Max-Age': '86400'
    }
  });
}

// Backward-compatible error envelope.
// - Existing clients: still can read `error` as string.
// - UI-friendly additions: `errorCode`, `errorDetails`.
function errorResponse(message, status = 400, details = undefined, code = undefined) {
  const payload = { success: false, error: message };
  if (code) payload.errorCode = code;
  if (details !== undefined) payload.errorDetails = details;
  return jsonResponse(payload, status);
}

// ============================================
// JWT Utilities
// ============================================

async function generateJWT(payload, secret, ttlMs = 86400000) {
  const now = Date.now();
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + ttlMs,
  };
  
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const body = btoa(JSON.stringify(fullPayload))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(`${header}.${body}`));
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
  return `${header}.${body}.${signature}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [header, body, signature] = parts;
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const sigBytes = Uint8Array.from(
      atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0)
    );
    
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      encoder.encode(`${header}.${body}`)
    );
    
    if (!isValid) return null;
    
    const payload = JSON.parse(
      atob(body.replace(/-/g, '+').replace(/_/g, '/'))
    );
    
    if (payload.exp < Date.now()) return null;
    
    return payload;
  } catch (e) {
    return null;
  }
}

async function hashPassword(password, secret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + secret);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ============================================
// MinIO Storage (AWS S3-compatible with Signature V4)
// ============================================

// Encode an S3 object key for use in the request path and CanonicalURI.
// AWS SigV4 spec: encode everything except A-Z a-z 0-9 - _ . ~
// encodeURIComponent leaves ( ) ! ' * unencoded, but S3/MinIO requires them encoded.
function s3UriEncode(str) {
  return encodeURIComponent(str)
    .replace(/!/g, '%21')
    .replace(/'/g, '%27')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
    .replace(/\*/g, '%2A');
}

function encodeS3KeyForPath(key) {
  return String(key || '')
    .split('/')
    .map((seg) => s3UriEncode(seg))
    .join('/');
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(key, message) {
  const keyBuffer = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const msgBuffer = new TextEncoder().encode(message);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msgBuffer));
}

async function hmacSha256Hex(key, message) {
  const sig = await hmacSha256(key, message);
  return [...sig].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function uploadToMinIO(env, path, content, contentType = 'application/json; charset=utf-8', retries = 2) {
  const endpoint = env.MINIO_ENDPOINT;
  const bucket = env.MINIO_BUCKET;

  if (!endpoint || !bucket || !env.MINIO_ACCESS_KEY || !env.MINIO_SECRET_KEY) {
    throw new Error(`MinIO config missing: endpoint=${!!endpoint}, bucket=${!!bucket}, accessKey=${!!env.MINIO_ACCESS_KEY}, secretKey=${!!env.MINIO_SECRET_KEY}`);
  }

  const key = path;
  const encodedKey = encodeS3KeyForPath(key);
  const base = String(endpoint || '').replace(/\/+$/, '');
  const url = `${base}/${bucket}/${encodedKey}`;
  
  const date = new Date().toISOString().replace(/[-:]/g, '').substring(0, 15) + 'Z';
  const dateStamp = date.substring(0, 8);
  const method = 'PUT';
  const payloadHash = await sha256(content);
  
  const canonicalUri = `/${bucket}/${encodedKey}`;
  const host = new URL(endpoint).host;
  const canonicalHeaders = [
    `content-type:${contentType}`,
    `host:${host}`,
    `x-amz-content-sha256:${payloadHash}`,
    `x-amz-date:${date}`,
  ].join('\n');
  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [
    method,
    canonicalUri,
    '',
    canonicalHeaders,
    '',
    signedHeaders,
    payloadHash,
  ].join('\n');
  
  const algorithm = 'AWS4-HMAC-SHA256';
  const region = 'us-east-1';
  const service = 's3';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    date,
    credentialScope,
    await sha256(canonicalRequest),
  ].join('\n');
  
  const kDate = await hmacSha256('AWS4' + env.MINIO_SECRET_KEY, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  const signature = await hmacSha256Hex(kSigning, stringToSign);
  
  const authorization = [
    `${algorithm} Credential=${env.MINIO_ACCESS_KEY}/${credentialScope}`,
    `SignedHeaders=${signedHeaders}`,
    `Signature=${signature}`,
  ].join(', ');

  let lastError = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      if (attempt > 0) {
        // Exponential backoff: 500ms, 1500ms
        await new Promise(r => setTimeout(r, 500 * attempt));
        console.log(`[MinIO] Retry ${attempt}/${retries} for ${key}`);
      }

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': contentType,
          'x-amz-content-sha256': payloadHash,
          'x-amz-date': date,
          'Authorization': authorization,
        },
        body: content,
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        lastError = new Error(`MinIO upload failed: ${response.status} - ${errorText}`);
        console.error(`[MinIO] Upload ${key} failed (attempt ${attempt}): ${response.status} - ${errorText}`);
        if (response.status >= 400 && response.status < 500) {
          // Client error — don't retry (wrong credentials, bad path, etc.)
          throw lastError;
        }
        continue; // Server error — retry
      }
      
      return { bucket, key, url };
    } catch (err) {
      lastError = err;
      if (err?.message?.includes('MinIO upload failed: 4')) {
        throw err; // Don't retry 4xx
      }
    }
  }

  throw lastError || new Error(`MinIO upload failed after ${retries + 1} attempts: ${key}`);
}

function safeNoteSlug(slug) {
  // Keep it deterministic and S3-key-friendly.
  // User preference: use slug; we only normalize path separators to avoid unintended folders.
  let s = String(slug || 'untitled').trim();
  // Frontend often sends URL-encoded slugs; decode so %2F becomes '/', then normalize separators.
  try {
    s = decodeURIComponent(s);
  } catch {
    // keep as-is
  }
  return s.replace(/^\/+/, '').replace(/[\\/]/g, '_');
}

function convertNoteToMarkdown(note) {
  const title = note?.title || note?.slug || 'Untitled';
  const tags = Array.isArray(note?.tags) && note.tags.length ? note.tags : [];
  const tagsLine = tags.length ? `\n\nTags: ${tags.map((t) => `#${t}`).join(' ')}` : '';
  return `# ${title}\n\n${note?.content || ''}${tagsLine}`;
}

/**
 * Ensures per-note Markdown files exist in MinIO:
 *   zones/{zoneId}/notes/{slug}.md
 * IMPORTANT: This is a hard requirement before triggering NotebookLM import,
 * otherwise the NotebookLM backend may fail with NoSuchKey.
 */
async function syncZoneNotesToMinIO(env, zoneId, notes) {
  const list = Array.isArray(notes) ? notes : [];
  if (list.length === 0) return [];

  // Cloudflare Workers free plan: max 50 subrequests per invocation.
  // Instead of uploading each note as a separate file (N fetches),
  // combine all notes into a single markdown file (1 fetch).
  const combined = list
    .map((n) => {
      const title = n?.title || n?.slug || 'Untitled';
      const tags = Array.isArray(n?.tags) ? n.tags : [];
      const tagsLine = tags.length ? `\n\nTags: ${tags.map((t) => `#${t}`).join(' ')}` : '';
      return `# ${title}\n\n${n?.content || ''}${tagsLine}`;
    })
    .join('\n\n---\n\n');

  const combinedKey = `zones/${zoneId}/notes-all.md`;
  await uploadToMinIO(env, combinedKey, combined, 'text/markdown');
  console.log(`[Zones] Uploaded combined markdown (${list.length} notes) to ${combinedKey}`);

  return [combinedKey];
}

async function deleteFromMinIO(env, path) {
  const endpoint = env.MINIO_ENDPOINT;
  const bucket = env.MINIO_BUCKET;
  const key = path;
  const encodedKey = encodeS3KeyForPath(key);
  const base = String(endpoint || '').replace(/\/+$/, '');
  const url = `${base}/${bucket}/${encodedKey}`;
  
  const date = new Date().toISOString().replace(/[-:]/g, '').substring(0, 15) + 'Z';
  const dateStamp = date.substring(0, 8);
  const method = 'DELETE';
  const payloadHash = await sha256('');
  
  const canonicalUri = `/${bucket}/${encodedKey}`;
  const host = new URL(endpoint).host;
  const canonicalHeaders = [
    `host:${host}`,
    `x-amz-content-sha256:${payloadHash}`,
    `x-amz-date:${date}`,
  ].join('\n');
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  
  const canonicalRequest = [
    method,
    canonicalUri,
    '',
    canonicalHeaders,
    '',
    signedHeaders,
    payloadHash,
  ].join('\n');
  
  const algorithm = 'AWS4-HMAC-SHA256';
  const region = 'us-east-1';
  const service = 's3';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    date,
    credentialScope,
    await sha256(canonicalRequest),
  ].join('\n');
  
  const kDate = await hmacSha256('AWS4' + env.MINIO_SECRET_KEY, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  const signature = await hmacSha256Hex(kSigning, stringToSign);
  
  const authorization = [
    `${algorithm} Credential=${env.MINIO_ACCESS_KEY}/${credentialScope}`,
    `SignedHeaders=${signedHeaders}`,
    `Signature=${signature}`,
  ].join(', ');
  
  await fetch(url, {
    method,
    headers: {
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': date,
      'Authorization': authorization,
    },
  });
}

// ============================================
// NotebookLM API Helper (UI Adapter)
// ============================================

/**
 * fetchNotebookLM(env, path, init)
 * - Uses env.NOTEBOOKLM_BASE_URL OR fallback https://notebooklm-gateway.replit.app
 * - Timeout via env.NOTEBOOKLM_TIMEOUT_MS (default 15000)
 * - Optional Bearer via env.NOTEBOOKLM_SERVICE_TOKEN
 * - Never throws for HTTP errors: returns { ok:false, status, data }
 */
async function fetchNotebookLM(env, path, init = {}) {
  const baseUrl = (env.NOTEBOOKLM_BASE_URL || 'https://notebooklm-gateway.replit.app').replace(/\/$/, '');
  const timeoutMs = Number.parseInt(env.NOTEBOOKLM_TIMEOUT_MS, 10) || 120000;
  const url = `${baseUrl}${path}`;

  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (env.NOTEBOOKLM_SERVICE_TOKEN && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${env.NOTEBOOKLM_SERVICE_TOKEN}`);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort('timeout'), timeoutMs);

  try {
    const res = await fetch(url, {
      ...init,
      headers,
      signal: controller.signal,
    });

    const contentType = res.headers.get('content-type') || '';
    const data = contentType.includes('application/json')
      ? await res.json().catch(() => null)
      : await res.text().catch(() => null);

    if (!res.ok) {
      return { ok: false, status: res.status, data };
    }

    return { ok: true, status: res.status, data };
  } catch (err) {
    const isTimeout = err?.name === 'AbortError' || err === 'timeout' || err?.message?.toLowerCase?.().includes('timeout');
    return {
      ok: false,
      status: isTimeout ? 504 : 502,
      data: {
        error: isTimeout ? `NotebookLM timeout after ${timeoutMs}ms` : `NotebookLM fetch failed: ${err?.message || String(err)}`,
      },
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================
// NotebookLM Chat (UI Adapter)
// ============================================

/**
 * Owner-only: proxy chat requests to the NotebookLM backend.
 * Frontend talks to Worker; Worker talks to Replit/FastAPI.
 *
 * Expected request body (frontend):
 * {
 *   notebookUrl: string;
 *   message: string;
 *   kind?: 'answer' | 'summary' | 'study_guide' | 'flashcards';
 *   history?: Array<{ role: 'user' | 'assistant'; content: string }>
 * }
 */
async function handleNotebookLMChat(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }

  const notebookUrl = typeof body?.notebookUrl === 'string' ? body.notebookUrl.trim() : '';
  const message = typeof body?.message === 'string' ? body.message.trim() : '';
  const kind = typeof body?.kind === 'string' ? body.kind : 'answer';
  const history = Array.isArray(body?.history) ? body.history : [];

  if (!notebookUrl) return errorResponse('notebookUrl is required', 400, body, 'NOTEBOOKLM_CHAT_INVALID');
  if (!message) return errorResponse('message is required', 400, body, 'NOTEBOOKLM_CHAT_INVALID');

  const chatRes = await fetchNotebookLM(env, '/v1/chat', {
    method: 'POST',
    body: JSON.stringify({
      notebook_url: notebookUrl,
      message,
      kind,
      history,
    }),
  });

  if (!chatRes.ok) {
    return errorResponse(
      chatRes?.data?.error || chatRes?.data?.detail || 'NotebookLM chat failed',
      chatRes.status || 502,
      chatRes.data,
      'NOTEBOOKLM_CHAT_FAILED'
    );
  }

  return jsonResponse({ success: true, ...chatRes.data });
}

// ============================================
// MCP JSON-RPC Helpers
// ============================================

function createJSONRPCResponse(id, result) {
  return {
    jsonrpc: '2.0',
    id: id !== null && id !== undefined ? id : 0,
    result,
  };
}

function createJSONRPCError(id, code, message, data) {
  return {
    jsonrpc: '2.0',
    id: id !== null && id !== undefined ? id : 0,
    error: { code, message, data },
  };
}

function getMCPTools() {
  return [
    {
      name: 'search_notes',
      description: 'Search notes by title, content, or tags',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query' },
          tags: { type: 'array', items: { type: 'string' }, description: 'Filter by tags' },
          limit: { type: 'number', description: 'Max results (default 10)' },
        },
        required: ['query'],
      },
    },
    {
      name: 'get_note',
      description: 'Get a specific note by slug',
      inputSchema: {
        type: 'object',
        properties: {
          slug: { type: 'string', description: 'Note slug/path' },
        },
        required: ['slug'],
      },
    },
    {
      name: 'list_notes',
      description: 'List all available notes',
      inputSchema: {
        type: 'object',
        properties: {
          folder: { type: 'string', description: 'Filter by folder path' },
          limit: { type: 'number', description: 'Max results (default 50)' },
        },
      },
    },
    {
      name: 'get_tags',
      description: 'Get all tags with note counts',
      inputSchema: {
        type: 'object',
        properties: {},
      },
    },
  ];
}

async function handleToolCall(params, session, env) {
  const notes = session && session.notes ? session.notes : [];

  switch (params.name) {
    case 'search_notes': {
      const query = (params.arguments.query || '').toLowerCase();
      const filterTags = params.arguments.tags || [];
      const limit = params.arguments.limit || 10;

      const results = notes
        .filter(note => {
          const matchesQuery = 
            note.title.toLowerCase().includes(query) ||
            note.content.toLowerCase().includes(query);
          const matchesTags = filterTags.length === 0 ||
            filterTags.some(tag => note.tags.includes(tag));
          return matchesQuery && matchesTags;
        })
        .slice(0, limit);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(results.map(n => ({
            slug: n.slug,
            title: n.title,
            tags: n.tags,
            preview: n.content.slice(0, 200),
          })), null, 2),
        }],
      };
    }

    case 'get_note': {
      const slug = params.arguments.slug;
      const note = notes.find(n => n.slug === slug || n.slug.endsWith(`/${slug}`));
      
      if (!note) {
        return {
          content: [{ type: 'text', text: `Note not found: ${slug}` }],
        };
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(note, null, 2),
        }],
      };
    }

    case 'list_notes': {
      const folder = params.arguments.folder || '';
      const limit = params.arguments.limit || 50;

      const results = notes
        .filter(n => !folder || n.slug.startsWith(folder))
        .slice(0, limit);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(results.map(n => ({
            slug: n.slug,
            title: n.title,
            tags: n.tags,
          })), null, 2),
        }],
      };
    }

    case 'get_tags': {
      const tagCounts = {};
      notes.forEach(note => {
        (note.tags || []).forEach(tag => {
          tagCounts[tag] = (tagCounts[tag] || 0) + 1;
        });
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(tagCounts, null, 2),
        }],
      };
    }

    default:
      return {
        content: [{ type: 'text', text: `Unknown tool: ${params.name}` }],
      };
  }
}

function getSessionResources(session) {
  return session.notes.map(note => ({
    uri: `note:///${note.slug}`,
    name: note.title,
    mimeType: 'text/markdown',
  }));
}

async function handleResourceRead(params, session, env) {
  if (!session) {
    return { contents: [] };
  }

  const slug = params.uri.replace('note:///', '');
  const note = session.notes.find(n => n.slug === slug);

  if (!note) {
    return { contents: [] };
  }

  return {
    contents: [{
      uri: params.uri,
      mimeType: 'text/markdown',
      text: note.content,
    }],
  };
}

// ============================================
// Route Handlers
// ============================================

async function handleHealth() {
  return jsonResponse({
    status: 'ok',
    version: '3.0',
    timestamp: new Date().toISOString(),
    features: ['rest-api', 'mcp-jsonrpc', 'sse-transport', 'minio-storage'],
    runtime: 'vanilla-cloudflare-workers'
  });
}

async function handleAuthStatus(env) {
  const initialized = await env.KV.get('owner_initialized');

  // Return auth status immediately — do NOT block on NotebookLM/Replit backend.
  // NotebookLM status is fetched separately with a short timeout (best-effort).
  const authResponse = {
    success: true,
    initialized: initialized === 'true',
    notebookLMReady: false,
    notebookLMMessage: null,
    notebookCount: null,
  };

  // Best-effort NotebookLM check with a short timeout (3s).
  // If Replit is down (e.g. credits exhausted), we still return auth status.
  try {
    const nlmTimeout = 3000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort('nlm-timeout'), nlmTimeout);

    const res = await fetchNotebookLM(env, '/auth/status', {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok && res.data) {
      authResponse.notebookLMReady = res.data.ok === true;
      authResponse.notebookLMMessage = res.data.message || null;
      authResponse.notebookCount = res.data.notebook_count || null;
    } else {
      authResponse.notebookLMMessage = res?.data?.message || res?.data?.error || 'Backend unavailable';
    }
  } catch (e) {
    authResponse.notebookLMMessage = 'Backend unreachable';
  }

  return jsonResponse(authResponse);
}

async function handleAuthSetup(request, env) {
  const body = await request.json();
  const password = body.password;
  
  const initialized = await env.KV.get('owner_initialized');
  if (initialized === 'true') {
    return errorResponse('Already initialized', 400);
  }

  const hashHex = await hashPassword(password, env.JWT_SECRET);

  await env.KV.put('owner_password_hash', hashHex);
  await env.KV.put('owner_initialized', 'true');

  return jsonResponse({ success: true });
}

async function handleAuthLogin(request, env) {
  const body = await request.json();
  const password = body.password;
  
  const storedHash = await env.KV.get('owner_password_hash');
  if (!storedHash) {
    return errorResponse('Not initialized', 401);
  }

  const hashHex = await hashPassword(password, env.JWT_SECRET);

  if (hashHex !== storedHash) {
    return errorResponse('Invalid password', 401);
  }

  const token = await generateJWT({ role: 'owner' }, env.JWT_SECRET, 86400000);

  return jsonResponse({ success: true, token });
}

async function handleAuthRefresh(request, env) {
  const authHeader = request.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return errorResponse('Token required', 401);
  }
  
  const oldToken = authHeader.slice(7);
  const payload = await verifyJWT(oldToken, env.JWT_SECRET);
  
  if (!payload) {
    return errorResponse('Invalid or expired token', 401);
  }
  
  const newToken = await generateJWT({ role: payload.role }, env.JWT_SECRET, 86400000);
  
  return jsonResponse({ success: true, token: newToken });
}

async function handleAuthValidate(request, env) {
  const body = await request.json();
  const token = body.token;
  
  if (!token) {
    return jsonResponse({ success: true, valid: false });
  }
  
  const payload = await verifyJWT(token, env.JWT_SECRET);
  
  return jsonResponse({ 
    success: true, 
    valid: !!payload,
    expiresAt: payload ? payload.exp : null,
  });
}

async function handleSessionsCreate(request, env, host) {
  const body = await request.json();
  const { folders, ttlMinutes, notes } = body;

  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

  const session = {
    sessionId,
    folders,
    notes,
    expiresAt,
    createdAt: new Date().toISOString(),
    createdBy: 'owner',
  };

  // Store session in KV
  await env.KV.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: ttlMinutes * 60 }
  );

  // Upload to MinIO (JSON, JSONL, MD formats)
  const baseUrl = `${env.MINIO_ENDPOINT}/${env.MINIO_BUCKET}`;
  
  try {
    await uploadToMinIO(env, `sessions/${sessionId}/notes.json`, JSON.stringify(notes, null, 2));
    await uploadToMinIO(env, `sessions/${sessionId}/notes.jsonl`, notes.map(n => JSON.stringify(n)).join('\n'), 'application/x-ndjson');
    await uploadToMinIO(env, `sessions/${sessionId}/notes.md`, notes.map(n => `# ${n.title}\n\n${n.content}`).join('\n\n---\n\n'), 'text/markdown');
  } catch (err) {
    console.error('MinIO upload error:', err);
    // Continue - KV is primary storage
  }

  return jsonResponse({
    success: true,
    sessionId,
    sessionUrl: `https://${host}/mcp?session=${sessionId}`,
    expiresAt,
    noteCount: notes.length,
    storage: 'minio',
    formats: {
      json: `${baseUrl}/sessions/${sessionId}/notes.json`,
      jsonl: `${baseUrl}/sessions/${sessionId}/notes.jsonl`,
      markdown: `${baseUrl}/sessions/${sessionId}/notes.md`,
    },
  });
}

async function handleSessionsRevoke(request, env) {
  const body = await request.json();
  const sessionId = body.sessionId;
  
  // Delete from KV
  await env.KV.delete(`session:${sessionId}`);
  
  // Delete from MinIO (all formats)
  try {
    await Promise.all([
      deleteFromMinIO(env, `sessions/${sessionId}/notes.json`),
      deleteFromMinIO(env, `sessions/${sessionId}/notes.jsonl`),
      deleteFromMinIO(env, `sessions/${sessionId}/notes.md`),
    ]);
  } catch (err) {
    console.error('MinIO cleanup error:', err);
  }
  
  return jsonResponse({ success: true });
}

async function handleSessionsList(env) {
  return jsonResponse({ 
    success: true, 
    message: 'Use KV list API or maintain session index' 
  });
}

async function handleZonesValidate(zoneId, env, request) {
  // Extract access code from query params
  const url = new URL(request.url);
  const providedCode = url.searchParams.get('code');

  const zoneData = await env.KV.get(`zone:${zoneId}`);
  
  if (!zoneData) {
    return errorResponse('Zone not found', 404);
  }

  const zone = JSON.parse(zoneData);
  
  // ✅ VALIDATE ACCESS CODE
  if (!providedCode || providedCode !== zone.accessCode) {
    return errorResponse('Invalid access code', 403);
  }
  
  if (new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410, { expired: true }, 'ZONE_EXPIRED');
  }

  // ✅ RETURN COMPLETE DATA
  return jsonResponse({
    success: true,
    id: zone.zoneId,
    name: zone.name,
    description: zone.description,
    folders: zone.allowedPaths,
    noteCount: zone.noteCount,
    notes: zone.notes || [],
    expiresAt: new Date(zone.expiresAt).getTime(),
    accessType: zone.accessType,
    consentRequired: zone.consentRequired !== false,
  });
}

async function handleZonesNotes(zoneId, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  
  if (!zoneData) {
    return errorResponse('Zone not found', 404);
  }

  const zone = JSON.parse(zoneData);
  
  if (new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410);
  }

  return jsonResponse({
    success: true,
    notes: zone.notes,
    expiresAt: zone.expiresAt,
  });
}

async function handleZonesCreate(request, env, host) {
  const body = await request.json();
  const {
    name,
    description,
    allowedPaths,
    ttlMinutes,
    notes,
    accessType,
    // Consent settings
    consentRequired = true,
    // NotebookLM integration fields
    createNotebookLM,
    notebookTitle,
    notebookShareEmails,
    notebookSourceMode = 'minio',
  } = body;

  console.log(`[Zones] Creating zone: name="${name}", notes=${Array.isArray(notes) ? notes.length : 0}, folders=${JSON.stringify(allowedPaths)}, createNotebookLM=${createNotebookLM}`);
  const zoneId = crypto.randomUUID().slice(0, 8);
  const accessCode = `ACCESS-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

  const zone = {
    zoneId,
    accessCode,
    name,
    description,
    accessType,
    consentRequired,
    allowedPaths,
    notes,
    noteCount: notes.length,
    expiresAt,
    createdAt: new Date().toISOString(),
    createdBy: 'owner',
  };

  await env.KV.put(
    `zone:${zoneId}`,
    JSON.stringify(zone),
    { expirationTtl: ttlMinutes * 60 }
  );

  // Update zones index
  const indexData = await env.KV.get('zones:index');
  const zoneIndex = indexData ? JSON.parse(indexData) : [];
  zoneIndex.push(zoneId);
  await env.KV.put('zones:index', JSON.stringify(zoneIndex));

  // ============================================
  // Upload zone content to MinIO for MCP access
  // ============================================
  let minioNoteKeys = null;
  let minioSyncError = null;
  // IMPORTANT: If NotebookLM is requested, per-note files must exist before we call import.
  if (createNotebookLM) {
    try {
      minioNoteKeys = await syncZoneNotesToMinIO(env, zoneId, notes);
      console.log(`[Zones] Synced per-note Markdown to MinIO for NotebookLM: ${zoneId} -> ${minioNoteKeys.length} files`);
    } catch (err) {
      console.error('[Zones] MinIO sync for NotebookLM failed (zone created, NotebookLM skipped):', err);
      minioSyncError = err?.message || String(err);
      // DON'T return error — zone is already created in KV.
      // NotebookLM import will be skipped, but zone is usable.
    }
  }

  // Best-effort: upload other formats for MCP access.
  // (Keep non-blocking so zone creation isn't prevented by MinIO issues unless NotebookLM is enabled.)
  try {
    const zoneContent = {
      id: zoneId,
      name,
      description,
      accessType,
      notes: notes.map((n) => ({
        slug: n.slug,
        title: n.title,
        content: n.content,
        tags: n.tags || [],
      })),
      createdAt: new Date().toISOString(),
      expiresAt,
    };

    // JSON format for structured access
    await uploadToMinIO(env, `zones/${zoneId}/notes.json`, JSON.stringify(zoneContent, null, 2));

    // JSONL format for streaming
    await uploadToMinIO(
      env,
      `zones/${zoneId}/notes.jsonl`,
      notes.map((n) => JSON.stringify({ slug: n.slug, title: n.title, content: n.content, tags: n.tags })).join('\n'),
      'application/x-ndjson'
    );

    // Per-note Markdown files (best-effort if NotebookLM not requested)
    if (!minioNoteKeys) {
      minioNoteKeys = await syncZoneNotesToMinIO(env, zoneId, notes);
    }

    console.log(`[Zones] Uploaded zone ${zoneId} to MinIO`);
  } catch (err) {
    console.error('[Zones] MinIO upload error:', err);
    // Continue - KV is primary storage
  }

  // ============================================
  // NotebookLM Integration (if requested)
  // ============================================
  let notebooklmResult = null;

  if (createNotebookLM && !minioSyncError) {
    const notebooklmMapping = {
      zoneId,
      notebookId: null,
      notebookUrl: null,
      importJobId: null,
      status: 'pending',
      createdAt: new Date().toISOString(),
      lastError: null,
    };

    try {
      // 1) Create notebook
      console.log(`[NotebookLM] Creating notebook for zone ${zoneId}, title: ${notebookTitle || name}`);
      const createRes = await fetchNotebookLM(env, '/v1/notebooks', {
        method: 'POST',
        body: JSON.stringify({ title: notebookTitle || name }),
      });
      console.log(`[NotebookLM] Create response: status=${createRes.status}, ok=${createRes.ok}, data=`, JSON.stringify(createRes.data)?.slice(0, 500));
      if (!createRes.ok) {
        throw new Error(createRes?.data?.error || createRes?.data?.detail || `Create notebook failed (${createRes.status})`);
      }

      const created = createRes.data;
      notebooklmMapping.notebookId = created?.id || created?.notebook_id || null;
      notebooklmMapping.notebookUrl = created?.url || created?.notebook_url || null;
      notebooklmMapping.status = 'created';

      if (!notebooklmMapping.notebookId) {
        throw new Error('NotebookLM create succeeded but notebookId is missing');
      }

      // 2) Import sources (async job)
      const notebookId = notebooklmMapping.notebookId;
      const importBody =
        notebookSourceMode === 'url'
          ? {
              sources: (minioNoteKeys || []).map((key) => ({
                type: 'url',
                url: `${env.MINIO_ENDPOINT}/${env.MINIO_BUCKET}/${key}`,
              })),
              idempotency_key: `zone-${zoneId}-import`,
            }
          : {
              sources: (minioNoteKeys || []).map((key) => ({
                type: 'minio',
                bucket: env.MINIO_BUCKET,
                key,
              })),
              idempotency_key: `zone-${zoneId}-import`,
            };

      if (!importBody.sources || importBody.sources.length === 0) {
        throw new Error('NotebookLM import blocked: no notes were exported to MinIO');
      }

      console.log(`[NotebookLM] Importing ${importBody.sources.length} sources for notebook ${notebookId}`);
      const importRes = await fetchNotebookLM(env, `/v1/notebooks/${notebookId}/sources/import`, {
        method: 'POST',
        body: JSON.stringify(importBody),
      });
      console.log(`[NotebookLM] Import response: status=${importRes.status}, ok=${importRes.ok}, data=`, JSON.stringify(importRes.data)?.slice(0, 500));
      if (!importRes.ok) {
        throw new Error(importRes?.data?.error || importRes?.data?.detail || `Import failed (${importRes.status})`);
      }

      const imported = importRes.data;
      notebooklmMapping.importJobId = imported?.job_id || imported?.id || null;
      notebooklmMapping.status = imported?.status || 'queued';

      // 3) Share notebook (optional, non-fatal)
      if (Array.isArray(notebookShareEmails) && notebookShareEmails.length > 0) {
        const shareRes = await fetchNotebookLM(env, `/v1/notebooks/${notebookId}/share`, {
          method: 'POST',
          body: JSON.stringify({ emails: notebookShareEmails, role: 'reader' }),
        });
        if (!shareRes.ok) {
          // non-fatal
          console.error('[NotebookLM] Share failed (non-fatal):', shareRes?.data);
        }
      }

      notebooklmResult = {
        notebookId: notebooklmMapping.notebookId,
        notebookUrl: notebooklmMapping.notebookUrl,
        importJobId: notebooklmMapping.importJobId,
        status: notebooklmMapping.status,
      };
    } catch (err) {
      notebooklmMapping.status = 'failed';
      notebooklmMapping.lastError = err?.message || String(err);
      notebooklmResult = {
        notebookId: notebooklmMapping.notebookId,
        notebookUrl: notebooklmMapping.notebookUrl,
        importJobId: notebooklmMapping.importJobId,
        status: 'failed',
        error: notebooklmMapping.lastError,
        lastError: notebooklmMapping.lastError,
      };
    }

    await env.KV.put(`zone_notebooklm:${zoneId}`, JSON.stringify(notebooklmMapping), {
      expirationTtl: ttlMinutes * 60,
    });
  } else if (createNotebookLM && minioSyncError) {
    // MinIO sync failed — zone created but NotebookLM skipped
    notebooklmResult = {
      notebookId: null,
      notebookUrl: null,
      importJobId: null,
      status: 'failed',
      error: `MinIO sync failed: ${minioSyncError}. Zone created, NotebookLM skipped. Use retry import.`,
      lastError: `MinIO sync failed: ${minioSyncError}. Zone created, NotebookLM skipped. Use retry import.`,
    };
  }

  const warnings = [];
  if (minioSyncError) {
    warnings.push(`MinIO sync failed: ${minioSyncError}. Zone created without MinIO files.`);
  }

  return jsonResponse({
    success: true,
    zoneId,
    accessCode,
    zoneUrl: `https://${host.replace('garden-mcp-server', 'exodus')}/zone/${zoneId}`,
    expiresAt,
    noteCount: notes.length,
    ...(notebooklmResult ? { notebooklm: notebooklmResult } : {}),
    ...(warnings.length ? { warnings } : {}),
  });
}

// ============================================
// NotebookLM Zone Handlers (UI Adapter)
// ============================================

async function handleZoneNotebookLMStatus(zoneId, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) return errorResponse('Zone not found', 404);

  const mappingData = await env.KV.get(`zone_notebooklm:${zoneId}`);
  if (!mappingData) {
    return jsonResponse({ success: true, zoneId, notebooklm: null });
  }

  const mapping = JSON.parse(mappingData);
  return jsonResponse({
    success: true,
    zoneId,
    notebooklm: {
      notebookId: mapping.notebookId,
      notebookUrl: mapping.notebookUrl,
      importJobId: mapping.importJobId,
      status: mapping.status,
      createdAt: mapping.createdAt,
      lastError: mapping.lastError,
    },
  });
}

async function handleZoneNotebookLMJobStatus(zoneId, jobId, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) return errorResponse('Zone not found', 404);

  const jobRes = await fetchNotebookLM(env, `/v1/jobs/${jobId}`, { method: 'GET' });
  if (!jobRes.ok) {
    return errorResponse(
      jobRes?.data?.error || jobRes?.data?.detail || 'Failed to get job status',
      jobRes.status || 502,
      jobRes.data,
      'NOTEBOOKLM_JOB_STATUS_FAILED'
    );
  }

  // Best-effort mapping sync (KV is the UI source of truth)
  const mappingData = await env.KV.get(`zone_notebooklm:${zoneId}`);
  if (mappingData) {
    const mapping = JSON.parse(mappingData);
    if (mapping.importJobId === jobId && jobRes.data?.status) {
      mapping.status = jobRes.data.status;
      if (jobRes.data.status === 'failed' && jobRes.data.error) {
        mapping.lastError = jobRes.data.error;
      }
      await env.KV.put(`zone_notebooklm:${zoneId}`, JSON.stringify(mapping));
    }
  }

  // IMPORTANT: return the raw job object on top-level for frontend compatibility
  // (NotebookLMJobStatus: { status, progress?, current_step?, total_steps?, notebook_url?, error? })
  return jsonResponse(jobRes.data);
}

async function handleZoneNotebookLMRetryImport(zoneId, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) return errorResponse('Zone not found', 404);
  const zone = JSON.parse(zoneData);

  const mappingData = await env.KV.get(`zone_notebooklm:${zoneId}`);
  const mapping = mappingData
    ? JSON.parse(mappingData)
    : {
        zoneId,
        notebookId: null,
        notebookUrl: null,
        importJobId: null,
        status: 'pending',
        createdAt: new Date().toISOString(),
        lastError: null,
      };

  try {
    // Ensure per-note markdown exists before retry import
    try {
      await syncZoneNotesToMinIO(env, zoneId, zone.notes || []);
    } catch (err) {
      return errorResponse(
        'Retry import blocked: failed to sync notes to MinIO',
        502,
        { message: err?.message || String(err), zoneId, prefix: `zones/${zoneId}/notes/` },
        'MINIO_SYNC_FAILED'
      );
    }

    // If notebook not created earlier – create now (allowed by requirements)
    if (!mapping.notebookId) {
      const createRes = await fetchNotebookLM(env, '/v1/notebooks', {
        method: 'POST',
        body: JSON.stringify({ title: zone.name || `Zone ${zoneId}` }),
      });
      if (!createRes.ok) {
        throw new Error(createRes?.data?.error || createRes?.data?.detail || `Create notebook failed (${createRes.status})`);
      }
      mapping.notebookId = createRes.data?.id || createRes.data?.notebook_id || null;
      mapping.notebookUrl = createRes.data?.url || createRes.data?.notebook_url || null;
      mapping.status = 'created';
    }

    if (!mapping.notebookId) {
      throw new Error('Cannot retry import: missing notebookId');
    }

    const timestamp = Date.now();
    const noteKeys = [`zones/${zoneId}/notes-all.md`];
    const importRes = await fetchNotebookLM(env, `/v1/notebooks/${mapping.notebookId}/sources/import`, {
      method: 'POST',
      body: JSON.stringify({
        sources: noteKeys.map((key) => ({ type: 'minio', bucket: env.MINIO_BUCKET, key })),
        idempotency_key: `zone-${zoneId}-import-retry-${timestamp}`,
      }),
    });
    if (!importRes.ok) {
      throw new Error(importRes?.data?.error || importRes?.data?.detail || `Import failed (${importRes.status})`);
    }

    mapping.importJobId = importRes.data?.job_id || importRes.data?.id || null;
    mapping.status = importRes.data?.status || 'queued';
    mapping.lastError = null;

    await env.KV.put(`zone_notebooklm:${zoneId}`, JSON.stringify(mapping), {
      expirationTtl: Math.max(60, Math.floor((new Date(zone.expiresAt).getTime() - Date.now()) / 1000)),
    });

    return jsonResponse({
      success: true,
      zoneId,
      notebooklm: {
        notebookId: mapping.notebookId,
        notebookUrl: mapping.notebookUrl,
        importJobId: mapping.importJobId,
        status: mapping.status,
      },
    });
  } catch (err) {
    mapping.status = 'failed';
    mapping.lastError = err?.message || String(err);
    await env.KV.put(`zone_notebooklm:${zoneId}`, JSON.stringify(mapping));
    return errorResponse('Retry import failed', 500, { message: mapping.lastError }, 'NOTEBOOKLM_RETRY_FAILED');
  }
}

/**
 * Guest-facing NotebookLM chat endpoint for zones.
 * Validates zone code from X-Zone-Code header, then proxies to NotebookLM backend.
 */
async function handleZoneNotebookLMChat(zoneId, request, env) {
  // 1. Validate zone code from header
  const zoneCode = request.headers.get('X-Zone-Code');
  if (!zoneCode) {
    return errorResponse('Missing zone access code', 401, undefined, 'ZONE_CODE_MISSING');
  }

  // 2. Fetch zone data
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) {
    return errorResponse('Zone not found', 404, undefined, 'ZONE_NOT_FOUND');
  }
  const zone = JSON.parse(zoneData);

  // 3. Validate access code
  if (zoneCode !== zone.accessCode) {
    return errorResponse('Invalid access code', 403, undefined, 'ZONE_CODE_INVALID');
  }

  // 4. Check zone expiration
  if (new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410, { expired: true }, 'ZONE_EXPIRED');
  }

  // 5. Fetch NotebookLM mapping
  const mappingData = await env.KV.get(`zone_notebooklm:${zoneId}`);
  if (!mappingData) {
    return errorResponse('NotebookLM not configured for this zone', 404, undefined, 'NOTEBOOKLM_NOT_FOUND');
  }
  const mapping = JSON.parse(mappingData);

  if (!mapping.notebookUrl) {
    return errorResponse('NotebookLM not ready', 400, { status: mapping.status }, 'NOTEBOOKLM_NOT_READY');
  }

  // 6. Parse request body
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }

  const message = typeof body?.message === 'string' ? body.message.trim() : '';
  const kind = typeof body?.kind === 'string' ? body.kind : 'answer';
  const history = Array.isArray(body?.history) ? body.history : [];

  if (!message) {
    return errorResponse('message is required', 400, body, 'NOTEBOOKLM_CHAT_INVALID');
  }

  // 7. Proxy to NotebookLM backend
  const chatRes = await fetchNotebookLM(env, '/v1/chat', {
    method: 'POST',
    body: JSON.stringify({
      notebook_url: mapping.notebookUrl,
      message,
      kind,
      history,
    }),
  });

  if (!chatRes.ok) {
    return errorResponse(
      chatRes?.data?.error || chatRes?.data?.detail || 'NotebookLM chat failed',
      chatRes.status || 502,
      chatRes.data,
      'NOTEBOOKLM_CHAT_FAILED'
    );
  }

  return jsonResponse({ success: true, ...chatRes.data });
}

async function handleZonesDelete(zoneId, env) {
  // Read zone before deleting so we can remove per-note objects from MinIO.
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  const zone = zoneData ? JSON.parse(zoneData) : null;

  await env.KV.delete(`zone:${zoneId}`);

  // Remove from zones index
  const indexData = await env.KV.get('zones:index');
  if (indexData) {
    const zoneIndex = JSON.parse(indexData);
    const updatedIndex = zoneIndex.filter(id => id !== zoneId);
    await env.KV.put('zones:index', JSON.stringify(updatedIndex));
  }

  // Delete from MinIO
  try {
    const perNoteDeletes = Array.isArray(zone?.notes)
      ? zone.notes.map((n) => deleteFromMinIO(env, `zones/${zoneId}/notes/${safeNoteSlug(n?.slug || n?.title)}.md`))
      : [];
    await Promise.all([
      deleteFromMinIO(env, `zones/${zoneId}/notes.json`),
      deleteFromMinIO(env, `zones/${zoneId}/notes.jsonl`),
      // Backward-compat cleanup (old aggregated path)
      deleteFromMinIO(env, `zones/${zoneId}/notes.md`).catch(() => null),
      ...perNoteDeletes,
    ]);
    console.log(`[Zones] Deleted zone ${zoneId} from MinIO`);
  } catch (err) {
    console.error('[Zones] MinIO cleanup error:', err);
  }

  return jsonResponse({ success: true });
}

async function handleZonesList(env) {
  const indexData = await env.KV.get('zones:index');

  if (!indexData) {
    return jsonResponse({ success: true, zones: [] });
  }

  const zoneIds = JSON.parse(indexData);

  // Fetch details for each zone
  const zones = await Promise.all(
    zoneIds.map(async (zoneId) => {
      const zoneData = await env.KV.get(`zone:${zoneId}`);
      if (!zoneData) return null;

      const zone = JSON.parse(zoneData);

      // Filter expired zones
      if (new Date(zone.expiresAt) < new Date()) {
        return null;
      }

      return {
        id: zone.zoneId,
        name: zone.name,
        description: zone.description,
        folders: zone.allowedPaths,
        noteCount: zone.noteCount,
        accessType: zone.accessType,
        createdAt: new Date(zone.createdAt).getTime(),
        expiresAt: new Date(zone.expiresAt).getTime(),
        accessCode: zone.accessCode,
      };
    })
  );

  // Remove null (expired/deleted zones)
  const validZones = zones.filter(z => z !== null);

  return jsonResponse({ success: true, zones: validZones });
}

// ============================================
// Comments Handlers
// ============================================

async function handleCommentsGet(articleSlug, env, request) {
  const indexKey = `comments:index:${articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  
  if (!indexData) {
    return jsonResponse({ success: true, comments: [], total: 0 });
  }
  
  const index = JSON.parse(indexData);
  const isOwner = await verifyOwnerAuth(request, env);
  
  const comments = await Promise.all(
    index.commentIds.map(async (id) => {
      const commentData = await env.KV.get(`comment:${id}`);
      if (!commentData) return null;
      return JSON.parse(commentData);
    })
  );
  
  // Filter: owners see all, guests see only approved
  const filteredComments = comments.filter(c => {
    if (!c) return false;
    if (isOwner) return true;
    return c.status === 'approved';
  });
  
  return jsonResponse({ 
    success: true, 
    comments: filteredComments, 
    total: filteredComments.length 
  });
}

async function handleCommentsCreate(request, env) {
  const body = await request.json();
  const { articleSlug, content, parentId, authorName, authorType, agentModel, zoneId, zoneCode } = body;
  
  if (!articleSlug || !content) {
    return errorResponse('articleSlug and content required', 400);
  }
  
  // Check if request comes from zone guest
  const headerZoneId = request.headers.get('X-Zone-Id') || zoneId;
  const headerZoneCode = request.headers.get('X-Zone-Code') || zoneCode;
  let isZoneGuest = false;
  
  if (headerZoneId && headerZoneCode) {
    // Validate zone access
    const zoneData = await env.KV.get(`zone:${headerZoneId}`);
    if (zoneData) {
      const zone = JSON.parse(zoneData);
      if (zone.accessCode === headerZoneCode && new Date(zone.expiresAt) > new Date()) {
        isZoneGuest = true;
      }
    }
  }
  
  const isOwner = await verifyOwnerAuth(request, env);
  const commentId = crypto.randomUUID();
  
  const comment = {
    id: commentId,
    articleSlug,
    parentId: parentId || null,
    author: {
      id: crypto.randomUUID(),
      name: authorName || (isOwner ? 'Owner' : isZoneGuest ? 'Zone Guest' : 'Guest'),
      domain: 'exodus.pp.ua',
      isOwner: !!isOwner,
      type: authorType || 'human',
      agentModel: agentModel || undefined,
    },
    content,
    createdAt: new Date().toISOString(),
    updatedAt: null,
    status: isOwner ? 'approved' : 'pending',
    origin: isZoneGuest ? 'zone' : 'local',
    zoneId: isZoneGuest ? headerZoneId : undefined,
  };
  
  // Store comment
  await env.KV.put(`comment:${commentId}`, JSON.stringify(comment));
  
  // Update index
  const indexKey = `comments:index:${articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  const index = indexData ? JSON.parse(indexData) : { 
    articleSlug, 
    commentIds: [], 
    lastUpdated: null 
  };
  
  index.commentIds.push(commentId);
  index.lastUpdated = new Date().toISOString();
  await env.KV.put(indexKey, JSON.stringify(index));
  
  // ============================================
  // Sync comments to MinIO for MCP access
  // ============================================
  try {
    // Get all comments for this article
    const allComments = await Promise.all(
      index.commentIds.map(async (id) => {
        const data = await env.KV.get(`comment:${id}`);
        return data ? JSON.parse(data) : null;
      })
    );
    const validComments = allComments.filter(c => c !== null);
    
    // Sanitize slug for file path
    const safeSlug = articleSlug.replace(/[\/\\]/g, '_');
    
    // Upload to MinIO
    await uploadToMinIO(env, 
      `comments/${safeSlug}/comments.json`,
      JSON.stringify(validComments, null, 2)
    );
    
    console.log(`[Comments] Synced ${validComments.length} comments for ${articleSlug} to MinIO`);
  } catch (err) {
    console.error('[Comments] MinIO sync error:', err);
    // Continue - KV is primary storage
  }
  
  return jsonResponse({ success: true, comment });
}

async function handleCommentsUpdate(commentId, request, env) {
  const body = await request.json();
  const { status, content } = body;
  
  const commentData = await env.KV.get(`comment:${commentId}`);
  if (!commentData) {
    return errorResponse('Comment not found', 404);
  }
  
  const comment = JSON.parse(commentData);
  
  if (status) comment.status = status;
  if (content) comment.content = content;
  comment.updatedAt = new Date().toISOString();
  
  await env.KV.put(`comment:${commentId}`, JSON.stringify(comment));
  
  // Sync to MinIO after update
  await syncCommentsToMinIO(comment.articleSlug, env);
  
  return jsonResponse({ success: true, comment });
}

async function handleCommentsDelete(commentId, env) {
  const commentData = await env.KV.get(`comment:${commentId}`);
  if (!commentData) {
    return errorResponse('Comment not found', 404);
  }
  
  const comment = JSON.parse(commentData);
  const articleSlug = comment.articleSlug;
  
  // Remove from index
  const indexKey = `comments:index:${articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  if (indexData) {
    const index = JSON.parse(indexData);
    index.commentIds = index.commentIds.filter(id => id !== commentId);
    await env.KV.put(indexKey, JSON.stringify(index));
  }
  
  // Delete comment
  await env.KV.delete(`comment:${commentId}`);
  
  // Sync to MinIO after delete
  await syncCommentsToMinIO(articleSlug, env);
  
  return jsonResponse({ success: true });
}

// Helper function to sync comments to MinIO
async function syncCommentsToMinIO(articleSlug, env) {
  try {
    const indexKey = `comments:index:${articleSlug}`;
    const indexData = await env.KV.get(indexKey);
    
    if (!indexData) return;
    
    const index = JSON.parse(indexData);
    const allComments = await Promise.all(
      index.commentIds.map(async (id) => {
        const data = await env.KV.get(`comment:${id}`);
        return data ? JSON.parse(data) : null;
      })
    );
    const validComments = allComments.filter(c => c !== null);
    
    const safeSlug = articleSlug.replace(/[\/\\]/g, '_');
    
    await uploadToMinIO(env, 
      `comments/${safeSlug}/comments.json`,
      JSON.stringify(validComments, null, 2)
    );
    
    console.log(`[Comments] Synced ${validComments.length} comments for ${articleSlug} to MinIO`);
  } catch (err) {
    console.error('[Comments] MinIO sync error:', err);
  }
}

// ============================================
// Annotations Handlers
// ============================================

async function handleAnnotationsGet(articleSlug, env, request) {
  const indexKey = `annotations:index:${articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  
  if (!indexData) {
    return jsonResponse({ success: true, annotations: [], total: 0 });
  }
  
  const index = JSON.parse(indexData);
  const isOwner = await verifyOwnerAuth(request, env);
  
  const annotations = await Promise.all(
    index.annotationIds.map(async (id) => {
      const annotationData = await env.KV.get(`annotation:${id}`);
      if (!annotationData) return null;
      const annotation = JSON.parse(annotationData);
      
      // Fetch linked comment if exists
      if (annotation.commentId) {
        const commentData = await env.KV.get(`comment:${annotation.commentId}`);
        if (commentData) {
          annotation.comment = JSON.parse(commentData);
        }
      }
      
      return annotation;
    })
  );
  
  // Filter: owners see all, guests see only approved annotations
  const filteredAnnotations = annotations.filter(a => {
    if (!a) return false;
    if (isOwner) return true;
    return a.comment?.status === 'approved' || !a.commentId;
  });
  
  return jsonResponse({ 
    success: true, 
    annotations: filteredAnnotations, 
    total: filteredAnnotations.length 
  });
}

async function handleAnnotationsCreate(request, env) {
  const body = await request.json();
  const { articleSlug, highlightedText, startOffset, endOffset, paragraphIndex, content, authorName, authorType } = body;
  
  if (!articleSlug || !highlightedText || startOffset === undefined || endOffset === undefined) {
    return errorResponse('articleSlug, highlightedText, startOffset, endOffset required', 400);
  }
  
  const isOwner = await verifyOwnerAuth(request, env);
  const annotationId = crypto.randomUUID();
  const commentId = content ? crypto.randomUUID() : null;
  
  // Create linked comment if content provided
  if (content && commentId) {
    const comment = {
      id: commentId,
      articleSlug,
      parentId: null,
      author: {
        id: crypto.randomUUID(),
        name: authorName || (isOwner ? 'Owner' : 'Guest'),
        domain: 'exodus.pp.ua',
        isOwner: !!isOwner,
        type: authorType || 'human',
      },
      content,
      createdAt: new Date().toISOString(),
      updatedAt: null,
      status: isOwner ? 'approved' : 'pending',
      origin: 'local',
      isAnnotation: true,
      annotationId,
    };
    
    await env.KV.put(`comment:${commentId}`, JSON.stringify(comment));
    
    // Update comments index
    const commentsIndexKey = `comments:index:${articleSlug}`;
    const commentsIndexData = await env.KV.get(commentsIndexKey);
    const commentsIndex = commentsIndexData ? JSON.parse(commentsIndexData) : { 
      articleSlug, 
      commentIds: [], 
      lastUpdated: null 
    };
    commentsIndex.commentIds.push(commentId);
    commentsIndex.lastUpdated = new Date().toISOString();
    await env.KV.put(commentsIndexKey, JSON.stringify(commentsIndex));
  }
  
  const annotation = {
    id: annotationId,
    articleSlug,
    highlightedText,
    startOffset,
    endOffset,
    paragraphIndex: paragraphIndex || 0,
    commentId,
    createdAt: new Date().toISOString(),
    createdBy: {
      id: crypto.randomUUID(),
      name: authorName || (isOwner ? 'Owner' : 'Guest'),
      domain: 'exodus.pp.ua',
      isOwner: !!isOwner,
      type: authorType || 'human',
    },
  };
  
  // Store annotation
  await env.KV.put(`annotation:${annotationId}`, JSON.stringify(annotation));
  
  // Update annotations index
  const indexKey = `annotations:index:${articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  const index = indexData ? JSON.parse(indexData) : { 
    articleSlug, 
    annotationIds: [], 
    lastUpdated: null 
  };
  
  index.annotationIds.push(annotationId);
  index.lastUpdated = new Date().toISOString();
  await env.KV.put(indexKey, JSON.stringify(index));
  
  return jsonResponse({ success: true, annotation, commentId });
}

async function handleAnnotationsDelete(annotationId, env) {
  const annotationData = await env.KV.get(`annotation:${annotationId}`);
  if (!annotationData) {
    return errorResponse('Annotation not found', 404);
  }
  
  const annotation = JSON.parse(annotationData);
  
  // Delete linked comment if exists
  if (annotation.commentId) {
    const commentData = await env.KV.get(`comment:${annotation.commentId}`);
    if (commentData) {
      const comment = JSON.parse(commentData);
      
      // Remove from comments index
      const commentsIndexKey = `comments:index:${comment.articleSlug}`;
      const commentsIndexData = await env.KV.get(commentsIndexKey);
      if (commentsIndexData) {
        const commentsIndex = JSON.parse(commentsIndexData);
        commentsIndex.commentIds = commentsIndex.commentIds.filter(id => id !== annotation.commentId);
        await env.KV.put(commentsIndexKey, JSON.stringify(commentsIndex));
      }
      
      await env.KV.delete(`comment:${annotation.commentId}`);
    }
  }
  
  // Remove from annotations index
  const indexKey = `annotations:index:${annotation.articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  if (indexData) {
    const index = JSON.parse(indexData);
    index.annotationIds = index.annotationIds.filter(id => id !== annotationId);
    await env.KV.put(indexKey, JSON.stringify(index));
  }
  
  // Delete annotation
  await env.KV.delete(`annotation:${annotationId}`);
  
  return jsonResponse({ success: true });
}

// ===================
// MCP JSON-RPC Handler
// ===================
async function handleMCPRPC(request, env) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  
  let session = null;
  if (sessionId) {
    const sessionData = await env.KV.get(`session:${sessionId}`);
    if (!sessionData) {
      return jsonResponse(createJSONRPCError(null, -32001, 'Session not found'));
    }
    session = JSON.parse(sessionData);
    
    if (new Date(session.expiresAt) < new Date()) {
      return jsonResponse(createJSONRPCError(null, -32002, 'Session expired'));
    }
  }

  const rpcRequest = await request.json();
  
  if (rpcRequest.jsonrpc !== '2.0') {
    return jsonResponse(createJSONRPCError(rpcRequest.id, -32600, 'Invalid JSON-RPC version'));
  }

  switch (rpcRequest.method) {
    case 'initialize':
      return jsonResponse(createJSONRPCResponse(rpcRequest.id, {
        protocolVersion: '2024-11-05',
        serverInfo: {
          name: 'garden-mcp-server',
          version: '3.0.0',
        },
        capabilities: {
          tools: {},
          resources: {},
        },
      }));

    case 'tools/list':
      return jsonResponse(createJSONRPCResponse(rpcRequest.id, {
        tools: getMCPTools(),
      }));

    case 'tools/call':
      const toolResult = await handleToolCall(
        rpcRequest.params,
        session,
        env
      );
      return jsonResponse(createJSONRPCResponse(rpcRequest.id, toolResult));

    case 'resources/list':
      return jsonResponse(createJSONRPCResponse(rpcRequest.id, {
        resources: session ? getSessionResources(session) : [],
      }));

    case 'resources/read':
      const resourceResult = await handleResourceRead(
        rpcRequest.params,
        session,
        env
      );
      return jsonResponse(createJSONRPCResponse(rpcRequest.id, resourceResult));

    default:
      return jsonResponse(createJSONRPCError(rpcRequest.id, -32601, `Method not found: ${rpcRequest.method}`));
  }
}

async function handleSSE(request, env, ctx) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  
  if (sessionId) {
    const sessionData = await env.KV.get(`session:${sessionId}`);
    if (!sessionData) {
      return errorResponse('Session not found', 404);
    }
  }

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();

  // Send initial connection message
  await writer.write(encoder.encode(`event: open\ndata: {\"status\":\"connected\",\"sessionId\":\"${sessionId || 'anonymous'}\"}\n\n`));

  // Send server info
  await writer.write(encoder.encode(`event: message\ndata: ${JSON.stringify({
    jsonrpc: '2.0',
    method: 'notifications/initialized',
    params: {
      serverInfo: {
        name: 'garden-mcp-server',
        version: '3.0.0',
      },
    },
  })}\n\n`));

  // Keep-alive ping every 30 seconds
  const pingInterval = setInterval(() => {
    writer.write(encoder.encode(`:ping\n\n`)).catch(() => {});
  }, 30000);

  // Clean up on close
  ctx.waitUntil(
    new Promise((resolve) => {
      setTimeout(() => {
        clearInterval(pingInterval);
        writer.close().catch(() => {});
        resolve();
      }, 3600000); // 1 hour max
    })
  );

  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ============================================
// Chats API Handlers
// ============================================

// ============================================
// Edit Proposals Handlers
// ============================================

/**
 * Proposal object shape in KV:
 * proposal:{proposalId} → {
 *   proposalId, zoneId, noteSlug, noteTitle,
 *   originalContent, proposedContent,
 *   guestName, guestEmail,
 *   status: 'pending' | 'accepted' | 'rejected',
 *   createdAt, updatedAt, reviewedAt
 * }
 *
 * Indexes:
 * proposals:zone:{zoneId} → [proposalId, ...]
 * proposals:pending → [proposalId, ...] (global pending list)
 */

async function handleProposalCreate(zoneId, request, env) {
  // Validate zone access
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) {
    return errorResponse('Zone not found', 404, { zoneId }, 'ZONE_NOT_FOUND');
  }
  
  const zone = JSON.parse(zoneData);
  
  // Check zone expiration
  if (zone.expiresAt && new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410, { zoneId }, 'ZONE_EXPIRED');
  }
  
  // Validate access code
  const providedCode = request.headers.get('X-Zone-Code');
  if (!providedCode || providedCode !== zone.accessCode) {
    return errorResponse('Invalid access code', 403, undefined, 'FORBIDDEN');
  }
  
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }
  
  const { noteSlug, noteTitle, originalContent, proposedContent, guestName, guestEmail } = body;
  
  if (!noteSlug || !proposedContent) {
    return errorResponse('noteSlug and proposedContent are required', 400, undefined, 'BAD_REQUEST');
  }
  
  // Verify note exists in zone
  const noteExists = zone.notes && zone.notes.some(n => n.slug === noteSlug);
  if (!noteExists) {
    return errorResponse('Note not found in zone', 404, { noteSlug }, 'NOT_FOUND');
  }
  
  const proposalId = `prop_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
  const now = Date.now();
  
  const proposal = {
    proposalId,
    zoneId,
    zoneName: zone.name,
    noteSlug,
    noteTitle: noteTitle || noteSlug,
    originalContent: originalContent || '',
    proposedContent,
    guestName: guestName || 'Anonymous',
    guestEmail: guestEmail || null,
    status: 'pending',
    createdAt: now,
    updatedAt: now,
    reviewedAt: null,
  };
  
  // Save proposal
  await env.KV.put(`proposal:${proposalId}`, JSON.stringify(proposal));
  
  // Add to zone proposals index
  const zoneProposalsKey = `proposals:zone:${zoneId}`;
  const zoneProposalsData = await env.KV.get(zoneProposalsKey);
  const zoneProposals = zoneProposalsData ? JSON.parse(zoneProposalsData) : [];
  zoneProposals.unshift(proposalId);
  await env.KV.put(zoneProposalsKey, JSON.stringify(zoneProposals.slice(0, 100)));
  
  // Add to global pending index
  const pendingKey = 'proposals:pending';
  const pendingData = await env.KV.get(pendingKey);
  const pending = pendingData ? JSON.parse(pendingData) : [];
  pending.unshift(proposalId);
  await env.KV.put(pendingKey, JSON.stringify(pending.slice(0, 200)));
  
  return jsonResponse({ success: true, proposal }, 201);
}

async function handleProposalsList(zoneId, request, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) {
    return errorResponse('Zone not found', 404, { zoneId }, 'ZONE_NOT_FOUND');
  }
  
  const zone = JSON.parse(zoneData);
  
  // Owner or guest with valid code can list
  const ownerPayload = await verifyOwnerAuth(request, env);
  const providedCode = request.headers.get('X-Zone-Code');
  const isOwner = !!ownerPayload;
  const isValidGuest = providedCode && zone.accessCode === providedCode;
  
  if (!isOwner && !isValidGuest) {
    return errorResponse('Unauthorized', 401, undefined, 'UNAUTHORIZED');
  }
  
  const url = new URL(request.url);
  const status = url.searchParams.get('status') || 'all';
  
  const zoneProposalsKey = `proposals:zone:${zoneId}`;
  const zoneProposalsData = await env.KV.get(zoneProposalsKey);
  const proposalIds = zoneProposalsData ? JSON.parse(zoneProposalsData) : [];
  
  const proposals = [];
  for (const id of proposalIds) {
    const data = await env.KV.get(`proposal:${id}`);
    if (data) {
      const p = JSON.parse(data);
      if (status === 'all' || p.status === status) {
        proposals.push(p);
      }
    }
  }
  
  return jsonResponse({
    success: true,
    proposals,
    total: proposals.length,
    zoneId,
    zoneName: zone.name,
  });
}

async function handleProposalsPending(env, request) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 50);
  
  const pendingData = await env.KV.get('proposals:pending');
  const pendingIds = pendingData ? JSON.parse(pendingData) : [];
  
  const proposals = [];
  for (const id of pendingIds.slice(0, limit * 2)) {
    const data = await env.KV.get(`proposal:${id}`);
    if (data) {
      const p = JSON.parse(data);
      if (p.status === 'pending') {
        proposals.push(p);
        if (proposals.length >= limit) break;
      }
    }
  }
  
  return jsonResponse({
    success: true,
    proposals,
    total: proposals.length,
  });
}

async function handleProposalGet(proposalId, request, env) {
  const data = await env.KV.get(`proposal:${proposalId}`);
  if (!data) {
    return errorResponse('Proposal not found', 404, { proposalId }, 'NOT_FOUND');
  }
  
  const proposal = JSON.parse(data);
  
  // Owner can always access; guest needs zone code
  const ownerPayload = await verifyOwnerAuth(request, env);
  if (!ownerPayload) {
    const zoneData = await env.KV.get(`zone:${proposal.zoneId}`);
    if (zoneData) {
      const zone = JSON.parse(zoneData);
      const providedCode = request.headers.get('X-Zone-Code');
      if (!providedCode || providedCode !== zone.accessCode) {
        return errorResponse('Unauthorized', 401, undefined, 'UNAUTHORIZED');
      }
    }
  }
  
  return jsonResponse({ success: true, proposal });
}

async function handleProposalAccept(proposalId, env) {
  const data = await env.KV.get(`proposal:${proposalId}`);
  if (!data) {
    return errorResponse('Proposal not found', 404, { proposalId }, 'NOT_FOUND');
  }
  
  const proposal = JSON.parse(data);
  
  if (proposal.status !== 'pending') {
    return errorResponse('Proposal already reviewed', 400, { status: proposal.status }, 'BAD_REQUEST');
  }
  
  // Update zone note with proposed content
  const zoneData = await env.KV.get(`zone:${proposal.zoneId}`);
  let updatedNote = null;
  if (zoneData) {
    const zone = JSON.parse(zoneData);
    const noteIndex = zone.notes.findIndex(n => n.slug === proposal.noteSlug);
    if (noteIndex !== -1) {
      zone.notes[noteIndex].content = proposal.proposedContent;
      updatedNote = zone.notes[noteIndex];
      await env.KV.put(`zone:${proposal.zoneId}`, JSON.stringify(zone));
      
      // Also update MinIO if exists
      try {
        const slug = safeNoteSlug(proposal.noteSlug);
        const key = `zones/${proposal.zoneId}/notes/${slug}.md`;
        const markdown = convertNoteToMarkdown({
          ...zone.notes[noteIndex],
          content: proposal.proposedContent,
        });
        await uploadToMinIO(env, key, markdown, 'text/markdown');
      } catch (err) {
        console.error('[Proposals] MinIO update failed (non-fatal):', err);
      }
    }
  }
  
  // Update proposal status
  proposal.status = 'accepted';
  proposal.reviewedAt = Date.now();
  proposal.updatedAt = Date.now();
  await env.KV.put(`proposal:${proposalId}`, JSON.stringify(proposal));
  
  // Remove from pending index
  const pendingData = await env.KV.get('proposals:pending');
  if (pendingData) {
    const pending = JSON.parse(pendingData).filter(id => id !== proposalId);
    await env.KV.put('proposals:pending', JSON.stringify(pending));
  }
  
  // ============================================
  // GitHub Commit via Replit Backend
  // ============================================
  let gitCommitResult = null;
  if (updatedNote) {
    try {
      // noteSlug already contains the full path like "exodus.pp.ua/SSH транссфер/ПРОМТ..."
      // We need to decode it and use it directly
      const decodedSlug = decodeURIComponent(proposal.noteSlug);
      const filePath = `src/site/notes/${decodedSlug}.md`;
      const markdown = convertNoteToMarkdown({
        ...updatedNote,
        content: proposal.proposedContent,
      });
      const commitMessage = `docs: accept edit proposal for "${proposal.noteTitle}" by ${proposal.guestName}`;
      
      console.log('[Proposals] Attempting GitHub commit:', { filePath, messageLength: markdown.length });
      
      const gitRes = await fetchNotebookLM(env, '/v1/git/commit', {
        method: 'POST',
        body: JSON.stringify({
          path: filePath,  // Replit API expects "path", not "file_path"
          content: markdown,
          message: commitMessage,
        }),
      });
      
      if (gitRes.ok) {
        gitCommitResult = {
          success: true,
          sha: gitRes.data?.sha,
          url: gitRes.data?.url,
        };
        console.log('[Proposals] GitHub commit successful:', gitRes.data?.sha);
      } else {
        // Extract error message from various possible formats
        const errData = gitRes.data;
        const errorMessage =
          errData?.error?.message || // Replit format: { error: { message: ... } }
          errData?.detail || // FastAPI validation: { detail: ... }
          errData?.error || // Simple format: { error: "..." }
          errData?.message || // Alternative: { message: "..." }
          `Git commit failed (HTTP ${gitRes.status})`;

        gitCommitResult = {
          success: false,
          error: errorMessage,
          status: gitRes.status,
          hint: errData?.hint,
          fullResponse: errData,
        };
        console.warn('[Proposals] GitHub commit failed (non-fatal):', JSON.stringify(gitRes));
      }
    } catch (err) {
      gitCommitResult = { success: false, error: err?.message || String(err) };
      console.error('[Proposals] GitHub commit error (non-fatal):', err);
    }
  }
  
  // Create notification message in zone chat (if chat exists)
  try {
    const zoneChatsData = await env.KV.get(`zone_chats:${proposal.zoneId}`);
    if (zoneChatsData) {
      const chatIds = JSON.parse(zoneChatsData);
      if (chatIds.length > 0) {
        const notifText = `✅ Edit accepted: "${proposal.noteTitle}" by ${proposal.guestName}`;
        for (const chatId of chatIds.slice(0, 3)) {
          const chatData = await env.KV.get(`chat:${chatId}`);
          if (chatData) {
            const chat = JSON.parse(chatData);
            chat.lastMessagePreview = notifText;
            chat.lastMessageAt = Date.now();
            chat.updatedAt = Date.now();
            await env.KV.put(`chat:${chatId}`, JSON.stringify(chat));
          }
        }
      }
    }
  } catch (err) {
    console.error('[Proposals] Chat notification failed (non-fatal):', err);
  }
  
  return jsonResponse({ success: true, proposal, gitCommit: gitCommitResult, gitCommitResult });
}

// ============================================
// Notes Management Handlers (GitHub Commits)
// ============================================

/**
 * POST /v1/notes/commit
 * Create or update a note in GitHub repository.
 * Body: { slug, title, content, tags, folder, isNew }
 */
async function handleNoteCommit(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, undefined, 'BAD_REQUEST');
  }

  const { slug, title, content, tags = [], folder, isNew } = body;

  if (!title || typeof title !== 'string') {
    return errorResponse('Title is required', 400, undefined, 'BAD_REQUEST');
  }
  if (typeof content !== 'string') {
    return errorResponse('Content is required', 400, undefined, 'BAD_REQUEST');
  }

  // Build file path
  // slug might be provided for existing notes, or we generate from folder + title for new ones
  let filePath;
  if (slug && !isNew) {
    const decodedSlug = decodeURIComponent(slug);
    filePath = `src/site/notes/${decodedSlug}.md`;
  } else {
    // New note: use folder + title
    const safeTitle = title.trim();
    const fullPath = folder ? `${folder}/${safeTitle}` : safeTitle;
    filePath = `src/site/notes/${fullPath}.md`;
  }

  // Build markdown with frontmatter
  const now = new Date().toISOString();
  const frontmatter = [
    '---',
    `title: "${title.replace(/"/g, '\\"')}"`,
    tags.length > 0 ? `tags: [${tags.map(t => `"${t}"`).join(', ')}]` : 'tags: []',
    `created: "${now}"`,
    `updated: "${now}"`,
    'dg-publish: true',
    '---',
    '',
  ].join('\n');

  const markdown = frontmatter + content;
  const commitMessage = isNew
    ? `docs: create note "${title}"`
    : `docs: update note "${title}"`;

  console.log('[Notes] Committing to GitHub:', { filePath, isNew, contentLength: markdown.length });

  try {
    const gitRes = await fetchNotebookLM(env, '/v1/git/commit', {
      method: 'POST',
      body: JSON.stringify({
        path: filePath,
        content: markdown,
        message: commitMessage,
      }),
    });

    if (gitRes.ok) {
      console.log('[Notes] GitHub commit successful:', gitRes.data?.sha);
      return jsonResponse({
        success: true,
        sha: gitRes.data?.sha,
        url: gitRes.data?.url,
        path: filePath,
      });
    } else {
      const errData = gitRes.data;
      const errorMessage =
        errData?.error?.message ||
        errData?.detail ||
        errData?.error ||
        errData?.message ||
        `Git commit failed (HTTP ${gitRes.status})`;

      console.error('[Notes] GitHub commit failed:', JSON.stringify(gitRes));
      return errorResponse(errorMessage, gitRes.status || 500, {
        hint: errData?.hint,
        path: filePath,
      }, 'GIT_COMMIT_FAILED');
    }
  } catch (err) {
    console.error('[Notes] GitHub commit error:', err);
    return errorResponse(`Git commit error: ${err?.message || String(err)}`, 500, undefined, 'GIT_ERROR');
  }
}

/**
 * DELETE /v1/notes/:slug
 * Delete a note from GitHub repository.
 */
async function handleNoteDelete(slug, env) {
  const decodedSlug = decodeURIComponent(slug);
  const filePath = `src/site/notes/${decodedSlug}.md`;
  const commitMessage = `docs: delete note "${decodedSlug.split('/').pop() || decodedSlug}"`;

  console.log('[Notes] Deleting from GitHub:', { filePath });

  try {
    const gitRes = await fetchNotebookLM(env, '/v1/git/delete', {
      method: 'POST',
      body: JSON.stringify({
        path: filePath,
        message: commitMessage,
      }),
    });

    if (gitRes.ok) {
      console.log('[Notes] GitHub delete successful');
      return jsonResponse({
        success: true,
        sha: gitRes.data?.sha,
        path: filePath,
      });
    } else {
      const errData = gitRes.data;
      const errorMessage =
        errData?.error?.message ||
        errData?.detail ||
        errData?.error ||
        errData?.message ||
        `Git delete failed (HTTP ${gitRes.status})`;

      // 404 might mean file doesn't exist in repo yet (only local)
      if (gitRes.status === 404) {
        console.log('[Notes] File not found in repo, treating as success');
        return jsonResponse({
          success: true,
          path: filePath,
          note: 'File was not in repository',
        });
      }

      console.error('[Notes] GitHub delete failed:', JSON.stringify(gitRes));
      return errorResponse(errorMessage, gitRes.status || 500, {
        hint: errData?.hint,
        path: filePath,
      }, 'GIT_DELETE_FAILED');
    }
  } catch (err) {
    console.error('[Notes] GitHub delete error:', err);
    return errorResponse(`Git delete error: ${err?.message || String(err)}`, 500, undefined, 'GIT_ERROR');
  }
}

/**
 * GET /v1/git/status?path=...
 * Check if a file exists in GitHub repository.
 * Public endpoint (no auth required) - used to show "syncing" message for new notes.
 */
async function handleGitStatus(request, env) {
  const url = new URL(request.url);
  const path = url.searchParams.get('path');

  if (!path) {
    return errorResponse('path query parameter is required', 400, undefined, 'MISSING_PATH');
  }

  // Security: only allow checking files in src/site/notes/
  if (!path.startsWith('src/site/notes/')) {
    return errorResponse('Path must start with src/site/notes/', 400, undefined, 'INVALID_PATH');
  }

  console.log('[GitStatus] Checking file existence:', { path });

  try {
    const gitRes = await fetchNotebookLM(env, `/v1/git/status?path=${encodeURIComponent(path)}`, {
      method: 'GET',
    });

    if (gitRes.ok) {
      return jsonResponse({
        exists: gitRes.data?.exists ?? false,
        path: path,
        sha: gitRes.data?.sha,
      });
    } else {
      // If backend returns 404 - file doesn't exist
      if (gitRes.status === 404) {
        return jsonResponse({
          exists: false,
          path: path,
        });
      }
      
      console.error('[GitStatus] Backend error:', JSON.stringify(gitRes));
      return errorResponse(
        gitRes.data?.error || `Git status check failed (HTTP ${gitRes.status})`,
        gitRes.status || 500,
        undefined,
        'GIT_STATUS_FAILED'
      );
    }
  } catch (err) {
    console.error('[GitStatus] Error:', err);
    return errorResponse(`Git status error: ${err?.message || String(err)}`, 500, undefined, 'GIT_ERROR');
  }
}

// ============================================
// DRAKON Diagrams Handlers
// ============================================

/**
 * POST /v1/drakon/commit
 * Create or update a DRAKON diagram in GitHub repository.
 * Diagrams are stored as JSON files in src/site/notes/{folderSlug}/diagrams/{diagramId}.drakon.json
 */
async function handleDrakonCommit(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }

  const { folderSlug, diagramId, diagram, name, isNew } = body;

  // Validate diagramId
  if (!diagramId || typeof diagramId !== 'string') {
    return errorResponse('diagramId is required', 400, undefined, 'MISSING_DIAGRAM_ID');
  }

  if (!/^[a-zA-Z0-9_-]+$/.test(diagramId)) {
    return errorResponse('diagramId must be alphanumeric with dashes/underscores only', 400, undefined, 'INVALID_DIAGRAM_ID');
  }

  if (!diagram || typeof diagram !== 'object') {
    return errorResponse('diagram object is required', 400, undefined, 'MISSING_DIAGRAM');
  }

  // Build file path
  let filePath;
  if (folderSlug && typeof folderSlug === 'string' && folderSlug.trim()) {
    // Decode URL-encoded slug (may contain Cyrillic, slashes, etc.)
    let decodedSlug = folderSlug;
    try {
      decodedSlug = decodeURIComponent(folderSlug);
    } catch {
      // keep as-is
    }
    filePath = `src/site/notes/${decodedSlug}/diagrams/${diagramId}.drakon.json`;
  } else {
    // Root-level diagrams (standalone)
    filePath = `src/site/notes/diagrams/${diagramId}.drakon.json`;
  }

  // Serialize diagram with formatting
  const diagramContent = JSON.stringify(diagram, null, 2);
  const diagramName = name || diagram.name || diagramId;
  const commitMessage = `chore(drakon): ${isNew ? 'create' : 'update'} ${diagramName}`;

  console.log('[DRAKON] Committing to GitHub:', { filePath, diagramId, isNew });

  try {
    const gitRes = await fetchNotebookLM(env, '/v1/git/commit', {
      method: 'POST',
      body: JSON.stringify({
        path: filePath,
        content: diagramContent,
        message: commitMessage,
      }),
    });

    if (gitRes.ok) {
      console.log('[DRAKON] GitHub commit successful');
      return jsonResponse({
        success: true,
        sha: gitRes.data?.sha,
        url: gitRes.data?.url,
        path: filePath,
      });
    } else {
      const errData = gitRes.data;
      const errorMessage =
        errData?.error?.message ||
        errData?.detail ||
        errData?.error ||
        errData?.message ||
        `Git commit failed (HTTP ${gitRes.status})`;

      console.error('[DRAKON] GitHub commit failed:', JSON.stringify(gitRes));
      return errorResponse(errorMessage, gitRes.status || 500, {
        hint: errData?.hint,
        path: filePath,
      }, 'GIT_COMMIT_FAILED');
    }
  } catch (err) {
    console.error('[DRAKON] GitHub commit error:', err);
    return errorResponse(`Git commit error: ${err?.message || String(err)}`, 500, undefined, 'GIT_ERROR');
  }
}

/**
 * DELETE /v1/drakon/:folderSlug/:diagramId
 * Delete a DRAKON diagram from GitHub repository.
 */
async function handleDrakonDelete(folderSlug, diagramId, env) {
  // Build file path
  let filePath;
  if (folderSlug && folderSlug !== '_root') {
    filePath = `src/site/notes/${folderSlug}/diagrams/${diagramId}.drakon.json`;
  } else {
    filePath = `src/site/notes/diagrams/${diagramId}.drakon.json`;
  }

  const commitMessage = `chore(drakon): delete ${diagramId}`;

  console.log('[DRAKON] Deleting from GitHub:', { filePath, diagramId });

  try {
    const gitRes = await fetchNotebookLM(env, '/v1/git/delete', {
      method: 'POST',
      body: JSON.stringify({
        path: filePath,
        message: commitMessage,
      }),
    });

    if (gitRes.ok) {
      console.log('[DRAKON] GitHub delete successful');
      return jsonResponse({
        success: true,
        sha: gitRes.data?.sha,
        path: filePath,
      });
    } else {
      // 404 might mean file doesn't exist in repo
      if (gitRes.status === 404) {
        console.log('[DRAKON] File not found in repo, treating as success');
        return jsonResponse({
          success: true,
          path: filePath,
          note: 'File was not in repository',
        });
      }

      const errData = gitRes.data;
      const errorMessage =
        errData?.error?.message ||
        errData?.detail ||
        errData?.error ||
        errData?.message ||
        `Git delete failed (HTTP ${gitRes.status})`;

      console.error('[DRAKON] GitHub delete failed:', JSON.stringify(gitRes));
      return errorResponse(errorMessage, gitRes.status || 500, {
        hint: errData?.hint,
        path: filePath,
      }, 'GIT_DELETE_FAILED');
    }
  } catch (err) {
    console.error('[DRAKON] GitHub delete error:', err);
    return errorResponse(`Git delete error: ${err?.message || String(err)}`, 500, undefined, 'GIT_ERROR');
  }
}

async function handleProposalReject(proposalId, env) {
  const data = await env.KV.get(`proposal:${proposalId}`);
  if (!data) {
    return errorResponse('Proposal not found', 404, { proposalId }, 'NOT_FOUND');
  }
  
  const proposal = JSON.parse(data);
  
  if (proposal.status !== 'pending') {
    return errorResponse('Proposal already reviewed', 400, { status: proposal.status }, 'BAD_REQUEST');
  }
  
  proposal.status = 'rejected';
  proposal.reviewedAt = Date.now();
  proposal.updatedAt = Date.now();
  await env.KV.put(`proposal:${proposalId}`, JSON.stringify(proposal));
  
  // Remove from pending index
  const pendingData = await env.KV.get('proposals:pending');
  if (pendingData) {
    const pending = JSON.parse(pendingData).filter(id => id !== proposalId);
    await env.KV.put('proposals:pending', JSON.stringify(pending));
  }
  
  return jsonResponse({ success: true, proposal });
}

// ============================================
// Chats API Handlers (continued)
// ============================================

/**
 * Chat metadata stored in KV:
 * - chat:{chatId} → full chat object
 * - chats:recent → array of last 100 chatIds (ordered by lastMessageAt desc)
 * - zone_chats:{zoneId} → array of chatIds for that zone
 *
 * Chat object shape:
 * {
 *   chatId, title, zoneId, zoneName, notebookUrl,
 *   lastMessagePreview, lastMessageAt, unreadCount,
 *   status: 'active' | 'archived',
 *   accessType: 'web' | 'mcp' | 'both',
 *   expiresAt, createdAt, updatedAt, pinned
 * }
 */

async function getOrCreateChatsIndex(env, key) {
  const data = await env.KV.get(key);
  return data ? JSON.parse(data) : [];
}

async function handleChatsRecent(env, request) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 50);
  const status = url.searchParams.get('status') || 'all'; // active, archived, all

  const recentIndex = await getOrCreateChatsIndex(env, 'chats:recent');
  
  // Fetch chat objects
  const chats = [];
  for (const chatId of recentIndex.slice(0, 100)) {
    const chatData = await env.KV.get(`chat:${chatId}`);
    if (chatData) {
      const chat = JSON.parse(chatData);
      // Filter by status
      if (status === 'all' || chat.status === status || (!chat.status && status === 'active')) {
        chats.push(chat);
      }
    }
  }

  // Sort by pinned first, then lastMessageAt desc
  chats.sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return (b.lastMessageAt || 0) - (a.lastMessageAt || 0);
  });

  return jsonResponse({
    success: true,
    chats: chats.slice(0, limit),
    total: chats.length,
  });
}

async function handleZoneChats(zoneId, env, request) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 50);
  const status = url.searchParams.get('status') || 'all';

  // Validate zone exists
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  if (!zoneData) {
    return errorResponse('Zone not found', 404, { zoneId }, 'ZONE_NOT_FOUND');
  }
  const zone = JSON.parse(zoneData);

  // Check zone expiration
  if (zone.expiresAt && new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410, { zoneId, expiresAt: zone.expiresAt }, 'ZONE_EXPIRED');
  }

  // Guest access validation (X-Zone-Code header)
  const providedCode = request.headers.get('X-Zone-Code');
  const ownerPayload = await verifyOwnerAuth(request, env);
  const isOwner = !!ownerPayload;
  const isValidGuest = providedCode && zone.accessCode === providedCode;

  if (!isOwner && !isValidGuest) {
    return errorResponse('Unauthorized: provide valid zone code or owner token', 401, undefined, 'UNAUTHORIZED');
  }

  const zoneChatsIndex = await getOrCreateChatsIndex(env, `zone_chats:${zoneId}`);

  const chats = [];
  for (const chatId of zoneChatsIndex) {
    const chatData = await env.KV.get(`chat:${chatId}`);
    if (chatData) {
      const chat = JSON.parse(chatData);
      if (status === 'all' || chat.status === status || (!chat.status && status === 'active')) {
        chats.push(chat);
      }
    }
  }

  // Sort
  chats.sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return (b.lastMessageAt || 0) - (a.lastMessageAt || 0);
  });

  return jsonResponse({
    success: true,
    chats: chats.slice(0, limit),
    total: chats.length,
    zoneId,
    zoneName: zone.name,
  });
}

async function handleChatTouch(chatId, env, request) {
  const chatData = await env.KV.get(`chat:${chatId}`);
  if (!chatData) {
    return errorResponse('Chat not found', 404, { chatId }, 'NOT_FOUND');
  }

  const chat = JSON.parse(chatData);

  let body = {};
  try {
    body = await request.json();
  } catch {
    // empty body ok
  }

  // Update fields
  const now = Date.now();
  if (body.lastMessagePreview !== undefined) {
    chat.lastMessagePreview = String(body.lastMessagePreview).slice(0, 200);
  }
  if (body.lastMessageAt !== undefined) {
    chat.lastMessageAt = body.lastMessageAt;
  } else {
    chat.lastMessageAt = now;
  }
  if (body.unreadCount !== undefined) {
    chat.unreadCount = Math.max(0, parseInt(body.unreadCount, 10) || 0);
  }
  chat.updatedAt = now;

  // Save
  await env.KV.put(`chat:${chatId}`, JSON.stringify(chat));

  // Update recent index (move to front)
  const recentIndex = await getOrCreateChatsIndex(env, 'chats:recent');
  const filtered = recentIndex.filter((id) => id !== chatId);
  filtered.unshift(chatId);
  await env.KV.put('chats:recent', JSON.stringify(filtered.slice(0, 100)));

  return jsonResponse({ success: true, chat });
}

async function handleChatPatch(chatId, env, request) {
  const chatData = await env.KV.get(`chat:${chatId}`);
  if (!chatData) {
    return errorResponse('Chat not found', 404, { chatId }, 'NOT_FOUND');
  }

  const chat = JSON.parse(chatData);

  let body = {};
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }

  // Allowed updates
  if (body.pinned !== undefined) {
    chat.pinned = !!body.pinned;
  }
  if (body.status !== undefined && ['active', 'archived'].includes(body.status)) {
    chat.status = body.status;
  }
  if (body.unreadCount !== undefined) {
    chat.unreadCount = Math.max(0, parseInt(body.unreadCount, 10) || 0);
  }
  if (body.title !== undefined) {
    chat.title = String(body.title).slice(0, 100);
  }
  chat.updatedAt = Date.now();

  await env.KV.put(`chat:${chatId}`, JSON.stringify(chat));

  return jsonResponse({ success: true, chat });
}

async function handleChatCreate(env, request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }

  const chatId = `chat_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
  const now = Date.now();

  const chat = {
    chatId,
    title: String(body.title || 'New Chat').slice(0, 100),
    zoneId: body.zoneId || null,
    zoneName: body.zoneName || null,
    notebookUrl: body.notebookUrl || null,
    lastMessagePreview: null,
    lastMessageAt: now,
    unreadCount: 0,
    status: 'active',
    accessType: body.accessType || 'web',
    expiresAt: body.expiresAt || null,
    createdAt: now,
    updatedAt: now,
    pinned: false,
  };

  await env.KV.put(`chat:${chatId}`, JSON.stringify(chat));

  // Add to recent index
  const recentIndex = await getOrCreateChatsIndex(env, 'chats:recent');
  recentIndex.unshift(chatId);
  await env.KV.put('chats:recent', JSON.stringify(recentIndex.slice(0, 100)));

  // Add to zone index if zoneId provided
  if (chat.zoneId) {
    const zoneChatsIndex = await getOrCreateChatsIndex(env, `zone_chats:${chat.zoneId}`);
    if (!zoneChatsIndex.includes(chatId)) {
      zoneChatsIndex.unshift(chatId);
      await env.KV.put(`zone_chats:${chat.zoneId}`, JSON.stringify(zoneChatsIndex));
    }
  }

  return jsonResponse({ success: true, chat }, 201);
}

// ============================================
// Auth Middleware Helper
// ============================================

async function verifyOwnerAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  
  if (!payload || payload.role !== 'owner') {
    return null;
  }
  
  return payload;
}

// ============================================
// Main Router
// ============================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const host = request.headers.get('host') || 'localhost';

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return corsResponse();
    }

    try {
      // ============================================
      // PUBLIC ENDPOINTS
      // ============================================
      
      // GET /health
      if (method === 'GET' && path === '/health') {
        return await handleHealth();
      }

      // POST /auth/status
      if (method === 'POST' && path === '/auth/status') {
        return await handleAuthStatus(env);
      }

      // POST /auth/setup
      if (method === 'POST' && path === '/auth/setup') {
        return await handleAuthSetup(request, env);
      }

      // POST /auth/login
      if (method === 'POST' && path === '/auth/login') {
        return await handleAuthLogin(request, env);
      }

      // POST /auth/refresh
      if (method === 'POST' && path === '/auth/refresh') {
        return await handleAuthRefresh(request, env);
      }

      // POST /auth/validate
      if (method === 'POST' && path === '/auth/validate') {
        return await handleAuthValidate(request, env);
      }

      // ============================================
      // ZONE PUBLIC ENDPOINTS
      // ============================================
      
      // GET /zones/validate/:zoneId
      const validateMatch = path.match(/^\/zones\/validate\/([^\/]+)$/);
      if (method === 'GET' && validateMatch) {
        return await handleZonesValidate(validateMatch[1], env, request);
      }

      // GET /zones/:zoneId/notes
      const zoneNotesMatch = path.match(/^\/zones\/([^\/]+)\/notes$/);
      if (method === 'GET' && zoneNotesMatch) {
        return await handleZonesNotes(zoneNotesMatch[1], env);
      }

      // ============================================
      // NOTEBOOKLM ZONE ENDPOINTS (public)
      // ============================================

      // GET /zones/:zoneId/notebooklm
      const zoneNotebookLMMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm$/);
      if (method === 'GET' && zoneNotebookLMMatch) {
        return await handleZoneNotebookLMStatus(zoneNotebookLMMatch[1], env);
      }

      // GET /zones/:zoneId/notebooklm/job/:jobId
      const zoneNotebookLMJobMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm\/job\/([^\/]+)$/);
      if (method === 'GET' && zoneNotebookLMJobMatch) {
        return await handleZoneNotebookLMJobStatus(zoneNotebookLMJobMatch[1], zoneNotebookLMJobMatch[2], env);
      }

      // POST /zones/:zoneId/notebooklm/retry-import (owner-only)
      const zoneNotebookLMRetryMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm\/retry-import$/);
      if (method === 'POST' && zoneNotebookLMRetryMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401);
        }
        return await handleZoneNotebookLMRetryImport(zoneNotebookLMRetryMatch[1], env);
      }

      // POST /zones/:zoneId/notebooklm/chat (guest access via zone code)
      const zoneNotebookLMChatMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm\/chat$/);
      if (method === 'POST' && zoneNotebookLMChatMatch) {
        return await handleZoneNotebookLMChat(zoneNotebookLMChatMatch[1], request, env);
      }

      // POST /notebooklm/chat (owner-only)
      if (method === 'POST' && path === '/notebooklm/chat') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401);
        }
        return await handleNotebookLMChat(request, env);
      }

      // ============================================
      // CHATS ENDPOINTS
      // ============================================

      // GET /v1/chats/recent - owner only, list all recent chats
      if (method === 'GET' && path === '/v1/chats/recent') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleChatsRecent(env, request);
      }

      // POST /v1/chats - create new chat (owner only)
      if (method === 'POST' && path === '/v1/chats') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleChatCreate(env, request);
      }

      // GET /v1/zones/:zoneId/chats - list chats for zone (owner or guest with code)
      const zoneChatsMatch = path.match(/^\/v1\/zones\/([^\/]+)\/chats$/);
      if (method === 'GET' && zoneChatsMatch) {
        return await handleZoneChats(zoneChatsMatch[1], env, request);
      }

      // POST /v1/chats/:chatId/touch - update lastMessage/activity (owner only)
      const chatTouchMatch = path.match(/^\/v1\/chats\/([^\/]+)\/touch$/);
      if (method === 'POST' && chatTouchMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleChatTouch(chatTouchMatch[1], env, request);
      }

      // PATCH /v1/chats/:chatId - update chat (pin/archive/title) (owner only)
      const chatPatchMatch = path.match(/^\/v1\/chats\/([^\/]+)$/);
      if (method === 'PATCH' && chatPatchMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleChatPatch(chatPatchMatch[1], env, request);
      }

      // ============================================
      // SESSION-BASED ENDPOINTS
      // ============================================
      
      // POST /mcp
      if (method === 'POST' && path === '/mcp') {
        return await handleMCP(request, env);
      }

      // GET /sse
      if (method === 'GET' && path === '/sse') {
        return await handleSSE(request, env, ctx);
      }

      // ============================================
      // COMMENTS ENDPOINTS
      // ============================================
      
      // GET /comments/:articleSlug
      const commentsGetMatch = path.match(/^\/comments\/(.+)$/);
      if (method === 'GET' && commentsGetMatch && !path.includes('/create')) {
        return await handleCommentsGet(decodeURIComponent(commentsGetMatch[1]), env, request);
      }

      // POST /comments/create
      if (method === 'POST' && path === '/comments/create') {
        return await handleCommentsCreate(request, env);
      }

      // PATCH /comments/:commentId
      const commentsPatchMatch = path.match(/^\/comments\/([a-f0-9-]+)$/);
      if (method === 'PATCH' && commentsPatchMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized', 401);
        }
        return await handleCommentsUpdate(commentsPatchMatch[1], request, env);
      }

      // DELETE /comments/:commentId
      const commentsDeleteMatch = path.match(/^\/comments\/([a-f0-9-]+)$/);
      if (method === 'DELETE' && commentsDeleteMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized', 401);
        }
        return await handleCommentsDelete(commentsDeleteMatch[1], env);
      }

      // ============================================
      // ANNOTATIONS ENDPOINTS
      // ============================================
      
      // GET /annotations/:articleSlug
      const annotationsGetMatch = path.match(/^\/annotations\/(.+)$/);
      if (method === 'GET' && annotationsGetMatch && !path.includes('/create')) {
        return await handleAnnotationsGet(decodeURIComponent(annotationsGetMatch[1]), env, request);
      }

      // POST /annotations/create
      if (method === 'POST' && path === '/annotations/create') {
        return await handleAnnotationsCreate(request, env);
      }

      // DELETE /annotations/:annotationId
      const annotationsDeleteMatch = path.match(/^\/annotations\/([a-f0-9-]+)$/);
      if (method === 'DELETE' && annotationsDeleteMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized', 401);
        }
        return await handleAnnotationsDelete(annotationsDeleteMatch[1], env);
      }

      // ============================================
      // OWNER-PROTECTED ENDPOINTS
      // ============================================
      
      // Check owner auth for protected routes
      const isProtectedRoute = 
        (method === 'POST' && path === '/sessions/create') ||
        (method === 'POST' && path === '/sessions/revoke') ||
        (method === 'GET' && path === '/sessions/list') ||
        (method === 'POST' && path === '/zones/create') ||
        (method === 'POST' && path === '/notebooklm/chat') ||
        (method === 'DELETE' && path.match(/^\/zones\/[^\/]+$/)) ||
        (method === 'GET' && path.match(/^\/zones\/[^\/]+\/download$/)) ||
        (method === 'GET' && path === '/zones/list');

      if (isProtectedRoute) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401);
        }
      }

      // POST /sessions/create
      if (method === 'POST' && path === '/sessions/create') {
        return await handleSessionsCreate(request, env, host);
      }

      // POST /sessions/revoke
      if (method === 'POST' && path === '/sessions/revoke') {
        return await handleSessionsRevoke(request, env);
      }

      // GET /sessions/list
      if (method === 'GET' && path === '/sessions/list') {
        return await handleSessionsList(env);
      }

      // POST /zones/create
      if (method === 'POST' && path === '/zones/create') {
        return await handleZonesCreate(request, env, host);
      }

      // DELETE /zones/:zoneId
      const zoneDeleteMatch = path.match(/^\/zones\/([^\/]+)$/);
      if (method === 'DELETE' && zoneDeleteMatch) {
        return await handleZonesDelete(zoneDeleteMatch[1], env);
      }

      // GET /zones/:zoneId/download (owner-only, proxy to Replit)
      const zoneDownloadMatch = path.match(/^\/zones\/([^\/]+)\/download$/);
      if (method === 'GET' && zoneDownloadMatch) {
        const zoneId = zoneDownloadMatch[1];
        try {
          const resp = await fetchNotebookLM(env, `/v1/zones/${zoneId}/download`);
          if (!resp.ok) {
            return errorResponse(`Download failed: ${resp.status}`, resp.status);
          }
          // resp.data is the text content (fetchNotebookLM consumes the body)
          const content = resp.data || '';
          return new Response(content, {
            status: 200,
            headers: {
              'Content-Type': 'text/markdown; charset=utf-8',
              'Content-Disposition': `attachment; filename="notes-all.md"`,
              'Access-Control-Allow-Origin': '*',
            },
          });
        } catch (e) {
          return errorResponse(`Download error: ${e.message}`, 502);
        }
      }

      // GET /zones/list
      if (method === 'GET' && path === '/zones/list') {
        return await handleZonesList(env);
      }

      // ============================================
      // 404 Not Found
      // ============================================
      // ============================================
      // EDIT PROPOSALS ENDPOINTS
      // ============================================
      
      // POST /zones/:zoneId/proposals - Guest submits edit proposal
      const proposalCreateMatch = path.match(/^\/zones\/([^\/]+)\/proposals$/);
      if (method === 'POST' && proposalCreateMatch) {
        return await handleProposalCreate(proposalCreateMatch[1], request, env);
      }

      // GET /zones/:zoneId/proposals - List proposals for zone (owner or guest with code)
      if (method === 'GET' && proposalCreateMatch) {
        return await handleProposalsList(proposalCreateMatch[1], request, env);
      }

      // GET /proposals/pending - Owner lists all pending proposals
      if (method === 'GET' && path === '/proposals/pending') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleProposalsPending(env, request);
      }

      // GET /proposals/:proposalId - Get single proposal
      const proposalGetMatch = path.match(/^\/proposals\/([^\/]+)$/);
      if (method === 'GET' && proposalGetMatch) {
        return await handleProposalGet(proposalGetMatch[1], request, env);
      }

      // POST /proposals/:proposalId/accept - Owner accepts proposal
      const proposalAcceptMatch = path.match(/^\/proposals\/([^\/]+)\/accept$/);
      if (method === 'POST' && proposalAcceptMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleProposalAccept(proposalAcceptMatch[1], env);
      }

      // POST /proposals/:proposalId/reject - Owner rejects proposal
      const proposalRejectMatch = path.match(/^\/proposals\/([^\/]+)\/reject$/);
      if (method === 'POST' && proposalRejectMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleProposalReject(proposalRejectMatch[1], env);
      }

      // ============================================
      // NOTES MANAGEMENT ENDPOINTS (Owner only)
      // ============================================

      // POST /v1/notes/commit - Create or update note via GitHub
      if (method === 'POST' && path === '/v1/notes/commit') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleNoteCommit(request, env);
      }

      // DELETE /v1/notes/:slug - Delete note via GitHub
      const noteDeleteMatch = path.match(/^\/v1\/notes\/(.+)$/);
      if (method === 'DELETE' && noteDeleteMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleNoteDelete(decodeURIComponent(noteDeleteMatch[1]), env);
      }

      // GET /v1/git/status - Check if file exists in GitHub (public, no auth required)
      if (method === 'GET' && path.startsWith('/v1/git/status')) {
        return await handleGitStatus(request, env);
      }

      // ============================================
      // DRAKON DIAGRAMS ENDPOINTS (Owner only, proxy to Replit)
      // ============================================

      // POST /v1/drakon/commit - Create/update DRAKON diagram via GitHub
      if (method === 'POST' && path === '/v1/drakon/commit') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        return await handleDrakonCommit(request, env);
      }

      // DELETE /v1/drakon/:folderSlug/:diagramId - Delete DRAKON diagram
      const drakonDeleteMatch = path.match(/^\/v1\/drakon\/([^\/]+)\/([^\/]+)$/);
      if (method === 'DELETE' && drakonDeleteMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401, undefined, 'UNAUTHORIZED');
        }
        const folderSlug = decodeURIComponent(drakonDeleteMatch[1]);
        const diagramId = decodeURIComponent(drakonDeleteMatch[2]);
        return await handleDrakonDelete(folderSlug, diagramId, env);
      }

      return errorResponse('Not found', 404);

    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse(`Internal error: ${err.message}`, 500);
    }
  }
};
