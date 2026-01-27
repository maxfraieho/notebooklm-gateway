// ============================================
// Garden MCP Worker v3.0 - Vanilla Cloudflare Workers
// NO EXTERNAL DEPENDENCIES - Pure ES2022 JavaScript
// FIXED: 2026-01-27 - notebookUrl field name + 120s chat timeout
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
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Id, X-Zone-Id, X-Zone-Code',
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
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Id, X-Zone-Id, X-Zone-Code',
      'Access-Control-Max-Age': '86400'
    }
  });
}

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

function encodeS3KeyForPath(key) {
  return String(key || '')
    .split('/')
    .map((seg) => encodeURIComponent(seg))
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

async function uploadToMinIO(env, path, content, contentType = 'application/json; charset=utf-8') {
  const endpoint = env.MINIO_ENDPOINT;
  const bucket = env.MINIO_BUCKET;
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
    throw new Error(`MinIO upload failed: ${response.status} - ${errorText}`);
  }
  
  return { bucket, key, url };
}

function safeNoteSlug(slug) {
  let s = String(slug || 'untitled').trim();
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

async function syncZoneNotesToMinIO(env, zoneId, notes) {
  const list = Array.isArray(notes) ? notes : [];
  const keys = [];

  for (const n of list) {
    const slug = safeNoteSlug(n?.slug || n?.title);
    const key = `zones/${zoneId}/notes/${slug}.md`;
    const markdown = convertNoteToMarkdown(n);
    await uploadToMinIO(env, key, markdown, 'text/markdown');
    keys.push(key);
  }

  return keys;
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
 * fetchNotebookLM(env, path, init, customTimeoutMs)
 * - Uses env.NOTEBOOKLM_BASE_URL OR fallback https://notebooklm-gateway.replit.app
 * - Timeout via customTimeoutMs param, or env.NOTEBOOKLM_TIMEOUT_MS (default 15000)
 * - Optional Bearer via env.NOTEBOOKLM_SERVICE_TOKEN
 * - Never throws for HTTP errors: returns { ok:false, status, data }
 */
async function fetchNotebookLM(env, path, init = {}, customTimeoutMs = null) {
  const baseUrl = (env.NOTEBOOKLM_BASE_URL || 'https://notebooklm-gateway.replit.app').replace(/\/$/, '');
  const timeoutMs = customTimeoutMs || Number.parseInt(env.NOTEBOOKLM_TIMEOUT_MS, 10) || 15000;
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
// NotebookLM Chat (UI Adapter) - FIXED
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
 * 
 * FIXES APPLIED:
 * 1. Changed notebook_url -> notebookUrl (camelCase to match backend)
 * 2. Increased timeout to 120000ms (120 seconds) for chat requests
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

  // FIX: Use 120 second timeout for chat (chat can take up to 90s)
  const CHAT_TIMEOUT_MS = 120000;

  const chatRes = await fetchNotebookLM(env, '/v1/chat', {
    method: 'POST',
    body: JSON.stringify({
      notebookUrl: notebookUrl,  // FIX: camelCase (was notebook_url)
      message,
      kind,
      history,
    }),
  }, CHAT_TIMEOUT_MS);  // FIX: pass custom timeout

  if (!chatRes.ok) {
    return errorResponse(
      chatRes?.data?.error?.message || chatRes?.data?.error || chatRes?.data?.detail || 'NotebookLM chat failed',
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

  let notebookLMReady = false;
  let notebookLMMessage = null;
  let notebookCount = null;

  try {
    const res = await fetchNotebookLM(env, '/auth/status', { method: 'GET' });
    if (res.ok && res.data) {
      notebookLMReady = res.data.ok === true;
      notebookLMMessage = res.data.message || null;
      notebookCount = res.data.notebook_count || null;
    } else {
      notebookLMReady = false;
      notebookLMMessage = res?.data?.message || res?.data?.error || null;
    }
  } catch (e) {
    notebookLMReady = false;
    notebookLMMessage = e?.message || String(e);
  }

  return jsonResponse({
    success: true,
    initialized: initialized === 'true',
    notebookLMReady,
    notebookLMMessage,
    notebookCount,
  });
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

  await env.KV.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: ttlMinutes * 60 }
  );

  const baseUrl = `${env.MINIO_ENDPOINT}/${env.MINIO_BUCKET}`;
  
  try {
    await uploadToMinIO(env, `sessions/${sessionId}/notes.json`, JSON.stringify(notes, null, 2));
    await uploadToMinIO(env, `sessions/${sessionId}/notes.jsonl`, notes.map(n => JSON.stringify(n)).join('\n'), 'application/x-ndjson');
    await uploadToMinIO(env, `sessions/${sessionId}/notes.md`, notes.map(n => `# ${n.title}\n\n${n.content}`).join('\n\n---\n\n'), 'text/markdown');
  } catch (err) {
    console.error('MinIO upload error:', err);
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
  
  await env.KV.delete(`session:${sessionId}`);
  
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
  const url = new URL(request.url);
  const providedCode = url.searchParams.get('code');

  const zoneData = await env.KV.get(`zone:${zoneId}`);
  
  if (!zoneData) {
    return errorResponse('Zone not found', 404);
  }

  const zone = JSON.parse(zoneData);
  
  if (!providedCode || providedCode !== zone.accessCode) {
    return errorResponse('Invalid access code', 403);
  }
  
  if (new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410, { expired: true }, 'ZONE_EXPIRED');
  }

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
    createNotebookLM,
    notebookTitle,
    notebookShareEmails,
    notebookSourceMode = 'minio',
  } = body;

  const zoneId = crypto.randomUUID().slice(0, 8);
  const accessCode = `ACCESS-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

  const zone = {
    zoneId,
    accessCode,
    name,
    description,
    accessType,
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

  const indexData = await env.KV.get('zones:index');
  const zoneIndex = indexData ? JSON.parse(indexData) : [];
  zoneIndex.push(zoneId);
  await env.KV.put('zones:index', JSON.stringify(zoneIndex));

  let minioNoteKeys = null;
  if (createNotebookLM) {
    try {
      minioNoteKeys = await syncZoneNotesToMinIO(env, zoneId, notes);
      console.log(`[Zones] Synced per-note Markdown to MinIO for NotebookLM: ${zoneId} -> ${minioNoteKeys.length} files`);
    } catch (err) {
      console.error('[Zones] MinIO sync required for NotebookLM failed:', err);
      return errorResponse(
        'Failed to sync notes to MinIO (required for NotebookLM import)',
        502,
        { message: err?.message || String(err), zoneId, prefix: `zones/${zoneId}/notes/` },
        'MINIO_SYNC_FAILED'
      );
    }
  }

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

    await uploadToMinIO(env, `zones/${zoneId}/notes.json`, JSON.stringify(zoneContent, null, 2));
    await uploadToMinIO(
      env,
      `zones/${zoneId}/notes.jsonl`,
      notes.map((n) => JSON.stringify({ slug: n.slug, title: n.title, content: n.content, tags: n.tags })).join('\n'),
      'application/x-ndjson'
    );

    if (!minioNoteKeys) {
      minioNoteKeys = await syncZoneNotesToMinIO(env, zoneId, notes);
    }

    console.log(`[Zones] Uploaded zone ${zoneId} to MinIO`);
  } catch (err) {
    console.error('[Zones] MinIO upload error:', err);
  }

  let notebooklmResult = null;

  if (createNotebookLM) {
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
      const createRes = await fetchNotebookLM(env, '/v1/notebooks', {
        method: 'POST',
        body: JSON.stringify({ title: notebookTitle || name }),
      });
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

      const importRes = await fetchNotebookLM(env, `/v1/notebooks/${notebookId}/sources/import`, {
        method: 'POST',
        body: JSON.stringify(importBody),
      });
      if (!importRes.ok) {
        throw new Error(importRes?.data?.error || importRes?.data?.detail || `Import failed (${importRes.status})`);
      }

      const imported = importRes.data;
      notebooklmMapping.importJobId = imported?.job_id || imported?.id || null;
      notebooklmMapping.status = imported?.status || 'queued';

      if (Array.isArray(notebookShareEmails) && notebookShareEmails.length > 0) {
        const shareRes = await fetchNotebookLM(env, `/v1/notebooks/${notebookId}/share`, {
          method: 'POST',
          body: JSON.stringify({ emails: notebookShareEmails, role: 'reader' }),
        });
        if (!shareRes.ok) {
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
      };
    }

    await env.KV.put(`zone_notebooklm:${zoneId}`, JSON.stringify(notebooklmMapping), {
      expirationTtl: ttlMinutes * 60,
    });
  }

  return jsonResponse({
    success: true,
    zoneId,
    accessCode,
    zoneUrl: `https://${host.replace('garden-mcp-server', 'exodus')}/zone/${zoneId}`,
    expiresAt,
    noteCount: notes.length,
    ...(notebooklmResult ? { notebooklm: notebooklmResult } : {}),
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
    const noteKeys = (zone.notes || []).map((n) => `zones/${zoneId}/notes/${safeNoteSlug(n?.slug || n?.title)}.md`);
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

async function handleZonesDelete(zoneId, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);
  const zone = zoneData ? JSON.parse(zoneData) : null;

  await env.KV.delete(`zone:${zoneId}`);

  const indexData = await env.KV.get('zones:index');
  if (indexData) {
    const zoneIndex = JSON.parse(indexData);
    const updatedIndex = zoneIndex.filter(id => id !== zoneId);
    await env.KV.put('zones:index', JSON.stringify(updatedIndex));
  }

  try {
    const perNoteDeletes = Array.isArray(zone?.notes)
      ? zone.notes.map((n) => deleteFromMinIO(env, `zones/${zoneId}/notes/${safeNoteSlug(n?.slug || n?.title)}.md`))
      : [];
    await Promise.all([
      deleteFromMinIO(env, `zones/${zoneId}/notes.json`),
      deleteFromMinIO(env, `zones/${zoneId}/notes.jsonl`),
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

  const zones = await Promise.all(
    zoneIds.map(async (zoneId) => {
      const zoneData = await env.KV.get(`zone:${zoneId}`);
      if (!zoneData) return null;

      const zone = JSON.parse(zoneData);

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
  
  const headerZoneId = request.headers.get('X-Zone-Id') || zoneId;
  const headerZoneCode = request.headers.get('X-Zone-Code') || zoneCode;
  let isZoneGuest = false;
  
  if (headerZoneId && headerZoneCode) {
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
  
  await env.KV.put(`comment:${commentId}`, JSON.stringify(comment));
  
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
  
  try {
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
  
  const indexKey = `comments:index:${articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  if (indexData) {
    const index = JSON.parse(indexData);
    index.commentIds = index.commentIds.filter(id => id !== commentId);
    await env.KV.put(indexKey, JSON.stringify(index));
  }
  
  await env.KV.delete(`comment:${commentId}`);
  
  await syncCommentsToMinIO(articleSlug, env);
  
  return jsonResponse({ success: true });
}

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
      
      if (annotation.commentId) {
        const commentData = await env.KV.get(`comment:${annotation.commentId}`);
        if (commentData) {
          annotation.comment = JSON.parse(commentData);
        }
      }
      
      return annotation;
    })
  );
  
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
  
  await env.KV.put(`annotation:${annotationId}`, JSON.stringify(annotation));
  
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
  
  if (annotation.commentId) {
    const commentData = await env.KV.get(`comment:${annotation.commentId}`);
    if (commentData) {
      const comment = JSON.parse(commentData);
      
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
  
  const indexKey = `annotations:index:${annotation.articleSlug}`;
  const indexData = await env.KV.get(indexKey);
  if (indexData) {
    const index = JSON.parse(indexData);
    index.annotationIds = index.annotationIds.filter(id => id !== annotationId);
    await env.KV.put(indexKey, JSON.stringify(index));
  }
  
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

  await writer.write(encoder.encode(`event: open\ndata: {\"status\":\"connected\",\"sessionId\":\"${sessionId || 'anonymous'}\"}\n\n`));

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

  const pingInterval = setInterval(() => {
    writer.write(encoder.encode(`:ping\n\n`)).catch(() => {});
  }, 30000);

  ctx.waitUntil(
    new Promise((resolve) => {
      setTimeout(() => {
        clearInterval(pingInterval);
        writer.close().catch(() => {});
        resolve();
      }, 3600000);
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

    if (method === 'OPTIONS') {
      return corsResponse();
    }

    try {
      // ============================================
      // PUBLIC ENDPOINTS
      // ============================================
      
      if (method === 'GET' && path === '/health') {
        return await handleHealth();
      }

      if (method === 'POST' && path === '/auth/status') {
        return await handleAuthStatus(env);
      }

      if (method === 'POST' && path === '/auth/setup') {
        return await handleAuthSetup(request, env);
      }

      if (method === 'POST' && path === '/auth/login') {
        return await handleAuthLogin(request, env);
      }

      if (method === 'POST' && path === '/auth/refresh') {
        return await handleAuthRefresh(request, env);
      }

      if (method === 'POST' && path === '/auth/validate') {
        return await handleAuthValidate(request, env);
      }

      // ============================================
      // ZONE PUBLIC ENDPOINTS
      // ============================================
      
      const validateMatch = path.match(/^\/zones\/validate\/([^\/]+)$/);
      if (method === 'GET' && validateMatch) {
        return await handleZonesValidate(validateMatch[1], env, request);
      }

      const zoneNotesMatch = path.match(/^\/zones\/([^\/]+)\/notes$/);
      if (method === 'GET' && zoneNotesMatch) {
        return await handleZonesNotes(zoneNotesMatch[1], env);
      }

      // ============================================
      // NOTEBOOKLM ZONE ENDPOINTS (public)
      // ============================================

      const zoneNotebookLMMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm$/);
      if (method === 'GET' && zoneNotebookLMMatch) {
        return await handleZoneNotebookLMStatus(zoneNotebookLMMatch[1], env);
      }

      const zoneNotebookLMJobMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm\/job\/([^\/]+)$/);
      if (method === 'GET' && zoneNotebookLMJobMatch) {
        return await handleZoneNotebookLMJobStatus(zoneNotebookLMJobMatch[1], zoneNotebookLMJobMatch[2], env);
      }

      const zoneNotebookLMRetryMatch = path.match(/^\/zones\/([^\/]+)\/notebooklm\/retry-import$/);
      if (method === 'POST' && zoneNotebookLMRetryMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401);
        }
        return await handleZoneNotebookLMRetryImport(zoneNotebookLMRetryMatch[1], env);
      }

      if (method === 'POST' && path === '/notebooklm/chat') {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401);
        }
        return await handleNotebookLMChat(request, env);
      }

      // ============================================
      // SESSION-BASED ENDPOINTS
      // ============================================
      
      if (method === 'POST' && path === '/mcp') {
        return await handleMCPRPC(request, env);
      }

      if (method === 'GET' && path === '/sse') {
        return await handleSSE(request, env, ctx);
      }

      // ============================================
      // COMMENTS ENDPOINTS
      // ============================================
      
      const commentsGetMatch = path.match(/^\/comments\/(.+)$/);
      if (method === 'GET' && commentsGetMatch && !path.includes('/create')) {
        return await handleCommentsGet(decodeURIComponent(commentsGetMatch[1]), env, request);
      }

      if (method === 'POST' && path === '/comments/create') {
        return await handleCommentsCreate(request, env);
      }

      const commentsPatchMatch = path.match(/^\/comments\/([a-f0-9-]+)$/);
      if (method === 'PATCH' && commentsPatchMatch) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized', 401);
        }
        return await handleCommentsUpdate(commentsPatchMatch[1], request, env);
      }

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
      
      const annotationsGetMatch = path.match(/^\/annotations\/(.+)$/);
      if (method === 'GET' && annotationsGetMatch && !path.includes('/create')) {
        return await handleAnnotationsGet(decodeURIComponent(annotationsGetMatch[1]), env, request);
      }

      if (method === 'POST' && path === '/annotations/create') {
        return await handleAnnotationsCreate(request, env);
      }

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
      
      const isProtectedRoute = 
        (method === 'POST' && path === '/sessions/create') ||
        (method === 'POST' && path === '/sessions/revoke') ||
        (method === 'GET' && path === '/sessions/list') ||
        (method === 'POST' && path === '/zones/create') ||
        (method === 'POST' && path === '/notebooklm/chat') ||
        (method === 'DELETE' && path.match(/^\/zones\/[^\/]+$/)) ||
        (method === 'GET' && path === '/zones/list');

      if (isProtectedRoute) {
        const ownerPayload = await verifyOwnerAuth(request, env);
        if (!ownerPayload) {
          return errorResponse('Unauthorized: Owner access required', 401);
        }
      }

      if (method === 'POST' && path === '/sessions/create') {
        return await handleSessionsCreate(request, env, host);
      }

      if (method === 'POST' && path === '/sessions/revoke') {
        return await handleSessionsRevoke(request, env);
      }

      if (method === 'GET' && path === '/sessions/list') {
        return await handleSessionsList(env);
      }

      if (method === 'POST' && path === '/zones/create') {
        return await handleZonesCreate(request, env, host);
      }

      const zoneDeleteMatch = path.match(/^\/zones\/([^\/]+)$/);
      if (method === 'DELETE' && zoneDeleteMatch) {
        return await handleZonesDelete(zoneDeleteMatch[1], env);
      }

      if (method === 'GET' && path === '/zones/list') {
        return await handleZonesList(env);
      }

      // ============================================
      // 404 Not Found
      // ============================================
      return errorResponse('Not found', 404);

    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse(`Internal error: ${err.message}`, 500);
    }
  }
};
