// ============================================
// Garden API Adapter - n8n Migration
// Replaces Cloudflare Workers
// Version: 3.0.0
// ============================================

import express from 'express';
import cors from 'cors';
import { createClient } from 'redis';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================
// Environment Variables
// ============================================
const config = {
  N8N_BASE_URL: process.env.N8N_BASE_URL || 'http://localhost:5678',
  JWT_SECRET: process.env.JWT_SECRET,
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  MINIO_ENDPOINT: process.env.MINIO_ENDPOINT,
  MINIO_BUCKET: process.env.MINIO_BUCKET,
  MINIO_ACCESS_KEY: process.env.MINIO_ACCESS_KEY,
  MINIO_SECRET_KEY: process.env.MINIO_SECRET_KEY,
  NOTEBOOKLM_BASE_URL: process.env.NOTEBOOKLM_BASE_URL || 'https://notebooklm-gateway.replit.app',
  NOTEBOOKLM_TIMEOUT_MS: parseInt(process.env.NOTEBOOKLM_TIMEOUT_MS || '15000', 10),
};

// Validate required env vars
if (!config.JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is required');
  process.exit(1);
}

// ============================================
// Redis Client (KV replacement)
// ============================================
const redis = createClient({ url: config.REDIS_URL });
redis.on('error', (err) => console.error('Redis error:', err));
redis.on('connect', () => console.log('Redis connected'));

await redis.connect();

// ============================================
// CORS Middleware
// ============================================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id', 'X-Zone-Id', 'X-Zone-Code'],
  maxAge: 86400,
}));

app.use(express.json({ limit: '10mb' }));

// ============================================
// JWT Utilities
// ============================================
async function generateJWT(payload, ttlMs = 86400000) {
  const now = Date.now();
  const fullPayload = { ...payload, iat: now, exp: now + ttlMs };

  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .toString('base64url');
  const body = Buffer.from(JSON.stringify(fullPayload))
    .toString('base64url');

  const signature = crypto
    .createHmac('sha256', config.JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');

  return `${header}.${body}.${signature}`;
}

async function verifyJWT(token) {
  try {
    const [header, body, signature] = token.split('.');
    if (!header || !body || !signature) return null;

    const expectedSig = crypto
      .createHmac('sha256', config.JWT_SECRET)
      .update(`${header}.${body}`)
      .digest('base64url');

    if (signature !== expectedSig) return null;

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  return crypto
    .createHash('sha256')
    .update(password + config.JWT_SECRET)
    .digest('hex');
}

// ============================================
// Helper: JSON Response
// ============================================
function jsonResponse(res, data, status = 200) {
  res.status(status).json(data);
}

function errorResponse(res, message, status = 400, code = undefined, details = undefined) {
  const payload = { success: false, error: message };
  if (code) payload.errorCode = code;
  if (details) payload.errorDetails = details;
  res.status(status).json(payload);
}

// ============================================
// Helper: Check Owner Auth (non-blocking)
// ============================================
async function checkOwnerAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return false;

  const token = authHeader.slice(7);
  const payload = await verifyJWT(token);

  return payload?.role === 'owner';
}

// ============================================
// Middleware: Owner Auth
// ============================================
async function requireOwnerAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return errorResponse(res, 'Unauthorized: Owner access required', 401);
  }

  const token = authHeader.slice(7);
  const payload = await verifyJWT(token);

  if (!payload || payload.role !== 'owner') {
    return errorResponse(res, 'Unauthorized: Invalid token', 401);
  }

  req.ownerPayload = payload;
  next();
}

// ============================================
// Health Check
// ============================================
app.get('/health', (req, res) => {
  jsonResponse(res, {
    status: 'ok',
    version: '3.0-n8n',
    timestamp: new Date().toISOString(),
    features: ['rest-api', 'mcp-jsonrpc', 'sse-transport', 'minio-storage'],
    runtime: 'node-n8n-adapter',
  });
});

// ============================================
// AUTH ENDPOINTS
// ============================================
app.post('/auth/status', async (req, res) => {
  try {
    const initialized = await redis.get('owner_initialized');

    // Check NotebookLM backend
    let notebookLMReady = false;
    let notebookLMMessage = null;
    let notebookCount = null;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.NOTEBOOKLM_TIMEOUT_MS);

      const response = await fetch(`${config.NOTEBOOKLM_BASE_URL}/auth/status`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        notebookLMReady = data.ok === true;
        notebookLMMessage = data.message;
        notebookCount = data.notebook_count;
      }
    } catch (e) {
      notebookLMMessage = e.name === 'AbortError' ? 'Timeout' : e.message;
    }

    jsonResponse(res, {
      success: true,
      initialized: initialized === 'true',
      notebookLMReady,
      notebookLMMessage,
      notebookCount,
    });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/auth/setup', async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return errorResponse(res, 'Password required', 400);
    }

    const initialized = await redis.get('owner_initialized');
    if (initialized === 'true') {
      return errorResponse(res, 'Already initialized', 400);
    }

    const hashHex = await hashPassword(password);
    await redis.set('owner_password_hash', hashHex);
    await redis.set('owner_initialized', 'true');

    jsonResponse(res, { success: true });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return errorResponse(res, 'Password required', 400);
    }

    const storedHash = await redis.get('owner_password_hash');
    if (!storedHash) {
      return errorResponse(res, 'Not initialized', 401);
    }

    const hashHex = await hashPassword(password);
    if (hashHex !== storedHash) {
      return errorResponse(res, 'Invalid password', 401);
    }

    const token = await generateJWT({ role: 'owner' });
    jsonResponse(res, { success: true, token });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse(res, 'Token required', 401);
    }

    const oldToken = authHeader.slice(7);
    const payload = await verifyJWT(oldToken);

    if (!payload) {
      return errorResponse(res, 'Invalid or expired token', 401);
    }

    const newToken = await generateJWT({ role: payload.role });
    jsonResponse(res, { success: true, token: newToken });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/auth/validate', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return jsonResponse(res, { success: true, valid: false });
    }

    const payload = await verifyJWT(token);
    jsonResponse(res, {
      success: true,
      valid: !!payload,
      expiresAt: payload?.exp || null,
    });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

// ============================================
// ZONES ENDPOINTS
// ============================================
app.get('/zones/validate/:zoneId', async (req, res) => {
  try {
    const { zoneId } = req.params;
    const code = req.query.code;

    const zoneData = await redis.get(`zone:${zoneId}`);
    if (!zoneData) {
      return errorResponse(res, 'Zone not found', 404);
    }

    const zone = JSON.parse(zoneData);

    if (!code || code !== zone.accessCode) {
      return errorResponse(res, 'Invalid access code', 403);
    }

    if (new Date(zone.expiresAt) < new Date()) {
      return errorResponse(res, 'Zone expired', 410, 'ZONE_EXPIRED', { expired: true });
    }

    jsonResponse(res, {
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
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.get('/zones/:zoneId/notes', async (req, res) => {
  try {
    const { zoneId } = req.params;

    const zoneData = await redis.get(`zone:${zoneId}`);
    if (!zoneData) {
      return errorResponse(res, 'Zone not found', 404);
    }

    const zone = JSON.parse(zoneData);

    if (new Date(zone.expiresAt) < new Date()) {
      return errorResponse(res, 'Zone expired', 410);
    }

    jsonResponse(res, {
      success: true,
      notes: zone.notes,
      expiresAt: zone.expiresAt,
    });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.get('/zones/list', requireOwnerAuth, async (req, res) => {
  try {
    const indexData = await redis.get('zones:index');

    if (!indexData) {
      return jsonResponse(res, { success: true, zones: [] });
    }

    const zoneIds = JSON.parse(indexData);
    const zones = [];

    for (const zoneId of zoneIds) {
      const zoneData = await redis.get(`zone:${zoneId}`);
      if (!zoneData) continue;

      const zone = JSON.parse(zoneData);
      if (new Date(zone.expiresAt) < new Date()) continue;

      zones.push({
        id: zone.zoneId,
        name: zone.name,
        description: zone.description,
        folders: zone.allowedPaths,
        noteCount: zone.noteCount,
        accessType: zone.accessType,
        createdAt: new Date(zone.createdAt).getTime(),
        expiresAt: new Date(zone.expiresAt).getTime(),
        accessCode: zone.accessCode,
      });
    }

    jsonResponse(res, { success: true, zones });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/zones/create', requireOwnerAuth, async (req, res) => {
  try {
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
    } = req.body;

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
      noteCount: notes?.length || 0,
      expiresAt,
      createdAt: new Date().toISOString(),
      createdBy: 'owner',
    };

    // Save to Redis with TTL
    await redis.set(`zone:${zoneId}`, JSON.stringify(zone), {
      EX: ttlMinutes * 60,
    });

    // Update zones index
    const indexData = await redis.get('zones:index');
    const zoneIndex = indexData ? JSON.parse(indexData) : [];
    zoneIndex.push(zoneId);
    await redis.set('zones:index', JSON.stringify(zoneIndex));

    // TODO: Upload to MinIO via n8n workflow
    // TODO: NotebookLM integration via n8n workflow

    let notebooklmResult = null;
    if (createNotebookLM) {
      // Placeholder for n8n workflow integration
      notebooklmResult = {
        status: 'pending',
        message: 'NotebookLM integration via n8n workflow',
      };
    }

    const host = req.headers.host || 'localhost';
    jsonResponse(res, {
      success: true,
      zoneId,
      accessCode,
      zoneUrl: `https://${host.replace('api.', '')}/zone/${zoneId}`,
      expiresAt,
      noteCount: notes?.length || 0,
      ...(notebooklmResult ? { notebooklm: notebooklmResult } : {}),
    });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.delete('/zones/:zoneId', requireOwnerAuth, async (req, res) => {
  try {
    const { zoneId } = req.params;

    // Delete from Redis
    await redis.del(`zone:${zoneId}`);
    await redis.del(`zone_notebooklm:${zoneId}`);

    // Update index
    const indexData = await redis.get('zones:index');
    if (indexData) {
      const zoneIndex = JSON.parse(indexData);
      const updated = zoneIndex.filter(id => id !== zoneId);
      await redis.set('zones:index', JSON.stringify(updated));
    }

    // TODO: Delete from MinIO via n8n workflow

    jsonResponse(res, { success: true });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

// ============================================
// NOTEBOOKLM ENDPOINTS
// ============================================
app.get('/zones/:zoneId/notebooklm', async (req, res) => {
  try {
    const { zoneId } = req.params;

    const zoneData = await redis.get(`zone:${zoneId}`);
    if (!zoneData) {
      return errorResponse(res, 'Zone not found', 404);
    }

    const mappingData = await redis.get(`zone_notebooklm:${zoneId}`);
    if (!mappingData) {
      return jsonResponse(res, { success: true, zoneId, notebooklm: null });
    }

    const mapping = JSON.parse(mappingData);
    jsonResponse(res, {
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
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.get('/zones/:zoneId/notebooklm/job/:jobId', async (req, res) => {
  try {
    const { zoneId, jobId } = req.params;

    const zoneData = await redis.get(`zone:${zoneId}`);
    if (!zoneData) {
      return errorResponse(res, 'Zone not found', 404);
    }

    // Proxy to NotebookLM backend
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.NOTEBOOKLM_TIMEOUT_MS);

    const response = await fetch(`${config.NOTEBOOKLM_BASE_URL}/v1/jobs/${jobId}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const data = await response.json();

    if (!response.ok) {
      return errorResponse(
        res,
        data?.error || data?.detail || 'Failed to get job status',
        response.status,
        'NOTEBOOKLM_JOB_STATUS_FAILED',
        data
      );
    }

    // Update mapping
    const mappingData = await redis.get(`zone_notebooklm:${zoneId}`);
    if (mappingData && data.status) {
      const mapping = JSON.parse(mappingData);
      if (mapping.importJobId === jobId) {
        mapping.status = data.status;
        if (data.status === 'failed' && data.error) {
          mapping.lastError = data.error;
        }
        await redis.set(`zone_notebooklm:${zoneId}`, JSON.stringify(mapping));
      }
    }

    jsonResponse(res, data);
  } catch (error) {
    if (error.name === 'AbortError') {
      return errorResponse(res, 'NotebookLM timeout', 504);
    }
    errorResponse(res, `NotebookLM error: ${error.message}`, 502);
  }
});

app.post('/zones/:zoneId/notebooklm/retry-import', requireOwnerAuth, async (req, res) => {
  try {
    const { zoneId } = req.params;

    const zoneData = await redis.get(`zone:${zoneId}`);
    if (!zoneData) {
      return errorResponse(res, 'Zone not found', 404);
    }

    // TODO: Implement retry via n8n workflow
    jsonResponse(res, {
      success: true,
      zoneId,
      message: 'Retry import via n8n workflow - not yet implemented',
    });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/notebooklm/chat', requireOwnerAuth, async (req, res) => {
  try {
    const { notebookUrl, message, kind = 'answer', history = [] } = req.body;

    if (!notebookUrl) {
      return errorResponse(res, 'notebookUrl is required', 400, 'NOTEBOOKLM_CHAT_INVALID');
    }
    if (!message) {
      return errorResponse(res, 'message is required', 400, 'NOTEBOOKLM_CHAT_INVALID');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.NOTEBOOKLM_TIMEOUT_MS);

    const response = await fetch(`${config.NOTEBOOKLM_BASE_URL}/v1/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        notebook_url: notebookUrl,
        message,
        kind,
        history,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const data = await response.json();

    if (!response.ok) {
      return errorResponse(
        res,
        data?.error || data?.detail || 'NotebookLM chat failed',
        response.status,
        'NOTEBOOKLM_CHAT_FAILED',
        data
      );
    }

    jsonResponse(res, { success: true, ...data });
  } catch (error) {
    if (error.name === 'AbortError') {
      return errorResponse(res, 'NotebookLM timeout', 504, 'NOTEBOOKLM_CHAT_FAILED');
    }
    errorResponse(res, `NotebookLM error: ${error.message}`, 502, 'NOTEBOOKLM_CHAT_FAILED');
  }
});

// ============================================
// COMMENTS ENDPOINTS
// ============================================
app.get('/comments/:articleSlug', async (req, res) => {
  try {
    const articleSlug = decodeURIComponent(req.params.articleSlug);

    const indexData = await redis.get(`comments:index:${articleSlug}`);
    if (!indexData) {
      return jsonResponse(res, { success: true, comments: [], total: 0 });
    }

    const index = JSON.parse(indexData);
    const isOwner = await checkOwnerAuth(req);

    const comments = [];
    for (const id of index.commentIds) {
      const commentData = await redis.get(`comment:${id}`);
      if (!commentData) continue;

      const comment = JSON.parse(commentData);

      // Filter: owners see all, guests see only approved
      if (isOwner || comment.status === 'approved') {
        comments.push(comment);
      }
    }

    jsonResponse(res, { success: true, comments, total: comments.length });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/comments/create', async (req, res) => {
  try {
    const { articleSlug, content, parentId, authorName, authorType, agentModel, zoneId, zoneCode } = req.body;

    if (!articleSlug || !content) {
      return errorResponse(res, 'articleSlug and content required', 400);
    }

    // Check zone guest
    const headerZoneId = req.headers['x-zone-id'] || zoneId;
    const headerZoneCode = req.headers['x-zone-code'] || zoneCode;
    let isZoneGuest = false;

    if (headerZoneId && headerZoneCode) {
      const zoneData = await redis.get(`zone:${headerZoneId}`);
      if (zoneData) {
        const zone = JSON.parse(zoneData);
        if (zone.accessCode === headerZoneCode && new Date(zone.expiresAt) > new Date()) {
          isZoneGuest = true;
        }
      }
    }

    const isOwner = await checkOwnerAuth(req);
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

    await redis.set(`comment:${commentId}`, JSON.stringify(comment));

    // Update index
    const indexKey = `comments:index:${articleSlug}`;
    const indexData = await redis.get(indexKey);
    const index = indexData ? JSON.parse(indexData) : {
      articleSlug,
      commentIds: [],
      lastUpdated: null,
    };

    index.commentIds.push(commentId);
    index.lastUpdated = new Date().toISOString();
    await redis.set(indexKey, JSON.stringify(index));

    // TODO: Sync to MinIO via n8n workflow

    jsonResponse(res, { success: true, comment });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.patch('/comments/:commentId', requireOwnerAuth, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { status, content } = req.body;

    const commentData = await redis.get(`comment:${commentId}`);
    if (!commentData) {
      return errorResponse(res, 'Comment not found', 404);
    }

    const comment = JSON.parse(commentData);

    if (status) comment.status = status;
    if (content) comment.content = content;
    comment.updatedAt = new Date().toISOString();

    await redis.set(`comment:${commentId}`, JSON.stringify(comment));

    jsonResponse(res, { success: true, comment });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.delete('/comments/:commentId', requireOwnerAuth, async (req, res) => {
  try {
    const { commentId } = req.params;

    const commentData = await redis.get(`comment:${commentId}`);
    if (!commentData) {
      return errorResponse(res, 'Comment not found', 404);
    }

    const comment = JSON.parse(commentData);
    const articleSlug = comment.articleSlug;

    // Remove from index
    const indexKey = `comments:index:${articleSlug}`;
    const indexData = await redis.get(indexKey);
    if (indexData) {
      const index = JSON.parse(indexData);
      index.commentIds = index.commentIds.filter(id => id !== commentId);
      await redis.set(indexKey, JSON.stringify(index));
    }

    await redis.del(`comment:${commentId}`);

    jsonResponse(res, { success: true });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

// ============================================
// ANNOTATIONS ENDPOINTS
// ============================================
app.get('/annotations/:articleSlug', async (req, res) => {
  try {
    const articleSlug = decodeURIComponent(req.params.articleSlug);

    const indexData = await redis.get(`annotations:index:${articleSlug}`);
    if (!indexData) {
      return jsonResponse(res, { success: true, annotations: [], total: 0 });
    }

    const index = JSON.parse(indexData);
    const isOwner = await checkOwnerAuth(req);

    const annotations = [];
    for (const id of index.annotationIds) {
      const annotationData = await redis.get(`annotation:${id}`);
      if (!annotationData) continue;

      const annotation = JSON.parse(annotationData);

      // Fetch linked comment if exists
      if (annotation.commentId) {
        const commentData = await redis.get(`comment:${annotation.commentId}`);
        if (commentData) {
          annotation.comment = JSON.parse(commentData);
        }
      }

      // Filter: owners see all, guests see only approved
      if (isOwner || annotation.comment?.status === 'approved' || !annotation.commentId) {
        annotations.push(annotation);
      }
    }

    jsonResponse(res, { success: true, annotations, total: annotations.length });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/annotations/create', async (req, res) => {
  try {
    const { articleSlug, highlightedText, startOffset, endOffset, paragraphIndex, content, authorName, authorType } = req.body;

    if (!articleSlug || !highlightedText || startOffset === undefined || endOffset === undefined) {
      return errorResponse(res, 'articleSlug, highlightedText, startOffset, endOffset required', 400);
    }

    const isOwner = await checkOwnerAuth(req);
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

      await redis.set(`comment:${commentId}`, JSON.stringify(comment));

      // Update comments index
      const commentsIndexKey = `comments:index:${articleSlug}`;
      const commentsIndexData = await redis.get(commentsIndexKey);
      const commentsIndex = commentsIndexData ? JSON.parse(commentsIndexData) : {
        articleSlug,
        commentIds: [],
        lastUpdated: null,
      };
      commentsIndex.commentIds.push(commentId);
      commentsIndex.lastUpdated = new Date().toISOString();
      await redis.set(commentsIndexKey, JSON.stringify(commentsIndex));
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

    await redis.set(`annotation:${annotationId}`, JSON.stringify(annotation));

    // Update annotations index
    const indexKey = `annotations:index:${articleSlug}`;
    const indexData = await redis.get(indexKey);
    const index = indexData ? JSON.parse(indexData) : {
      articleSlug,
      annotationIds: [],
      lastUpdated: null,
    };

    index.annotationIds.push(annotationId);
    index.lastUpdated = new Date().toISOString();
    await redis.set(indexKey, JSON.stringify(index));

    jsonResponse(res, { success: true, annotation, commentId });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.delete('/annotations/:annotationId', requireOwnerAuth, async (req, res) => {
  try {
    const { annotationId } = req.params;

    const annotationData = await redis.get(`annotation:${annotationId}`);
    if (!annotationData) {
      return errorResponse(res, 'Annotation not found', 404);
    }

    const annotation = JSON.parse(annotationData);

    // Delete linked comment if exists
    if (annotation.commentId) {
      const commentData = await redis.get(`comment:${annotation.commentId}`);
      if (commentData) {
        const comment = JSON.parse(commentData);

        // Remove from comments index
        const commentsIndexKey = `comments:index:${comment.articleSlug}`;
        const commentsIndexData = await redis.get(commentsIndexKey);
        if (commentsIndexData) {
          const commentsIndex = JSON.parse(commentsIndexData);
          commentsIndex.commentIds = commentsIndex.commentIds.filter(id => id !== annotation.commentId);
          await redis.set(commentsIndexKey, JSON.stringify(commentsIndex));
        }

        await redis.del(`comment:${annotation.commentId}`);
      }
    }

    // Remove from annotations index
    const indexKey = `annotations:index:${annotation.articleSlug}`;
    const indexData = await redis.get(indexKey);
    if (indexData) {
      const index = JSON.parse(indexData);
      index.annotationIds = index.annotationIds.filter(id => id !== annotationId);
      await redis.set(indexKey, JSON.stringify(index));
    }

    await redis.del(`annotation:${annotationId}`);

    jsonResponse(res, { success: true });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

// ============================================
// SESSIONS ENDPOINTS
// ============================================
app.post('/sessions/create', requireOwnerAuth, async (req, res) => {
  try {
    const { folders, ttlMinutes, notes } = req.body;

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

    await redis.set(`session:${sessionId}`, JSON.stringify(session), {
      EX: ttlMinutes * 60,
    });

    // TODO: Upload to MinIO via n8n workflow

    const host = req.headers.host || 'localhost';
    jsonResponse(res, {
      success: true,
      sessionId,
      sessionUrl: `https://${host}/mcp?session=${sessionId}`,
      expiresAt,
      noteCount: notes?.length || 0,
      storage: 'redis',
    });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.post('/sessions/revoke', requireOwnerAuth, async (req, res) => {
  try {
    const { sessionId } = req.body;
    await redis.del(`session:${sessionId}`);
    jsonResponse(res, { success: true });
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

app.get('/sessions/list', requireOwnerAuth, (req, res) => {
  jsonResponse(res, {
    success: true,
    message: 'Use Redis SCAN for session listing',
  });
});

// ============================================
// MCP JSON-RPC ENDPOINT (Stateful)
// ============================================
app.post('/mcp', async (req, res) => {
  try {
    const sessionId = req.query.session;

    let session = null;
    if (sessionId) {
      const sessionData = await redis.get(`session:${sessionId}`);
      if (!sessionData) {
        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32001, message: 'Session not found' },
        });
      }
      session = JSON.parse(sessionData);

      if (new Date(session.expiresAt) < new Date()) {
        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32002, message: 'Session expired' },
        });
      }
    }

    const rpcRequest = req.body;

    if (rpcRequest.jsonrpc !== '2.0') {
      return jsonResponse(res, {
        jsonrpc: '2.0',
        id: rpcRequest.id,
        error: { code: -32600, message: 'Invalid JSON-RPC version' },
      });
    }

    const notes = session?.notes || [];

    // Handle MCP methods
    switch (rpcRequest.method) {
      case 'initialize':
        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: rpcRequest.id,
          result: {
            protocolVersion: '2024-11-05',
            serverInfo: { name: 'garden-mcp-server', version: '3.0.0' },
            capabilities: { tools: {}, resources: {} },
          },
        });

      case 'tools/list':
        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: rpcRequest.id,
          result: {
            tools: [
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
            ],
          },
        });

      case 'tools/call': {
        const params = rpcRequest.params;
        let result;

        switch (params.name) {
          case 'search_notes': {
            const query = (params.arguments?.query || '').toLowerCase();
            const filterTags = params.arguments?.tags || [];
            const limit = params.arguments?.limit || 10;

            const results = notes
              .filter(note => {
                const matchesQuery =
                  note.title?.toLowerCase().includes(query) ||
                  note.content?.toLowerCase().includes(query);
                const matchesTags = filterTags.length === 0 ||
                  filterTags.some(tag => note.tags?.includes(tag));
                return matchesQuery && matchesTags;
              })
              .slice(0, limit);

            result = {
              content: [{
                type: 'text',
                text: JSON.stringify(results.map(n => ({
                  slug: n.slug,
                  title: n.title,
                  tags: n.tags,
                  preview: n.content?.slice(0, 200),
                })), null, 2),
              }],
            };
            break;
          }

          case 'get_note': {
            const slug = params.arguments?.slug;
            const note = notes.find(n => n.slug === slug || n.slug?.endsWith(`/${slug}`));

            if (!note) {
              result = { content: [{ type: 'text', text: `Note not found: ${slug}` }] };
            } else {
              result = { content: [{ type: 'text', text: JSON.stringify(note, null, 2) }] };
            }
            break;
          }

          case 'list_notes': {
            const folder = params.arguments?.folder || '';
            const limit = params.arguments?.limit || 50;

            const results = notes
              .filter(n => !folder || n.slug?.startsWith(folder))
              .slice(0, limit);

            result = {
              content: [{
                type: 'text',
                text: JSON.stringify(results.map(n => ({
                  slug: n.slug,
                  title: n.title,
                  tags: n.tags,
                })), null, 2),
              }],
            };
            break;
          }

          case 'get_tags': {
            const tagCounts = {};
            notes.forEach(note => {
              (note.tags || []).forEach(tag => {
                tagCounts[tag] = (tagCounts[tag] || 0) + 1;
              });
            });

            result = { content: [{ type: 'text', text: JSON.stringify(tagCounts, null, 2) }] };
            break;
          }

          default:
            result = { content: [{ type: 'text', text: `Unknown tool: ${params.name}` }] };
        }

        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: rpcRequest.id,
          result,
        });
      }

      case 'resources/list':
        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: rpcRequest.id,
          result: {
            resources: notes.map(note => ({
              uri: `note:///${note.slug}`,
              name: note.title,
              mimeType: 'text/markdown',
            })),
          },
        });

      case 'resources/read': {
        const uri = rpcRequest.params?.uri;
        const slug = uri?.replace('note:///', '');
        const note = notes.find(n => n.slug === slug);

        if (!note) {
          return jsonResponse(res, {
            jsonrpc: '2.0',
            id: rpcRequest.id,
            result: { contents: [] },
          });
        }

        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: rpcRequest.id,
          result: {
            contents: [{
              uri,
              mimeType: 'text/markdown',
              text: note.content,
            }],
          },
        });
      }

      default:
        return jsonResponse(res, {
          jsonrpc: '2.0',
          id: rpcRequest.id,
          error: { code: -32601, message: `Method not found: ${rpcRequest.method}` },
        });
    }
  } catch (error) {
    jsonResponse(res, {
      jsonrpc: '2.0',
      id: req.body?.id,
      error: { code: -32603, message: `Internal error: ${error.message}` },
    });
  }
});

// ============================================
// SSE ENDPOINT (Streaming)
// ============================================
app.get('/sse', async (req, res) => {
  try {
    const sessionId = req.query.session;

    if (sessionId) {
      const sessionData = await redis.get(`session:${sessionId}`);
      if (!sessionData) {
        return errorResponse(res, 'Session not found', 404);
      }
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Initial connection
    res.write(`event: open\ndata: {"status":"connected","sessionId":"${sessionId || 'anonymous'}"}\n\n`);

    // Server info
    res.write(`event: message\ndata: ${JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: { serverInfo: { name: 'garden-mcp-server', version: '3.0.0' } },
    })}\n\n`);

    // Keep-alive
    const pingInterval = setInterval(() => {
      res.write(':ping\n\n');
    }, 30000);

    // Cleanup on close
    req.on('close', () => {
      clearInterval(pingInterval);
    });

    // 1 hour max
    setTimeout(() => {
      clearInterval(pingInterval);
      res.end();
    }, 3600000);
  } catch (error) {
    errorResponse(res, `Internal error: ${error.message}`, 500);
  }
});

// ============================================
// 404 Handler
// ============================================
app.use((req, res) => {
  errorResponse(res, 'Not found', 404);
});

// ============================================
// Error Handler
// ============================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  errorResponse(res, `Internal error: ${err.message}`, 500);
});

// ============================================
// Start Server
// ============================================
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║     Garden API Adapter v3.0 (n8n Migration)   ║
╠═══════════════════════════════════════════════╣
║  Port:      ${PORT.toString().padEnd(33)}║
║  n8n:       ${config.N8N_BASE_URL.padEnd(33)}║
║  Redis:     ${config.REDIS_URL.padEnd(33)}║
║  NotebookLM: ${config.NOTEBOOKLM_BASE_URL.slice(0, 31).padEnd(32)}║
╚═══════════════════════════════════════════════╝
  `);
});
