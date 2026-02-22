# AccessZone Frontend & Integration - Diagnostic Report

**Generated:** 2026-01-15
**Analyst:** Claude Code
**Scope:** Frontend access control, zone rendering, owner UX persistence

---

## Executive Summary

Three critical issues identified in AccessZone frontend implementation:

1. **Problem A (Owner UX):** Access data (Web URL, MCP URL, QR) displayed only at creation, not persistently available
2. **Problem B (Security):** No global access control - public can access entire site without authentication
3. **Problem C (Critical Bug):** Zone pages show blank screen due to missing backend validation and incomplete data response

**Impact:** Owners cannot re-share zones, site is publicly accessible, guest access is completely broken.

**Complexity:** Medium - requires backend API fix for Problem C, frontend-only fixes for A and B.

---

## Problem A: Access Data Loss (Owner UX)

### Symptoms
- Owner creates AccessZone
- Receives Web URL, MCP URL, QR code in creation modal
- **After closing modal** - cannot retrieve these again
- Zone list shows name, TTL, folders - but no access URLs

### Root Cause

**File:** `src/hooks/useAccessZones.ts:62` + `infrastructure/cloudflare/worker/index.js:774-784`

```typescript
// Frontend expects (line 10-22):
interface AccessZone {
  webUrl?: string;   // ❌ Expected
  mcpUrl?: string;   // ❌ Expected
  accessCode?: string; // ✅ Returned
}

// Backend returns (worker line 774-784):
{
  id: zone.zoneId,
  accessCode: zone.accessCode,  // ✅ Returned
  // ❌ webUrl - NOT returned
  // ❌ mcpUrl - NOT returned
}
```

**File:** `src/components/garden/AccessZonesManager.tsx:183-211`

```tsx
{zone.webUrl && (  // ❌ Always false - webUrl is undefined
  <Button onClick={() => copyToClipboard(zone.webUrl!, 'Web URL')}>
    Web URL
  </Button>
)}
```

### Technical Analysis

1. `createZone` (line 105-121) generates URLs **locally** after creation
2. `fetchZones` (line 42-69) loads zones from backend `/zones/list`
3. Backend returns `accessCode` but **not** `webUrl`/`mcpUrl`
4. Frontend buttons have `zone.webUrl &&` guard → never render

### Impact
- **Severity:** High (owner cannot re-share access)
- **User Flow Broken:** Cannot copy URLs after initial creation
- **Workaround:** None - data permanently inaccessible

### Solution

**Approach:** Generate URLs on frontend from returned data (avoid backend changes per constraints)

**Changes Required:**

**File:** `src/hooks/useAccessZones.ts`

Add URL generation helper:
```typescript
function generateZoneUrls(zone: any) {
  const APP_BASE_URL = window.location.origin;
  return {
    ...zone,
    webUrl: zone.accessType !== 'mcp'
      ? `${APP_BASE_URL}/zone/${zone.id}?code=${zone.accessCode}`
      : undefined,
    mcpUrl: zone.accessType !== 'web'
      ? `${MCP_GATEWAY_URL}/mcp/${zone.id}`
      : undefined,
  };
}
```

Apply in `fetchZones` (after line 62):
```typescript
const data = await response.json();
const zonesWithUrls = (data.zones || []).map(generateZoneUrls);
setZones(zonesWithUrls);
```

**Verification:**
- Create zone → close modal
- Reopen AccessZonesManager
- Verify Web URL, MCP URL, QR buttons visible and functional

---

## Problem B: Missing Global Access Gate (Security Critical)

### Symptoms
- Anyone can visit `https://exodus.pp.ua/`
- No authentication required
- Full site navigation accessible
- Owner-only content visible to public

### Root Cause

**File:** `src/App.tsx:40-57`

```tsx
// After checking isInitialized, renders ALL routes:
return (
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<Index />} />           // ❌ Public
      <Route path="/notes/:slug" element={<NotePage />} /> // ❌ Public
      <Route path="/tags" element={<TagsIndex />} />   // ❌ Public
      <Route path="/graph" element={<GraphPage />} />  // ❌ Public
      <Route path="/files" element={<FilesPage />} />  // ❌ Public
      <Route path="/zone/:zoneId" element={<ZoneViewPage />} /> // ✅ Should be only public route
    </Routes>
  </BrowserRouter>
);
```

**File:** `src/hooks/useOwnerAuth.tsx:8-13`

```typescript
interface OwnerAuthState {
  isAuthenticated: boolean;  // ✅ Tracked
  isInitialized: boolean;    // ✅ Checked in App.tsx
  // ❌ No access control enforcement
}
```

### Technical Analysis

1. `AppContent` checks `isInitialized` → shows setup wizard if false
2. If initialized → renders **all routes** without access check
3. `useOwnerAuth.isAuthenticated` exists but **not used** for route protection
4. Zone route (`/zone/:zoneId`) relies on `useZoneValidation` but that's **internal** to component

### Security Impact
- **Severity:** CRITICAL
- **Exposure:** Entire knowledge base publicly accessible
- **Data Leak:** All notes, tags, graph visible without authentication
- **Compliance:** Violates core requirement "fully closed by default"

### Solution

**Approach:** Create Access Guard wrapper component

**New File:** `src/components/AccessGuard.tsx`

```typescript
import { ReactNode } from 'react';
import { useLocation, Navigate } from 'react-router-dom';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { AccessGateUI } from './AccessGateUI';

export function AccessGuard({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { isAuthenticated } = useOwnerAuth();

  // Allow zone access routes (validation happens in ZoneViewPage)
  if (location.pathname.startsWith('/zone/')) {
    return <>{children}</>;
  }

  // Require owner authentication for all other routes
  if (!isAuthenticated) {
    return <AccessGateUI />;
  }

  return <>{children}</>;
}
```

**New File:** `src/components/AccessGateUI.tsx`

```tsx
import { useState } from 'react';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export function AccessGateUI() {
  const [password, setPassword] = useState('');
  const { login } = useOwnerAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await login(password);
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Access Required</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              type="password"
              placeholder="Enter master code"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button type="submit" className="w-full">
              Unlock Garden
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
```

**File:** `src/App.tsx` (modify line 41)

```tsx
return (
  <BrowserRouter>
    <AccessGuard>  {/* 👈 Wrap routes */}
      <SearchHighlightProvider>
        <Routes>
          {/* ... all routes ... */}
        </Routes>
      </SearchHighlightProvider>
    </AccessGuard>
  </BrowserRouter>
);
```

**Verification:**
1. Logout (if authenticated)
2. Visit `/` → should show Access Gate
3. Visit `/notes/anything` → should show Access Gate
4. Visit `/zone/abc123?code=ACCESS-XYZ` → should allow through to ZoneViewPage
5. Enter master password → should unlock site

---

## Problem C: Zone Page Blank Screen (Critical Bug)

### Symptoms
- User clicks zone QR code or URL
- Browser navigates to `/zone/abc123?code=ACCESS-XYZ`
- Shows loading spinner ~1 second
- Then **completely blank white screen**
- No error message, no content, no UI

### Root Cause #1: Backend Missing Access Code Validation

**File:** `infrastructure/cloudflare/worker/index.js:650-672`

```javascript
async function handleZonesValidate(zoneId, env) {
  const zoneData = await env.KV.get(`zone:${zoneId}`);

  if (!zoneData) {
    return errorResponse('Zone not found', 404);
  }

  const zone = JSON.parse(zoneData);

  // ❌ CRITICAL: Never validates accessCode query parameter!
  // Anyone with zoneId can access without code

  if (new Date(zone.expiresAt) < new Date()) {
    return errorResponse('Zone expired', 410);
  }

  return jsonResponse({
    success: true,
    zone: {
      zoneId: zone.zoneId,
      allowedPaths: zone.allowedPaths,
      expiresAt: zone.expiresAt,
      noteCount: zone.noteCount,
      // ❌ Missing fields that frontend expects
    },
  });
}
```

**File:** `src/hooks/useZoneValidation.ts:58-61`

```typescript
const url = new URL(`${MCP_GATEWAY_URL}/zones/validate/${zoneId}`);
if (accessCode) {
  url.searchParams.set('code', accessCode);  // ✅ Sent
}
// ❌ But backend never reads or validates it!
```

### Root Cause #2: Incomplete Response Data

**Frontend Expects (useZoneValidation.ts:13-22):**
```typescript
interface ZoneData {
  id: string;
  name: string;          // ❌ Not returned
  description?: string;  // ❌ Not returned
  folders: string[];     // ❌ Not returned (returns allowedPaths instead)
  noteCount: number;     // ✅ Returned
  notes: ZoneNote[];     // ❌ Not returned
  expiresAt: number;     // ✅ Returned
  accessType: string;    // ❌ Not returned
}
```

**Backend Returns:**
```javascript
{
  zoneId: zone.zoneId,        // ✅
  allowedPaths: zone.allowedPaths,  // ❌ Frontend expects 'folders'
  expiresAt: zone.expiresAt,  // ✅
  noteCount: zone.noteCount,  // ✅
  // Missing: name, description, notes, accessType
}
```

**File:** `src/pages/ZoneViewPage.tsx:146-189`

```tsx
<h1>{zone?.name}</h1>  {/* ❌ undefined → blank */}
<p>{zone?.description}</p>  {/* ❌ undefined → blank */}
{/* ... */}
{zone?.notes.map((note) => (  {/* ❌ undefined.map() → crash or empty */}
  <button>{note.title}</button>
))}
```

### Why Blank Screen?

1. Backend returns incomplete data
2. `zone.name` → `undefined` → header blank
3. `zone.notes` → `undefined` → sidebar empty
4. No notes to select → main content shows "select a note" placeholder
5. Result: completely blank interface

### Security Impact

**CRITICAL:** No access code validation means:
- Anyone who guesses/discovers a `zoneId` can access without code
- QR codes and URLs are security theater
- Zone system is completely insecure

### Solution

**REQUIRED BACKEND FIX** (Cannot avoid - security critical)

**File:** `infrastructure/cloudflare/worker/index.js:650-672`

Replace entire `handleZonesValidate`:

```javascript
async function handleZonesValidate(zoneId, env, request) {
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
    return errorResponse('Zone expired', 410);
  }

  // ✅ RETURN COMPLETE DATA
  return jsonResponse({
    success: true,
    id: zone.zoneId,
    name: zone.name,
    description: zone.description,
    folders: zone.allowedPaths,  // Map to frontend field name
    noteCount: zone.noteCount,
    notes: zone.notes,
    expiresAt: new Date(zone.expiresAt).getTime(),
    accessType: zone.accessType,
  });
}
```

**File:** `infrastructure/cloudflare/worker/index.js:995-998` (router)

Update to pass request object:

```javascript
const validateMatch = path.match(/^\/zones\/validate\/([^\/]+)$/);
if (method === 'GET' && validateMatch) {
  return await handleZonesValidate(validateMatch[1], env, request);  // 👈 Add request
}
```

**Verification Steps:**

1. Create zone → get URL with code
2. Visit URL without `?code=` param → should show "Invalid access code"
3. Visit URL with wrong code `?code=WRONG` → should show "Invalid access code"
4. Visit URL with correct code → should show zone content
5. Verify header shows zone name
6. Verify sidebar shows notes list
7. Click note → verify content renders

---

## Implementation Plan

### Phase 1: Fix Zone Rendering (CRITICAL - Blocks all guest access)

**Priority:** P0 - System broken without this

1. Update backend `handleZonesValidate` to:
   - Validate `code` query parameter
   - Return complete zone data structure
2. Deploy Worker
3. Test zone access with valid/invalid codes

**Files:**
- `infrastructure/cloudflare/worker/index.js` (lines 650-672, 995-998)

**Estimated Effort:** 30 minutes
**Risk:** Low (isolated function, well-defined contract)

---

### Phase 2: Fix Owner Access Data Persistence

**Priority:** P1 - Owner UX broken

1. Add URL generation helper to `useAccessZones.ts`
2. Apply to `fetchZones` result mapping
3. Test zone list shows all buttons

**Files:**
- `src/hooks/useAccessZones.ts` (after line 62)

**Estimated Effort:** 15 minutes
**Risk:** Low (frontend-only, no API changes)

---

### Phase 3: Implement Global Access Gate

**Priority:** P0 - Security critical

1. Create `src/components/AccessGuard.tsx`
2. Create `src/components/AccessGateUI.tsx`
3. Update `src/App.tsx` to wrap routes
4. Test public access blocked, owner login works, zones accessible

**Files:**
- `src/components/AccessGuard.tsx` (new)
- `src/components/AccessGateUI.tsx` (new)
- `src/App.tsx` (line 41)

**Estimated Effort:** 45 minutes
**Risk:** Medium (affects routing, requires careful testing)

---

## Acceptance Criteria Checklist

### Problem A: Owner Access Data
- [ ] Owner can copy Web URL from zone list
- [ ] Owner can copy MCP URL from zone list
- [ ] Owner can show QR code from zone list
- [ ] Data persists across page refreshes
- [ ] No regression in zone creation flow

### Problem B: Access Control
- [ ] Public visitor to `/` sees Access Gate (not content)
- [ ] Public visitor to `/notes/*` sees Access Gate
- [ ] Owner can login via Access Gate
- [ ] After login, owner sees full site
- [ ] Zone URLs (`/zone/:id?code=`) bypass gate (validated internally)

### Problem C: Zone Rendering
- [ ] Valid zone URL shows content (not blank screen)
- [ ] Zone header shows correct name and description
- [ ] Sidebar shows list of notes
- [ ] Clicking note renders content
- [ ] Invalid code shows "Access Denied"
- [ ] Expired zone shows "Expired"
- [ ] Missing zone shows "Not Found"

---

## Risk Assessment

### High Risk Items
1. **Backend API Change (Problem C)** - Breaks existing integrations if deployed incorrectly
   - **Mitigation:** Test with existing zone URLs before deploy

2. **Access Guard (Problem B)** - Could lock out owner if login broken
   - **Mitigation:** Test login flow thoroughly, ensure `/zone/*` bypass works

### Dependencies
- Worker deployment required for Problem C fix
- No external dependencies
- All changes within Garden Bloom codebase

### Rollback Plan
- Problem A: Frontend-only, revert commit
- Problem B: Frontend-only, revert commit
- Problem C: Revert Worker deployment (previous version in git)

---

## Post-Implementation Verification

### Manual Test Checklist
1. [ ] Create new zone with 3 notes
2. [ ] Copy Web URL from zone list
3. [ ] Logout
4. [ ] Visit `/` → verify Access Gate shown
5. [ ] Paste zone URL in new tab → verify content loads
6. [ ] Click through all 3 notes → verify content renders
7. [ ] Login via Access Gate → verify site accessible
8. [ ] Delete zone → verify removed from list

### Automated Test Candidates
- Zone URL generation (unit test)
- Access Guard routing logic (component test)
- Zone validation response parsing (integration test)

---

## Conclusion

**Summary:**
- 3 critical issues identified, all blocking production use
- Problem C requires backend fix (unavoidable for security)
- Problems A & B can be fixed frontend-only
- Total estimated effort: ~90 minutes
- All fixes are surgical, low risk of side effects

**Next Steps:**
1. Get approval for backend API change (Problem C)
2. Implement in order: C → B → A (priority order)
3. Deploy Worker first, then frontend
4. Run full acceptance test suite

**Deployment Order:**
1. Deploy Worker with `handleZonesValidate` fix
2. Verify existing zones still work
3. Deploy frontend with all 3 fixes
4. Run smoke tests

---

**Report Status:** ✅ Complete
**Ready for Implementation:** Yes
**Blocking Issues:** None
