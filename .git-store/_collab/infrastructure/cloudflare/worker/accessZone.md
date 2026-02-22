# AccessZone Logic

## Поточний стан (оновлено)

**СТАТУС:** 🟢 ПРАЦЮЄ + Collaborative Editing

### Можливості

AccessZone тепер підтримує:
1. ✅ Створення зон з TTL
2. ✅ Web/MCP/Both доступ
3. ✅ NotebookLM інтеграція
4. ✅ **Collaborative Editing** — гості можуть пропонувати зміни

## Collaborative Editing API

### Proposal Endpoints

```javascript
// Guest creates edit proposal
POST /zones/:zoneId/proposals
Headers: X-Zone-Code: ACCESS-XXXXXXXX
Body: {
  "noteSlug": "note-slug",
  "noteTitle": "Note Title",
  "originalContent": "...",
  "proposedContent": "...",
  "guestName": "Guest Name",
  "guestEmail": "email@example.com"
}
Response: { success: true, proposal: {...} }

// List proposals for zone (owner or guest)
GET /zones/:zoneId/proposals?status=pending
Headers: Authorization: Bearer <token> OR X-Zone-Code: <code>
Response: { success: true, proposals: [...], total: N }

// Owner lists all pending proposals
GET /proposals/pending?limit=20
Headers: Authorization: Bearer <token>
Response: { success: true, proposals: [...] }

// Get single proposal
GET /proposals/:proposalId
Headers: Authorization: Bearer <token> OR X-Zone-Code: <code>
Response: { success: true, proposal: {...} }

// Owner accepts proposal
POST /proposals/:proposalId/accept
Headers: Authorization: Bearer <token>
Response: { success: true, proposal: {...} }

// Owner rejects proposal
POST /proposals/:proposalId/reject
Headers: Authorization: Bearer <token>
Response: { success: true, proposal: {...} }
```

### Proposal KV Storage

```javascript
// Key patterns
proposal:{proposalId} → {
  proposalId,
  zoneId,
  zoneName,
  noteSlug,
  noteTitle,
  originalContent,
  proposedContent,
  guestName,
  guestEmail,
  status: 'pending' | 'accepted' | 'rejected',
  createdAt,
  updatedAt,
  reviewedAt
}

// Indexes
proposals:zone:{zoneId} → [proposalId, ...]
proposals:pending → [proposalId, ...] // global pending list
```

## Frontend Flow

1. Гість відкриває `/zone/:zoneId?code=...`
2. Обирає нотатку, натискає Edit (іконка олівця)
3. Переходить на `/zone/:zoneId/edit/:noteSlug?code=...`
4. Редагує контент, натискає "Submit Proposal"
5. Власник бачить нову пропозицію в Chat → Proposals Inbox
6. Власник переглядає diff, Accept або Reject
7. При Accept: контент нотатки оновлюється в zone KV та MinIO

## Пов'язані файли

- Worker код: `./index.js`
- Frontend API client: `src/lib/api/mcpGatewayClient.ts`
- Frontend hook: `src/hooks/useAccessZones.ts`
- Zone Edit Page: `src/pages/ZoneEditPage.tsx`
- Proposals Inbox: `src/components/garden/ProposalsInbox.tsx`
- Diff View: `src/components/garden/ProposalDiffView.tsx`
