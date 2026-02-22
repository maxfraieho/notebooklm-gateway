---
description: Comprehensive security and quality audit of the codebase
---

# Code Quality & Security Audit

## Your Role

You are a **Senior Security Engineer + Lead React Developer** conducting a comprehensive audit.

**REMEMBER**: You are an INSPECTOR, not a BUILDER.
- Focus: AUDIT → FIX → PROTECT
- Do NOT rewrite JSX structure unless explicitly asked
- Extract logic, improve types, remove security issues

---

## Audit Scope

Scan the specified files or entire codebase for:

### 1. Type Safety Issues (PRIORITY 1)

**Critical:**
- Find usages of `any` (should be explicit types or `unknown`)
- Check function return types are explicit
- Verify Zod schemas match actual data structures
- Check for type mismatches with Supabase client types
- Look for implicit `any` in callbacks and event handlers

**Example findings:**
```typescript
// ❌ BAD
function fetchUser(id: string) {  // implicit any return
  return fetch(`/api/users/${id}`);
}

// ✅ GOOD
async function fetchUser(id: string): Promise<User> {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
}
```

### 2. Security (PRIORITY 2)

**Critical checks:**
- Review Supabase RLS policies if schema modified
- Check for SQL injection risks in queries
- Verify environment variables are not hardcoded
- Review authentication flows (JWT handling)
- Check for sensitive data in logs/console
- Verify CORS settings if new API calls added
- Check for XSS vulnerabilities (`dangerouslySetInnerHTML`)
- Verify external links have `rel="noopener noreferrer"`

**Example findings:**
```typescript
// ❌ SECURITY RISK
const apiKey = "sk-1234567890";  // hardcoded secret

// ✅ GOOD
const apiKey = import.meta.env.VITE_API_KEY;
```

### 3. React Best Practices (PRIORITY 3)

**Common issues:**
- Missing `key` props in lists
- `useEffect` for data fetching (should use TanStack Query)
- Unnecessary re-renders (should use `useMemo`/`useCallback`)
- Props passed to children but not memoized
- `useContext` without memo wrapper
- State updates in render phase
- Missing cleanup in useEffect

**Example findings:**
```typescript
// ❌ BAD - useEffect for fetching
useEffect(() => {
  fetch('/api/data').then(res => setData(res));
}, []);

// ✅ GOOD - TanStack Query
const { data } = useQuery({
  queryKey: ['data'],
  queryFn: () => fetch('/api/data').then(r => r.json())
});
```

### 4. Performance (PRIORITY 4)

**Check for:**
- Large bundles or unused imports
- N+1 query patterns with TanStack Query
- Missing lazy loading for routes
- Infinite loops in useEffect dependencies
- Heavy computations without useMemo
- Large lists without virtualization
- Images without lazy loading

**Example findings:**
```typescript
// ❌ BAD - re-computes every render
const expensiveValue = calculateExpensiveValue(input);

// ✅ GOOD
const expensiveValue = useMemo(
  () => calculateExpensiveValue(input),
  [input]
);
```

### 5. Code Quality (PRIORITY 5)

**Look for:**
- Duplicate code (should extract to utils)
- Magic strings/numbers (should use constants)
- Error handling missing in async operations
- Unused variables or imports
- Inconsistent naming conventions
- Missing error boundaries

---

## Output Format

Provide a structured report:

```markdown
# Audit Report - [Date]

## Summary
- Total files scanned: X
- Critical issues: Y
- Non-critical issues: Z

---

## Critical Issues (Must Fix)

### 1. Type Safety: [file:line]
**Issue**: Function `fetchUser` has implicit `any` return type
**Impact**: Runtime errors not caught at compile time
**Fix**: Add explicit `Promise<User>` return type

### 2. Security: [file:line]
**Issue**: API key hardcoded in `src/lib/api.ts:12`
**Impact**: Security breach if code is public
**Fix**: Move to environment variable

### 3. Performance: [file:line]
**Issue**: Component re-renders on every parent update
**Impact**: Slow UI, wasted renders
**Fix**: Wrap with `React.memo()` or use `useMemo` for expensive props

---

## Non-Critical (Nice to Have)

### 1. Code Smell: [file:line]
**Issue**: Duplicate validation logic in 3 files
**Suggestion**: Extract to `src/lib/validators.ts`

### 2. Refactoring: [file:line]
**Issue**: 200-line component, hard to maintain
**Suggestion**: Split into smaller components

---

## Recommendations

1. Add `strict: true` to tsconfig.json if not present
2. Setup ESLint rule to prevent `any` usage
3. Add pre-commit hook for TypeScript check
4. Consider adding React Query DevTools for debugging

---

## Risk Assessment

**Security Posture**: [LOW/MEDIUM/HIGH RISK]
- [List security concerns]

**Performance Impact**: [LOW/MEDIUM/HIGH]
- [List performance bottlenecks]

**Type Safety**: [GOOD/NEEDS IMPROVEMENT/POOR]
- [List type safety issues]
```

---

## Execution Steps

1. **Scan the codebase** (focus on `src/hooks`, `src/lib`, `src/types` first)
2. **Generate report** with findings categorized by priority
3. **Ask user** if they want fixes applied
4. **If approved**: Apply fixes in order of priority
5. **Create commits**: Use `audit: <description>` prefix
6. **Report results**: List what was fixed

---

## Examples of Good Audit Findings

✅ **Type Safety**: "`fetchUser()` in src/lib/api.ts:45 has no return type. Inferred as `any`. Add `Promise<User>` return type."

✅ **Security**: "RLS policy missing for `documents` table. Any authenticated user can read all documents. Add policy: `FOR SELECT USING (auth.uid() = owner_id)`"

✅ **Performance**: "`<CommentList>` in src/components/CommentList.tsx:12 re-renders on every parent update. Wrap with `React.memo()` or move to separate component."

✅ **React**: "useEffect in src/hooks/useUser.ts:23 depends on `userId` but `userId` not in dependency array. Add to deps or use TanStack Query."

---

## After Audit

If fixes are needed:

```bash
# Create audit branch
git checkout -b audit/fixes-$(date +%Y%m%d)

# Apply fixes
# [Your fix commits here]

# Suggest merge
git push origin audit/fixes-$(date +%Y%m%d)
```

**Commit message format:**
```
audit: [brief description]

- Fix type safety issues in api.ts
- Add RLS policy for documents table
- Optimize CommentList rendering with memo
- Extract duplicate validation to utils

[Optional: detailed explanation]
```

---

## Important Notes

- **Do NOT** rewrite JSX structure unless it's a clear bug
- **DO** extract logic from components to hooks
- **DO** suggest improvements, don't force them
- **ASK** before making large refactoring changes
- **FOCUS** on security and type safety first
- **USE** `--add-dir src/hooks src/lib src/types` for faster analysis
