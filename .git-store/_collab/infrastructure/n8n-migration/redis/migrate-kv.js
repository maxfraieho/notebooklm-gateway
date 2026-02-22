#!/usr/bin/env node
/**
 * Migrate data from Cloudflare KV to Redis
 *
 * Usage:
 *   1. Export KV data using wrangler CLI
 *   2. Run this script with the exported JSON
 *
 * Example:
 *   node migrate-kv.js --input kv-export.json --redis redis://localhost:6379
 */

import { createClient } from 'redis';
import { readFileSync, existsSync } from 'fs';
import { parseArgs } from 'util';

// Parse CLI arguments
const { values } = parseArgs({
  options: {
    input: { type: 'string', short: 'i' },
    redis: { type: 'string', short: 'r', default: 'redis://localhost:6379' },
    dry: { type: 'boolean', short: 'd', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

if (values.help) {
  console.log(`
Migrate Cloudflare KV to Redis

Usage:
  node migrate-kv.js --input <file.json> [--redis <url>] [--dry]

Options:
  -i, --input   Path to KV export JSON file (required)
  -r, --redis   Redis URL (default: redis://localhost:6379)
  -d, --dry     Dry run - don't write to Redis
  -h, --help    Show this help

KV Export Format:
  [
    { "key": "owner_initialized", "value": "true" },
    { "key": "zone:abc123", "value": "{...json...}", "expiration": 1738500000 }
  ]

Steps to export from Cloudflare:
  1. wrangler kv:key list --namespace-id=YOUR_ID > keys.json
  2. For each key, use wrangler kv:key get to fetch value
  3. Combine into the format above
  `);
  process.exit(0);
}

if (!values.input) {
  console.error('ERROR: --input is required');
  process.exit(1);
}

if (!existsSync(values.input)) {
  console.error(`ERROR: File not found: ${values.input}`);
  process.exit(1);
}

// Read KV export
console.log(`Reading KV export from: ${values.input}`);
const kvData = JSON.parse(readFileSync(values.input, 'utf-8'));

if (!Array.isArray(kvData)) {
  console.error('ERROR: KV export must be an array');
  process.exit(1);
}

console.log(`Found ${kvData.length} keys to migrate`);

if (values.dry) {
  console.log('\n=== DRY RUN - No changes will be made ===\n');

  for (const item of kvData) {
    const ttl = item.expiration
      ? Math.floor((item.expiration * 1000 - Date.now()) / 1000)
      : null;

    console.log(`Key: ${item.key}`);
    console.log(`  Value length: ${item.value?.length || 0} bytes`);
    if (ttl !== null) {
      if (ttl > 0) {
        console.log(`  TTL: ${ttl} seconds`);
      } else {
        console.log(`  EXPIRED (skipping)`);
      }
    }
    console.log('');
  }

  process.exit(0);
}

// Connect to Redis
console.log(`Connecting to Redis: ${values.redis}`);
const redis = createClient({ url: values.redis });
redis.on('error', (err) => console.error('Redis error:', err));
await redis.connect();

// Migrate each key
let migrated = 0;
let skipped = 0;
let errors = 0;

for (const item of kvData) {
  try {
    const { key, value, expiration } = item;

    // Skip expired keys
    if (expiration) {
      const ttl = Math.floor((expiration * 1000 - Date.now()) / 1000);
      if (ttl <= 0) {
        console.log(`SKIP (expired): ${key}`);
        skipped++;
        continue;
      }

      // Set with TTL
      await redis.set(key, value, { EX: ttl });
      console.log(`SET (TTL ${ttl}s): ${key}`);
    } else {
      // Set without TTL
      await redis.set(key, value);
      console.log(`SET: ${key}`);
    }

    migrated++;
  } catch (err) {
    console.error(`ERROR: ${item.key} - ${err.message}`);
    errors++;
  }
}

await redis.disconnect();

console.log(`
=== Migration Complete ===
Migrated: ${migrated}
Skipped:  ${skipped}
Errors:   ${errors}
Total:    ${kvData.length}
`);

process.exit(errors > 0 ? 1 : 0);
