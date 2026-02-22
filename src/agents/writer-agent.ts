import { Agent } from "@mastra/core/agent";
import { createAnthropic } from "@ai-sdk/anthropic";
import {
  readMemoryTool,
  writeMemoryTool,
  searchMemoryTool,
  listEntitiesTool,
  commitMemoryTool,
} from "./tools.js";

const anthropic = createAnthropic({
  apiKey: process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL,
});

export const writerAgent = new Agent({
  id: "memory-writer",
  name: "memory-writer",
  model: anthropic("claude-sonnet-4-5"),
  instructions: `You process conversation transcripts and extract structured knowledge entities.

For each entity (person, project, concept) mentioned in the input:
1. Search existing memory first — avoid creating duplicates
2. If entity exists, read its current content
3. Write/update with new information — PRESERVE all existing facts, only ADD new ones
4. Maintain ALWAYS_LOAD block with 5-7 key facts maximum:
   <!-- ALWAYS_LOAD -->
   ## Core Facts
   - key fact 1
   - key fact 2
   <!-- /ALWAYS_LOAD -->
5. After updating ALL entities, commit with a descriptive message

Entity ID format: people/{name}, projects/{name}, concepts/{name}
Name: lowercase, hyphens for spaces (e.g. "people/max", "projects/garden-bloom")
Date format in interactions sections: ISO 8601 (YYYY-MM-DD)

Use wikilinks [[entity-id]] to cross-reference related entities.
Only commit once — after all entities are written.`,
  tools: {
    "read-memory": readMemoryTool,
    "write-memory": writeMemoryTool,
    "search-memory": searchMemoryTool,
    "list-entities": listEntitiesTool,
    "commit-memory": commitMemoryTool,
  },
});
