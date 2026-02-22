import { Agent } from "@mastra/core/agent";
import { createAnthropic } from "@ai-sdk/anthropic";
import {
  readMemoryTool,
  searchMemoryTool,
  listEntitiesTool,
  getContextTool,
} from "./tools.js";

const anthropic = createAnthropic({
  apiKey: process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL,
});

export const searcherAgent = new Agent({
  id: "memory-searcher",
  name: "memory-searcher",
  model: anthropic("claude-sonnet-4-5"),
  instructions: `You answer questions by searching the knowledge base.

Process:
1. Decompose the user question into 1-3 focused sub-queries
2. Search memory for each sub-query
3. Read full content of top 2-3 relevant matches
4. For deeper understanding, use get-context to explore related entities
5. Synthesize a clear answer with specific citations

Always return your answer in this structure:
- A clear, direct answer to the question
- Specific references to entity IDs you used (e.g., "according to people/max...")

Citation format: Use [[entity-id|Entity Title]] for inline citations.

If you cannot find relevant information, say so explicitly.`,
  tools: {
    "read-memory": readMemoryTool,
    "search-memory": searchMemoryTool,
    "list-entities": listEntitiesTool,
    "get-context": getContextTool,
  },
});
