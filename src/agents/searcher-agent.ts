import Anthropic from "@anthropic-ai/sdk";
import { memoryTools, executeMemoryTool } from "./tools.js";

const searchTools = memoryTools.filter((t) =>
  ["search_memory", "read_entity", "get_context", "list_entities"].includes(
    t.name,
  ),
);

const SYSTEM_PROMPT = `You are a knowledge assistant for a personal knowledge garden. Your role is to answer questions by searching the knowledge base and providing well-cited answers.

Instructions:
1. Use the search_memory tool to find relevant entities for the user's question.
2. Use read_entity to get full content of the most relevant results.
3. Use get_context to explore related entities when deeper understanding is needed.
4. Synthesize a clear, accurate answer based ONLY on information found in the knowledge base.
5. Always cite your sources by referencing entity titles and IDs.
6. If you cannot find relevant information, say so honestly rather than making things up.
7. When listing entities or providing overviews, use list_entities to see what's available.

Citation format: Use [[entity-id|Entity Title]] for inline citations.`;

export interface ConversationMessage {
  role: "user" | "assistant";
  content: string;
}

export interface SearchResult {
  answer: string;
  citations: Array<{ id: string; title: string }>;
  toolCalls: number;
}

export async function orchestratedSearch(
  conversation: ConversationMessage[],
): Promise<SearchResult> {
  const client = new Anthropic({
    apiKey: process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY,
    baseURL: process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL,
  });

  const citations = new Map<string, string>();
  let toolCalls = 0;

  const messages: Anthropic.MessageParam[] = conversation.map((m) => ({
    role: m.role,
    content: m.content,
  }));

  let response = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 8192,
    system: SYSTEM_PROMPT,
    tools: searchTools,
    messages,
  });

  const MAX_ITERATIONS = 15;
  let iterations = 0;

  while (response.stop_reason === "tool_use" && iterations < MAX_ITERATIONS) {
    iterations++;
    const assistantContent = response.content;

    const toolResults: Anthropic.ToolResultBlockParam[] = [];

    for (const block of assistantContent) {
      if (block.type !== "tool_use") continue;
      toolCalls++;

      const toolName = block.name;
      const toolInput = block.input as Record<string, unknown>;
      const toolId = block.id;

      const result = await executeMemoryTool(toolName, toolInput);

      if (toolName === "read_entity" || toolName === "get_context") {
        try {
          const parsed = JSON.parse(result);
          if (parsed.id && parsed.title) {
            citations.set(parsed.id, parsed.title);
          }
          if (parsed.nodes) {
            for (const node of parsed.nodes) {
              if (node.id && node.title) {
                citations.set(node.id, node.title);
              }
            }
          }
        } catch {}
      }

      if (toolName === "search_memory") {
        try {
          const parsed = JSON.parse(result);
          if (Array.isArray(parsed)) {
            for (const r of parsed) {
              if (r.id && r.title) {
                citations.set(r.id, r.title);
              }
            }
          }
        } catch {}
      }

      toolResults.push({
        type: "tool_result",
        tool_use_id: toolId,
        content: result,
      });
    }

    messages.push({ role: "assistant", content: assistantContent });
    messages.push({ role: "user", content: toolResults });

    response = await client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 8192,
      system: SYSTEM_PROMPT,
      tools: searchTools,
      messages,
    });
  }

  let answer = "";
  for (const block of response.content) {
    if (block.type === "text") {
      answer += block.text;
    }
  }

  return {
    answer,
    citations: [...citations.entries()].map(([id, title]) => ({ id, title })),
    toolCalls,
  };
}
