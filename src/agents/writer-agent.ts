import Anthropic from "@anthropic-ai/sdk";
import { memoryTools, executeMemoryTool } from "./tools.js";

const writeTools = memoryTools.filter((t) =>
  [
    "search_memory",
    "read_entity",
    "write_entity",
    "commit_changes",
    "list_entities",
  ].includes(t.name),
);

const SYSTEM_PROMPT = `You are a knowledge garden writer agent. Your role is to process transcripts, notes, or raw text and extract structured knowledge entities from them.

Instructions:
1. First, search the existing knowledge base to understand what entities already exist.
2. Identify key concepts, topics, people, projects, or ideas in the provided text.
3. For each identified concept, either update an existing entity or create a new one.
4. Use wikilinks [[entity-id]] to cross-reference related entities.
5. Preserve existing content when updating - add new information rather than replacing.
6. Use meaningful IDs in kebab-case (e.g., "machine-learning", "project-alpha").
7. Add relevant tags to each entity for categorization.
8. After writing all entities, commit the changes with a descriptive message.

Entity format guidelines:
- Title should be clear and descriptive
- Content should be well-structured markdown
- Use ## headings to organize sections
- Include wikilinks to related entities: [[related-entity-id]]
- Add tags for discoverability`;

export interface WriteResult {
  entitiesCreated: string[];
  entitiesUpdated: string[];
  committed: boolean;
  commitMessage: string;
  toolCalls: number;
}

export async function processTranscript(
  text: string,
  instructions?: string,
): Promise<WriteResult> {
  const client = new Anthropic({
    apiKey: process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY,
    baseURL: process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL,
  });

  const entitiesCreated: string[] = [];
  const entitiesUpdated: string[] = [];
  let committed = false;
  let commitMessage = "";
  let toolCalls = 0;

  const userPrompt = instructions
    ? `Process the following text and extract knowledge entities.\n\nAdditional instructions: ${instructions}\n\nText:\n${text}`
    : `Process the following text and extract knowledge entities.\n\nText:\n${text}`;

  const messages: Anthropic.MessageParam[] = [
    { role: "user", content: userPrompt },
  ];

  let response = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 8192,
    system: SYSTEM_PROMPT,
    tools: writeTools,
    messages,
  });

  const MAX_ITERATIONS = 20;
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

      if (toolName === "write_entity") {
        try {
          const parsed = JSON.parse(result);
          if (parsed.diff) {
            if (parsed.diff.deletions === 0 && parsed.diff.additions > 0) {
              entitiesCreated.push(parsed.id);
            } else {
              entitiesUpdated.push(parsed.id);
            }
          }
        } catch {}
      }

      if (toolName === "commit_changes") {
        try {
          const parsed = JSON.parse(result);
          if (parsed.sha) {
            committed = true;
            commitMessage = parsed.message || "";
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
      tools: writeTools,
      messages,
    });
  }

  return {
    entitiesCreated,
    entitiesUpdated,
    committed,
    commitMessage,
    toolCalls,
  };
}
