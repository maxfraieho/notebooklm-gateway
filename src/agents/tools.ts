import type Anthropic from "@anthropic-ai/sdk";
import { memory } from "../memory/adapter.js";

export const memoryTools: Anthropic.Tool[] = [
  {
    name: "search_memory",
    description:
      "Search the knowledge base using BM25 full-text search. Returns matching entities with relevance scores. Use this to find information related to a query.",
    input_schema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "The search query to find relevant entities",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return (default: 5)",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "read_entity",
    description:
      "Read the full content of a specific entity by its ID. Use this after search to get the complete content of a relevant entity.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "The entity ID to read",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "get_context",
    description:
      "Get a graph context from an entity, traversing its links and backlinks up to a configurable depth. Returns related entities forming a knowledge neighborhood.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "The root entity ID to build context from",
        },
        maxDepth: {
          type: "number",
          description: "Maximum traversal depth (default: 4)",
        },
        maxTokens: {
          type: "number",
          description: "Maximum token budget for context (default: 8000)",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "list_entities",
    description:
      "List all entities in the knowledge base. Returns entity IDs, titles, and tags. Use this to get an overview of what's available.",
    input_schema: {
      type: "object" as const,
      properties: {
        limit: {
          type: "number",
          description: "Maximum number of entities to list (default: 50)",
        },
      },
      required: [],
    },
  },
  {
    name: "write_entity",
    description:
      "Create or update an entity in the knowledge base. Provide an ID, title, and markdown content.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "The entity ID (kebab-case, e.g., 'my-new-entity')",
        },
        title: {
          type: "string",
          description: "The entity title",
        },
        content: {
          type: "string",
          description: "The entity content in markdown format",
        },
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Tags for the entity",
        },
      },
      required: ["id", "title", "content"],
    },
  },
  {
    name: "commit_changes",
    description:
      "Commit and push all pending changes to the GitHub repository.",
    input_schema: {
      type: "object" as const,
      properties: {
        message: {
          type: "string",
          description: "The commit message",
        },
      },
      required: ["message"],
    },
  },
];

export async function executeMemoryTool(
  name: string,
  input: Record<string, unknown>,
): Promise<string> {
  try {
    switch (name) {
      case "search_memory": {
        const results = memory.search(
          input.query as string,
          (input.limit as number) || 5,
        );
        return JSON.stringify(results, null, 2);
      }

      case "read_entity": {
        const entity = memory.getEntity(input.id as string);
        if (!entity) return JSON.stringify({ error: "Entity not found" });
        return JSON.stringify(entity, null, 2);
      }

      case "get_context": {
        const graph = memory.getContext(
          input.id as string,
          input.maxDepth as number | undefined,
          input.maxTokens as number | undefined,
        );
        return JSON.stringify(
          {
            root: graph.root,
            totalTokens: graph.totalTokens,
            nodes: graph.nodes.map((n) => ({
              id: n.entity.id,
              title: n.entity.title,
              depth: n.depth,
              relevance: n.relevance,
              content: n.entity.content,
              tags: n.entity.tags,
            })),
          },
          null,
          2,
        );
      }

      case "list_entities": {
        const entities = memory.listEntities();
        const limit = (input.limit as number) || 50;
        return JSON.stringify(
          entities.slice(0, limit).map((e) => ({
            id: e.id,
            title: e.title,
            tags: e.tags,
          })),
          null,
          2,
        );
      }

      case "write_entity": {
        const result = await memory.write({
          id: input.id as string,
          title: input.title as string,
          content: input.content as string,
          tags: input.tags as string[] | undefined,
        });
        return JSON.stringify(
          {
            id: result.entity.id,
            title: result.entity.title,
            diff: {
              additions: result.diff.additions,
              deletions: result.diff.deletions,
            },
          },
          null,
          2,
        );
      }

      case "commit_changes": {
        const commitResult = await memory.commit(input.message as string);
        return JSON.stringify(commitResult, null, 2);
      }

      default:
        return JSON.stringify({ error: `Unknown tool: ${name}` });
    }
  } catch (err) {
    return JSON.stringify({
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
