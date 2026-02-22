import { Mastra } from "@mastra/core/mastra";
import { writerAgent } from "./agents/writer-agent.js";
import { searcherAgent } from "./agents/searcher-agent.js";

export const mastra = new Mastra({
  agents: {
    "memory-writer": writerAgent,
    "memory-searcher": searcherAgent,
  },
});
