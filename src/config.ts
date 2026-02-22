export const config = {
  port: parseInt(process.env.MEMORY_PORT || "3001", 10),
  serviceToken: process.env.NOTEBOOKLM_SERVICE_TOKEN || "",
  githubToken: process.env.GITHUB_TOKEN || "",
  githubRepo: process.env.GITHUB_REPO || "maxfraieho/garden-seedling",
  githubBranch: process.env.GITHUB_BRANCH || "main",
  githubBasePath: process.env.GITHUB_BASE_PATH || "src/site/notes",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY || "",
  maxContextTokens: parseInt(process.env.MAX_CONTEXT_TOKENS || "8000", 10),
  maxDepth: parseInt(process.env.MAX_DEPTH || "4", 10),
} as const;
