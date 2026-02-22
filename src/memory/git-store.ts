import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import * as fs from "node:fs";
import * as path from "node:path";
import { config } from "../config.js";
import { withLock } from "../utils/lock.js";

const REPO_DIR = path.join(process.cwd(), ".git-store");

let initialized = false;

function authHeaders() {
  return {
    headers: {
      Authorization: `Bearer ${config.githubToken}`,
    },
  };
}

export async function initGitStore(): Promise<void> {
  if (initialized) return;

  await withLock("git-init", async () => {
    if (initialized) return;

    if (!fs.existsSync(REPO_DIR)) {
      fs.mkdirSync(REPO_DIR, { recursive: true });
      const url = `https://github.com/${config.githubRepo}.git`;
      await git.clone({
        fs,
        http,
        dir: REPO_DIR,
        url,
        ref: config.githubBranch,
        singleBranch: true,
        depth: 1,
        onAuth: () => ({
          username: "x-access-token",
          password: config.githubToken,
        }),
      });
    }

    initialized = true;
  });
}

export async function pullLatest(): Promise<void> {
  await withLock("git-pull", async () => {
    await git.pull({
      fs,
      http,
      dir: REPO_DIR,
      ref: config.githubBranch,
      singleBranch: true,
      author: { name: "memory-agent", email: "agent@memory.local" },
      onAuth: () => ({
        username: "x-access-token",
        password: config.githubToken,
      }),
    });
  });
}

export async function readFile(relPath: string): Promise<string | null> {
  const fullPath = path.join(REPO_DIR, relPath);
  try {
    return fs.readFileSync(fullPath, "utf-8");
  } catch {
    return null;
  }
}

export async function writeFile(
  relPath: string,
  content: string,
): Promise<void> {
  const fullPath = path.join(REPO_DIR, relPath);
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(fullPath, content, "utf-8");
  await git.add({ fs, dir: REPO_DIR, filepath: relPath });
}

export async function deleteFile(relPath: string): Promise<void> {
  const fullPath = path.join(REPO_DIR, relPath);
  if (fs.existsSync(fullPath)) {
    fs.unlinkSync(fullPath);
    await git.remove({ fs, dir: REPO_DIR, filepath: relPath });
  }
}

export async function commitAndPush(message: string): Promise<string> {
  return withLock("git-commit", async () => {
    const sha = await git.commit({
      fs,
      dir: REPO_DIR,
      message,
      author: { name: "memory-agent", email: "agent@memory.local" },
    });

    await git.push({
      fs,
      http,
      dir: REPO_DIR,
      remote: "origin",
      ref: config.githubBranch,
      onAuth: () => ({
        username: "x-access-token",
        password: config.githubToken,
      }),
    });

    return sha;
  });
}

export async function listFiles(dirPath: string): Promise<string[]> {
  const fullPath = path.join(REPO_DIR, dirPath);
  if (!fs.existsSync(fullPath)) return [];

  const results: string[] = [];
  const entries = fs.readdirSync(fullPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".md")) {
      results.push(path.join(dirPath, entry.name));
    } else if (entry.isDirectory()) {
      const sub = await listFiles(path.join(dirPath, entry.name));
      results.push(...sub);
    }
  }
  return results;
}

export function getRepoDir(): string {
  return REPO_DIR;
}
