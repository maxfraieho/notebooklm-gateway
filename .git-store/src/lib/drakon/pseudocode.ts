// src/lib/drakon/pseudocode.ts
// Wrapper for drakongen browser bundle to generate pseudocode from DRAKON diagrams

declare global {
  interface Window {
    drakongen?: {
      toPseudocode: (drakonJson: string, name: string, filename: string, language: string) => string;
      toMindTree: (mindJson: string, name: string, filename: string, language: string) => string;
      toTree: (drakonJson: string, name: string, filename: string, language: string) => string;
    };
  }
}

let loadPromise: Promise<void> | null = null;

function loadDrakongen(): Promise<void> {
  if (window.drakongen) return Promise.resolve();
  if (loadPromise) return loadPromise;

  loadPromise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = '/libs/drakongen.js';
    script.onload = () => {
      if (window.drakongen) {
        resolve();
      } else {
        reject(new Error('drakongen failed to initialize'));
      }
    };
    script.onerror = () => reject(new Error('Failed to load drakongen.js'));
    document.head.appendChild(script);
  });

  return loadPromise;
}

/**
 * Convert a DRAKON diagram JSON to pseudocode text.
 * Uses the drakongen library from the project root.
 */
export async function diagramToPseudocode(
  diagramJson: object,
  name: string,
  language: string = 'en'
): Promise<string> {
  await loadDrakongen();
  if (!window.drakongen) throw new Error('drakongen not available');

  const jsonString = JSON.stringify(diagramJson);
  const filename = `${name}.drakon`;
  return window.drakongen.toPseudocode(jsonString, name, filename, language);
}

/**
 * Convert a DRAKON diagram JSON to a structured tree (JSON string).
 */
export async function diagramToTree(
  diagramJson: object,
  name: string,
  language: string = 'en'
): Promise<string> {
  await loadDrakongen();
  if (!window.drakongen) throw new Error('drakongen not available');

  const jsonString = JSON.stringify(diagramJson);
  const filename = `${name}.drakon`;
  return window.drakongen.toTree(jsonString, name, filename, language);
}

/**
 * Wrap pseudocode in markdown format for saving as .md file
 */
export function pseudocodeToMarkdown(pseudocode: string, diagramName: string): string {
  const frontmatter = [
    '---',
    `title: "${diagramName}"`,
    `type: pseudocode`,
    `generated: true`,
    `date: "${new Date().toISOString()}"`,
    '---',
    '',
  ].join('\n');

  return frontmatter + pseudocode + '\n';
}
